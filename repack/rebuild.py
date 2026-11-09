"""SDK primitives shared by the M0 fixture builder and later rebuild work."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[1]


class PrerequisiteError(RuntimeError):
    pass


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
    os.replace(temporary, path)


def report_reference(index: Path) -> dict:
    """Resolve a mutable report index to its matching immutable per-run record."""
    summary = json.loads(index.read_text())
    references = summary.get('evidence_refs', [])
    if not references:
        raise PrerequisiteError(str(index) + ' immutable report reference missing')
    immutable = Path(references[0])
    if not immutable.is_file():
        raise PrerequisiteError(str(index) + ' immutable report missing')
    raw = json.loads(immutable.read_text())
    if ({k: v for k, v in summary.items() if k != 'evidence_refs'} !=
            {k: v for k, v in raw.items() if k != 'evidence_refs'}):
        raise RuntimeError(str(index) + ' summary differs from its immutable report')
    return {'path': str(immutable), 'sha256': sha256(immutable), 'index': str(index)}


def source_hash() -> str:
    digest = hashlib.sha256()
    for folder in ('repack', 'scripts', 'shim', 'tools', 'native', 'tests/fixtures'):
        for path in sorted((ROOT / folder).rglob('*')):
            if path.is_file() and path.suffix in ('.py', '.java', '.xml', '.c', '.h', '.cpp', '.S', '.dart', '.yaml', '.lock', '.js'):
                digest.update(str(path.relative_to(ROOT)).encode() + b'\0' + path.read_bytes())
    return digest.hexdigest()


def fixture_source_hash() -> str:
    """Fingerprint only sources that determine the original fixture artifacts."""
    digest = hashlib.sha256()
    paths = [ROOT / 'repack/rebuild.py', ROOT / 'scripts/build_fixtures.py']
    paths.extend(path for path in (ROOT / 'tests/fixtures').rglob('*')
                 if path.is_file() and path.suffix in ('.java', '.xml', '.c', '.h', '.cpp', '.S'))
    for path in sorted(paths):
        digest.update(str(path.relative_to(ROOT)).encode() + b'\0' + path.read_bytes())
    return digest.hexdigest()


def report(case: str) -> tuple[dict, Path]:
    run_id = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S') + '-' + uuid.uuid4().hex[:10]
    evidence = ROOT / '.work/evidence/runs' / run_id
    evidence.mkdir(parents=True, mode=0o700)
    return {
        'schema_version': 1, 'run_id': run_id, 'case_id': case, 'source_sha256': source_hash(),
        'transformation': 'skipped', 'verification': 'not-run', 'enforcement': 'unknown',
        'cell': None, 'process': {'name': None, 'pid': None}, 'inputs': [], 'outputs': [],
        'signer_sha256': [], 'comparisons': [], 'prerequisite_failures': [],
        'device_mutations': [], 'cleanup': [], 'logs': [], 'evidence_refs': [],
        'command': {'argv': [], 'exit_status': None},
    }, evidence


def execute(argv: list[str], evidence: Path, label: str, *, env=None, check=True, timeout=120):
    argv = [str(x) for x in argv]
    timed_out = False
    try:
        completed = subprocess.run(argv, stdin=subprocess.DEVNULL, text=True, capture_output=True,
                                   env=env, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        timed_out = True
        stdout = error.stdout or ''
        stderr = error.stderr or ''
        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors='replace')
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors='replace')
        completed = subprocess.CompletedProcess(argv, 124, stdout, stderr)
    write_json(evidence / (label + '.command.json'), {'argv': argv, 'exit_status': completed.returncode,
                                                    'timed_out': timed_out, 'timeout_seconds': timeout})
    (evidence / (label + '.stdout.log')).write_text(completed.stdout)
    (evidence / (label + '.stderr.log')).write_text(completed.stderr)
    if check and completed.returncode:
        raise RuntimeError(f'{label} exited {completed.returncode}; see {evidence / (label + ".stderr.log")}')
    return completed


def load_lock() -> dict:
    path = ROOT / 'config/implementation-lock.json'
    if not path.exists():
        raise PrerequisiteError('Run acceptance.py host first')
    return json.loads(path.read_text())


def environment(lock: dict) -> dict:
    env = os.environ.copy()
    env['JAVA_HOME'] = lock['jdk_path']
    if lock.get('adb_server_socket') and not env.get('ADB_SERVER_SOCKET'):
        env['ADB_SERVER_SOCKET'] = lock['adb_server_socket']
    return env


def tool(lock: dict, name: str) -> str:
    return lock['tools'][name]['path']


def signer_records(text: str) -> list[dict]:
    return [{'min_sdk': int(low) if low else None, 'max_sdk': int(high) if high else None, 'sha256': digest.lower()}
            for low, high, digest in re.findall(
                r'^Signer (?:#\d+|\(minSdkVersion=(\d+), maxSdkVersion=(\d+)\)) certificate SHA-256 digest:\s*([0-9a-fA-F]{64})$', text, re.M)]


def signer_digests(apk: Path, lock: dict, evidence: Path, label: str, *, api: int | None = None) -> list[str]:
    flags = ['--min-sdk-version', str(api), '--max-sdk-version', str(api)] if api is not None else []
    result = execute([tool(lock, 'apksigner'), 'verify', '--verbose', '--print-certs', *flags, str(apk)],
                     evidence, label, env=environment(lock))
    values = [item['sha256'] for item in signer_records(result.stdout)
              if api is None or item['min_sdk'] is None or item['min_sdk'] <= api <= item['max_sdk']]
    if not values:
        raise RuntimeError('apksigner did not report a verified signer')
    return sorted(set(x.lower() for x in values))


def ensure_keys(lock: dict, evidence: Path) -> dict:
    directory = ROOT / '.work/keys'
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    password = directory / 'fixture.pass'
    existing = [directory / (name + '.p12') for name in ('original', 'other', 'repack')]
    if not password.exists():
        if any(path.exists() for path in existing):
            raise PrerequisiteError('Existing fixture keys have no password file; restore credentials')
        with os.fdopen(os.open(password, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as stream:
            stream.write(secrets.token_urlsafe(32) + '\n')
    result = {}
    for name, key in zip(('original', 'other', 'repack'), existing):
        args = [tool(lock, 'keytool'), '-keystore', str(key), '-storepass:file', str(password)]
        if not key.exists():
            execute([args[0], '-genkeypair', *args[1:], '-alias', name, '-keyalg', 'RSA',
                     '-keysize', '2048', '-validity', '3650', '-storetype', 'PKCS12',
                     '-keypass:file', str(password), '-dname', f'CN=Repack fixture {name}'],
                    evidence, f'key-{name}-create', env=environment(lock))
            key.chmod(0o600)
        exported = evidence / f'{name}-cert.der'
        execute([args[0], '-exportcert', *args[1:], '-alias', name, '-file', str(exported)],
                evidence, f'key-{name}-export', env=environment(lock))
        result[name] = {'path': str(key), 'alias': name, 'password_file': str(password),
                        'certificate': str(exported), 'sha256': sha256(exported)}
    if len({x['sha256'] for x in result.values()}) != 3:
        raise RuntimeError('Fixture original, other and repack identities must differ')
    return result


def align_sign(unsigned: Path, out: Path, key: dict, lock: dict, evidence: Path) -> None:
    aligned = out.with_suffix('.aligned.apk')
    execute([tool(lock, 'zipalign'), '-P', '16', '-f', '4', str(unsigned), str(aligned)],
            evidence, 'align', env=environment(lock))
    execute([tool(lock, 'apksigner'), 'sign', '--ks', key['path'], '--ks-key-alias', key['alias'],
             '--ks-pass', 'file:' + key['password_file'],
             *(['--key-pass', 'file:' + key['key_password_file']] if key.get('key_password_file') else []),
             '--out', str(out), str(aligned)], evidence, 'sign', env=environment(lock))
    execute([tool(lock, 'zipalign'), '-c', '-P', '16', '4', str(out)], evidence, 'alignment-check')
    if signer_digests(out, lock, evidence, 'signature-check') != [key['sha256']]:
        raise RuntimeError('APK signer differs from independently exported key certificate')


def badging(apk: Path, lock: dict, evidence: Path, label: str) -> tuple[dict, str]:
    text = execute([tool(lock, 'aapt2'), 'dump', 'badging', str(apk)], evidence, label).stdout
    match = re.search(r"package: name='([^']+)' versionCode='([^']+)'", text)
    if not match:
        raise RuntimeError('Missing APK package/version metadata')
    return {'package': match[1], 'version_code': int(match[2])}, text


def copy_archive(original: Path, unsigned: Path, replacements: dict[str, bytes] | None = None,
                 additions: dict[str, bytes] | None = None) -> list[dict]:
    """Copy unedited entry payloads and methods into a fresh unsigned ZIP."""
    if original.resolve() == unsigned.resolve():
        raise RuntimeError('In-place APK replacement is forbidden')
    replacements, additions = replacements or {}, additions or {}
    preserved = []
    with zipfile.ZipFile(original) as archive, zipfile.ZipFile(unsigned, 'w') as target:
        names = archive.namelist()
        if len(names) != len(set(names)) or not set(replacements).issubset(names) or set(additions) & set(names):
            raise RuntimeError('Ambiguous, missing or colliding ZIP entries')
        for item in archive.infolist():
            if item.filename == 'stamp-cert-sha256':
                continue  # Distribution stamp is invalid after editing; apksigner removes it.
            if item.filename.startswith('META-INF/') and item.filename.upper().endswith(('.SF', '.RSA', '.DSA', '.EC', 'MANIFEST.MF')):
                continue
            data = replacements.get(item.filename, archive.read(item.filename))
            target.writestr(item, data)
            if item.filename not in replacements:
                preserved.append({'entry': item.filename, 'sha256': hashlib.sha256(data).hexdigest(),
                                  'compression': item.compress_type})
        for name, data in additions.items():
            target.writestr(name, data, compress_type=zipfile.ZIP_STORED)
    return preserved


def build_fixture(module: str, variant: str, key: dict, core: Path | None,
                  lock: dict, output: Path, evidence: Path) -> dict:
    output.mkdir(parents=True)
    evidence.mkdir(parents=True)
    fixture = ROOT / 'tests/fixtures/identity'
    manifest = (fixture / module / 'AndroidManifest.xml').read_text()
    if variant == 'androidx':
        manifest = manifest.replace('dev.repack.fixture.common.FixtureFactory',
                                    'androidx.core.app.CoreComponentFactory')
    source_manifest = output / 'AndroidManifest.xml'
    source_manifest.write_text(manifest)
    resources = output / 'resources.zip'
    linked = output / 'linked.apk'
    classes = output / 'classes'
    dex = output / 'dex'
    classes.mkdir()
    dex.mkdir()
    execute([tool(lock, 'aapt2'), 'compile', '--dir', str(fixture / 'common/res'),
             '-o', str(resources)], evidence, 'resource-compile')
    execute([tool(lock, 'aapt2'), 'link', '-o', str(linked), '-I', lock['android_jar'],
             '--manifest', str(source_manifest), '--min-sdk-version', '28',
             '--target-sdk-version', '35', str(resources)], evidence, 'resource-link')
    sources = sorted((fixture / 'common/src').rglob('*.java')) + sorted((fixture / module / 'src').rglob('*.java'))
    execute([tool(lock, 'javac'), '--release', '8', '-classpath', lock['android_jar'],
             '-d', str(classes), *map(str, sources)], evidence, 'java-compile', env=environment(lock))
    program = output / 'program.jar'
    with zipfile.ZipFile(program, 'w') as jar:
        for path in sorted(classes.rglob('*.class')):
            jar.write(path, str(path.relative_to(classes)))
    inputs = [str(program)] + ([str(core)] if variant == 'androidx' else [])
    execute([tool(lock, 'd8'), '--release', '--min-api', '28', '--lib', lock['android_jar'],
             '--output', str(dex), *inputs], evidence, 'dex', env=environment(lock))
    unsigned = output / 'unsigned.apk'
    with zipfile.ZipFile(linked) as original, zipfile.ZipFile(unsigned, 'w') as target:
        for item in original.infolist():
            target.writestr(item, original.read(item.filename))
        for path in sorted(dex.glob('classes*.dex')):
            target.write(path, path.name, compress_type=zipfile.ZIP_STORED)
    apk = output / 'fixture.apk'
    align_sign(unsigned, apk, key, lock, evidence)
    info, text = badging(apk, lock, evidence, 'badging')
    if ('application-debuggable' in text or not re.search(r"(?:minSdkVersion|sdkVersion):'28'", text)
            or "targetSdkVersion:'35'" not in text):
        raise RuntimeError('Fixture is not the requested non-debuggable min28/target35 build')
    xml = execute([tool(lock, 'aapt2'), 'dump', 'xmltree', str(apk), '--file', 'AndroidManifest.xml'],
                  evidence, 'manifest-tree').stdout
    nsc = execute([tool(lock, 'aapt2'), 'dump', 'xmltree', str(apk), '--file',
                   'res/xml/network_security_config.xml'], evidence, 'nsc-tree').stdout
    factory = 'androidx.core.app.CoreComponentFactory' if variant == 'androidx' else 'dev.repack.fixture.common.FixtureFactory'
    if factory not in xml or '127.0.0.1' not in nsc or 'cleartextTrafficPermitted' not in nsc:
        raise RuntimeError('Compiled factory/NSC references were not found')
    return {**info, 'id': module + '-' + variant, 'variant': variant, 'apk': str(apk),
            'sha256': sha256(apk), 'signer_sha256': [key['sha256']], 'factory': factory,
            'min_sdk': 28, 'target_sdk': 35, 'evidence': str(evidence)}
