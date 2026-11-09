"""Compile the public-SDK manifest bootstrap and edit its binary manifest attribute."""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import urllib.request
import zipfile

from .rebuild import ROOT, PrerequisiteError, align_sign, badging, copy_archive, environment, execute, sha256, tool, write_json

ARSCLIB_URL = 'https://github.com/REAndroid/ARSCLib/releases/download/V1.4.0/ARSCLib-1.4.0.jar'
ARSCLIB_SHA256 = '0cc95b160ba4c731a5cadb455f32b79f4e64b4160bc5ec3e5183ea3676b385ce'
FACTORY = 'dev.repack.shim.RepackFactory'


def parse_proxy(endpoint: str) -> dict:
    """Parse a baked HTTP CONNECT endpoint before producing any artifact."""
    if not isinstance(endpoint, str) or not endpoint or re.search(r'[\s/@?#\\]', endpoint):
        raise ValueError('Proxy must be host:port or [IPv6]:port')
    if endpoint.startswith('['):
        match = re.fullmatch(r'\[([^%\]]+)\]:([0-9]+)', endpoint)
        if not match:
            raise ValueError('Invalid bracketed IPv6 endpoint')
        host, port = str(ipaddress.IPv6Address(match[1])), match[2]
    else:
        match = re.fullmatch(r'([^:]+):([0-9]+)', endpoint)
        if not match:
            raise ValueError('Invalid host:port endpoint')
        host, port = match.groups()
        host = host.encode('idna').decode('ascii').lower()
        if len(host) > 253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                                      for label in host.split('.')):
            raise ValueError('Invalid proxy hostname')
        if re.fullmatch(r'[0-9.]+', host):
            host = str(ipaddress.IPv4Address(host))
    port = int(port)
    if not 1 <= port <= 65535:
        raise ValueError('Proxy port outside 1..65535')
    return {'host': host, 'port': port}


def manifest_editor(lock: dict, evidence: Path) -> tuple[Path, Path]:
    directory = ROOT / '.work/tools/arsclib-1.4.0'
    directory.mkdir(parents=True, exist_ok=True)
    jar = directory / 'ARSCLib-1.4.0.jar'
    if not jar.exists():
        data = urllib.request.urlopen(ARSCLIB_URL, timeout=60).read()
        if hashlib.sha256(data).hexdigest() != ARSCLIB_SHA256:
            raise RuntimeError('ARSCLib download checksum mismatch')
        jar.write_bytes(data)
    if sha256(jar) != ARSCLIB_SHA256:
        raise RuntimeError('Pinned ARSCLib artifact changed')
    classes = directory / 'editor-classes'
    classes.mkdir(exist_ok=True)
    source = ROOT / 'tools/ManifestEdit.java'
    execute([tool(lock, 'javac'), '--release', '8', '-classpath', str(jar) + ':' + lock['android_jar'],
             '-d', str(classes), str(source)], evidence, 'manifest-editor-compile', env=environment(lock))
    return jar, classes


def edit_manifest(manifest: bytes, out: Path, lock: dict, evidence: Path, factory=None, *, clear_factory=False) -> dict:
    jar, classes = manifest_editor(lock, evidence)
    original = evidence / 'original-manifest.axml'
    original.write_bytes(manifest)
    args = (['clear-factory', str(original), str(out)] if clear_factory else
            ['inspect', str(original)] if factory is None else ['factory', str(original), str(out), factory])
    completed = execute([tool(lock, 'java'), '-classpath', str(classes) + ':' + str(jar),
                         'ManifestEdit', *args], evidence, 'manifest-edit', env=environment(lock))
    metadata = {}
    for line in completed.stdout.splitlines():
        name, separator, value = line.partition('=')
        if separator and name in ('package', 'factory'):
            metadata[name] = base64.b64decode(value).decode()
    if set(metadata) != {'package', 'factory'}:
        raise RuntimeError('Manifest editor did not return package/factory metadata')
    metadata['editor'] = {'name': 'ARSCLib', 'version': '1.4.0', 'sha256': ARSCLIB_SHA256,
                          'license': 'Apache-2.0', 'source_url': ARSCLIB_URL}
    return metadata


def build_bootstrap(original: Path, out: Path, key: dict, lock: dict, evidence: Path,
                    *, proxy: dict | None = None, fixture_request: dict | None = None,
                    identity_mode: str = 'none', probe_token: str = '',
                    original_certificates: list[bytes] | None = None, original_scheme: int = 0,
                    fixture_early_query: dict | None = None,
                    historical_certificates: list[bytes] | None = None, signing_contracts: bool = False,
                    fixture_bad_signing_layout: bool = False, fixture_cache: dict | None = None,
                    package_binder: bool = False, fixture_binder: dict | None = None,
                    identity_input_sha256: str | None = None,
                    integrity: dict | None = None, retained_original: bytes | None = None, gadget: dict | None = None) -> dict:
    if identity_mode not in ('none', 'ordinary-probe', 'identity-access', 'public-metadata', 'identity', 'identity-failure', 'identity-archive', 'identity-deferred'):
        raise ValueError('Identity mode is not implemented')
    if identity_input_sha256 is not None and not re.fullmatch(r'[0-9a-f]{64}', identity_input_sha256):
        raise ValueError('Original identity input hash must be SHA-256 lowercase hex')
    if (integrity is None) != (retained_original is None):
        raise ValueError('Native integrity requires its exact retained original')
    if integrity is not None:
        callers = integrity.get('callers', [])
        if (not isinstance(callers, list) or not 1 <= len(callers) <= 2 or len(set(callers)) != len(callers)
                or any(not isinstance(name, str) or len(name) > 128 or not re.fullmatch(r'lib[A-Za-z0-9_.-]+\.so', name) for name in callers)):
            raise ValueError('Native integrity requires one or two distinct literal caller basenames')
        if hashlib.sha256(retained_original).hexdigest() != (identity_input_sha256 or sha256(original)):
            raise ValueError('Retained original does not match the declared input base')
    if identity_mode == 'identity-archive' and identity_input_sha256 not in (None, sha256(original)):
        raise ValueError('Archive experiment must embed the exact identity input')
    if identity_mode in ('public-metadata', 'identity', 'identity-failure', 'identity-archive', 'identity-deferred') and (not original_certificates or original_scheme not in (1, 2, 3)):
        raise ValueError('Metadata probe requires verified original certificates and signing scheme')
    if proxy is not None:
        host = proxy['host']
        proxy = parse_proxy(('[' + host + ']' if ':' in host else host) + ':' + str(proxy['port']))
    out.mkdir(parents=True, exist_ok=False)
    with zipfile.ZipFile(original) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise RuntimeError('Duplicate archive entry names')
        if 'assets/repack/marker.json' in names or 'assets/repack/artifact.json' in names:
            raise RuntimeError('Previously patched input')
        dex_names = [name for name in names if re.fullmatch(r'classes(?:[2-9]|[1-9][0-9]+)?\.dex', name)]
        dex_names.sort(key=lambda name: 1 if name == 'classes.dex' else int(name[7:-4]))
        expected = ['classes.dex'] + [f'classes{i}.dex' for i in range(2, len(dex_names) + 1)]
        if not dex_names or dex_names != expected:
            raise RuntimeError('Original DEX indices must be unique and contiguous')
        updated_manifest = out / 'AndroidManifest.xml'
        metadata = edit_manifest(archive.read('AndroidManifest.xml'), updated_manifest, lock, evidence, FACTORY)
        original_factory = metadata['factory']
        if fixture_bad_signing_layout and (metadata['package'] not in ('dev.repack.fixture.identity', 'dev.repack.fixture.other')
                                          or identity_mode != 'public-metadata'):
            raise ValueError('Invalid-layout control is restricted to the non-publishing owned metadata fixture')
        if original_factory == FACTORY:
            raise RuntimeError('Previously patched manifest factory')
        if original_factory.startswith('.'):
            original_factory = metadata['package'] + original_factory
        elif original_factory and '.' not in original_factory:
            original_factory = metadata['package'] + '.' + original_factory
        if original_factory and not re.fullmatch(r'[A-Za-z_$][\w.$]*', original_factory):
            raise PrerequisiteError('Factory class must be a resolved literal Java class name')
        generated = out / 'generated/dev/repack/shim'
        generated.mkdir(parents=True)
        config = generated / 'RepackConfig.java'
        config.write_text('package dev.repack.shim;\nfinal class RepackConfig {\n'
                          'static final String ORIGINAL_FACTORY = ' + json.dumps(original_factory) + ';\n'
                          'static final boolean ROUTE_ENABLED = ' + str(proxy is not None).lower() + ';\n'
                          'static final String PROXY_HOST = ' + json.dumps(proxy['host'] if proxy else '') + ';\n'
                          'static final int PROXY_PORT = ' + str(proxy['port'] if proxy else 0) + ';\n'
                          'static final String IDENTITY_MODE = ' + json.dumps(identity_mode) + ';\n'
                          'static final String PROBE_TOKEN = ' + json.dumps(probe_token) + ';\n'
                          'static final String PACKAGE_NAME = ' + json.dumps(metadata['package']) + ';\n'
                          'static final String ORIGINAL_APK_SHA256 = ' + json.dumps(identity_input_sha256 or sha256(original)) + ';\n'
                          'static final boolean GADGET_ENABLED = ' + str(gadget is not None).lower() + ';\n'
                          'static final boolean INTEGRITY_ENABLED = ' + str(integrity is not None).lower() + ';\n'
                          'static final String INTEGRITY_CALLERS = ' + json.dumps(json.dumps(integrity['callers'] if integrity else [])) + ';\n'
                          'static final int ORIGINAL_SCHEME = ' + str(original_scheme) + ';\n'
                          'static final boolean PACKAGE_BINDER_ENABLED = ' + str(package_binder).lower() + ';\n'
                          'static final boolean CONTRACTS_ENABLED = ' + str(signing_contracts).lower() + ';\n'
                          'static final boolean FIXTURE_BAD_SIGNING_LAYOUT = ' + str(fixture_bad_signing_layout).lower() + ';\n'
                          'static final String[] ORIGINAL_HISTORY = new String[] {'
                          + ','.join(json.dumps(base64.b64encode(value).decode()) for value in (historical_certificates or [])) + '};\n'
                          'static final String[] ORIGINAL_CERTIFICATES = new String[] {'
                          + ','.join(json.dumps(base64.b64encode(value).decode()) for value in (original_certificates or []))
                          + '};\n}\n')
        classes = out / 'classes'
        classes.mkdir()
        sources = sorted((ROOT / 'shim/src').rglob('*.java')) + [config]
        execute([tool(lock, 'javac'), '--release', '8', '-classpath', lock['android_jar'], '-d', str(classes),
                 *map(str, sources)], evidence, 'shim-javac', env=environment(lock))
        program = out / 'shim.jar'
        with zipfile.ZipFile(program, 'w') as jar:
            for path in sorted(classes.rglob('*.class')):
                jar.write(path, str(path.relative_to(classes)))
        dex = out / 'dex'
        dex.mkdir()
        extra = []
        if identity_mode in ('identity-access', 'identity', 'identity-failure', 'identity-archive', 'identity-deferred'):
            pin = json.loads((ROOT / 'config/hiddenapi-dependency.json').read_text())
            for kind in ('aar', 'pom', 'module', 'classes', 'license'):
                path = ROOT / pin[kind]['path']
                if not path.is_file() or sha256(path) != pin[kind]['sha256']:
                    raise PrerequisiteError('Pinned hidden-API dependency missing/changed: ' + kind)
            extra = [str(ROOT / pin['classes']['path'])]
        execute([tool(lock, 'd8'), '--release', '--min-api', '28', '--lib', lock['android_jar'],
                 '--output', str(dex), str(program), *extra], evidence, 'shim-d8', env=environment(lock))
        if [path.name for path in dex.glob('*.dex')] != ['classes.dex']:
            raise PrerequisiteError('Initial bootstrap supports one appended helper DEX')
        appended = f'classes{len(dex_names) + 1}.dex'
        unsigned = out / 'unsigned.apk'
        additions = {appended: (dex / 'classes.dex').read_bytes(),
                     'assets/repack/marker.json': json.dumps({'schema_version': 1,
                         'packaging': 'manifest', 'input_sha256': sha256(original)}).encode()}
        if identity_mode == 'identity-archive': additions['assets/repack/original.apk'] = original.read_bytes()
        if integrity is not None: additions['assets/repack/original.apk'] = retained_original
        if fixture_binder is not None:
            if metadata['package'] != 'dev.repack.fixture.identity' or not package_binder or identity_mode not in ('identity', 'identity-deferred'):
                raise ValueError('Binder scenario assets require the owned fixture and Binder shim')
            additions['assets/repack-fixture-binder.json'] = json.dumps(fixture_binder).encode()
        if fixture_cache is not None:
            if metadata['package'] != 'dev.repack.fixture.identity' or identity_mode != 'identity-deferred':
                raise ValueError('Deferred publication is restricted to the owned cache fixture')
            additions['assets/repack-fixture-cache.json'] = json.dumps(fixture_cache).encode()
        if fixture_early_query is not None:
            if metadata['package'] not in ('dev.repack.fixture.identity', 'dev.repack.fixture.other'):
                raise ValueError('Early query assets are restricted to owned fixtures')
            additions['assets/repack-fixture-early-query.json'] = json.dumps(fixture_early_query).encode()
        if fixture_request is not None:
            if metadata['package'] not in ('dev.repack.fixture.identity', 'dev.repack.fixture.other'):
                raise ValueError('Network scenario assets are restricted to owned fixtures')
            additions['assets/repack-fixture-request.json'] = json.dumps(fixture_request).encode()
        preserved = copy_archive(original, unsigned, {'AndroidManifest.xml': updated_manifest.read_bytes()},
                                 additions)
    apk = out / 'patched.apk'
    align_sign(unsigned, apk, key, lock, evidence)
    with zipfile.ZipFile(apk) as check:
        for entry in preserved:
            if hashlib.sha256(check.read(entry['entry'])).hexdigest() != entry['sha256']:
                raise RuntimeError('Unedited ZIP payload changed: ' + entry['entry'])
            if check.getinfo(entry['entry']).compress_type != entry['compression']:
                raise RuntimeError('Unedited ZIP compression changed')
    info, _ = badging(apk, lock, evidence, 'patched-badging')
    result = {**info, 'apk': str(apk), 'sha256': sha256(apk), 'signer_sha256': [key['sha256']],
              'input': str(original), 'input_sha256': sha256(original), 'original_factory': original_factory,
              'factory': FACTORY, 'packaging': 'manifest', 'appended_dex': appended,
              'original_dex': dex_names, 'preserved_entries': preserved, 'editor': metadata['editor'],
              'proxy': proxy, 'route_enabled': proxy is not None, 'identity_mode': identity_mode,
              'integrity': integrity,
              'probe_token': probe_token,
              'configured_original_signer_sha256': [hashlib.sha256(value).hexdigest() for value in (original_certificates or [])],
              'metadata_api': 30 if original_certificates else None}
    write_json(out / 'artifact.json', result)
    return result
