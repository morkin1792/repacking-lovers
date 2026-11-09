"""Owned target35 Android acceptance. Read-only host fixtures + production patcher."""
import argparse
import json
from pathlib import Path
import re
import socket
import subprocess
import sys
import time
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from repack.rebuild import report, load_lock, environment, tool, execute, ensure_keys, copy_archive, align_sign, sha256, write_json
from repack.patches import java_dependencies, patch_apk
from repack.verify import shell, adb, preflight, install, capture_startup, owned_reverse
from repack.startup import _installed_hashes as _split_hashes
from scripts.pinning_extension_cases import jar_directory, dependencies


def _installed_hashes(artifact, *args):
    return _split_hashes({**artifact, 'members': [artifact]}, *args)

PACKAGE = 'dev.repack.fixture.extensions'
HERE = ROOT / "tests/fixtures/pinning_extensions/android"
FIXTURES = ROOT / 'tests/fixtures/pinning_extensions'
HOST = ROOT / '.work/evidence/PINNING-EXTENSIONS-host.json'
AAR = ROOT / '.work/tools/pinning-extension-upstream/conscrypt-android-2.5.2.aar'
AAR_SHA = '42d18979caf53f5ef68548c76d4c98b41adb910a32ad9448133f9c5b20bd65a3'

def main():
    p = argparse.ArgumentParser(); p.add_argument('--case', action='append', choices=['okhttp', 'ct', 'interceptor', 'plugins', 'conscrypt-engine', 'conscrypt-fd'])
    p.add_argument('--device'); p.add_argument('--tls-bind', default='127.0.0.1'); p.add_argument('--tls-port', type=int, default=18443)
    p.add_argument('--host-report', type=Path, default=HOST); p.add_argument('--fetch-dependencies', action='store_true')
    args = p.parse_args(); modes = args.case or ['okhttp', 'ct', 'interceptor', 'plugins', 'conscrypt-engine', 'conscrypt-fd']
    lock = load_lock(); env = environment(lock); serial = args.device or lock['cell']['serial']
    result, evidence = report('PINNING-EXTENSIONS-Android'); keys = ensure_keys(lock, evidence)
    host_input = evidence / 'host-input.json'; host_input.write_bytes(args.host_report.read_bytes())
    result.update(cell=lock['cell'], cases={}, host_evidence=str(host_input), host_evidence_sha256=sha256(host_input), host_input_source=str(args.host_report.resolve()), fixture_package=PACKAGE,
        scope='Owned target35 app on ART; real Java libraries, Flutter channel adapters, actual Android Conscrypt AAR/JNI')
    host = json.loads(host_input.read_text())
    if host['verification'] != 'passed': raise RuntimeError('Host fixture prerequisites did not pass')
    existing = shell(lock, evidence, 'initial-fixture-paths', serial, ['pm', 'path', PACKAGE], check=False)
    if 'package:' in existing.stdout: raise RuntimeError('Fixture package already exists; refusing to claim ownership')
    global_before = shell(lock, evidence, 'global-before', serial, ['settings', 'get', 'global', 'http_proxy']).stdout
    latest = None; process = None
    try:
        dependencies(args.fetch_dependencies)
        observed_api = int(shell(lock, evidence, 'observed-api', serial, ['getprop', 'ro.build.version.sdk']).stdout.strip())
        abi = shell(lock, evidence, 'observed-abi', serial, ['getprop', 'ro.product.cpu.abi']).stdout.strip()
        result['cell'] = {'serial': serial, 'api': observed_api, 'abi': abi, 'target_sdk': 35}
        lock = {**lock, 'cell': {**lock['cell'], 'api': observed_api, 'abi': abi, 'serial': serial}}
        if observed_api < 28: raise RuntimeError('Fixture requires API28+')
        source = evidence / 'src'; source.mkdir(); classes = evidence / 'classes'; classes.mkdir()
        packaged = source / 'HostHarness.java'; packaged.write_text('package dev.repack.fixture.extensions;\n' + (FIXTURES / 'HostHarness.java').read_text())
        http = [a['path'] for a in java_dependencies('http-fixture')]
        stubs = [*sorted((FIXTURES / 'stubs/io').rglob('*.java')), *sorted((FIXTURES / 'stubs/androidx').rglob('*.java'))]
        execute([tool(lock, 'javac'), '--release', '8', '-cp', ':'.join([lock['android_jar'], *http]), '-d', str(classes), str(packaged), str(HERE / 'AndroidProbeActivity.java'), *map(str, stubs)], evidence, 'activity-javac', env=env)
        support = evidence / 'support.jar'; jar_directory(classes, support)
        manifest = source / 'AndroidManifest.xml'
        manifest.write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="' + PACKAGE + '" android:versionCode="1"><uses-sdk android:minSdkVersion="28" android:targetSdkVersion="35"/><uses-permission android:name="android.permission.INTERNET"/><application android:extractNativeLibs="true" android:label="Owned pinning verification"><activity android:name="' + PACKAGE + '.AndroidProbeActivity" android:exported="true"/></application></manifest>')
        linked = evidence / 'linked.apk'
        execute([tool(lock, 'aapt2'), 'link', '-I', lock['android_jar'], '--manifest', str(manifest), '-o', str(linked)], evidence, 'aapt-link', env=env)
        with zipfile.ZipFile(linked) as z: binary_manifest = z.read('AndroidManifest.xml')
        support_dex = {}
        for flavor in set('okhttp' if m == 'okhttp' else 'modern' for m in modes):
            deps = http if flavor == 'modern' else [str(ROOT / '.work/tools/pinning-extension-upstream/okio-1.17.2.jar'), *[p for p in http if 'okhttp-4.' not in p and 'okio-jvm-' not in p]]
            directory = evidence / ('support-' + flavor); directory.mkdir()
            execute([tool(lock, 'd8'), '--release', '--min-api', '28', '--lib', lock['android_jar'], '--output', str(directory), str(support), *deps], evidence, 'support-d8-' + flavor, env=env, timeout=180)
            support_dex[flavor] = sorted(directory.glob('classes*.dex'), key=lambda p: 1 if p.name == 'classes.dex' else int(p.stem[7:]))
        conscrypt = None
        if any(m.startswith('conscrypt') for m in modes):
            if sha256(AAR) != AAR_SHA: raise RuntimeError('Android Conscrypt dependency hash mismatch')
            part = evidence / 'conscrypt-build'; part.mkdir()
            with zipfile.ZipFile(AAR) as z: (part / 'program.jar').write_bytes(z.read('classes.jar'))
            dex = part / 'dex'; dex.mkdir()
            execute([tool(lock, 'd8'), '--release', '--min-api', '28', '--lib', lock['android_jar'], '--output', str(dex), str(part / 'program.jar')], part, 'd8', env=env)
            copy_archive(linked, part / 'unsigned.apk', additions={p.name: p.read_bytes() for p in dex.glob('classes*.dex')})
            original = part / 'original.apk'; align_sign(part / 'unsigned.apk', original, keys['repack'], lock, part)
            logs = part / 'patch-logs'; logs.mkdir()
            patched = patch_apk(original, part / 'patched', keys['repack'], lock, logs)
            conscrypt = {'original_apk': {'path': str(original)}, 'patched_apk': {'path': patched['apk']}, 'replacements': patched['patches']}
            server = evidence / 'server'; server.mkdir()
            execute([tool(lock, 'javac'), '--release', '8', '-d', str(server), str(HERE / 'FixtureTLSServer.java')], evidence, 'server-javac', env=env)
            with socket.socket() as probe: probe.bind((args.tls_bind, args.tls_port))
            out = (evidence / 'server.stdout.log').open('w'); err = (evidence / 'server.stderr.log').open('w')
            process = subprocess.Popen([tool(lock, 'java'), '-cp', str(server), 'FixtureTLSServer', keys['original']['path'], keys['original']['password_file'], args.tls_bind, str(args.tls_port)], stdin=subprocess.DEVNULL, stdout=out, stderr=err, env=env)
            for _ in range(50):
                if process.poll() is not None: raise RuntimeError('Owned TLS server exited')
                if 'READY' in (evidence / 'server.stdout.log').read_text(): break
                time.sleep(.1)
            else: raise RuntimeError('TLS server readiness timeout')
            result['android_conscrypt_dependency'] = {'path': str(AAR), 'sha256': AAR_SHA}
        from contextlib import nullcontext
        mapping = owned_reverse(lock, serial, args.tls_port, args.tls_bind, args.tls_port, evidence, 'tls', result['device_mutations'], result['cleanup']) if conscrypt else nullcontext()
        with mapping:
            for mode in modes:
                base = conscrypt if mode.startswith('conscrypt') else dict(host['cases'][mode])
                if not mode.startswith('conscrypt'):
                    original = Path(base['original_apk']['path'])
                    if sha256(original) != base['original_apk']['sha256']: raise RuntimeError('Host input APK hash changed')
                    build = evidence / (mode + '-build'); build.mkdir()
                    patched = patch_apk(original, build / 'patched', keys['repack'], lock, build)
                    base['patched_apk'] = {'path': patched['apk']}
                    base['replacements'] = patched['patches']
                result['cases'][mode] = {'replacements': base['replacements'], 'observations': []}
                for patched in (False, True):
                    label = mode + ('-patched' if patched else '-original'); part = evidence / label; part.mkdir()
                    library = Path(base['patched_apk' if patched else 'original_apk']['path'])
                    with zipfile.ZipFile(library) as z: count = len([n for n in z.namelist() if re.fullmatch(r'classes(?:\d+)?\.dex', n)])
                    additions = {'assets/fixture.der': Path(keys['original']['certificate']).read_bytes()}
                    for offset, dex in enumerate(support_dex['okhttp' if mode == 'okhttp' else 'modern']): additions['classes' + str(count + offset + 1) + '.dex'] = dex.read_bytes()
                    if mode.startswith('conscrypt'):
                        with zipfile.ZipFile(AAR) as z: additions['lib/' + abi + '/libconscrypt_jni.so'] = z.read('jni/' + abi + '/libconscrypt_jni.so')
                    copy_archive(library, part / 'unsigned.apk', replacements={'AndroidManifest.xml': binary_manifest}, additions=additions)
                    apk = part / 'fixture.apk'; align_sign(part / 'unsigned.apk', apk, keys['repack'], lock, part)
                    artifact = {'package': PACKAGE, 'version_code': 1, 'apk': str(apk), 'sha256': sha256(apk), 'signer_sha256': [keys['repack']['sha256']]}
                    write_json(part / 'artifact.json', artifact)
                    if latest is not None: _installed_hashes(latest, serial, lock, part, 'owned-before-update')
                    plan = preflight(artifact, serial, False, lock, part, 'fixture', requested_package=PACKAGE)
                    install(artifact, serial, plan, lock, part, 'fixture', result['device_mutations']); latest = artifact
                    _installed_hashes(artifact, serial, lock, part, 'installed')
                    token = uuid.uuid4().hex; observation = None
                    with capture_startup(lock, serial, part, 'fixture') as log:
                        shell(lock, part, 'stop', serial, ['am', 'force-stop', PACKAGE])
                        shell(lock, part, 'launch', serial, ['am', 'start', '-W', '-n', PACKAGE + '/.AndroidProbeActivity', '--es', 'case', mode, '--es', 'token', token, '--ez', 'patched', str(patched).lower(), '--ei', 'tls_port', str(args.tls_port)], timeout=30)
                        for _ in range(200):
                            for line in log.read_text(errors='replace').splitlines():
                                if 'REPACK_ANDROID' in line and token in line and '{' in line:
                                    try: event = json.loads(line[line.index('{'):])
                                    except ValueError: continue
                                    if event.get('token') == token: observation = event
                            if observation is not None: break
                            time.sleep(.1)
                    if observation is None: raise RuntimeError('Missing Android result: ' + label)
                    observation.update(evidence=str(part), apk_sha256=artifact['sha256'])
                    result['cases'][mode]['observations'].append(observation); write_json(part / 'result.json', observation)
                    print('ANDROID', label, json.dumps(observation), flush=True)
                    if not observation.get('ok') or observation.get('patched') != patched or observation.get('target_sdk') != 35 or observation.get('uid', 0) < 10000: raise RuntimeError('Android case failed: ' + label)
                result['cases'][mode]['verification'] = 'passed'
        result['verification'] = 'passed'
    except BaseException as error:
        result.update(verification='failed', error_class=type(error).__name__, error=str(error))
        raise
    finally:
        if latest:
            try:
                _installed_hashes(latest, serial, lock, evidence, 'cleanup-owned')
                shell(lock, evidence, 'cleanup-stop', serial, ['am', 'force-stop', PACKAGE])
                removed = adb(lock, evidence, 'cleanup-uninstall', ['uninstall', PACKAGE], serial=serial)
                absent = shell(lock, evidence, 'cleanup-absent', serial, ['pm', 'path', PACKAGE], check=False)
                if 'Success' not in removed.stdout or 'package:' in absent.stdout: raise RuntimeError('Owned fixture removal not confirmed')
                result['cleanup'].append({'action': 'remove-owned-fixture', 'package': PACKAGE, 'verification': 'passed'})
            except Exception as error: result['cleanup'].append({'action': 'remove-owned-fixture', 'verification': 'inconclusive', 'error': str(error)}); result['verification'] = 'failed'
        if process is not None:
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=3)
            out.close(); err.close()
        result['operator_global_proxy_preserved'] = shell(lock, evidence, 'global-after', serial, ['settings', 'get', 'global', 'http_proxy']).stdout == global_before
        if not result['operator_global_proxy_preserved']: result['verification'] = 'failed'
        write_json(evidence / 'report.json', result)
        write_json(ROOT / '.work/evidence/PINNING-EXTENSIONS-android.json', {**result, 'evidence_refs': [str(evidence / 'report.json')]})
        print('EVIDENCE', evidence / 'report.json', flush=True)
    if result['verification'] != 'passed': raise RuntimeError('Android verification or cleanup did not pass')

if __name__ == '__main__': main()
