"""Real Cronet/hostname/native TLS Android fixture, isolated from operator apps."""
import argparse
import json
from pathlib import Path
import sys
import time
import uuid
import zipfile

from repack.rebuild import ROOT, align_sign, copy_archive, ensure_keys, environment, execute, load_lock, report, sha256, tool, write_json
from repack.patches import patch_apk, java_dependencies
from repack.elf_tls import patch_library
from repack.trust import public_ca
from repack.verify import shell, adb, preflight, install, capture_startup, owned_reverse
from repack.startup import _installed_hashes
from scripts.pinning_extension_cases import jar_directory
from scripts.routing_cases import origin

PACKAGE = 'dev.repack.fixture.expansion'
FIXTURE = ROOT / 'tests/fixtures/pinning_expansion'


def inputs():
    pin = json.loads((ROOT / 'config/pinning-expansion-dependencies.json').read_text())
    result = {}
    for row in pin['artifacts']:
        path = Path(row['path']); path = path if path.is_absolute() else ROOT / path
        if not path.is_file() or sha256(path) != row['sha256']: raise RuntimeError('Missing/changed test input: ' + row['name'])
        result[row['name']] = path
    return result


def build(lock, keys, evidence):
    pins = inputs(); env = environment(lock); evidence.mkdir()
    cronet = evidence / 'cronet.jar'
    with zipfile.ZipFile(pins['cronet-embedded-119.6045.31.aar']) as z:
        cronet.write_bytes(z.read('classes.jar')); native = z.read('jni/arm64-v8a/libcronet.119.0.6045.31.so')
    api = evidence / 'cronet-api.jar'
    with zipfile.ZipFile(pins['cronet-api-119.6045.31.aar']) as z: api.write_bytes(z.read('classes.jar'))
    common = evidence / 'cronet-common.jar'
    with zipfile.ZipFile(pins['cronet-common-119.6045.31.aar']) as z: common.write_bytes(z.read('classes.jar'))
    http = [a['path'] for a in java_dependencies('http-fixture')]
    jars = [str(cronet), str(api), str(common), *http, *[str(p) for n,p in pins.items() if n.endswith('.jar')]]
    classes = evidence / 'classes'; classes.mkdir(); dex = evidence / 'dex'; dex.mkdir()
    execute([tool(lock, 'javac'), '--release', '8', '-cp', ':'.join([lock['android_jar'], *jars]), '-d', str(classes), str(FIXTURE / 'ExpansionActivity.java')], evidence, 'javac', env=env)
    own = evidence / 'own.jar'; jar_directory(classes, own)
    execute([tool(lock, 'd8'), '--release', '--min-api', '28', '--lib', lock['android_jar'], '--output', str(dex), str(own), *jars], evidence, 'd8', env=env)
    ndk = json.loads((ROOT / 'config/ndk-dependency.json').read_text()); cc = ROOT / ndk['tools']['clang']['path']
    if sha256(cc) != ndk['tools']['clang']['sha256']: raise RuntimeError('Pinned NDK compiler changed')
    bridge = evidence / 'librepack_tls_probe.so'
    execute([str(cc), '--target=aarch64-linux-android28', '-shared', '-fPIC', '-O2', '-Wall', '-Wextra', '-Werror', '-Wl,-z,max-page-size=16384', '-Wl,-z,common-page-size=16384', str(FIXTURE / 'probe.c'), '-ldl', '-o', str(bridge)], evidence, 'native-bridge', env=env)
    manifest = evidence / 'AndroidManifest.xml'; manifest.write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="' + PACKAGE + '" android:versionCode="1"><uses-sdk android:minSdkVersion="28" android:targetSdkVersion="35"/><uses-permission android:name="android.permission.INTERNET"/><uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/><application android:extractNativeLibs="true" android:label="Owned TLS expansion"><activity android:name=".ExpansionActivity" android:exported="true"/></application></manifest>')
    linked = evidence / 'linked.apk'; execute([tool(lock, 'aapt2'), 'link', '-I', lock['android_jar'], '--manifest', str(manifest), '-o', str(linked)], evidence, 'link', env=env)
    cert = public_ca(ROOT / '.work/keys/fixture-tls/origin-good.pem')[1]
    additions = {p.name: p.read_bytes() for p in dex.glob('classes*.dex')}
    additions.update({'assets/origin.der': cert, 'lib/arm64-v8a/libcronet.119.0.6045.31.so': native,
        'lib/arm64-v8a/librepack_tls_probe.so': bridge.read_bytes(),
        'lib/arm64-v8a/libfixture_ossl3.so': pins['testossl-3.0.16.so'].read_bytes(),
        'lib/arm64-v8a/libfixture_ossl34.so': pins['testossl-3.4.1.so'].read_bytes()})
    unsigned = evidence / 'unsigned.apk'; copy_archive(linked, unsigned, additions=additions)
    original = evidence / 'original.apk'; align_sign(unsigned, original, keys['repack'], lock, evidence)
    variants = {'original': original}; ca = public_ca(ROOT / '.work/keys/fixture-tls/origin-ca.pem')[1]
    for name, kwargs in [('chromium', {'chromium_ca': ca}), ('hostname', {'relax_hostname': True})]:
        logs = evidence / (name + '-logs'); logs.mkdir()
        changed = patch_apk(original, evidence / name, keys['repack'], lock, logs, **kwargs); variants[name] = Path(changed['apk'])
        write_json(evidence / (name + '-selection.json'), changed['patches'])
        if name == 'chromium':
            # Isolate the native pin gate: trust the selected root while leaving
            # Cronet's configured pins intact. Both controls use the same real
            # verifier/result chain; only the pin-list getter differs.
            selection = [row for row in changed['patches'] if row['kind'] == 'chromium-owned-verifier']
            selected = evidence / 'anchor-only.tsv'; selected.write_text(''.join(row['class']+'\t'+row['method']+'\t'+row['replacement']+'\n' for row in selection))
            command = json.loads((logs/'dex-shadow.command.json').read_text())['argv']; prefix = command[:command.index('shadow')]
            shadow = evidence / 'anchor-only.dex'
            execute([*prefix,'shadow',str(lock['cell']['api']),str(evidence/name/'original-dex'),str(selected),str(shadow),str(evidence/name/'chromium-anchor.der')],evidence,'anchor-only-shadow',env=env)
            part=evidence/'anchor-only';part.mkdir()
            copy_archive(variants[name],part/'unsigned.apk',replacements={'classes.dex':shadow.read_bytes(),
                'assets/repack/java-patches.json':json.dumps({'schema_version':1,'input_sha256':sha256(original),'selection':selection}).encode()})
            variants['anchor-only']=part/'fixture.apk';align_sign(part/'unsigned.apk',variants['anchor-only'],keys['repack'],lock,part)
    replacements = {}; transforms = []
    for name in ('libfixture_ossl3.so', 'libfixture_ossl34.so'):
        entry = 'lib/arm64-v8a/' + name; changed, transform = patch_library(additions[entry], name)
        replacements[entry] = changed; transforms.append({'entry': entry, **transform})
    logs = evidence / 'native'; logs.mkdir(); copy_archive(original, logs / 'unsigned.apk', replacements=replacements)
    variants['native'] = logs / 'patched.apk'; align_sign(logs / 'unsigned.apk', variants['native'], keys['repack'], lock, logs)
    write_json(evidence / 'native-transforms.json', transforms)
    return {name: {'package': PACKAGE, 'version_code': 1, 'apk': str(apk), 'sha256': sha256(apk), 'signer_sha256': [keys['repack']['sha256']]} for name, apk in variants.items()}


def installed(artifact, serial, lock, evidence, label):
    _installed_hashes({**artifact, 'members': [artifact]}, serial, lock, evidence, label)


def run(args):
    result, evidence = report('PINNING-EXPANSION-Android'); lock = load_lock(); serial = args.device or lock['cell']['serial']
    latest = None
    existing = shell(lock, evidence, 'initial-paths', serial, ['pm', 'path', PACKAGE], check=False)
    if 'package:' in existing.stdout: raise RuntimeError('Refusing ownership of existing fixture package')
    before = shell(lock, evidence, 'global-before', serial, ['settings', 'get', 'global', 'http_proxy']).stdout
    result.update(observations=[], fixture_package=PACKAGE)
    try:
        keys = ensure_keys(lock, evidence); variants = build(lock, keys, evidence / 'build'); result['artifacts'] = variants
        tls_dir=evidence/'tls';tls_dir.mkdir(mode=0o700)
        execute(['openssl','req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=pinned.localhost',
                 '-keyout',str(tls_dir/'leaf.key'),'-out',str(tls_dir/'leaf.csr')],tls_dir,'keygen')
        (tls_dir/'extensions').write_text('basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:pinned.localhost,IP:127.0.0.1\n')
        execute(['openssl','x509','-req','-in',str(tls_dir/'leaf.csr'),'-CA',str(ROOT/'.work/keys/fixture-tls/origin-ca.pem'),
                 '-CAkey',str(ROOT/'.work/keys/fixture-tls/origin-ca.key'),'-set_serial','0x'+uuid.uuid4().hex,'-days','2',
                 '-extfile',str(tls_dir/'extensions'),'-out',str(tls_dir/'leaf.pem')],tls_dir,'issue')
        (tls_dir/'leaf.key').chmod(0o600)
        tls={'certificate':str(tls_dir/'leaf.pem'),'key':str(tls_dir/'leaf.key')}
        cases = [('cronet', 'original', False, {}), ('cronet-pins', 'anchor-only', False, {}), ('cronet', 'chromium', True, {}),
                 ('cronet-wrong-host', 'chromium', True, {}), ('hostname', 'original', False, {}), ('hostname', 'hostname', True, {})]
        for lib in ('libfixture_ossl3.so', 'libfixture_ossl34.so'):
            for variant in (0, 1):
                for name, patched in [('original', False), ('native', True)]: cases.append(('native', name, patched, {'library': lib, 'variant': variant}))
        with origin(evidence / 'origin', args.bind, 18443, tls=tls):
            with owned_reverse(lock, serial, 18443, args.bind, 18443, evidence, 'origin', result['device_mutations'], result['cleanup']):
                for index, (case, name, patched, extras) in enumerate(cases):
                    if args.case and case not in args.case: continue
                    part = evidence / ('case-' + str(index)); part.mkdir(); artifact = variants[name]
                    if latest: installed(latest, serial, lock, part, 'owned-before-update')
                    plan = preflight(artifact, serial, False, lock, part, 'fixture', requested_package=PACKAGE)
                    install(artifact, serial, plan, lock, part, 'fixture', result['device_mutations']); latest = artifact
                    installed(artifact, serial, lock, part, 'installed')
                    token = uuid.uuid4().hex
                    url = 'https://' + ('localhost' if case == 'cronet-wrong-host' else 'pinned.localhost') + ':18443/repack/' + token
                    command = ['am', 'start', '-n', PACKAGE + '/.ExpansionActivity', '--es', 'case', case, '--es', 'token', token, '--ez', 'patched', str(patched).lower(), '--es', 'url', url]
                    if extras: command += ['--es', 'library', extras['library'], '--ei', 'variant', str(extras['variant'])]
                    observed = None
                    with capture_startup(lock, serial, part, 'fixture') as log:
                        shell(lock, part, 'stop', serial, ['am', 'force-stop', PACKAGE]); shell(lock, part, 'start', serial, command, timeout=30)
                        for _ in range(220):
                            for line in log.read_text(errors='replace').splitlines():
                                if 'REPACK_EXPANSION' not in line or token not in line or '{' not in line: continue
                                try: row = json.loads(line[line.index('{'):])
                                except ValueError: continue
                                if row.get('token') == token: observed = row
                            if observed: break
                            time.sleep(.1)
                    if not observed: raise RuntimeError('No Android result: ' + case + '/' + name)
                    observed.update(artifact=name, apk_sha256=artifact['sha256'], evidence=str(part), **extras)
                    result['observations'].append(observed); write_json(part / 'result.json', observed); print('ANDROID', json.dumps(observed), flush=True)
                    if not observed.get('ok'): raise RuntimeError('Android case failed: ' + str(observed))
                    if case == 'cronet-pins' and 'PINNED_KEY_NOT_IN_CERT_CHAIN' not in observed.get('cronet_error',''):
                        raise RuntimeError('Cronet trust-only control did not reach the actual public-key pin gate')
        result['verification'] = 'passed'
    except BaseException as error:
        result.update(verification='failed', error_class=type(error).__name__, error=str(error)); raise
    finally:
        if latest:
            try:
                installed(latest, serial, lock, evidence, 'cleanup-owned')
                shell(lock, evidence, 'cleanup-stop', serial, ['am', 'force-stop', PACKAGE])
                removed = adb(lock, evidence, 'cleanup-uninstall', ['uninstall', PACKAGE], serial=serial)
                if 'Success' not in removed.stdout: raise RuntimeError('Fixture removal failed')
                result['cleanup'].append({'action': 'remove-owned-fixture', 'verification': 'passed'})
            except Exception as error: result['cleanup'].append({'action': 'remove-owned-fixture', 'verification': 'inconclusive', 'error': str(error)}); result['verification'] = 'failed'
        result['operator_global_proxy_preserved'] = shell(lock, evidence, 'global-after', serial, ['settings', 'get', 'global', 'http_proxy']).stdout == before
        if not result['operator_global_proxy_preserved']: result['verification'] = 'failed'
        write_json(evidence / 'report.json', result); write_json(ROOT / '.work/evidence/PINNING-EXPANSION-android.json', {**result, 'evidence_refs': [str(evidence / 'report.json')]})
        print('EVIDENCE', evidence / 'report.json', flush=True)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--device'); parser.add_argument('--bind', default='127.0.0.1')
    parser.add_argument('--case', action='append', choices=['cronet', 'cronet-pins', 'cronet-wrong-host', 'hostname', 'native'])
    result = run(parser.parse_args()); sys.exit(0 if result['verification'] == 'passed' else 1)
