"""Known Flutter AOT engine replacement; routing and trust are measured independently."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import time
import zipfile

from repack.native_tls import dependencies, patch_engine, NativeTlsUnsupported
from repack.rebuild import (ROOT, PrerequisiteError, align_sign, copy_archive, ensure_keys, environment,
    execute, load_lock, report_reference, sha256, source_hash, tool, write_json)
from repack.verify import capture_startup, install, owned_reverse, preflight, shell
from scripts.acceptance import read_cell, select_serial
from scripts.routing_cases import origin, rows, MITM_VERSION, MITM_WHEEL_SHA256
from scripts.contract_cases import SELF


def build_flutter(lock, keys, evidence):
    evidence.mkdir(parents=True); pin = dependencies()
    for row in pin['inputs']:
        if sha256(ROOT / row['path']) != row['sha256']: raise PrerequisiteError('Flutter SDK input changed')
    sdk = ROOT / '.work/tools/flutter-3.10.6'; project = evidence / 'project'; project.mkdir(); (project / 'lib').mkdir()
    for name in ('pubspec.yaml', 'pubspec.lock'): shutil.copyfile(ROOT / 'native/flutter' / name, project / name)
    shutil.copyfile(ROOT / 'native/flutter/main.dart', project / 'lib/main.dart')
    env = environment(lock); env.update(FLUTTER_SUPPRESS_ANALYTICS='true', DART_SUPPRESS_ANALYTICS='true')
    # --directory is a Dart pub option; the Flutter tool needs cwd. Its child launcher is bounded here.
    flutter = sdk / 'bin/flutter'
    for label, arguments in [('pub-get', ['pub', 'get', '--offline']), ('assemble', ['assemble', '--output=build/native-bundle',
            '-dTargetFile=lib/main.dart', '-dTargetPlatform=android-arm64', '-dBuildMode=release', '-dDartObfuscation=false',
            '-dTrackWidgetCreation=false', '-dTreeShakeIcons=false', 'android_aot_bundle_release_android-arm64'])]:
        command = [str(flutter), '--no-version-check', *arguments]
        done = subprocess.run(command, cwd=project, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120)
        write_json(evidence / (label + '.command.json'), {'argv': command, 'cwd': str(project), 'exit_status': done.returncode})
        (evidence / (label + '.stdout.log')).write_text(done.stdout); (evidence / (label + '.stderr.log')).write_text(done.stderr)
        if done.returncode: raise RuntimeError('Flutter fixture build failed: ' + label)
    build = project / 'build/native-bundle'; app = build / 'arm64-v8a/app.so'
    flutter_jar = sdk / 'bin/cache/artifacts/engine/android-arm64-release/flutter.jar'
    libraries = [flutter_jar]
    for row in pin['dependencies']:
        if sha256(ROOT / row['path']) != row['sha256']: raise PrerequisiteError('Flutter Android dependency changed')
        path = ROOT / row.get('classes_path', row['path'])
        if sha256(path) != row.get('classes_sha256', row['sha256']): raise PrerequisiteError('Flutter dependency classes changed')
        libraries.append(path)
    classes = evidence / 'classes'; classes.mkdir(); dex = evidence / 'dex'; dex.mkdir()
    execute([tool(lock, 'javac'), '--release', '8', '-classpath', ':'.join(map(str, [Path(lock['android_jar']), *libraries])),
        '-d', str(classes), str(ROOT / 'native/flutter/NativeTlsActivity.java')], evidence, 'javac', env=env)
    ownjar = evidence / 'activity.jar'
    with zipfile.ZipFile(ownjar, 'w') as out:
        for file in classes.rglob('*.class'): out.write(file, str(file.relative_to(classes)))
    execute([tool(lock, 'd8'), '--release', '--min-api', '28', '--lib', lock['android_jar'], '--output', str(dex),
        str(ownjar), *map(str, libraries)], evidence, 'd8', env=env, timeout=120)
    manifest = evidence / 'AndroidManifest.xml'
    manifest.write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="' + SELF + '" '
        'android:versionCode="1"><uses-sdk android:minSdkVersion="28" android:targetSdkVersion="35"/>'
        '<uses-permission android:name="android.permission.INTERNET"/><application android:label="Repack native fixture" '
        'android:extractNativeLibs="true" android:allowBackup="false"><activity android:name=".NativeTlsActivity" '
        'android:exported="true"/><meta-data android:name="flutterEmbedding" android:value="2"/></application></manifest>')
    linked = evidence / 'linked.apk'
    execute([tool(lock, 'aapt2'), 'link', '-I', lock['android_jar'], '--manifest', str(manifest), '-o', str(linked)], evidence, 'link')
    additions = {'lib/arm64-v8a/libapp.so': app.read_bytes()}
    for file in dex.glob('classes*.dex'): additions[file.name] = file.read_bytes()
    for file in (build / 'flutter_assets').rglob('*'):
        if file.is_file(): additions['assets/flutter_assets/' + str(file.relative_to(build / 'flutter_assets'))] = file.read_bytes()
    with zipfile.ZipFile(flutter_jar) as z: original = z.read('lib/arm64-v8a/libflutter.so')
    changed, transform = patch_engine(original, 'arm64-v8a', app.read_bytes())
    outputs = {}
    for label, payload in [('original', original), ('patched', changed)]:
        part = evidence / label; part.mkdir(); additions['lib/arm64-v8a/libflutter.so'] = payload
        unsigned = part / 'unsigned.apk'; apk = part / 'fixture.apk'; copy_archive(linked, unsigned, additions=additions)
        align_sign(unsigned, apk, keys['original'], lock, part)
        outputs[label] = {'apk': str(apk), 'sha256': sha256(apk), 'package': SELF, 'version_code': 1,
                          'split': None, 'signer_sha256': [keys['original']['sha256']]}
    write_json(evidence / 'transform.json', transform)
    return outputs, transform, {'original_engine': original, 'aot': app.read_bytes()}


@contextmanager
def tls_oracle(evidence, bind):
    evidence.mkdir(parents=True)
    executable = ROOT / ('.work/tools/mitmproxy-' + MITM_VERSION + '/bin/mitmdump')
    wheel = ROOT / ('.work/tools/wheels/mitmproxy-' + MITM_VERSION + '-py3-none-any.whl')
    if sha256(wheel) != MITM_WHEEL_SHA256: raise PrerequisiteError('Proxy wheel changed')
    with socket.socket() as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind((bind, 8083))
    command = [str(executable), '--listen-host', bind, '-p', '8083', '--mode', 'reverse:https://127.0.0.1:18443',
        '-s', str(ROOT / 'scripts/mitm_oracle.py'), '--set', 'connection_strategy=lazy', '--set', 'upstream_cert=false',
        '--set', 'confdir=' + str(ROOT / '.work/keys/mitmproxy')]
    env = os.environ.copy(); env['REPACK_ORACLE_LOG'] = str(evidence / 'requests.jsonl')
    write_json(evidence / 'command.json', {'argv': command, 'wire_mode': 'TLS without CONNECT'})
    with (evidence / 'stdout.log').open('w') as stdout, (evidence / 'stderr.log').open('w') as stderr:
        process = subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, start_new_session=True)
        try:
            for _ in range(100):
                if process.poll() is not None: raise RuntimeError('Native TLS oracle exited')
                try:
                    with socket.create_connection((bind, 8083), timeout=.1): pass
                    break
                except OSError: time.sleep(.1)
            else: raise RuntimeError('Native TLS oracle startup timed out')
            yield evidence / 'requests.jsonl'
        finally:
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=3)


def query(result, evidence, lock, serial, label):
    token = result['run_id'] + '-' + label
    shell(lock, evidence, label + '-stop', serial, ['am', 'force-stop', SELF])
    with capture_startup(lock, serial, evidence, label + '-startup') as log:
        shell(lock, evidence, label + '-start', serial, ['am', 'start', '-W', '-n', SELF + '/.NativeTlsActivity',
            '--es', 'token', token, '--es', 'url', 'https://127.0.0.1:18443/repack/' + token])
        pid = shell(lock, evidence, label + '-pid', serial, ['pidof', SELF]).stdout.strip()
        for _ in range(180):
            events = []
            for line in log.read_text(errors='replace').splitlines():
                match = re.search(r'REPACK_NATIVE\s*:\s*(\{.*\})$', line)
                if match:
                    row = json.loads(match[1])
                    if row.get('token') == token: events.append(row)
            if events: break
            time.sleep(.1)
    if len(events) != 1 or str(events[0]['pid']) != pid or events[0]['process'] != SELF:
        raise RuntimeError('Native TLS result missing/ambiguous or PID differs: ' + label)
    write_json(evidence / (label + '-observation.json'), events[0])
    return events[0]


def run_t_u60(result, evidence, args):
    lock = load_lock(); serial = select_serial(lock, evidence, args.device); result['cell'] = read_cell(lock, evidence, serial)
    if result['cell']['api'] != 30: raise PrerequisiteError('Native TLS experiment requires the measured API30 cell')
    result['inputs'] = [report_reference(ROOT / '.work/evidence/M5.json')]
    keys = ensure_keys(lock, evidence); artifacts, transform, inputs = build_flutter(lock, keys, evidence / 'fixture')
    result.update(native_transform=transform, outputs=list(artifacts.values()))
    result['comparisons'].append({'name': 'known-original-and-replacement', 'result': 'passed', 'transform': transform})
    tls = {'certificate': str(ROOT / '.work/keys/fixture-tls/origin-good.pem'),
           'key': str(ROOT / '.work/keys/fixture-tls/origin-good.key')}
    global_before = shell(lock, evidence, 'global-before', serial, ['settings', 'get', 'global', 'http_proxy']).stdout
    with origin(evidence / 'origin', args.proxy_bind, 18443, tls=tls) as originlog:
        with owned_reverse(lock, serial, 18443, args.proxy_bind, 18443, evidence, 'origin', result['device_mutations'], result['cleanup']):
            for label in ('original', 'patched'):
                artifact = artifacts[label]; plan = preflight(artifact, serial, args.replace_existing_and_wipe_data, lock, evidence, label)
                install(artifact, serial, plan, lock, evidence, label, result['device_mutations'])
                with tls_oracle(evidence / (label + '-proxy'), args.proxy_bind) as proxylog:
                    with owned_reverse(lock, serial, 8083, args.proxy_bind, 8083, evidence, label, result['device_mutations'], result['cleanup']):
                        event = query(result, evidence, lock, serial, label)
                    traffic = rows(proxylog)
                if label == 'original':
                    if event['status'] != 'failed' or 'CERTIFICATE_VERIFY_FAILED' not in event.get('error', '') or traffic:
                        raise RuntimeError('Original Flutter TLS rejection control failed')
                else:
                    if (event['status'] != 'response' or event['http_status'] != 200
                            or json.loads(event['body']) != {'token': event['token'], 'via': 'proxy'}
                            or len(traffic) != 1 or traffic[0]['token'] != event['token'] or not traffic[0]['tls']):
                        raise RuntimeError('Patched Flutter marked/decrypted proxy response failed')
                if event['unrelated'] != 42: raise RuntimeError('Unrelated Dart computation changed')
                result['comparisons'].append({'name': label + '-tls', 'result': 'passed', 'event': event, 'proxy_requests': traffic})
            with owned_reverse(lock, serial, 8083, args.proxy_bind, 8083, evidence, 'down', result['device_mutations'], result['cleanup']):
                event = query(result, evidence, lock, serial, 'proxy-down')
            if event['status'] != 'failed' or any(row['token'] == event['token'] for row in rows(originlog)):
                raise RuntimeError('Native fixed-route proxy-down control escaped to origin')
            result['comparisons'].append({'name': 'proxy-down', 'result': 'passed', 'event': event, 'origin_requests': rows(originlog)})
    if shell(lock, evidence, 'global-after', serial, ['settings', 'get', 'global', 'http_proxy']).stdout != global_before:
        raise RuntimeError('Native TLS fixture changed global proxy')
    result['comparisons'].append({'name': 'operator-proxy-preserved', 'result': 'passed'})
    result.update(verification='passed', transformation='applied', scope='Exact Flutter3.10.6 official ARM64 AOT engine -> pinned third-party reFlutter engine, fixed loopback8083 raw TLS, API30/4KB only',
        native_dependency=dependencies(), unsupported=dependencies()['limits'])


def run_t_u61(result, evidence, args):
    prior = report_reference(ROOT / '.work/evidence/T-U60.json'); child = json.loads(Path(prior['path']).read_text())
    if child['verification'] != 'passed' or child['source_sha256'] != source_hash(): raise PrerequisiteError('Accept current known Flutter request first')
    result['inputs'] = [prior]; result['cell'] = child['cell']; pin = dependencies()
    jar = ROOT / '.work/tools/flutter-3.10.6/bin/cache/artifacts/engine/android-arm64-release/flutter.jar'
    with zipfile.ZipFile(jar) as z: original = z.read('lib/arm64-v8a/libflutter.so')
    fixture = Path(child['outputs'][0]['apk'])
    with zipfile.ZipFile(fixture) as z: app = z.read('lib/arm64-v8a/libapp.so')
    for label, payload, abi, aot, function in [('wrong-hash', original + b'changed', 'arm64-v8a', app, 'ssl_crypto_x509_session_verify_cert_chain'),
            ('wrong-ABI', original, 'armeabi-v7a', app, 'ssl_crypto_x509_session_verify_cert_chain'),
            ('wrong-snapshot', original, 'arm64-v8a', b'wrong', 'ssl_crypto_x509_session_verify_cert_chain'),
            ('ambiguous-snapshot', original, 'arm64-v8a', app.replace(pin['snapshot_hash'].encode(), b'0' * 32, 1), 'ssl_crypto_x509_session_verify_cert_chain'),
            ('different-zero-success-contract', original, 'arm64-v8a', app, 'SSL_get_verify_result')]:
        try: patch_engine(payload, abi, aot, function=function)
        except NativeTlsUnsupported as error:
            result['comparisons'].append({'name': label, 'result': 'passed', 'reason': str(error)})
        else: raise RuntimeError('Unknown native function/build accepted: ' + label)
    patched, transform = patch_engine(original, 'arm64-v8a', app)
    if transform['patched_sha256'] != child['native_transform']['patched_sha256'] or transform['function_contract']['accept'] is not True:
        raise RuntimeError('Native TLS adapter result or boolean contract changed')
    result['comparisons'].append({'name': 'boolean-function-contract', 'result': 'passed', 'transform': transform})
    result.update(verification='passed', transformation='skipped', native_dependency=pin,
        scope='Known boolean chain-verification engine contract; wrong build/ABI/snapshot/zero-success function refused; managed DLL rewriting unimplemented')


def run_t_u62(result, evidence, args):
    from scripts.cli_cases import cli
    from repack.report import load_artifact
    lock = load_lock(); serial = select_serial(lock, evidence, args.device); result['cell'] = read_cell(lock, evidence, serial)
    prior = report_reference(ROOT / '.work/evidence/T-U60.json'); child = json.loads(Path(prior['path']).read_text())
    if child['verification'] != 'passed' or child['source_sha256'] != source_hash(): raise PrerequisiteError('Current known native TLS runtime is required')
    result['inputs'] = [prior]; keys = ensure_keys(lock, evidence)
    original = Path(child['outputs'][0]['apk']); outputs = ROOT / '.work/outputs/native-tls' / result['run_id']; outputs.mkdir(parents=True)
    ca = ROOT / '.work/keys/mitmproxy/mitmproxy-ca-cert.pem'; key = Path(keys['repack']['path'])
    with zipfile.ZipFile(original) as source: original_aot = source.read('lib/arm64-v8a/libapp.so')
    for label, enabled in [('off', False), ('on', True)]:
        output = outputs / (label + '.apk')
        args_ = ['patch', original, '--out', output, '--key', key, '--ca', ca, '--device', serial]
        if enabled: args_ += ['--native-tls', 'reflutter-3.10.6-arm64']
        cli(result, evidence, label + '-build', args_, lock)
        manifest = output.with_suffix('.artifact.json'); document, artifact = load_artifact(manifest)
        with zipfile.ZipFile(output) as source:
            engine_sha = hashlib.sha256(source.read('lib/arm64-v8a/libflutter.so')).hexdigest()
            if source.read('lib/arm64-v8a/libapp.so') != original_aot: raise RuntimeError('Public native TLS path changed Dart AOT')
        expected = child['native_transform']['patched_sha256'] if enabled else dependencies()['original_engine_sha256']
        if engine_sha != expected or bool(document['semantic']['configuration'].get('native_tls')) != enabled:
            raise RuntimeError('Public native TLS opt-in or engine bytes differ')
        cli(result, evidence, label + '-install', ['verify', manifest, '--device', serial, '--replace-existing-and-wipe-data'], lock)
        tls = {'certificate': str(ROOT / '.work/keys/fixture-tls/origin-good.pem'), 'key': str(ROOT / '.work/keys/fixture-tls/origin-good.key')}
        with origin(evidence / (label + '-origin'), args.proxy_bind, 18443, tls=tls):
            with tls_oracle(evidence / (label + '-proxy'), args.proxy_bind) as proxylog:
                with owned_reverse(lock, serial, 18443, args.proxy_bind, 18443, evidence, label + '-origin', result['device_mutations'], result['cleanup']):
                    with owned_reverse(lock, serial, 8083, args.proxy_bind, 8083, evidence, label + '-proxy', result['device_mutations'], result['cleanup']):
                        event = query(result, evidence, lock, serial, label)
                traffic = rows(proxylog)
        if enabled:
            if event['status'] != 'response' or json.loads(event['body']) != {'via': 'proxy', 'token': event['token']} or len(traffic) != 1 or not traffic[0]['tls']:
                raise RuntimeError('Public native TLS artifact did not return marked decrypted response')
        elif event['status'] != 'failed' or 'CERTIFICATE_VERIFY_FAILED' not in event.get('error', '') or traffic:
            raise RuntimeError('Default public routing/trust path silently enabled native TLS')
        result['comparisons'].append({'name': label + '-public-runtime', 'result': 'passed', 'engine_sha256': engine_sha, 'event': event, 'traffic': traffic})
        result['outputs'].append({'manifest': str(manifest), 'sha256': sha256(manifest)})
    result['comparisons'].append({'name': 'AOT-preserved', 'result': 'passed', 'sha256': hashlib.sha256(original_aot).hexdigest()})
    unsigned = evidence / 'unknown-unsigned.apk'; unknown = evidence / 'unknown.apk'; part = evidence / 'unknown-sign'; part.mkdir()
    with zipfile.ZipFile(original) as source: payload = source.read('lib/arm64-v8a/libflutter.so')
    copy_archive(original, unsigned, replacements={'lib/arm64-v8a/libflutter.so': payload + b'changed-build'})
    align_sign(unsigned, unknown, keys['original'], lock, part)
    before = shell(lock, evidence, 'refusals-before', serial, ['pm', 'path', SELF]).stdout
    for label, input_, flags, status in [('unknown-build', unknown, ['--native-tls', 'reflutter-3.10.6-arm64'], 4),
            ('unknown-mode', original, ['--native-tls', 'automatic'], 2),
            ('trust-only-conflict', original, ['--trust-only', '--native-tls', 'reflutter-3.10.6-arm64'], 1)]:
        output = outputs / (label + '.apk')
        cli(result, evidence, label, ['patch', input_, '--out', output, '--key', key, '--ca', ca, '--device', serial, *flags], lock, expected=status)
        if output.exists(): raise RuntimeError('Invalid native TLS mode published an artifact')
        result['comparisons'].append({'name': label + '-refused', 'result': 'passed'})
    if shell(lock, evidence, 'refusals-after', serial, ['pm', 'path', SELF]).stdout != before: raise RuntimeError('Native TLS refusals changed installed fixture')
    result['comparisons'].append({'name': 'refusals-preserved-installed-state', 'result': 'passed'})
    result.update(verification='passed', transformation='applied', native_dependency=dependencies(), scope='Explicit public native-tls third-party mode, exact engine and AOT preservation, default-off and unknown build controls')


def gate_native_tls(result, evidence, args):
    children = {}; reports = {}
    for name in ('T-U60', 'T-U61', 'T-U62'):
        ref = report_reference((args.reports / (name + '.json')).resolve()); child = json.loads(Path(ref['path']).read_text())
        if child['verification'] != 'passed' or child['source_sha256'] != source_hash(): raise PrerequisiteError(name + ' failed/stale')
        children[name] = ref; reports[name] = child
    if [len(reports[name]['comparisons']) for name in reports] != [5, 6, 7] or any(row['cell'] != reports['T-U60']['cell'] for row in reports.values()):
        raise RuntimeError('Native TLS controls/cells incomplete')
    for name in ('T-U61', 'T-U62'):
        if not any(row['sha256'] == children['T-U60']['sha256'] for row in reports[name]['inputs']): raise RuntimeError('Native TLS parent differs')
    if any(row['native_dependency'] != dependencies() for row in reports.values()): raise PrerequisiteError('Native TLS dependency changed')
    for child in reports.values():
        for row in [*child['inputs'], *child.get('cli_reports', [])]:
            if sha256(Path(row['path'])) != row['sha256']: raise RuntimeError('Native TLS evidence reference changed')
        for row in child['outputs']:
            path = Path(row.get('apk') or row['manifest'])
            if sha256(path) != row['sha256']: raise RuntimeError('Native TLS output changed')
    result.update(verification='passed', gate_progress='accepted', cell=reports['T-U60']['cell'], children=children,
        scope=reports['T-U60']['scope'], unsupported=reports['T-U60']['unsupported'] + ['Xamarin/managed-DLL-rewriting'], next_gate='M7')
