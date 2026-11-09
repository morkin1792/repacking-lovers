"""Explicit gadget fallback for an owned raw-syscall integrity gate, with detection control."""
import json
from pathlib import Path
import re
import time
import zipfile

from repack.gadget import dependencies
from repack.rebuild import (ROOT, PrerequisiteError, align_sign, copy_archive, ensure_keys, environment, execute,
    load_lock, report_reference, sha256, source_hash, tool, write_json)
from repack.report import load_artifact
from repack.verify import capture_startup, owned_reverse, shell
from scripts.acceptance import read_cell, select_serial
from scripts.cli_cases import cli
from scripts.contract_cases import SELF
from scripts.routing_cases import oracle, rows


def build_gadget_fixture(lock, keys, evidence):
    evidence.mkdir(parents=True); ndk = json.loads((ROOT / 'config/ndk-dependency.json').read_text())
    for row in ndk['tools'].values():
        if sha256(ROOT / row['path']) != row['sha256']: raise PrerequisiteError('Gadget fixture NDK tool changed')
    compiler = ROOT / ndk['tools']['clang']['path']; library = evidence / 'librepack_gadget_fixture.so'
    execute([str(compiler), '--target=aarch64-linux-android28', '-shared', '-fPIC', '-O1', '-Wall', '-Wextra', '-Werror',
        '-Wl,-z,max-page-size=16384', '-Wl,-z,common-page-size=16384', '-Wl,-soname,librepack_gadget_fixture.so',
        str(ROOT / 'native/gadget/raw_gate.c'), '-o', str(library)], evidence, 'native-compile')
    pin = dependencies()
    if sha256(library) != pin['fixture_library']['sha256']: raise PrerequisiteError('Raw syscall fixture native hash differs from its pinned contract')
    reader = ROOT / ndk['tools']['llvm-readelf']['path']
    imports = execute([str(reader), '--dyn-symbols', '--wide', str(library)], evidence, 'native-imports').stdout
    if 'repack_fixture_raw_gate' not in imports or not re.search(r'\bUND\s+syscall(?:@|\s)', imports):
        raise RuntimeError('Gadget fixture lost its raw syscall/export contract')
    classes = evidence / 'classes'; classes.mkdir(); dex = evidence / 'dex'; dex.mkdir()
    execute([tool(lock, 'javac'), '--release', '8', '-classpath', lock['android_jar'], '-d', str(classes),
        str(ROOT / 'native/gadget/GadgetActivity.java')], evidence, 'javac', env=environment(lock))
    program = evidence / 'activity.jar'
    with zipfile.ZipFile(program, 'w') as archive:
        for file in classes.rglob('*.class'): archive.write(file, str(file.relative_to(classes)))
    execute([tool(lock, 'd8'), '--release', '--min-api', '28', '--lib', lock['android_jar'], '--output', str(dex), str(program)],
        evidence, 'd8', env=environment(lock))
    resources = evidence / 'res'; (resources / 'values').mkdir(parents=True)
    (resources / 'values/strings.xml').write_text('<resources><string name="app_name">Repack gadget fixture</string></resources>')
    manifest = evidence / 'AndroidManifest.xml'
    manifest.write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="' + SELF + '" android:versionCode="1">'
        '<uses-sdk android:minSdkVersion="28" android:targetSdkVersion="35"/><uses-permission android:name="android.permission.INTERNET"/>'
        '<application android:extractNativeLibs="true" android:label="@string/app_name" android:allowBackup="false">'
        '<activity android:name=".GadgetActivity" android:exported="true"/></application></manifest>')
    compiled = evidence / 'resources.zip'; linked = evidence / 'linked.apk'
    execute([tool(lock, 'aapt2'), 'compile', '--dir', str(resources), '-o', str(compiled)], evidence, 'resources-compile')
    execute([tool(lock, 'aapt2'), 'link', '-I', lock['android_jar'], '--manifest', str(manifest), '-o', str(linked), str(compiled)], evidence, 'resources-link')
    unsigned = evidence / 'unsigned.apk'; signed = evidence / 'original.apk'
    copy_archive(linked, unsigned, additions={'classes.dex': (dex / 'classes.dex').read_bytes(),
        'lib/arm64-v8a/librepack_gadget_fixture.so': library.read_bytes()})
    align_sign(unsigned, signed, keys['original'], lock, evidence)
    return signed, {'library_sha256': sha256(library), 'imported_syscall': True, 'opening_imports': False}


def fnv(path):
    value = 14695981039346656037
    with path.open('rb') as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b''):
            for byte in data: value = ((value ^ byte) * 1099511628211) & 0xffffffffffffffff
    return format(value, '016x')


def query(result, evidence, lock, serial, label, expected, *, detect=False):
    token = result['run_id'] + '-' + label
    shell(lock, evidence, label + '-stop', serial, ['am', 'force-stop', SELF])
    with capture_startup(lock, serial, evidence, label + '-startup') as logfile:
        # Gadget affects startup timing. The trigger starts asynchronously, then token+PID+HTTP
        # observations join the actual process; a blocked am -W cannot substitute for evidence.
        shell(lock, evidence, label + '-start', serial, ['am', 'start', '-n', SELF + '/.GadgetActivity',
            '--es', 'token', token, '--es', 'expected_fnv', expected, '--es', 'url', 'https://127.0.0.1:18443/repack/' + token,
            '--ez', 'detect_gadget', str(detect).lower()], timeout=20)
        for _ in range(200):
            text = logfile.read_text(errors='replace'); events = []
            for line in text.splitlines():
                match = re.search(r'REPACK_GADGET_FIXTURE\s*:\s*(\{.*\})$', line)
                if match:
                    row = json.loads(match[1])
                    if row.get('token') == token: events.append(row)
            if events: break
            time.sleep(.1)
        pid = shell(lock, evidence, label + '-pid', serial, ['pidof', SELF]).stdout.strip()
    if len(events) != 1 or str(events[0]['pid']) != pid or events[0]['process'] != SELF:
        raise RuntimeError('Gadget fixture response is missing/ambiguous or PID differs: ' + label)
    gadget = []
    for line in logfile.read_text(errors='replace').splitlines():
        match = re.search(r'REPACK_GADGET\s*:\s*(\{.*\})$', line)
        if match:
            row = json.loads(match[1])
            if row.get('pid') == int(pid): gadget.append(row)
    write_json(evidence / (label + '-observation.json'), {'event': events[0], 'gadget_events': gadget})
    return events[0], gadget, logfile


def run_t_g70(result, evidence, args):
    lock = load_lock(); serial = select_serial(lock, evidence, args.device); result['cell'] = read_cell(lock, evidence, serial)
    if result['cell']['api'] != 30 or result['cell']['abi'] != 'arm64-v8a' or result['cell']['page_size'] != 4096:
        raise PrerequisiteError('Gadget fixture is measured only on API30/ARM64/4KB')
    result['inputs'] = [report_reference(ROOT / '.work/evidence/M6.json')]; keys = ensure_keys(lock, evidence)
    original, native = build_gadget_fixture(lock, keys, evidence / 'fixture'); original_fnv = fnv(original)
    result['comparisons'].append({'name': 'raw-syscall-native-contract', 'result': 'passed', **native, 'original_fnv': original_fnv})
    outputs = ROOT / '.work/outputs/gadget' / result['run_id']; outputs.mkdir(parents=True)
    key = Path(keys['repack']['path']); ca = ROOT / '.work/keys/mitmproxy/mitmproxy-ca-cert.pem'
    for label, flags, status, reason in [('static-integrity-refusal', ['--integrity', 'native-base-bytes:librepack_gadget_fixture.so'], 4, 'no supported file-opening'),
            ('trust-only-refusal', ['--trust-only', '--gadget', 'raw-apk-fixture'], 1, 'changes trust alone'),
            ('unknown-mode-refusal', ['--gadget', 'automatic'], 2, 'invalid choice')]:
        output = outputs / (label + '.apk')
        cli(result, evidence, label, ['patch', original, '--out', output, '--key', key, '--ca', ca, '--device', serial, *flags], lock, expected=status, reason=reason)
        if output.exists(): raise RuntimeError('Unsupported gadget/static case published output')
        result['comparisons'].append({'name': label, 'result': 'passed'})
    artifacts = {}; documents = {}
    for label, enabled in [('off', False), ('on', True)]:
        output = outputs / (label + '.apk'); flags = ['--gadget', 'raw-apk-fixture'] if enabled else []
        cli(result, evidence, label + '-build', ['patch', original, '--out', output, '--key', key, '--ca', ca, '--device', serial, *flags], lock)
        manifest = output.with_suffix('.artifact.json'); document, artifact = load_artifact(manifest)
        with zipfile.ZipFile(output) as archive:
            injected = sorted(name for name in archive.namelist() if name.startswith('assets/repack/gadget/'))
        if bool(injected) != enabled or bool(document['semantic']['configuration'].get('gadget')) != enabled:
            raise RuntimeError('Gadget dependency was injected without explicit mode or omitted')
        if enabled and document['semantic']['configuration']['gadget']['listener'] is not False: raise RuntimeError('Gadget opened an instrumentation listener')
        result['comparisons'].append({'name': label + '-packaging', 'result': 'passed', 'assets': injected})
        artifacts[label] = artifact; documents[label] = manifest
        result['outputs'].append({'manifest': str(manifest), 'sha256': sha256(manifest)})
    global_before = shell(lock, evidence, 'global-before', serial, ['settings', 'get', 'global', 'http_proxy']).stdout
    cli(result, evidence, 'off-install', ['verify', documents['off'], '--device', serial, '--replace-existing-and-wipe-data'], lock)
    with oracle(evidence / 'off-proxy', args.proxy_bind) as (_, log):
        with owned_reverse(lock, serial, 8080, args.proxy_bind, 8080, evidence, 'off', result['device_mutations'], result['cleanup']):
            event, gadget, _ = query(result, evidence, lock, serial, 'off-positive', fnv(Path(artifacts['off']['apk'])))
            if event['status'] != 'response' or event['gadget_present'] or not event['gate'] or event['unrelated'] != 42:
                raise RuntimeError('Raw checksum positive calibration or ordinary no-gadget network path failed')
            if json.loads(event['body']) != {'token': event['token'], 'via': 'proxy'}: raise RuntimeError('Gadget positive control response marker differs')
            result['comparisons'].append({'name': 'ordinary-positive-network', 'result': 'passed', 'event': event})
            negative, _, _ = query(result, evidence, lock, serial, 'off-original', original_fnv)
            if negative['status'] != 'blocked-integrity' or negative['gate'] or negative['gadget_present'] or any(row['token'] == negative['token'] for row in rows(log)):
                raise RuntimeError('Original-byte raw syscall negative did not prevent the request')
            result['comparisons'].append({'name': 'raw-original-bytes-blocked', 'result': 'passed', 'event': negative})
    cli(result, evidence, 'on-install', ['verify', documents['on'], '--device', serial, '--replace-existing-and-wipe-data'], lock)
    with oracle(evidence / 'on-proxy', args.proxy_bind) as (_, log):
        with owned_reverse(lock, serial, 8080, args.proxy_bind, 8080, evidence, 'on', result['device_mutations'], result['cleanup']):
            event, gadget, logfile = query(result, evidence, lock, serial, 'on-original', original_fnv)
            observed = [row for row in rows(log) if row['token'] == event['token']]
            if (event['status'] != 'response' or not event['gadget_present'] or not event['gate'] or event['unrelated'] != 42
                    or json.loads(event['body']) != {'token': event['token'], 'via': 'proxy'} or len(observed) != 1 or not observed[0]['tls']):
                raise RuntimeError('Explicit gadget mode did not produce a marked decrypted response')
            returns = [row for row in gadget if row['event'] == 'raw-gate-return']; attached = [row for row in gadget if row['event'] == 'attached']
            if len(returns) != 1 or returns[0]['original'] != 0 or returns[0]['replacement'] != 1 or len(attached) != 1:
                raise RuntimeError('Gadget result lacks actual native return/attachment evidence')
            if 'Fatal signal' in logfile.read_text(errors='replace'): raise RuntimeError('Gadget fixture crashed')
            result['comparisons'].append({'name': 'gadget-marked-native-response', 'result': 'passed', 'event': event, 'hook_events': gadget, 'traffic': observed})
            detected, _, _ = query(result, evidence, lock, serial, 'detect', original_fnv, detect=True)
            if detected['status'] != 'blocked-gadget' or not detected['gadget_present'] or any(row['token'] == detected['token'] for row in rows(log)):
                raise RuntimeError('Gadget detectability negative control failed')
            result['comparisons'].append({'name': 'gadget-detection-blocks-request', 'result': 'passed', 'event': detected})
    with owned_reverse(lock, serial, 8080, args.proxy_bind, 8080, evidence, 'down', result['device_mutations'], result['cleanup']):
        event, _, _ = query(result, evidence, lock, serial, 'down', original_fnv)
    if event['status'] != 'failed' or not event['gate'] or event['unrelated'] != 42:
        raise RuntimeError('Gadget proxy-down request did not fail independently of native gate')
    result['comparisons'].append({'name': 'proxy-down-independent', 'result': 'passed', 'event': event})
    if shell(lock, evidence, 'global-after', serial, ['settings', 'get', 'global', 'http_proxy']).stdout != global_before:
        raise RuntimeError('Gadget case changed operator global proxy')
    result['comparisons'].append({'name': 'operator-proxy-preserved', 'result': 'passed'})
    result.update(verification='passed', transformation='applied', gadget_dependency=dependencies(),
        scope='Explicit script-mode Frida17.26.0, preloaded named raw-syscall fixture export, API30/ARM64/4KB; observed native override, TLS payload, default-off and detection controls',
        unsupported=['real-target-gadget-bypass', 'other-API/ABI/page-cells', 'module-observer', 'isolated/other-processes', 'generic-RASP-coverage'])


def gate_gadget(result, evidence, args):
    reference = report_reference((args.reports / 'T-G70.json').resolve()); child = json.loads(Path(reference['path']).read_text())
    if child['verification'] != 'passed' or child['source_sha256'] != source_hash(): raise PrerequisiteError('T-G70 failed/stale')
    if len(child['comparisons']) != 12 or any(row['result'] != 'passed' for row in child['comparisons']): raise RuntimeError('Gadget controls incomplete')
    if child['gadget_dependency'] != dependencies(): raise PrerequisiteError('Gadget dependency changed')
    for row in [*child['inputs'], *child.get('cli_reports', [])]:
        if sha256(Path(row['path'])) != row['sha256']: raise RuntimeError('Gadget evidence reference changed')
    for row in child['outputs']:
        if sha256(Path(row['manifest'])) != row['sha256']: raise RuntimeError('Gadget output manifest changed')
        load_artifact(Path(row['manifest']))
    result.update(verification='passed', gate_progress='accepted', cell=child['cell'], children={'T-G70': reference},
        scope=child['scope'], unsupported=child['unsupported'], next_gate='M8')
