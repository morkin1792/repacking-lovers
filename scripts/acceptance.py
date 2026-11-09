#!/usr/bin/env python3
"""M0 acceptance: host, device, T-A00 and the M0 gate. Standard library only."""
from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import re
import shutil
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from repack.rebuild import (ROOT, PrerequisiteError, align_sign, badging, copy_archive, ensure_keys, environment, execute, fixture_source_hash, load_lock,
                            report, report_reference, sha256, signer_digests, source_hash, tool, write_json)
from repack.verify import adb, shell, preflight, install
from repack.shim import build_bootstrap, edit_manifest
import hashlib
import zipfile

PACKAGES = {'dev.repack.fixture.identity', 'dev.repack.fixture.other'}
PATHS = ('direct-legacy', 'direct-current', 'reflect-legacy', 'reflect-current')
EVENT_FIELDS = set(('schema_version run_id case_id pid process event scenario query_path package flags '
                    'actual_signer_sha256 expected_signer_sha256 comparison response_marker error_class').split())


def connected(lock: dict, evidence: Path) -> list[str]:
    result = adb(lock, evidence, 'adb-devices', ['devices', '-l'])
    return [parts[0] for line in result.stdout.splitlines()
            if len(parts := line.split()) > 1 and parts[1] == 'device']


def select_serial(lock: dict, evidence: Path, requested=None) -> str:
    devices = connected(lock, evidence)
    if requested:
        if requested not in devices:
            raise PrerequisiteError(f'Selected serial {requested} is unavailable')
        return requested
    physical = [serial for i, serial in enumerate(devices) if shell(
        lock, evidence, f'candidate-{i}', serial, ['getprop', 'ro.kernel.qemu']).stdout.strip() != '1']
    choices = physical or devices
    if len(choices) != 1:
        raise PrerequisiteError('Select one authorized --device serial' if choices else
                                'No configured ADB device; source the operator tools/configure')
    return choices[0]


def read_cell(lock: dict, evidence: Path, serial: str) -> dict:
    values = {}
    properties = {'api': 'ro.build.version.sdk', 'abi': 'ro.product.cpu.abi',
                  'fingerprint': 'ro.build.fingerprint', 'ro_debuggable': 'ro.debuggable',
                  'build_type': 'ro.build.type', 'security_patch': 'ro.build.version.security_patch'}
    for name, prop in properties.items():
        values[name] = shell(lock, evidence, 'property-' + name, serial, ['getprop', prop]).stdout.strip()
    values['api'] = int(values['api'])
    values['page_size'] = int(shell(lock, evidence, 'page-size', serial, ['getconf', 'PAGE_SIZE']).stdout.strip())
    values['shell_id'] = shell(lock, evidence, 'shell-id', serial, ['id']).stdout.strip()
    values['user'] = int(shell(lock, evidence, 'current-user', serial, ['am', 'get-current-user']).stdout.strip())
    if values['api'] < 28 or not values['shell_id'].startswith('uid=2000('):
        raise PrerequisiteError('M0 requires API28+ and an ordinary non-root ADB shell')
    return {**values, 'serial': serial, 'target_sdk': 35, 'min_sdk': 28,
            'id': f"api{values['api']}-target35-{values['abi']}-p{values['page_size']}"}


def host(result: dict, evidence: Path, args) -> None:
    sdk = Path(os.environ.get('ANDROID_SDK_ROOT') or os.environ.get('ANDROID_HOME') or Path.home() / 'Android/Sdk')
    java = shutil.which('javac')
    if not java:
        raise PrerequisiteError('javac missing')
    jdk = Path(java).resolve().parent.parent
    build_tools = sdk / 'build-tools/36.0.0'
    android_jar = sdk / 'platforms/android-36/android.jar'
    if not android_jar.is_file():
        raise PrerequisiteError('Installed compileSdk36 android.jar missing')
    lock = {
        'schema_version': 1, 'sdk_path': str(sdk), 'jdk_path': str(jdk), 'android_jar': str(android_jar),
        'adb_server_socket': os.environ.get('ADB_SERVER_SOCKET'),
        'build': {'java_release': 8, 'compile_sdk': 36, 'target_sdk': 35, 'min_sdk': 28, 'build_tools': '36.0.0'},
        'tools': {}, 'cell': None,
    }
    old_path = ROOT / 'config/implementation-lock.json'
    if old_path.exists():
        previous = json.loads(old_path.read_text())
        for name in ('release_target', 'identity_access', 'resource_engine'):
            if name in previous: lock[name] = previous[name]
        lock['cell'] = previous.get('cell')
        if previous.get('adb_server_socket') and not lock['adb_server_socket']:
            lock['adb_server_socket'] = previous['adb_server_socket']
        if previous.get('tools', {}).get('androidx-core-factory'):
            lock['tools']['androidx-core-factory'] = previous['tools']['androidx-core-factory']
    candidates = {
        'java': (jdk / 'bin/java', ['-version']), 'javac': (jdk / 'bin/javac', ['--version']),
        'keytool': (jdk / 'bin/keytool', ['-help']),
        'adb': (Path(shutil.which('adb') or sdk / 'platform-tools/adb'), ['version']),
        'aapt2': (build_tools / 'aapt2', ['version']), 'd8': (build_tools / 'd8', ['--version']),
        'apksigner': (build_tools / 'apksigner', ['version']), 'zipalign': (build_tools / 'zipalign', []),
    }
    for name, (path, flags) in candidates.items():
        if not path.is_file():
            raise PrerequisiteError(f'Missing {name}: {path}')
        command = execute([str(path), *flags], evidence, 'tool-' + name, env=environment(lock), check=False)
        output = (command.stdout + command.stderr).strip()
        ok = command.returncode == 0 or (name == 'zipalign' and 'Zip alignment utility' in output)
        if not ok:
            raise PrerequisiteError(f'{name} launch failed; see tool logs')
        lock['tools'][name] = {'path': str(path), 'sha256': sha256(path), 'version_output': output,
                               'launch_exit_status': command.returncode}
    lock['build']['jdk_major'] = int(re.search(r'(\d+)', lock['tools']['javac']['version_output'])[1])
    for name in ('d8', 'apksigner'):
        jar = build_tools / 'lib' / (name + '.jar')
        lock['tools'][name]['jar_sha256'] = sha256(jar)
    lock['tools']['android-jar'] = {'path': str(android_jar), 'sha256': sha256(android_jar)}
    lock['android_jar_sha256'] = sha256(android_jar)
    git_root = execute(['git', 'rev-parse', '--show-toplevel'], evidence, 'git-root').stdout.strip()
    execute(['git', 'check-ignore', '.work/keys/fixture.pass'], evidence, 'git-ignore')
    if Path(git_root) != ROOT:
        raise PrerequisiteError('Unexpected Git root')
    lock['measurements_complete'] = True
    write_json(old_path, lock)
    result.update(verification='passed', tools=lock['tools'], build=lock['build'],
                  kvm={'exists': Path('/dev/kvm').exists(), 'read_write': os.access('/dev/kvm', os.R_OK | os.W_OK)},
                  devices=connected(lock, evidence))


def device(result: dict, evidence: Path, args) -> None:
    lock = load_lock()
    serial = select_serial(lock, evidence, args.device)
    cell = read_cell(lock, evidence, serial)
    lock['cell'] = cell
    lock['release_target'] = dict(cell)
    write_json(ROOT / 'config/implementation-lock.json', lock)
    result.update(verification='passed', cell=cell)


def read_events(text: str, run_id: str) -> list[dict]:
    events = []
    for line in text.splitlines():
        match = re.search(r'REPACK_FIXTURE\s*:\s*(\{.*\})\s*$', line)
        if match:
            value = json.loads(match[1])
            if value.get('run_id') == run_id:
                if set(value) != EVENT_FIELDS:
                    raise RuntimeError('Fixture event does not match the v1 event schema')
                events.append(value)
    return events


def run_t_a00(result: dict, evidence: Path, args) -> None:
    lock = load_lock()
    serial = select_serial(lock, evidence, args.device)
    cell = read_cell(lock, evidence, serial)
    result['cell'] = cell
    build_path = ROOT / '.work/evidence/M0-build.json'
    if not build_path.exists():
        raise PrerequisiteError('Build fixtures first')
    build = json.loads(build_path.read_text())
    if build['verification'] != 'passed' or build.get('fixture_source_sha256') != fixture_source_hash():
        raise PrerequisiteError('Fixture build is missing, failed or stale')
    entries = build['outputs']
    if len(entries) != 4 or {entry['package'] for entry in entries} != PACKAGES:
        raise RuntimeError('Unexpected fixture inventory')
    # Validate every candidate before any install/uninstall.
    for entry in entries:
        apk = Path(entry['apk'])
        if sha256(apk) != entry['sha256']:
            raise RuntimeError('Fixture artifact changed after build')
        meta, _ = badging(apk, lock, evidence, 'input-' + entry['id'])
        signers = signer_digests(apk, lock, evidence, 'input-signer-' + entry['id'])
        if meta['package'] != entry['package'] or signers != entry['signer_sha256']:
            raise RuntimeError('Fixture metadata/signature changed')
    result['inputs'] = [report_reference(build_path)]
    for variant in ('own', 'androidx'):
        active = [entry for entry in entries if entry['variant'] == variant]
        for entry in active:
            plan = preflight(entry, serial, args.replace_existing_and_wipe_data, lock, evidence, entry['id'])
            install(entry, serial, plan, lock, evidence, entry['id'], result['device_mutations'])
        truth = {entry['package']: entry['signer_sha256'] for entry in active}
        scenarios = [(entry['package'], target, path, False)
                     for entry in active for target in sorted(PACKAGES) for path in PATHS]
        scenarios.append(('dev.repack.fixture.identity', 'dev.repack.fixture.identity', 'direct-current', True))
        for index, (package, target, path, negative) in enumerate(scenarios):
            token = result['run_id'] + '-' + variant + '-' + str(index)
            label = variant + '-query-' + str(index)
            expected = ['0' * 64] if negative else truth[target]
            shell(lock, evidence, label + '-stop', serial, ['am', 'force-stop', '--user', str(cell['user']), package])
            timestamp = shell(lock, evidence, label + '-time', serial,
                              ['date', '+%m-%d %H:%M:%S.000']).stdout.strip()
            command = ['am', 'start', '-W', '--user', str(cell['user']), '-n', package + '/.ProbeActivity']
            extras = {'run_id': token, 'case_id': 'T-A00', 'scenario': 'negative' if negative else 'baseline',
                      'query_path': path, 'query_package': target, 'expected_signer_sha256': ','.join(expected)}
            for name, value in extras.items():
                command.extend(['--es', name, value])
            launch = shell(lock, evidence, label + '-launch', serial, command, check=False, timeout=5)
            if launch.returncode not in (0, 124):
                raise RuntimeError('Fixture launch command failed: ' + label)
            pid = shell(lock, evidence, label + '-pid', serial, ['pidof', '-s', package], check=False).stdout.strip()
            if not pid.isdigit():
                shell(lock, evidence, label + '-crash-window', serial,
                      ['logcat', '-d', '-v', 'threadtime', '-T', timestamp], check=False)
                raise RuntimeError('Fixture process absent after launch; retained launch-window logs')
            logs = shell(lock, evidence, label + '-logcat', serial,
                         ['logcat', '-d', '-v', 'threadtime', '--pid=' + pid, '-T', timestamp])
            events = read_events(logs.stdout, token)
            if len(events) != 1:
                raise RuntimeError(f'Expected one fresh fixture query, got {len(events)} ({label})')
            event = events[0]
            good = (event.get('event') == 'query' and event.get('case_id') == 'T-A00'
                    and event.get('schema_version') == 1 and event.get('pid') == int(pid)
                    and event.get('process') == package and event.get('scenario') == extras['scenario']
                    and event.get('flags') == (64 if path.endswith('legacy') else 0x08000000)
                    and event.get('query_path') == path and event.get('package') == target
                    and event.get('actual_signer_sha256') == truth[target]
                    and event.get('expected_signer_sha256') == expected and event.get('error_class') is None
                    and event.get('comparison') == ('failed' if negative else 'passed'))
            result['comparisons'].append({'variant': variant, 'caller': package, 'target': target,
                'query_path': path, 'negative_control': negative, 'pid': int(pid), 'token': token,
                'expected': truth[target], 'observed': event.get('actual_signer_sha256'),
                'launch_exit_status': launch.returncode, 'launch_wait_timed_out': launch.returncode == 124,
                'fixture_comparison': event.get('comparison'), 'result': 'passed' if good else 'failed'})
            if not good:
                raise RuntimeError('Signing query/oracle comparison failed: ' + label)
    result.update(verification='passed')
    result['cleanup'] = [{'action': 'retain-owned-fixtures', 'packages': sorted(PACKAGES),
                          'reason': 'Next gate reuses these fixtures; no user app was replaced'}]


def tagged_events(text: str, tag: str) -> list[dict]:
    return [json.loads(match[1]) for line in text.splitlines()
            if (match := re.search(re.escape(tag) + r'\s*:\s*(\{.*\})\s*$', line))]


def launch_query(artifact: dict, serial: str, token: str, case: str, expected: list[str],
                 target: str, path: str, lock: dict, evidence: Path, label: str,
                 *, allow_failure=False) -> tuple[dict, str, str, str]:
    package = artifact['package']
    shell(lock, evidence, label + '-stop', serial, ['am', 'force-stop', package])
    timestamp = shell(lock, evidence, label + '-time', serial, ['date', '+%m-%d %H:%M:%S.000']).stdout.strip()
    command = ['am', 'start', '-W', '-n', package + '/.ProbeActivity']
    extras = {'run_id': token, 'case_id': case, 'scenario': case, 'query_path': path,
              'query_package': target, 'expected_signer_sha256': ','.join(expected)}
    for name, value in extras.items():
        command.extend(['--es', name, value])
    response = shell(lock, evidence, label + '-launch', serial, command, check=False, timeout=10)
    if response.returncode:
        raise RuntimeError('Fixture launch wait failed: ' + label)
    pid = shell(lock, evidence, label + '-pid', serial, ['pidof', '-s', package]).stdout.strip()
    text = shell(lock, evidence, label + '-logs', serial,
                 ['logcat', '-d', '-v', 'threadtime', '--pid=' + pid, '-T', timestamp]).stdout
    events = read_events(text, token)
    if (not events or events[0]['event'] not in (('query', 'failure') if allow_failure else ('query',)) or events[0]['pid'] != int(pid)
            or events[0]['case_id'] != case or events[0]['process'] != package
            or events[0]['package'] != target or events[0]['query_path'] != path
            or events[0]['expected_signer_sha256'] != expected
            or any(event != events[0] for event in events[1:])):
        raise RuntimeError('Fresh query event missing or ambiguous')
    write_json(evidence / (label + '-query-observation.json'),
               {'event': events[0], 'identical_observation_count': len(events)})
    return events[0], text, pid, timestamp


def make_factory_control(original: dict, factory: str | None, key: dict, lock: dict,
                         out: Path, evidence: Path) -> dict:
    out.mkdir(parents=True)
    evidence.mkdir(parents=True)
    source = Path(original['apk'])
    with zipfile.ZipFile(source) as archive:
        edited = out / 'AndroidManifest.xml'
        edit_manifest(archive.read('AndroidManifest.xml'), edited, lock, evidence, factory,
                      clear_factory=factory is None)
    unsigned = out / 'unsigned.apk'
    copy_archive(source, unsigned, {'AndroidManifest.xml': edited.read_bytes()})
    apk = out / 'original.apk'
    align_sign(unsigned, apk, key, lock, evidence)
    return {**original, 'apk': str(apk), 'sha256': sha256(apk), 'factory': factory or ''}


def expect_factory_exception(artifact: dict, serial: str, lock: dict, evidence: Path, label: str) -> None:
    package = artifact['package']
    shell(lock, evidence, label + '-stop', serial, ['am', 'force-stop', package])
    timestamp = shell(lock, evidence, label + '-time', serial, ['date', '+%m-%d %H:%M:%S.000']).stdout.strip()
    token = evidence.parent.name + '-' + label
    shell(lock, evidence, label + '-launch', serial,
          ['am', 'start', '-W', '-n', package + '/dev.repack.fixture.common.FailureActivity',
           '--es', 'factory_failure_token', token], check=False, timeout=10)
    logs = shell(lock, evidence, label + '-logs', serial,
                 ['logcat', '-d', '-v', 'threadtime', '-T', timestamp]).stdout
    markers = [event for event in tagged_events(logs, 'REPACK_FIXTURE')
               if event.get('response_marker') == 'factory-delegate-failure:' + token]
    if len(markers) != 1:
        raise RuntimeError('Fresh original factory exception marker missing')
    pid = str(markers[0]['pid'])
    process_logs = '\n'.join(line for line in logs.splitlines() if len(line.split()) > 2 and line.split()[2] == pid)
    if 'java.lang.IllegalAccessException: fixture-delegate-contract' not in process_logs:
        raise RuntimeError('Original factory exception cause was not preserved')


def run_t_a01(result: dict, evidence: Path, args) -> None:
    lock = load_lock()
    serial = select_serial(lock, evidence, args.device)
    result['cell'] = read_cell(lock, evidence, serial)
    if not args.replace_existing_and_wipe_data:
        raise PrerequisiteError('T-A01 changes fixture signing identity; explicit fixture replacement flag required')
    baseline = json.loads((ROOT / '.work/evidence/M0-build.json').read_text())
    if baseline['verification'] != 'passed' or baseline.get('fixture_source_sha256') != fixture_source_hash():
        raise PrerequisiteError('Build current fixtures first')
    keys = ensure_keys(lock, evidence)
    own = next(x for x in baseline['outputs'] if x['id'] == 'app-own')
    core = next(x for x in baseline['outputs'] if x['id'] == 'app-androidx')
    root = ROOT / '.work/outputs/bootstrap' / result['run_id']
    variants = [('own-final', own), ('androidx', core)]
    for name, factory in [('platform-default', None),
                          ('custom-loader', 'dev.repack.fixture.common.LoaderFactory'),
                          ('exception', 'dev.repack.fixture.common.ThrowFactory')]:
        control = make_factory_control(own, factory, keys['original'], lock, root / (name + '-control'),
                                       evidence / (name + '-control'))
        variants.append((name, control))
    artifacts = []
    for name, original in variants:
        part = evidence / name
        part.mkdir()
        if name == 'exception':
            plan = preflight(original, serial, True, lock, part, 'original')
            install(original, serial, plan, lock, part, 'original', result['device_mutations'])
            expect_factory_exception(original, serial, lock, part, 'original-exception')
        artifact = build_bootstrap(Path(original['apk']), root / name, keys['repack'], lock, part)
        artifact['variant'] = name
        plan = preflight(artifact, serial, True, lock, part, 'patched')
        install(artifact, serial, plan, lock, part, 'patched', result['device_mutations'])
        for stage in ('first', 'compiled'):
            if stage == 'compiled':
                compiled = shell(lock, part, 'compile', serial,
                                 ['cmd', 'package', 'compile', '-m', 'speed', '-f', artifact['package']])
                if 'Success' not in compiled.stdout:
                    raise RuntimeError('Package compilation did not report success')
            token = result['run_id'] + '-' + name + '-' + stage
            observed, text, pid, timestamp = launch_query(artifact, serial, token, 'T-A01',
                      artifact['signer_sha256'], artifact['package'], 'direct-current', lock, part, stage)
            if observed['actual_signer_sha256'] != artifact['signer_sha256'] or observed['comparison'] != 'passed':
                raise RuntimeError('Bootstrap changed identity before A was enabled')
            shim = tagged_events(text, 'REPACK_SHIM')
            for phase in ('initEarly', 'initLate'):
                complete = [event for event in shim if event['event'] == 'complete' and event['phase'] == phase]
                if len(complete) != 1:
                    raise RuntimeError('Non-idempotent/missing bootstrap completion: ' + phase)
            # Full log order binds shim completion to actual app/provider initialization.
            early_line = next(i for i, line in enumerate(text.splitlines()) if 'REPACK_SHIM' in line and '"complete"' in line and '"initEarly"' in line)
            late_line = next(i for i, line in enumerate(text.splitlines()) if 'REPACK_SHIM' in line and '"complete"' in line and '"initLate"' in line)
            markers = {event.get('response_marker'): i for i, event in enumerate(tagged_events(text, 'REPACK_FIXTURE'))}
            for marker in ('application-attach', 'provider-onCreate', 'application-onCreate'):
                line = next((i for i, line in enumerate(text.splitlines()) if 'REPACK_FIXTURE' in line and '"' + marker + '"' in line), None)
                if line is None or not early_line < late_line < line:
                    raise RuntimeError('Bootstrap ordering failed at ' + marker)
            if name == 'custom-loader' and not {'custom-loader-created', 'custom-loader-retained'}.issubset(markers):
                raise RuntimeError('Original custom loader was not retained')
            component = artifact['package'] + '/dev.repack.fixture.common.'
            shell(lock, part, stage + '-receiver', serial,
                  ['am', 'broadcast', '-n', component + 'FixtureReceiver', '--es', 'token', token])
            shell(lock, part, stage + '-service', serial,
                  ['am', 'start-foreground-service', '-n', component + 'FixtureService', '--es', 'token', token])
            for attempt in range(10):
                component_logs = shell(lock, part, stage + '-component-logs-' + str(attempt), serial,
                            ['logcat', '-d', '-v', 'threadtime', '--pid=' + pid, '-T', timestamp]).stdout
                if 'receiver-onReceive:' + token in component_logs and 'service-onStart:' + token in component_logs:
                    break
                time.sleep(0.1)
            if 'receiver-onReceive:' + token not in component_logs or 'service-onStart:' + token not in component_logs:
                raise RuntimeError('Receiver/service delegation did not execute')
            shell(lock, part, stage + '-service-stop', serial,
                  ['am', 'stopservice', '-n', component + 'FixtureService'], check=False)
            for attempt in range(10):
                stopped_logs = shell(lock, part, stage + '-service-stopped-' + str(attempt), serial,
                         ['logcat', '-d', '-v', 'threadtime', '--pid=' + pid, '-T', timestamp]).stdout
                if 'service-onDestroy:' + token in stopped_logs:
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError('Service cleanup callback was not observed')
            if name == 'own-final':
                for component_marker in ('factory-classloader-entry', 'factory-application-entry', 'factory-activity-entry',
                                         'factory-provider-entry', 'factory-receiver-entry', 'factory-service-entry'):
                    if component_marker not in component_logs:
                        raise RuntimeError('Factory method was not delegated: ' + component_marker)
            result['comparisons'].append({'variant': name, 'stage': stage, 'pid': int(pid),
                                           'result': 'passed', 'early_late_idempotent': True,
                                           'provider_receiver_service': True})
        if name == 'exception':
            expect_factory_exception(artifact, serial, lock, part, 'patched-exception')
            result['comparisons'].append({'variant': name, 'exception_contract': 'IllegalAccessException', 'result': 'passed'})
        artifacts.append(artifact)
    result.update(verification='passed', outputs=artifacts)
    result['inputs'] = [report_reference(ROOT / '.work/evidence/M0-build.json')]


def run_t_a02(result: dict, evidence: Path, args) -> None:
    lock = load_lock()
    serial = select_serial(lock, evidence, args.device)
    result['cell'] = read_cell(lock, evidence, serial)
    bootstrap_path = ROOT / '.work/evidence/T-A01.json'
    boot = json.loads(bootstrap_path.read_text())
    if boot['verification'] != 'passed' or boot['source_sha256'] != source_hash():
        raise PrerequisiteError('Current T-A01 must pass first')
    artifact = next(x for x in boot['outputs'] if x['variant'] == 'own-final')
    keys = ensure_keys(lock, evidence)
    base = json.loads((ROOT / '.work/evidence/M0-build.json').read_text())
    other = next(x for x in base['outputs'] if x['id'] == 'other-own')
    for label, item in [('other', other), ('self', artifact)]:
        plan = preflight(item, serial, args.replace_existing_and_wipe_data, lock, evidence, label)
        install(item, serial, plan, lock, evidence, label, result['device_mutations'])
    for target, expected, actual in [(artifact['package'], [keys['original']['sha256']], artifact['signer_sha256']),
                                     (other['package'], other['signer_sha256'], other['signer_sha256'])]:
        for path in PATHS:
            label = ('self' if target == artifact['package'] else 'other') + '-' + path
            event, _, _, _ = launch_query(artifact, serial, result['run_id'] + label, 'T-A02', expected,
                                         target, path, lock, evidence, label)
            negative = target == artifact['package']
            if (event['actual_signer_sha256'] != actual or event['expected_signer_sha256'] != expected
                    or event['comparison'] != ('failed' if negative else 'passed')):
                raise RuntimeError('No-A identity negative control failed')
            result['comparisons'].append({'target': target, 'query_path': path, 'expected_original': expected,
                                         'observed': event['actual_signer_sha256'], 'negative_control': negative, 'result': 'passed'})
    control_dir = ROOT / '.work/outputs/bootstrap' / result['run_id']
    control_dir.mkdir(parents=True)
    bad_unsigned = control_dir / 'compressed-unsigned.apk'
    with zipfile.ZipFile(artifact['apk']) as archive, zipfile.ZipFile(bad_unsigned, 'w') as target:
        for item in archive.infolist():
            if item.filename.startswith('META-INF/'):
                continue
            payload = archive.read(item.filename)
            item = copy.copy(item)
            if item.filename == 'resources.arsc':
                item.compress_type = zipfile.ZIP_DEFLATED
            target.writestr(item, payload)
    bad_apk = control_dir / 'compressed.apk'
    align_sign(bad_unsigned, bad_apk, keys['repack'], lock, evidence)
    bad = {**artifact, 'apk': str(bad_apk), 'sha256': sha256(bad_apk)}
    try:
        preflight(bad, serial, True, lock, evidence, 'compressed-control')
    except RuntimeError as error:
        if 'resources.arsc' not in str(error):
            raise
    else:
        raise RuntimeError('Compressed resource negative control was accepted')
    result['comparisons'].append({'compressed_resources_rejected_before_install': True, 'result': 'passed'})
    result.update(verification='passed', inputs=[report_reference(bootstrap_path)])


def gate_bootstrap(result: dict, evidence: Path, args) -> None:
    children = {}
    for name in ('M0', 'T-A01', 'T-A02'):
        path = args.reports / (name + '.json')
        child = json.loads(path.read_text())
        if child['verification'] != 'passed':
            raise PrerequisiteError(name + ' has not passed')
        if name != 'M0' and child['source_sha256'] != source_hash():
            raise PrerequisiteError(name + ' source revision is stale')
        children[name] = report_reference(path)
    t1 = json.loads((args.reports / 'T-A01.json').read_text())
    t2 = json.loads((args.reports / 'T-A02.json').read_text())
    stages = {(item.get('variant'), item.get('stage')) for item in t1['comparisons'] if 'stage' in item}
    expected = {(variant, stage) for variant in ('own-final', 'androidx', 'platform-default', 'custom-loader', 'exception')
                for stage in ('first', 'compiled')}
    m0 = json.loads((args.reports / 'M0.json').read_text())
    if m0.get('evidence_contract_version') != 2:
        raise PrerequisiteError('Refresh M0 with immutable child references before joining BOOTSTRAP')
    if (t1['cell'] != t2['cell'] or t1['cell'] != m0['cell'] or stages != expected
            or len(t1['comparisons']) != 11 or len(t2['comparisons']) != 9):
        raise RuntimeError('Incomplete bootstrap cells/controls')
    if t2['inputs'][0]['sha256'] != children['T-A01']['sha256']:
        raise RuntimeError('T-A02 used another T-A01 report revision')
    result.update(verification='passed', gate_progress='accepted', cell=t1['cell'], children=children,
                  next_gate='M1b-5')


def gate_m0(result: dict, evidence: Path, args) -> None:
    lock = load_lock()
    children = {}
    for name in ('M0-host', 'M0-device', 'M0-build', 'T-A00'):
        path = args.reports / (name + '.json')
        if not path.is_file():
            raise PrerequisiteError('Missing ' + name + ' report')
        child = json.loads(path.read_text())
        if child['verification'] != 'passed' or (name == 'T-A00' and child['source_sha256'] != source_hash()):
            raise PrerequisiteError(name + ' is failed, unavailable or stale')
        if not child.get('evidence_refs'):
            raise PrerequisiteError(name + ' immutable report reference missing')
        for reference in child.get('evidence_refs', []):
            if not Path(reference).is_file():
                raise PrerequisiteError(name + ' immutable report missing')
            immutable = json.loads(Path(reference).read_text())
            if ({k: v for k, v in child.items() if k != 'evidence_refs'} !=
                    {k: v for k, v in immutable.items() if k != 'evidence_refs'}):
                raise RuntimeError(name + ' summary differs from its immutable report')
        children[name] = report_reference(path)
    host_report = json.loads((args.reports / 'M0-host.json').read_text())
    for name, current in lock['tools'].items():
        if 'path' not in current:
            continue
        recorded = host_report['tools'].get(name)
        if not recorded or current['sha256'] != recorded['sha256'] or sha256(Path(current['path'])) != recorded['sha256']:
            raise PrerequisiteError('Tool lock changed: ' + name)
        if 'jar_sha256' in current:
            jar = Path(current['path']).parent / 'lib' / (name + '.jar')
            if current['jar_sha256'] != recorded.get('jar_sha256') or sha256(jar) != recorded['jar_sha256']:
                raise PrerequisiteError('Tool JAR changed: ' + name)
    fixture_build = json.loads((args.reports / 'M0-build.json').read_text())
    if fixture_build.get('fixture_source_sha256') != fixture_source_hash():
        raise PrerequisiteError('Original fixture build sources changed')
    for entry in fixture_build['outputs']:
        if sha256(Path(entry['apk'])) != entry['sha256']:
            raise PrerequisiteError('Built fixture changed: ' + entry['id'])
    child_device = json.loads((args.reports / 'M0-device.json').read_text())['cell']
    baseline = json.loads((args.reports / 'T-A00.json').read_text())
    if child_device != baseline['cell'] or child_device != lock['cell']:
        raise PrerequisiteError('Device/baseline/current-lock cells differ')
    baseline_build = baseline['inputs'][0]
    if baseline_build['sha256'] != children['M0-build']['sha256']:
        raise PrerequisiteError('Baseline used a different fixture build report')
    if len(baseline['comparisons']) != 34 or any(x['result'] != 'passed' for x in baseline['comparisons']):
        raise RuntimeError('Incomplete original/AndroidX baseline or negative controls')
    result.update(verification='passed', cell=lock['cell'], children=children,
                  gate_progress='accepted', evidence_contract_version=2, next_gate='BOOTSTRAP')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('host', 'device'):
        command = commands.add_parser(name)
        command.add_argument('--device')
        command.add_argument('--out', type=Path, required=True)
    run = commands.add_parser('run')
    run.add_argument('case', choices=['T-A00', 'T-A01', 'T-A02', 'T-A03', 'T-A04', 'T-A05', 'T-A06', 'T-A10', 'T-A11', 'T-A12', 'T-A13', 'T-A14', 'T-A15', 'T-A16', 'T-B00', 'T-B01', 'T-B02', 'T-B03', 'T-B04', 'T-I50', 'T-P10', 'T-P11', 'T-P12', 'T-N10', 'T-N11', 'T-N12', 'T-T19', 'T-T20', 'T-T21', 'T-T21-CA', 'T-U30', 'T-U31', 'T-U32', 'T-U60', 'T-U61', 'T-U62', 'T-G70', 'T-V80'])
    run.add_argument('--device')
    run.add_argument('--replace-existing-and-wipe-data', action='store_true')
    run.add_argument('--out', type=Path, required=True)
    run.add_argument('--proxy-bind', default='127.0.0.1', help='Explicit local oracle interface reachable from the ADB server')
    run.add_argument('--scenario', choices=['ordinary-probe', 'identity-access'], default='ordinary-probe')
    gate = commands.add_parser('gate')
    gate.add_argument('gate', choices=['M0', 'BOOTSTRAP', 'M1b-5', 'M2', 'M3', 'M1a', 'M1b-1', 'M1b-2', 'M1b-3', 'M1b-4', 'RELEASE-1', 'M4', 'M5', 'M6', 'M7', 'M8'])
    gate.add_argument('--reports', type=Path, required=True)
    gate.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    os.chdir(ROOT)
    case = args.case if args.command == 'run' else args.gate if args.command == 'gate' else 'M0-' + args.command
    result, evidence = report(case)
    result['command']['argv'] = sys.argv
    status = 'FAIL'
    try:
        from scripts.routing_cases import run_t_n10, run_t_n11, run_t_n12, gate_routing
        from scripts.trust_cases import run_t_t19, run_t_t20, run_t_t21, run_t_t21_ca, gate_trust
        from scripts.pinning_cases import run_t_u30, run_t_u31, run_t_u32, gate_pinning
        from scripts.identity_cases import run_t_a03, run_t_a04, run_t_a05, run_t_a06, run_t_a16, gate_identity
        from scripts.contract_cases import run_t_a10
        from scripts.cache_cases import run_t_a11, gate_contracts
        from scripts.binder_cases import run_t_a12, run_t_a13, gate_binder
        from scripts.process_cases import run_t_a14
        from scripts.release_cases import run_t_a15, gate_process, gate_release
        from scripts.verification_cases import run_t_v80, gate_verification
        from scripts.gadget_cases import run_t_g70, gate_gadget
        from scripts.native_tls_cases import run_t_u60, run_t_u61, run_t_u62, gate_native_tls
        from scripts.container_cases import run_t_i50, gate_containers
        from scripts.native_cases import run_t_b00, run_t_b01, run_t_b02, run_t_b03, run_t_b04, gate_native
        from scripts.selected_cases import run_t_p10
        from scripts.install_cases import run_t_p11
        from scripts.cli_cases import run_t_p12, gate_integration
        handler = {'T-V80': run_t_v80, 'T-G70': run_t_g70, 'T-U62': run_t_u62, 'T-U60': run_t_u60, 'T-U61': run_t_u61, 'T-I50': run_t_i50, 'T-A00': run_t_a00, 'T-A01': run_t_a01, 'T-A02': run_t_a02, 'T-A03': run_t_a03, 'T-A04': run_t_a04, 'T-A05': run_t_a05, 'T-A06': run_t_a06, 'T-A10': run_t_a10, 'T-A11': run_t_a11, 'T-A12': run_t_a12, 'T-A13': run_t_a13, 'T-A16': run_t_a16, 'T-P10': run_t_p10, 'T-P11': run_t_p11, 'T-P12': run_t_p12,
                   'T-A14': run_t_a14, 'T-A15': run_t_a15, 'T-B00': run_t_b00, 'T-B01': run_t_b01, 'T-B02': run_t_b02, 'T-B03': run_t_b03, 'T-B04': run_t_b04, 'T-N10': run_t_n10, 'T-N11': run_t_n11, 'T-N12': run_t_n12,
                   'T-T19': run_t_t19, 'T-T20': run_t_t20, 'T-T21': run_t_t21, 'T-T21-CA': run_t_t21_ca, 'T-U30': run_t_u30,
                   'T-U31': run_t_u31, 'T-U32': run_t_u32}.get(case) if args.command == 'run' else {'M0': gate_m0, 'BOOTSTRAP': gate_bootstrap, 'M1b-5': gate_routing, 'M2': gate_trust, 'M3': gate_pinning, 'M1a': gate_identity, 'M1b-1': gate_contracts, 'M1b-2': gate_binder, 'M1b-3': gate_integration, 'M1b-4': gate_process, 'RELEASE-1': gate_release, 'M4': gate_native, 'M5': gate_containers, 'M6': gate_native_tls, 'M7': gate_gadget, 'M8': gate_verification}.get(case) if args.command == 'gate' else {'host': host, 'device': device}[args.command]
        handler(result, evidence, args)
        status = 'NOT-RUN' if result['verification'] == 'not-run' else 'PASS'
    except PrerequisiteError as error:
        result['prerequisite_failures'].append(str(error))
        status = 'BLOCKED'
    except Exception as error:
        result.update(verification='failed', error_class=type(error).__name__, error=str(error))
    exit_status = 0 if status in ('PASS', 'NOT-RUN') else (3 if status == 'BLOCKED' else 1)
    result['command']['exit_status'] = exit_status
    result['logs'].append(str(evidence))
    immutable = evidence / 'report.json'
    write_json(immutable, result)
    result['evidence_refs'].append(str(immutable))
    write_json(args.out, result)
    print(f'{status} {case} {args.out}')
    if status not in ('PASS', 'NOT-RUN'):
        print(result.get('error') or '; '.join(result['prerequisite_failures']), file=sys.stderr)
    return exit_status


if __name__ == '__main__':
    raise SystemExit(main())
