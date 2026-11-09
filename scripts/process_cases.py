"""Per-process observations, app-local provider changes and prepared-wrapper rollback."""
import json
import re
from pathlib import Path
import time

from repack.rebuild import (ROOT, PrerequisiteError, align_sign, copy_archive, ensure_keys,
                            fixture_source_hash, load_lock, report_reference, sha256)
from repack.shim import build_bootstrap
from repack.verify import capture_startup, install, preflight, shell
from scripts.acceptance import read_cell, read_events, select_serial, tagged_events
from scripts.binder_cases import with_libraries
from scripts.contract_cases import SELF, OTHER


def launch_process(result, evidence, serial, lock, label, role):
    token = result['run_id'] + '-' + label
    shell(lock, evidence, label + '-stop', serial, ['am', 'force-stop', SELF])
    with capture_startup(lock, serial, evidence, label) as captured:
        shell(lock, evidence, label + '-launch', serial, ['am', 'start', '-W', '-n', SELF + '/.ProbeActivity',
            '--es', 'scenario', 'process', '--es', 'run_id', token, '--es', 'process_role', role], timeout=15)
        for _ in range(100):
            if len(read_events(captured.read_text(errors='replace'), token)) >= 13: break
            time.sleep(.1)
    text = captured.read_text(errors='replace'); rows = {}
    for event in read_events(text, token):
        if event['case_id'] != 'T-A14' or event['scenario'] != 'process': raise RuntimeError('Mismatched process event')
        path = event['query_path']
        if path in rows and rows[path] != event: raise RuntimeError('Conflicting process observation')
        rows[path] = event
    paths = {role + '/' + who + '/' + path for who in ('self', 'other')
             for path in ('direct-legacy', 'direct-current', 'reflect-legacy', 'reflect-current', 'jni-legacy', 'jni-current')}
    paths.add(role + '/missing/direct-current')
    if set(rows) != paths: raise RuntimeError('Incomplete process queries: ' + str(paths ^ set(rows)))
    pids = {event['pid'] for event in rows.values()}; names = {event['process'] for event in rows.values()}
    expected_name = SELF if role == 'main' else SELF + ':repack_' + role
    if role == 'isolated': expected_name += ':dev.repack.fixture.common.ProcessProbe$IsolatedService'
    if len(pids) != 1 or names != {expected_name}: raise RuntimeError('Queries came from a different process')
    pid = next(iter(pids))
    shim = [item for item in tagged_events(text, 'REPACK_SHIM') if item['pid'] == pid]
    fixture = [item for item in tagged_events(text, 'REPACK_FIXTURE') if item['pid'] == pid]
    markers = [item['response_marker'] for item in fixture if item['event'] == 'marker']
    combined = []
    for line in text.splitlines():
        match = re.search(r'(REPACK_SHIM|REPACK_FIXTURE)\s*:\s*(\{.*\})\s*$', line)
        if match:
            item = json.loads(match[2])
            if item['pid'] == pid: combined.append((match[1], item))
    if shim:
        positions = []
        for phase in ('initEarly', 'initLate'):
            matches = [index for index, (tag, item) in enumerate(combined) if tag == 'REPACK_SHIM'
                       and item['phase'] == phase and item['event'] == 'complete' and not item['details']]
            if len(matches) != 1: raise RuntimeError('Missing/duplicate bootstrap phase in process ' + role)
            positions.append(matches[0])
        attach = next(index for index, (tag, item) in enumerate(combined)
                      if tag == 'REPACK_FIXTURE' and item['response_marker'] == 'application-attach')
        constructor = next(index for index, (tag, item) in enumerate(combined)
                           if tag == 'REPACK_FIXTURE' and item['response_marker'] == 'factory-constructor')
        if not positions[0] < constructor < positions[1] < attach:
            raise RuntimeError('Per-process early/late ordering changed')
    for marker in ('factory-constructor', 'factory-classloader-entry', 'factory-application-entry',
                   'application-attach', 'application-onCreate'):
        if markers.count(marker) != 1: raise RuntimeError('Missing/duplicate per-process startup marker: ' + marker)
    if role != 'main' and markers.count('factory-service-entry') != 1: raise RuntimeError('Service factory was bypassed')
    if role == 'main' and markers.index('provider-onCreate') > markers.index('application-onCreate'):
        raise RuntimeError('Unexpected provider ordering')
    return {'role': role, 'pid': pid, 'process': expected_name, 'queries': rows, 'shim': shim, 'markers': markers,
            'raw_capture': str(captured)}


def run_t_a14(result, evidence, args):
    lock = load_lock(); serial = select_serial(lock, evidence, args.device); result['cell'] = read_cell(lock, evidence, serial)
    if result['cell']['api'] != 30: raise PrerequisiteError('Process identity adapter is API30-specific')
    gate = ROOT / '.work/evidence/M1b-3.json'; build_path = ROOT / '.work/evidence/M0-build.json'
    if json.loads(gate.read_text()).get('gate_progress') != 'accepted': raise PrerequisiteError('Accept M1b-3 first')
    build = json.loads(build_path.read_text())
    if build.get('fixture_source_sha256') != fixture_source_hash(): raise PrerequisiteError('Build current process fixtures first')
    native_path = ROOT / '.work/evidence/T-A12.json'; native = json.loads(native_path.read_text())
    libraries = native['native_build']
    if any(sha256(Path(item['library'])) != item['sha256'] for item in libraries): raise PrerequisiteError('JNI fixture changed')
    result['inputs'] = [report_reference(path) for path in (gate, build_path, native_path)]
    keys = ensure_keys(lock, evidence)
    original = with_libraries(next(item for item in build['outputs'] if item['id'] == 'app-own'),
                              libraries, keys['original'], lock, evidence / 'native-original')
    other = next(item for item in build['outputs'] if item['id'] == 'other-own')
    certificate = Path(keys['original']['certificate']).read_bytes()
    original_provider = evidence / 'provider-original'; original_provider.mkdir()
    unsigned = original_provider / 'unsigned.apk'; signed = original_provider / 'original.apk'
    copy_archive(Path(original['apk']), unsigned, additions={'assets/repack-fixture-x509-provider.json': b'{"enabled":true}'})
    align_sign(unsigned, signed, keys['original'], lock, original_provider)
    provider = {**original, 'apk': str(signed), 'sha256': sha256(signed)}
    artifacts = {'genuine': original, 'provider-genuine': provider}
    result['outputs'] = list(artifacts.values()); result['observations'] = {}
    # Build once per arrangement, then force-stop/restart each selected process independently.
    for label, source, mode in [('patched', original, 'identity'), ('provider-patched', provider, 'identity'),
                                 ('rollback', original, 'identity-failure')]:
        part = evidence / label; part.mkdir()
        artifacts[label] = build_bootstrap(Path(source['apk']), ROOT / '.work/outputs/process' / result['run_id'] / label,
            keys['repack'], lock, part, identity_mode=mode, probe_token=result['run_id'] + '-' + label,
            original_certificates=[certificate], original_scheme=3, signing_contracts=True, package_binder=True)
        result['outputs'].append(artifacts[label])
    for name in ('genuine', 'patched', 'provider-genuine', 'provider-patched', 'rollback'):
        artifact = artifacts[name]
        for label, entry in [(name, artifact), (name + '-other', other)]:
            plan = preflight(entry, serial, args.replace_existing_and_wipe_data, lock, evidence, label)
            install(entry, serial, plan, lock, evidence, label, result['device_mutations'])
        installed = {}
        for package in (SELF, OTHER):
            uid_output = shell(lock, evidence, name + '-' + package + '-uid', serial,
                               ['pm', 'list', 'packages', '-U', package]).stdout
            match = re.search(r'package:' + re.escape(package) + r'\s+uid:(\d+)', uid_output)
            paths = shell(lock, evidence, name + '-' + package + '-paths', serial, ['pm', 'path', package]).stdout.splitlines()
            if not match or len(paths) != 1 or not paths[0].startswith('package:'):
                raise RuntimeError('Missing independent installed process metadata')
            installed[package] = {'package_uid': int(match[1]), 'source_dir': paths[0][8:], 'version_code': 1}
        roles = ('main', 'remote', 'isolated', 'remote') if name in ('genuine', 'patched') else ('main',)
        previous_remote = None
        for index, role in enumerate(roles):
            label = name + '-' + str(index) + '-' + role
            observation = launch_process(result, evidence, serial, lock, label, role)
            result['observations'][label] = observation
            observation['installed_metadata'] = installed
            if role == 'remote':
                if previous_remote == observation['pid']: raise RuntimeError('Force-stop did not restart remote process')
                previous_remote = observation['pid']
            publications = [item for item in observation['shim'] if item['details'].get('metadata_source') == 'embedded-host-verified-certificates']
            failures = [item for item in observation['shim'] if item['details'].get('forced_failure')]
            is_patched = name in ('patched', 'provider-patched')
            if is_patched and role != 'isolated' and (len(publications) != 1 or not publications[0]['reference_replaced']):
                raise RuntimeError('Missing identity publication in process ' + role)
            if name == 'rollback' and (len(failures) != 1 or not failures[0]['details'].get('rollback_verified')
                                       or not failures[0]['details'].get('binder_rollback_verified')
                                       or failures[0]['reference_replaced'] or publications):
                raise RuntimeError('Prepared Binder/PM rollback did not restore original references')
            if name == 'rollback' and len([item for item in observation['shim']
                    if item['details'].get('operation') == 'service-cache-publication']) != 1:
                raise RuntimeError('Binder rollback fixture failed before actual cache publication')
            for path, event in observation['queries'].items():
                who = path.split('/')[1]; details = json.loads(event['response_marker'])
                if role == 'isolated':
                    if details['process_uid'] == installed[SELF]['package_uid']:
                        raise RuntimeError('Isolated service reused the application UID')
                elif details['process_uid'] != installed[SELF]['package_uid']:
                    raise RuntimeError('Ordinary process UID differs from installed package')
                if event['event'] == 'query' and any(details[key] != value for key, value in installed[event['package']].items()):
                    raise RuntimeError('Signing transformation changed installed process metadata')
                if role == 'isolated':
                    reference = result['observations']['genuine-2-isolated']['queries'][path]
                    # A restricted baseline path can only establish equivalent failure, never identity support.
                    if reference['event'] == 'failure':
                        if event['event'] != 'failure' or event['error_class'] != reference['error_class']:
                            raise RuntimeError('Isolated-process error contract changed: ' + path)
                        status = 'baseline-restriction-preserved'
                    else:
                        expected = other['signer_sha256'] if who == 'other' else original['signer_sha256']
                        if event['actual_signer_sha256'] != expected: raise RuntimeError('Isolated signer mismatch: ' + path)
                        status = 'identity-query-passed'
                elif who == 'missing':
                    if event['error_class'] != 'android.content.pm.PackageManager$NameNotFoundException':
                        raise RuntimeError('Process missing-package exception changed')
                    status = 'missing-error-preserved'
                else:
                    expected = other['signer_sha256'] if who == 'other' else original['signer_sha256'] if name != 'rollback' else artifact['signer_sha256']
                    if event['event'] != 'query' or event['actual_signer_sha256'] != expected:
                        raise RuntimeError('Process signing contract failed: ' + label + '/' + path + ': ' + str(event))
                    if path.endswith('/jni-current') or path.endswith('/jni-legacy'):
                        if details['loaded_abi'] != result['cell']['abi']: raise RuntimeError('Unexpected process JNI ABI')
                    if name == 'provider-patched' and details['x509_factory_calls']:
                        raise RuntimeError('Identity reconstruction invoked the application provider')
                    status = 'identity-query-passed'
                result['comparisons'].append({'name': label + '/' + path, 'result': 'passed', 'classification': status, 'event': event})
            if name.startswith('provider-') and 'fixture-x509-provider-installed' not in observation['markers']:
                raise RuntimeError('Provider control did not execute')
    result.update(verification='passed', transformation='applied', scope='API30 owned main/remote/restarted/isolated-process Java/reflection/JNI identity, app-provider independence, caller-copy isolation and published Binder rollback',
        unsupported=['external/GMS-processes', 'WebView-renderer-process', 'unobserved-classloaders', 'other-API-levels',
                     'other-firmware-isolated-process-behavior'])
