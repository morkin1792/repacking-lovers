"""M1a's API30 inventory and non-publishing interface-proxy observations."""
import csv
import json
from pathlib import Path
import re
import zipfile

from repack.rebuild import (ROOT, PrerequisiteError, ensure_keys, fixture_source_hash, load_lock,
                            environment, execute, report_reference, sha256, tool, write_json)
from repack.shim import build_bootstrap
from repack.verify import capture_startup, install, preflight, shell
from scripts.acceptance import launch_query, read_cell, select_serial, tagged_events

FLAGS_SHA256 = 'a19d839f4f61dc9c94960ae977b2e0f3eb30f880ba1ffe5108e790010b477a56'
FLAGS_URL = 'https://dl.google.com/developers/android/rvc/non-sdk/hiddenapi-flags.csv'


def inventory(cell):
    if cell['api'] != 30: raise PrerequisiteError('This identity access spike is locked to the selected API30 cell')
    flags = ROOT / '.work/inputs/api30-hiddenapi-flags.csv'
    if not flags.is_file() or sha256(flags) != FLAGS_SHA256: raise PrerequisiteError('Pinned API30 flag inventory missing/changed')
    required = {
        'Landroid/app/ActivityThread;->sPackageManager:Landroid/content/pm/IPackageManager;': 'primary-slot',
        'Landroid/app/ActivityThread;->getPackageManager()Landroid/content/pm/IPackageManager;': 'initialize-real',
        'Landroid/app/ActivityThread;->currentActivityThread()Landroid/app/ActivityThread;': 'known-contexts',
        'Landroid/content/pm/IPackageManager;->getPackageInfo(Ljava/lang/String;II)Landroid/content/pm/PackageInfo;': 'self-query',
        'Landroid/content/pm/IPackageManager;->getApplicationInfo(Ljava/lang/String;II)Landroid/content/pm/ApplicationInfo;': 'framework-canary',
    }
    optional = {
        'Landroid/app/ContextImpl;->mPackageManager:Landroid/app/ApplicationPackageManager;': 'cached-context-manager',
        'Landroid/app/ApplicationPackageManager;->mPM:Landroid/content/pm/IPackageManager;': 'existing-manager-interface',
        'Landroid/os/ServiceManager;->sCache:Ljava/util/Map;': 'raw-binder-cache-later',
        'Landroid/content/pm/PackageManager;->sPackageInfoCache:Landroid/app/PropertyInvalidatedCache;': 'optional-cache-owner',
        'Landroid/app/ApplicationPackageManager;->sPackageInfoCache:Landroid/app/PropertyInvalidatedCache;': 'optional-api30-cache-owner',
        'Landroid/net/Proxy;->sDefaultProxySelector:Ljava/net/ProxySelector;': 'optional-routing-state',
    }
    starts = tuple(required) + tuple(optional) + ('Landroid/content/pm/IPackageManager;->',)
    with flags.open(newline='') as stream:
        expected = {row[0]: row[1:] for row in csv.reader(stream) if row and row[0].startswith(starts)}
    members = []
    for descriptor in sorted(set(expected) | set(required) | set(optional)):
        members.append({'descriptor': descriptor, 'role': required.get(descriptor, optional.get(descriptor, 'interface-inventory')),
            'required': descriptor in required, 'expected_flags': expected.get(descriptor, []),
            'csv_match': 'matched' if descriptor in expected else 'missing', 'modifiers': None,
            'ordinary_read': 'not-run', 'ordinary_write': 'not-run'})
    data = {'schema_version': 1, 'api': 30, 'aosp_revision': 'android-11.0.0_r48-reference',
            'flags_url': FLAGS_URL, 'flags_sha256': FLAGS_SHA256, 'members': members,
            'source_image_note': 'Official API30 inventory; selected vendor image is not an exact AOSP source build',
            'proxy_probe': {key: 'not-run' for key in ('discovery', 'direct_lookup', 'enumeration', 'generation', 'forwarding')},
            'observation_policy': 'Expectations stay immutable; per-run observations and descriptor differences are retained in evidence'}
    data['proxy_probe']['references_replaced'] = False
    path = ROOT / 'tests/platform/api30-members.json'
    if path.exists():
        if json.loads(path.read_text()) != data: raise PrerequisiteError('Preserve prior inventory revision before changing expectations')
    else: write_json(path, data)
    return path, data


def run_t_a06(result, evidence, args):
    lock = load_lock(); serial = select_serial(lock, evidence, args.device)
    cell = read_cell(lock, evidence, serial); result['cell'] = cell
    gate = ROOT / '.work/evidence/M3.json'
    if json.loads(gate.read_text()).get('gate_progress') != 'accepted': raise PrerequisiteError('Accept M3 before returning to identity')
    path, expectations = inventory(cell)
    result['inputs'] = [report_reference(gate), {'path': str(path), 'sha256': sha256(path)}]
    baseline_path = ROOT / '.work/evidence/M0-build.json'; baseline = json.loads(baseline_path.read_text())
    if baseline['verification'] != 'passed' or baseline.get('fixture_source_sha256') != fixture_source_hash():
        raise PrerequisiteError('Build the current original fixtures first')
    result['inputs'].append(report_reference(baseline_path))
    original = next(item for item in baseline['outputs'] if item['id'] == 'app-own')
    if sha256(Path(original['apk'])) != original['sha256']: raise RuntimeError('Original fixture changed')
    keys = ensure_keys(lock, evidence); mode = args.scenario
    token = result['run_id'] + '-' + mode
    artifact = build_bootstrap(Path(original['apk']), ROOT / '.work/outputs/identity-probe' / result['run_id'],
                               keys['repack'], lock, evidence, identity_mode=mode, probe_token=token)
    result['outputs'] = [artifact]
    plan = preflight(artifact, serial, args.replace_existing_and_wipe_data, lock, evidence, 'probe')
    install(artifact, serial, plan, lock, evidence, 'probe', result['device_mutations'])
    with capture_startup(lock, serial, evidence, 'startup') as captured:
        query, _, pid, _ = launch_query(artifact, serial, token + '-public-control', 'T-A06',
                        artifact['signer_sha256'], artifact['package'], 'direct-current', lock, evidence, 'probe')
    logs = captured.read_text(errors='replace')
    result['logs'].append(str(captured))
    if query['comparison'] != 'passed' or query['actual_signer_sha256'] != artifact['signer_sha256']:
        raise RuntimeError('Probe changed the real public signing result')
    events = [item for item in tagged_events(logs, 'REPACK_SHIM') if item['details'].get('probe_token') == token and item['pid'] == int(pid)]
    complete = [item for item in events if item['details'].get('probe_stage') == 'complete']
    if len(complete) != 1 or any(item['pid'] != int(pid) or item['reference_replaced'] for item in events):
        raise RuntimeError('Fresh complete non-publishing probe observation missing')
    expected_bypass = mode == 'identity-access'
    if any(item['details']['bypass_active'] != expected_bypass for item in events):
        raise RuntimeError('Unexpected process-local bypass state')
    stages = {item['details']['probe_stage']: item for item in events if item['details']['probe_stage'] != 'enumeration-member'}
    enumerated = sorted({item['details']['descriptor'] for item in events if item['details']['probe_stage'] == 'enumeration-member'})
    expected = sorted({item['descriptor'] for item in expectations['members'] if
                       item['descriptor'].startswith('Landroid/content/pm/IPackageManager;->') and '(' in item['descriptor']})
    result['descriptor_inventory'] = {'csv': expected, 'app_visible': enumerated,
        'csv_only': sorted(set(expected) - set(enumerated)), 'image_only': sorted(set(enumerated) - set(expected))}
    result['observations'] = events; result['scenario'] = mode
    result['functional_verification'] = complete[0]['details']['outcome']
    if complete[0]['details']['outcome'] == 'passed':
        forwarding = stages.get('forwarding', {}).get('details', {})
        if forwarding.get('actual_signer_sha256') != artifact['signer_sha256'] or forwarding.get('package') != artifact['package']:
            raise RuntimeError('Interface forwarding does not match independent installed certificate truth')
        current_paths = shell(lock, evidence, 'installed-path', serial, ['pm', 'path', artifact['package']]).stdout.splitlines()
        if 'package:' + forwarding.get('source_dir', '') not in current_paths:
            raise RuntimeError('Forwarded PackageInfo does not retain installed paths')
        if stages.get('canary', {}).get('details', {}).get('uid') != forwarding.get('uid'):
            raise RuntimeError('Forwarded framework canary UID mismatch')
        if complete[0]['details'].get('forwarded_calls') != 2: raise RuntimeError('Expected two actual proxy forwards')
    elif not complete[0]['error_class']: raise RuntimeError('Failed functional probe lacks its actual exception class')
    if expected_bypass:
        if result['functional_verification'] != 'passed': raise RuntimeError('Pinned functional access probe failed')
        if stages.get('bypass', {}).get('details', {}).get('prefixes') != ['L']: raise RuntimeError('Wrong bypass prefix')
        result['dependency'] = json.loads((ROOT / 'config/hiddenapi-dependency.json').read_text())
        lock['identity_access'] = {'mode': 'process-local-bypass', 'version': '6.2', 'prefixes': ['L'],
                                   'artifact_sha256': result['dependency']['aar']['sha256']}
        write_json(ROOT / 'config/implementation-lock.json', lock)
    result['comparisons'].append({'name': 'actual-public-query-unmodified', 'result': 'passed', 'event': query})
    result.update(verification='passed', scope='Complete ordinary observations' if not expected_bypass else
                  'Pinned non-publishing interface generation/forwarding and field-access probe',
                  process={'name': artifact['package'], 'pid': int(pid)})


def run_t_a16(result, evidence, args):
    lock = load_lock(); serial = select_serial(lock, evidence, args.device)
    result['cell'] = read_cell(lock, evidence, serial)
    if result['cell']['api'] != 30: raise PrerequisiteError('First legacy adapter experiment is locked to API30')
    access_path = ROOT / '.work/evidence/T-A06-identity.json'; access = json.loads(access_path.read_text())
    if access['verification'] != 'passed' or access.get('functional_verification') != 'passed':
        raise PrerequisiteError('Complete the pinned access probe first')
    baseline_path = ROOT / '.work/evidence/M0-build.json'; baseline = json.loads(baseline_path.read_text())
    original = next(item for item in baseline['outputs'] if item['id'] == 'app-own')
    if sha256(Path(original['apk'])) != original['sha256']: raise RuntimeError('Original fixture changed')
    keys = ensure_keys(lock, evidence)
    if original['signer_sha256'] != [keys['original']['sha256']]: raise RuntimeError('Original signer does not match exported DER')
    verified = execute([tool(lock, 'apksigner'), 'verify', '--verbose', '--print-certs', original['apk']],
                       evidence, 'original-scheme', env=environment(lock)).stdout
    if 'Verified using v3 scheme (APK Signature Scheme v3): true' not in verified:
        raise PrerequisiteError('The controlled adapter fixture requires observed APK v3 signing')
    token = result['run_id'] + '-public-metadata'
    artifact = build_bootstrap(Path(original['apk']), ROOT / '.work/outputs/identity-metadata' / result['run_id'],
        keys['repack'], lock, evidence, identity_mode='public-metadata', probe_token=token,
        original_certificates=[Path(keys['original']['certificate']).read_bytes()], original_scheme=3)
    result['inputs'] = [report_reference(access_path), report_reference(baseline_path)]
    result['outputs'] = [artifact]
    plan = preflight(artifact, serial, args.replace_existing_and_wipe_data, lock, evidence, 'metadata')
    install(artifact, serial, plan, lock, evidence, 'metadata', result['device_mutations'])
    with capture_startup(lock, serial, evidence, 'startup') as captured:
        query, _, pid, _ = launch_query(artifact, serial, token + '-public-control', 'T-A16',
                    artifact['signer_sha256'], artifact['package'], 'direct-current', lock, evidence, 'metadata')
    events = [item for item in tagged_events(captured.read_text(errors='replace'), 'REPACK_SHIM')
              if item['details'].get('probe_token') == token and item['pid'] == int(pid)]
    if len(events) != 1: raise RuntimeError('Fresh metadata adapter observation missing')
    event = events[0]; data = event['details']; expected = original['signer_sha256']
    if (data.get('outcome') != 'passed' or data.get('actual_signer_sha256') != expected
            or data.get('actual_history_sha256') != expected or data.get('roundtrip_signer_sha256') != expected
            or data.get('has_multiple_signers') is not False or data.get('has_past_signing_certificates') is not False
            or data.get('bypass_active') is not False or event['access_mode'] != 'none'):
        raise RuntimeError('API30 public SigningInfo adapter failed: ' + json.dumps(event))
    if query['actual_signer_sha256'] != artifact['signer_sha256'] or query['comparison'] != 'passed':
        raise RuntimeError('Metadata probe altered the actual installed signing result')
    result.update(verification='passed', adapter='public-parcel-api30', observations=events,
                  comparisons=[{'name': 'public-adapter-roundtrip-single-signer-no-rotation', 'result': 'passed', 'event': event},
                               {'name': 'public-query-remains-real-repack-identity', 'result': 'passed', 'event': query}],
                  scope='API30 single original signer, no rotation; no hidden access needed by this adapter')


def run_t_a03(result, evidence, args):
    lock = load_lock(); serial = select_serial(lock, evidence, args.device)
    result['cell'] = read_cell(lock, evidence, serial)
    adapter_path = ROOT / '.work/evidence/T-A16.json'; adapter = json.loads(adapter_path.read_text())
    access_path = ROOT / '.work/evidence/T-A06-identity.json'; access = json.loads(access_path.read_text())
    if (adapter['verification'] != 'passed' or adapter['cell'] != result['cell']
            or access['verification'] != 'passed' or access['functional_verification'] != 'passed'):
        raise PrerequisiteError('Accept the selected access path and legacy metadata adapter first')
    baseline_path = ROOT / '.work/evidence/M0-build.json'; baseline = json.loads(baseline_path.read_text())
    if baseline['verification'] != 'passed' or baseline.get('fixture_source_sha256') != fixture_source_hash():
        raise PrerequisiteError('Build current signing/canary fixtures first')
    original = next(item for item in baseline['outputs'] if item['id'] == 'app-own')
    other = next(item for item in baseline['outputs'] if item['id'] == 'other-own')
    for entry in (original, other):
        if sha256(Path(entry['apk'])) != entry['sha256']: raise RuntimeError('Original fixture changed')
    keys = ensure_keys(lock, evidence)
    if original['signer_sha256'] != [keys['original']['sha256']]: raise RuntimeError('Original certificate truth mismatch')
    token = result['run_id'] + '-identity'
    artifact = build_bootstrap(Path(original['apk']), ROOT / '.work/outputs/identity' / result['run_id'],
        keys['repack'], lock, evidence, identity_mode='identity', probe_token=token,
        original_certificates=[Path(keys['original']['certificate']).read_bytes()], original_scheme=3)
    result['inputs'] = [report_reference(access_path), report_reference(adapter_path), report_reference(baseline_path)]
    result['outputs'] = [artifact]
    for label, item in [('other', other), ('self', artifact)]:
        plan = preflight(item, serial, args.replace_existing_and_wipe_data, lock, evidence, label)
        install(item, serial, plan, lock, evidence, label, result['device_mutations'])
    installed_paths = {}
    installed_uids = {}
    for item in (artifact, other):
        package = item['package']
        paths = shell(lock, evidence, package + '-paths', serial, ['pm', 'path', package]).stdout.splitlines()
        if len(paths) != 1 or not paths[0].startswith('package:'): raise RuntimeError('Unexpected installed fixture layout')
        installed_paths[package] = paths[0][8:]
        output = shell(lock, evidence, package + '-uid', serial, ['pm', 'list', 'packages', '-U', package]).stdout
        match = re.search(r'package:' + re.escape(package) + r'\s+uid:(\d+)', output)
        if not match: raise RuntimeError('Installed UID oracle missing')
        installed_uids[package] = int(match[1])
    for target, expected in [(artifact['package'], original['signer_sha256']), (other['package'], other['signer_sha256'])]:
        for path in ('direct-legacy', 'direct-current', 'reflect-legacy', 'reflect-current'):
            label = ('self-' if target == artifact['package'] else 'other-') + path
            with capture_startup(lock, serial, evidence, label) as captured:
                query, _, pid, _ = launch_query(artifact, serial, result['run_id'] + '-' + label, 'T-A03', expected,
                                             target, path, lock, evidence, label)
            if query['comparison'] != 'passed' or query['actual_signer_sha256'] != expected:
                raise RuntimeError('Published identity does not match host certificate truth: ' + label)
            fields = json.loads(query['response_marker'])
            if (fields['uid'] != installed_uids[target] or fields['source_dir'] != installed_paths[target]
                    or fields['public_source_dir'] != installed_paths[target] or fields['version_code'] != artifact['version_code']
                    or fields['package'] != target or fields['context_canary_uid'] != installed_uids[artifact['package']]
                    or fields['context_canary_source_dir'] != installed_paths[artifact['package']]):
                raise RuntimeError('Installed non-signing fields/framework context changed: ' + label)
            events = [item for item in tagged_events(captured.read_text(errors='replace'), 'REPACK_SHIM')
                      if item['pid'] == int(pid) and item['details'].get('capability') == 'identity']
            published = [item for item in events if item['phase'] == 'initEarly' and item['event'] == 'complete']
            if len(published) != 1 or not published[0]['reference_replaced']:
                raise RuntimeError('Identity was not published before app startup')
            canaries = [item for item in events if item['event'] == 'forward' and '->getApplicationInfo(' in (item['descriptor'] or '')]
            if not canaries: raise RuntimeError('Public createPackageContext/getApplicationInfo canary did not traverse the wrapper')
            transformations = [item for item in events if 'flags' in item['details']]
            if target == artifact['package']:
                if not transformations or transformations[0]['details']['flags'] != query['flags']:
                    raise RuntimeError('First self signing query did not enter the handler')
                if any(item['details']['before_fields'] != item['details']['after_fields'] for item in transformations):
                    raise RuntimeError('Handler altered installed non-signing fields')
            elif transformations: raise RuntimeError('Unrelated package signing data was transformed')
            result['comparisons'].append({'name': label, 'result': 'passed', 'event': query,
                'publication': published[0], 'framework_canary_count': len(canaries), 'handler_signing_queries': transformations,
                'installed_path_oracle': installed_paths[target], 'installed_uid_oracle': installed_uids[target]})
    missing = 'dev.repack.fixture.missing'
    if 'package:' in shell(lock, evidence, 'missing-check', serial, ['pm', 'path', missing], check=False).stdout:
        raise PrerequisiteError('Missing-package control is unexpectedly installed')
    for path in ('direct-current', 'reflect-current'):
        label = 'missing-' + path
        with capture_startup(lock, serial, evidence, label) as captured:
            query, _, pid, _ = launch_query(artifact, serial, result['run_id'] + '-' + label, 'T-A03',
                artifact['signer_sha256'], missing, path, lock, evidence, label, allow_failure=True)
        published = [item for item in tagged_events(captured.read_text(errors='replace'), 'REPACK_SHIM')
                     if item['pid'] == int(pid) and item['details'].get('capability') == 'identity'
                     and item['phase'] == 'initEarly' and item['reference_replaced']]
        if (not published or query['event'] != 'failure'
                or query['error_class'] != 'android.content.pm.PackageManager$NameNotFoundException'):
            raise RuntimeError('Published wrapper changed missing-package exception semantics')
        result['comparisons'].append({'name': label, 'result': 'passed', 'negative_control': True, 'event': query})
    result.update(verification='passed', transformation='applied',
                  scope='API30 scalar self signing flags, direct/reflective paths; unrelated packages and installed fields preserved')


def identity_fixture(result, evidence, args, mode):
    lock = load_lock(); serial = select_serial(lock, evidence, args.device)
    result['cell'] = read_cell(lock, evidence, serial)
    a03_path = ROOT / '.work/evidence/T-A03.json'; first = json.loads(a03_path.read_text())
    if first['verification'] != 'passed' or first['cell'] != result['cell']:
        raise PrerequisiteError('Accept the first scalar identity path before broader experiments')
    baseline_path = ROOT / '.work/evidence/M0-build.json'; baseline = json.loads(baseline_path.read_text())
    if baseline['verification'] != 'passed' or baseline.get('fixture_source_sha256') != fixture_source_hash():
        raise PrerequisiteError('Build the current early-provider fixtures first')
    original = next(item for item in baseline['outputs'] if item['id'] == 'app-own')
    other = next(item for item in baseline['outputs'] if item['id'] == 'other-own')
    for item in (original, other):
        if sha256(Path(item['apk'])) != item['sha256']: raise RuntimeError('Original fixture changed')
    keys = ensure_keys(lock, evidence)
    token = result['run_id'] + '-' + mode
    early = {'run_id': token + '-early', 'case_id': result['case_id'],
             'expected_signer_sha256': original['signer_sha256']} if mode == 'identity-archive' else None
    artifact = build_bootstrap(Path(original['apk']), ROOT / '.work/outputs/identity' / result['run_id'],
        keys['repack'], lock, evidence, identity_mode=mode, probe_token=token,
        original_certificates=[Path(keys['original']['certificate']).read_bytes()], original_scheme=3,
        fixture_early_query=early)
    result['inputs'] = [report_reference(a03_path), report_reference(baseline_path)]
    result['outputs'] = [artifact]
    for label, item in [('other', other), ('self', artifact)]:
        plan = preflight(item, serial, args.replace_existing_and_wipe_data, lock, evidence, label)
        install(item, serial, plan, lock, evidence, label, result['device_mutations'])
    return lock, serial, original, other, artifact, token


def run_t_a04(result, evidence, args):
    lock, serial, original, other, artifact, token = identity_fixture(result, evidence, args, 'identity-failure')
    missing = 'dev.repack.fixture.missing'
    absent = shell(lock, evidence, 'missing-package', serial, ['pm', 'path', missing], check=False)
    if 'package:' in absent.stdout: raise PrerequisiteError('Missing-package control is unexpectedly installed')
    for label, target, path, expected, failure in [
            ('self', artifact['package'], 'direct-current', artifact['signer_sha256'], False),
            ('other', other['package'], 'direct-current', other['signer_sha256'], False),
            ('missing-direct', missing, 'direct-current', artifact['signer_sha256'], True),
            ('missing-reflect', missing, 'reflect-current', artifact['signer_sha256'], True)]:
        with capture_startup(lock, serial, evidence, label) as captured:
            query, _, pid, _ = launch_query(artifact, serial, result['run_id'] + '-' + label, 'T-A04', expected,
                        target, path, lock, evidence, label, allow_failure=failure)
        events = [item for item in tagged_events(captured.read_text(errors='replace'), 'REPACK_SHIM')
                  if item['pid'] == int(pid) and item['details'].get('capability') == 'identity']
        failed = [item for item in events if item['event'] == 'failure']
        if (len(failed) != 1 or not failed[0]['details'].get('forced_failure')
                or not failed[0]['details'].get('rollback_verified') or any(item['reference_replaced'] for item in events)):
            raise RuntimeError('Failure left a partial published identity state')
        if failure:
            if query['event'] != 'failure' or query['error_class'] != 'android.content.pm.PackageManager$NameNotFoundException':
                raise RuntimeError('Missing-package exception cause changed')
        elif query['comparison'] != 'passed' or query['actual_signer_sha256'] != expected:
            raise RuntimeError('Real package queries stopped working after initialization failure')
        result['comparisons'].append({'name': label, 'result': 'passed', 'query': query, 'failure': failed[0]})
    result.update(verification='passed', scope='Forced recoverable failure before publication; original queries and exception causes remain usable')


def run_t_a05(result, evidence, args):
    lock, serial, original, other, artifact, token = identity_fixture(result, evidence, args, 'identity-archive')
    with zipfile.ZipFile(artifact['apk']) as archive:
        if archive.read('assets/repack/original.apk') != Path(original['apk']).read_bytes():
            raise RuntimeError('Retained original APK bytes differ before installation')
    with capture_startup(lock, serial, evidence, 'archive') as captured:
        query, _, pid, _ = launch_query(artifact, serial, token + '-late', 'T-A05', original['signer_sha256'],
                    artifact['package'], 'direct-current', lock, evidence, 'archive')
    text = captured.read_text(errors='replace')
    events = [item for item in tagged_events(text, 'REPACK_SHIM')
              if item['pid'] == int(pid) and item['details'].get('probe_token') == token]
    completed = [item for item in events if item['details'].get('capability') == 'original-archive' and item['event'] == 'complete']
    if len(completed) != 1: raise RuntimeError('Framework archive parsing did not complete: ' + json.dumps(events[-3:]))
    data = completed[0]['details']
    paths = shell(lock, evidence, 'installed-path', serial, ['pm', 'path', artifact['package']]).stdout.splitlines()
    if (data['original_sha256'] != original['sha256'] or data['original_size'] != Path(original['apk']).stat().st_size
            or data['current_signer_sha256'] != original['signer_sha256'] or data['legacy_signer_sha256'] != original['signer_sha256']
            or data['history_sha256'] != original['signer_sha256'] or data['package'] != original['package']
            or 'package:' + data['installed_source_dir'] not in paths or data['installed_source_redirected'] is not False
            or data['archive_path'] == data['installed_source_dir']):
        raise RuntimeError('Framework-parsed metadata/bytes/installed source differ from independent truth')
    fixture = [item for item in tagged_events(text, 'REPACK_FIXTURE') if item['pid'] == int(pid)]
    early = [item for item in fixture if item['run_id'] == token + '-early']
    if len(early) != 1 or early[0]['comparison'] != 'passed' or early[0]['actual_signer_sha256'] != original['signer_sha256']:
        raise RuntimeError('Provider signing query did not use the original embedded metadata before archive provisioning')
    lines = text.splitlines()
    provider = next(i for i, line in enumerate(lines) if 'REPACK_FIXTURE' in line and '"run_id":"' + token + '-early"' in line)
    app_created = next(i for i, line in enumerate(lines) if 'REPACK_FIXTURE' in line and '"application-onCreate"' in line and str(pid) in line.split())
    entry = next(i for i, line in enumerate(lines) if 'REPACK_SHIM' in line and '"original-archive"' in line and '"event":"entry"' in line)
    done = next(i for i, line in enumerate(lines) if 'REPACK_SHIM' in line and '"original-archive"' in line and '"event":"complete"' in line)
    if not provider < app_created < entry < done: raise RuntimeError('Context-dependent parser ran before synchronous startup callbacks completed')
    if any('"capability":"identity"' in line and '"flags"' in line for line in lines[entry:done]):
        raise RuntimeError('Archive-parser window unexpectedly queried the signing proxy')
    if query['comparison'] != 'passed' or query['actual_signer_sha256'] != original['signer_sha256']:
        raise RuntimeError('Later self signing query differs after archive parsing')
    result.update(verification='passed', transformation='applied', observations=completed,
        comparisons=[{'name': 'retained-apk-and-framework-current-legacy-history', 'result': 'passed', 'event': completed[0]},
                     {'name': 'provider-before-context-experiment', 'result': 'passed', 'event': early[0]},
                     {'name': 'later-signing-query', 'result': 'passed', 'event': query}],
        recommendation='Use the accepted embedded API30 adapter for synchronous startup; framework-parsed metadata is available only after this post-context callback.',
        scope='App-private original provisioning and framework archive parsing; no B/file-read redirect')


def gate_identity(result, evidence, args):
    from repack.rebuild import source_hash
    children = {}; reports = {}
    for name in ('T-A06-ordinary', 'T-A06-identity', 'T-A16', 'T-A03', 'T-A04', 'T-A05'):
        index = args.reports / (name + '.json'); child = json.loads(index.read_text())
        if child['verification'] != 'passed' or child['source_sha256'] != source_hash():
            raise PrerequisiteError(name + ' unavailable/failed/stale')
        children[name] = report_reference(index); reports[name] = child
    if any(child['cell'] != reports['T-A03']['cell'] for child in reports.values()): raise RuntimeError('Identity cases used different cells')
    if reports['T-A06-identity']['functional_verification'] != 'passed': raise RuntimeError('Functional access is unavailable')
    if [len(reports[name]['comparisons']) for name in ('T-A16', 'T-A03', 'T-A04', 'T-A05')] != [2, 10, 4, 3]:
        raise RuntimeError('Identity spike controls incomplete')
    for name in ('T-A04', 'T-A05'):
        if reports[name]['inputs'][0]['sha256'] != children['T-A03']['sha256']:
            raise RuntimeError(name + ' used another scalar identity experiment revision')
    result.update(verification='passed', gate_progress='accepted', children=children, cell=reports['T-A03']['cell'],
                  scope='API30 self scalar getPackageInfo signing flags, direct/reflection, original installed fields and framework canaries',
                  access_mode='process-local-bypass', metadata_adapter='public-parcel-api30',
                  unsupported=['other-APIs-until-M1b-1', 'list-queries-until-M1b-1', 'prewarmed-caches-until-M1b-1',
                               'JNI-and-fresh-Binder-until-M1b-2', 'other-API-levels', 'native-file-integrity'], next_gate='M1b-1')
