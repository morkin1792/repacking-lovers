"""M1b-1 signing API contracts against real unmodified reference installations."""
import base64
import hashlib
import json
from pathlib import Path
import re
import time

from repack.rebuild import (ROOT, PrerequisiteError, align_sign, badging, copy_archive, ensure_keys, environment,
                            execute, fixture_source_hash, load_lock, report_reference, sha256, signer_digests, tool, write_json)
from repack.shim import build_bootstrap
from repack.verify import adb, capture_startup, install, preflight, shell
from scripts.acceptance import launch_query, read_cell, read_events, select_serial, tagged_events

SELF = 'dev.repack.fixture.identity'
OTHER = 'dev.repack.fixture.other'


def signing_env(lock, keys):
    env = environment(lock)
    env['REPACK_FIXTURE_SIGN_PASSWORD'] = Path(keys['original']['password_file']).read_text().strip()
    return env


def signer_args(key):
    return ['--ks', key['path'], '--ks-key-alias', key['alias'], '--ks-pass', 'env:REPACK_FIXTURE_SIGN_PASSWORD']


def lineage(lock, keys, evidence):
    path = ROOT / '.work/keys/fixture-original-to-other.lineage'
    env = signing_env(lock, keys)
    if not path.exists():
        execute([tool(lock, 'apksigner'), 'rotate', '--out', str(path), '--old-signer', *signer_args(keys['original']),
                 '--new-signer', *signer_args(keys['other'])], evidence, 'lineage-create', env=env)
    check = execute([tool(lock, 'apksigner'), 'lineage', '--in', str(path), '--print-certs'],
                    evidence, 'lineage-verify', env=env)
    digests = re.findall(r'certificate SHA-256 digest:\s*([0-9a-fA-F]{64})', check.stdout)
    if digests != [keys['original']['sha256'], keys['other']['sha256']]:
        raise RuntimeError('Persistent fixture lineage does not match original->other certificates')
    return path


def sign_profile(original, key_names, lock, keys, evidence, *, rotated=False, rotation_min_sdk=28):
    evidence.mkdir(parents=True)
    unsigned = evidence / 'unsigned.apk'; copy_archive(Path(original['apk']), unsigned)
    aligned = evidence / 'aligned.apk'
    execute([tool(lock, 'zipalign'), '-P', '16', '-f', '4', str(unsigned), str(aligned)], evidence, 'profile-align')
    apk = evidence / 'original.apk'
    command = [tool(lock, 'apksigner'), 'sign', '--v1-signing-enabled', 'false', '--v2-signing-enabled', 'true',
               '--v3-signing-enabled', 'false' if len(key_names) > 1 else 'true', '--v4-signing-enabled', 'false']
    if rotated:
        command += ['--lineage', str(lineage(lock, keys, evidence)), '--rotation-min-sdk-version', str(rotation_min_sdk)]
    signing_names = ['original', 'other'] if rotated else key_names
    for index, name in enumerate(signing_names):
        if index: command.append('--next-signer')
        command += signer_args(keys[name])
    command += ['--out', str(apk), str(aligned)]
    execute(command, evidence, 'profile-sign', env=signing_env(lock, keys))
    actual = signer_digests(apk, lock, evidence, 'profile-verify', api=rotation_min_sdk if rotated else None)
    if actual != sorted(keys[name]['sha256'] for name in key_names): raise RuntimeError('Profile signer set differs')
    if rotated:
        output = execute([tool(lock, 'apksigner'), 'lineage', '--in', str(apk), '--print-certs'],
                         evidence, 'profile-lineage', env=environment(lock)).stdout
        history = re.findall(r'certificate SHA-256 digest:\s*([0-9a-fA-F]{64})', output)
        if history != [keys['original']['sha256'], keys['other']['sha256']]: raise RuntimeError('Signed APK lacks the verified rotation history')
    info, _ = badging(apk, lock, evidence, 'profile-badging')
    return {**info, 'apk': str(apk), 'sha256': sha256(apk), 'signer_sha256': actual}


def cases(keys):
    result = []
    for target, label in [(SELF, 'self'), (OTHER, 'other')]:
        for key_name in ('original', 'other', 'repack'):
            certificate = Path(keys[key_name]['certificate']).read_bytes()
            for kind in (0, 1):
                encoded = base64.b64encode(certificate if kind == 0 else hashlib.sha256(certificate).digest()).decode()
                for op in ('predicate-package', 'predicate-uid'):
                    result.append({'id': f'{label}-{key_name}-{kind}-{op}', 'operation': op, 'package': target,
                                   'certificate': encoded, 'certificate_type': kind})
    for op in ('predicate-package', 'predicate-uid'):
        for label, certificate, kind in [('empty', '', 0), ('null', None, 0), ('invalid-type', '', 999)]:
            result.append({'id': op + '-' + label, 'operation': op, 'package': SELF,
                           'certificate': certificate, 'certificate_type': kind})
    for op in ('compare-package', 'compare-uid'):
        result.append({'id': op + '-self', 'operation': op, 'package': SELF, 'other_package': SELF})
        result.append({'id': op + '-other', 'operation': op, 'package': SELF, 'other_package': OTHER})
    for flags, label in [(0x8000040, 'both'), (0, 'none'), (0x40, 'legacy'), (0x8000000, 'current')]:
        result.append({'id': 'metadata-' + label, 'operation': 'metadata', 'package': SELF, 'flags': flags})
        for op in ('list-installed', 'list-permissions'):
            result.append({'id': op + '-' + label, 'operation': op, 'flags': flags})
    result.append({'id': 'installer', 'operation': 'installer', 'package': SELF})
    cert = base64.b64encode(Path(keys['original']['certificate']).read_bytes()).decode()
    result.extend([
        {'id': 'missing-package-predicate', 'operation': 'predicate-package', 'package': 'dev.repack.fixture.missing', 'certificate': cert, 'certificate_type': 0},
        {'id': 'missing-uid-predicate', 'operation': 'predicate-uid', 'package': SELF, 'uid': -1, 'certificate': cert, 'certificate_type': 0},
        {'id': 'missing-package-comparison', 'operation': 'compare-package', 'package': SELF, 'other_package': 'dev.repack.fixture.missing'},
        {'id': 'missing-uid-comparison', 'operation': 'compare-uid', 'package': SELF, 'other_package': OTHER, 'second_uid': -1}])
    return result


def batch(result, evidence, label, artifact, configs, serial, lock, args, *, companion=None):
    plan = preflight(artifact, serial, args.replace_existing_and_wipe_data, lock, evidence, label)
    install(artifact, serial, plan, lock, evidence, label, result['device_mutations'])
    if companion is not None:
        companion_plan = preflight(companion, serial, args.replace_existing_and_wipe_data, lock, evidence, label + '-companion')
        install(companion, serial, companion_plan, lock, evidence, label + '-companion', result['device_mutations'])
    shell(lock, evidence, label + '-stop', serial, ['am', 'force-stop', artifact['package']])
    token = result['run_id'] + '-' + label
    with capture_startup(lock, serial, evidence, label) as captured:
        shell(lock, evidence, label + '-launch', serial, ['am', 'start', '-W', '-n', SELF + '/.ProbeActivity',
              '--es', 'scenario', 'contract', '--es', 'run_id', token, '--es', 'case_id', result['case_id'],
              '--es', 'contract_json', json.dumps(configs, separators=(',', ':'))], check=False, timeout=10)
        pid = shell(lock, evidence, label + '-pid', serial, ['pidof', '-s', SELF]).stdout.strip()
        for _ in range(60):
            observations = read_events(captured.read_text(errors='replace'), token)
            if len(observations) >= len(configs): break
            time.sleep(.1)
    observations = read_events(captured.read_text(errors='replace'), token)
    by_id = {}
    for event in observations:
        if event['pid'] != int(pid) or event['case_id'] != result['case_id'] or event['scenario'] != 'signing-contracts':
            raise RuntimeError('Stale/mismatched contract observation')
        name = event['query_path']
        if name in by_id and by_id[name] != event: raise RuntimeError('Conflicting contract observations')
        by_id[name] = event
    if set(by_id) != {item['id'] for item in configs}: raise RuntimeError('Contract batch missing observations: ' + label)
    write_json(evidence / (label + '-observed.json'), {'artifact_sha256': artifact['sha256'], 'pid': int(pid), 'events': by_id})
    shim = [item for item in tagged_events(captured.read_text(errors='replace'), 'REPACK_SHIM') if item['pid'] == int(pid)]
    return by_id, shim, plan


def crypto(metadata):
    return {key: metadata[key] for key in ('legacy', 'legacy_present', 'current', 'current_present', 'history', 'history_null', 'multiple', 'past')}


def projected(event):
    observed = json.loads(event['response_marker'])
    if event['event'] == 'failure': return {'error_class': event['error_class']}
    operation = observed['operation']; value = observed['value']
    if operation == 'metadata': value = crypto(value)
    elif operation.startswith('list-'): value = {package: crypto(info) for package, info in value.items()}
    return {'value': value}


def metadata_adapter(result, evidence, lock, keys, source, names, history, serial, args, label, *, bad_layout=False, invalid_cert=False):
    part = evidence / (label + '-metadata'); part.mkdir()
    artifact = build_bootstrap(Path(source['apk']), ROOT / '.work/outputs/signing-contracts' / result['run_id'] / (label + '-metadata'),
        keys['repack'], lock, part, identity_mode='public-metadata', probe_token=result['run_id'] + '-' + label,
        original_certificates=[b'invalid-certificate'] if invalid_cert else [Path(keys[name]['certificate']).read_bytes() for name in names],
        historical_certificates=[Path(keys[name]['certificate']).read_bytes() for name in history],
        original_scheme=2 if len(names) > 1 else 3, fixture_bad_signing_layout=bad_layout)
    plan = preflight(artifact, serial, args.replace_existing_and_wipe_data, lock, evidence, label + '-metadata')
    install(artifact, serial, plan, lock, evidence, label + '-metadata', result['device_mutations'])
    with capture_startup(lock, serial, evidence, label + '-metadata') as captured:
        query, _, pid, _ = launch_query(artifact, serial, result['run_id'] + '-' + label + '-control', 'T-A10',
            artifact['signer_sha256'], SELF, 'direct-current', lock, evidence, label + '-metadata-control')
    events = [item for item in tagged_events(captured.read_text(errors='replace'), 'REPACK_SHIM')
              if item['pid'] == int(pid) and item['details'].get('capability') == 'identity-metadata']
    if len(events) != 1 or events[0]['access_mode'] != 'none': raise RuntimeError('Public metadata adapter unexpectedly used hidden access')
    data = events[0]['details']
    if bad_layout or invalid_cert:
        if data['outcome'] != 'failed' or not events[0]['error_class']: raise RuntimeError('Invalid metadata control was accepted')
    else:
        current = sorted(keys[name]['sha256'] for name in names)
        past = [keys[name]['sha256'] for name in history] if history else current if len(names) == 1 else []
        if (data['outcome'] != 'passed' or data['actual_signer_sha256'] != current
                or data['actual_history_sha256'] != past or data['roundtrip_history_sha256'] != past
                or data['has_multiple_signers'] != (len(names) > 1) or data['has_past_signing_certificates'] != bool(history)):
            raise RuntimeError('Public metadata adapter disagrees with verified signer/history profile')
    if query['comparison'] != 'passed' or query['actual_signer_sha256'] != artifact['signer_sha256']:
        raise RuntimeError('Metadata-only control changed the real installed certificate')
    result['comparisons'].append({'name': label + '-public-metadata-adapter', 'result': 'passed',
        'negative_control': bad_layout or invalid_cert, 'event': events[0], 'installed_query': query})


def installed_fields(events, artifacts, serial, lock, evidence, label):
    truth = {}
    for package, artifact in artifacts.items():
        paths = shell(lock, evidence, label + package + '-paths', serial, ['pm', 'path', package]).stdout.splitlines()
        uid_text = shell(lock, evidence, label + package + '-uid', serial, ['pm', 'list', 'packages', '-U', package]).stdout
        match = re.search(r'package:' + re.escape(package) + r'\s+uid:(\d+)', uid_text)
        if len(paths) != 1 or not match: raise RuntimeError('Installed metadata oracle missing')
        truth[package] = {'uid': int(match[1]), 'source_dir': paths[0][8:], 'version_code': artifact['version_code']}
    for event in events.values():
        if event['event'] == 'failure': continue
        data = json.loads(event['response_marker'])
        values = [data['value']] if data['operation'] == 'metadata' else list(data['value'].values()) if data['operation'].startswith('list-') else []
        for value in values:
            if any(value[key] != expected for key, expected in truth[value['package']].items()):
                raise RuntimeError('Contract response changed installed UID/path/version')


def list_oracles(configs, events, shim):
    """Join independent public-list observations to the actual transformed Binder container."""
    for config in configs:
        operation = config['operation']
        if not operation.startswith('list-') or not config['flags']: continue
        method = 'getInstalledPackages' if operation == 'list-installed' else 'getPackagesHoldingPermissions'
        observed = json.loads(events[config['id']]['response_marker'])
        matches = [item['details'] for item in shim if item['details'].get('operation') == method
                   and item['details'].get('list_flags') == config['flags']]
        if not matches or any(item['self_entries_changed'] != 1
                              or item['list_count'] != observed['list_count']
                              or item['list_order_sha256'] != observed['list_order_sha256'] for item in matches):
            raise RuntimeError('Public list order/container evidence differs: ' + config['id'])


def run_t_a10(result, evidence, args):
    lock = load_lock(); serial = select_serial(lock, evidence, args.device)
    result['cell'] = read_cell(lock, evidence, serial)
    gate = ROOT / '.work/evidence/M1a.json'
    if json.loads(gate.read_text()).get('gate_progress') != 'accepted': raise PrerequisiteError('Accept M1a first')
    baseline_path = ROOT / '.work/evidence/M0-build.json'; baseline = json.loads(baseline_path.read_text())
    if baseline.get('fixture_source_sha256') != fixture_source_hash(): raise PrerequisiteError('Build current contract/permission fixtures first')
    original = next(item for item in baseline['outputs'] if item['id'] == 'app-own')
    other = next(item for item in baseline['outputs'] if item['id'] == 'other-own')
    keys = ensure_keys(lock, evidence); configs = cases(keys)
    result['inputs'] = [report_reference(gate), report_reference(baseline_path)]
    # Deliberately establish a known installer for our owned fixture, then let the shared
    # preflight/installer capture and preserve it throughout real signer replacements.
    seed_plan = preflight(original, serial, args.replace_existing_and_wipe_data, lock, evidence, 'installer-seed')
    install(original, serial, seed_plan, lock, evidence, 'installer-seed', result['device_mutations'])
    response = adb(lock, evidence, 'installer-seed-record', ['install', '-r', '-i', 'com.android.shell', original['apk']], serial=serial)
    if 'Success' not in response.stdout: raise RuntimeError('Owned installer seed failed')
    result['device_mutations'].append({'action': 'fixture-installer-seed', 'package': SELF, 'installer': 'com.android.shell'})
    recorded = shell(lock, evidence, 'installer-seed-observed', serial, ['pm', 'list', 'packages', '-i', SELF]).stdout
    if 'installer=com.android.shell' not in recorded: raise RuntimeError('Known fixture installer was not recorded')
    result['installer_fixture_seed'] = 'com.android.shell'
    result['profiles'] = []
    for profile, names, history in [('single', ['original'], []), ('multi-v2', ['original', 'other'], []),
                                     ('rotated-v3', ['other'], ['original', 'other'])]:
        source = sign_profile(original, names, lock, keys, evidence / (profile + '-source'), rotated=bool(history))
        metadata_adapter(result, evidence, lock, keys, source, names, history, serial, args, profile)
        if profile == 'single':
            metadata_adapter(result, evidence, lock, keys, source, names, history, serial, args, 'invalid-layout', bad_layout=True)
            metadata_adapter(result, evidence, lock, keys, source, names, history, serial, args, 'invalid-certificate', invalid_cert=True)
        for companion in (['matching', 'different', 'ancestor'] if history else ['matching', 'different']):
            label = profile + '-' + companion
            other_names = names if companion == 'matching' else ['original'] if companion == 'ancestor' else ['repack']
            # Matching rotated companion uses the new key without history, proving current-set matching.
            other_source = sign_profile(other, other_names, lock, keys, evidence / (label + '-other'))
            reference, _, _ = batch(result, evidence, label + '-reference', source, configs, serial, lock, args, companion=other_source)
            installed_fields(reference, {SELF: source, OTHER: other_source}, serial, lock, evidence, label + '-reference')
            for config in configs:
                if config['operation'].startswith('list-'):
                    selected = json.loads(reference[config['id']]['response_marker']).get('value', {})
                    if set(selected) != {SELF, OTHER}: raise RuntimeError('Reference list does not expose both permission/visibility fixtures')
            expected_current = sorted(keys[name]['sha256'] for name in names)
            expected_history = [keys[name]['sha256'] for name in history] if history else expected_current if len(names) == 1 else []
            truth = json.loads(reference['metadata-both']['response_marker'])['value']
            if (truth['current'] != expected_current or truth['history'] != expected_history
                    or truth['legacy'] != ([expected_history[0]] if history else expected_current)
                    or truth['multiple'] != (len(names) > 1) or truth['past'] != bool(history)):
                raise RuntimeError('Reference fixture does not match cryptographically verified profile: ' + label)
            part = evidence / (label + '-patch'); part.mkdir()
            patched = build_bootstrap(Path(source['apk']), ROOT / '.work/outputs/signing-contracts' / result['run_id'] / label,
                keys['repack'], lock, part, identity_mode='identity', probe_token=result['run_id'] + '-' + label,
                original_certificates=[Path(keys[name]['certificate']).read_bytes() for name in names],
                historical_certificates=[Path(keys[name]['certificate']).read_bytes() for name in history],
                original_scheme=2 if len(names) > 1 else 3, signing_contracts=True)
            actual, shim, install_plan = batch(result, evidence, label + '-patched', patched, configs, serial, lock, args, companion=other_source)
            installed_fields(actual, {SELF: patched, OTHER: other_source}, serial, lock, evidence, label + '-patched')
            for config in configs:
                name = config['id']; expected = projected(reference[name]); observed = projected(actual[name])
                if expected != observed:
                    raise RuntimeError('Signing contract mismatch ' + label + '/' + name + ': ' + json.dumps({'expected': expected, 'observed': observed}))
                result['comparisons'].append({'name': label + '/' + name, 'result': 'passed', 'expected': expected, 'observed': observed})
            installer = json.loads(actual['installer']['response_marker'])['value']
            if install_plan.get('existing_installer') and installer['installing'] != install_plan['existing_installer']:
                raise RuntimeError('Measured installer of record was not preserved')
            list_oracles(configs, actual, shim)
            result['profiles'].append({'profile': profile, 'companion': companion, 'reference': source, 'other': other_source,
                                       'patched': patched, 'installer': installer})
    result.update(verification='passed', transformation='applied',
                  scope='API30 controlled scalar predicates/comparisons, real multi-signer/rotation metadata and lists; unique/current-user UIDs')
