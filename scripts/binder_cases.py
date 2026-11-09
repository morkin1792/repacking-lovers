"""M1b-2 native-to-Java and fresh Java Binder acquisition controls."""
import json
from pathlib import Path
import re

from repack.rebuild import (ROOT, PrerequisiteError, align_sign, copy_archive, ensure_keys, execute,
                            fixture_source_hash, load_lock, report_reference, sha256, source_hash, write_json)
from repack.shim import build_bootstrap
from repack.verify import capture_startup, install, preflight, shell
from scripts.acceptance import launch_query, read_cell, read_events, select_serial, tagged_events
from scripts.contract_cases import SELF, OTHER


def native_libraries(lock, evidence):
    pin = json.loads((ROOT / 'config/ndk-dependency.json').read_text())
    if pin['version'] != '28.2.13676358': raise PrerequisiteError('Selected fixture NDK differs')
    for item in [*pin['tools'].values(), *pin['inputs']]:
        path = ROOT / item['path']
        if not path.is_file() or sha256(path) != item['sha256']: raise PrerequisiteError('Pinned NDK input changed: ' + str(path))
    compiler = str(ROOT / pin['tools']['clang']['path'])
    reader = str(ROOT / pin['tools']['llvm-readelf']['path'])
    source = ROOT / 'tests/fixtures/identity/app/src/main/cpp/signing_probe.c'
    result = []
    for abi, triple, machine in [('x86_64', 'x86_64-linux-android', 'Advanced Micro Devices X86-64'),
                                 ('arm64-v8a', 'aarch64-linux-android', 'AArch64')]:
        part = evidence / abi; part.mkdir(parents=True)
        library = part / 'librepack_fixture.so'
        execute([compiler, '--target=' + triple + '28', '-shared', '-fPIC', '-O2', '-Wall', '-Wextra', '-Werror',
                 '-Wl,-z,max-page-size=16384', '-Wl,-z,common-page-size=16384', '-DREPACK_ABI="' + abi + '"',
                 str(source), '-o', str(library)], part, 'compile')
        elf = execute([reader, '-h', '-l', '-d', '-s', str(library)], part, 'elf').stdout
        loads = [line.split() for line in elf.splitlines() if line.strip().startswith('LOAD ')]
        if machine not in elf or not loads or any(int(row[-1], 16) < 16384 for row in loads):
            raise RuntimeError('JNI fixture ELF machine/page alignment differs')
        for symbol in ('Java_dev_repack_fixture_common_NativeProbe_query', 'Java_dev_repack_fixture_common_NativeProbe_abi'):
            if symbol not in elf: raise RuntimeError('JNI fixture export missing')
        result.append({'abi': abi, 'library': str(library), 'sha256': sha256(library), 'load_alignment': [int(row[-1], 16) for row in loads]})
    return result


def with_libraries(original, libraries, key, lock, evidence):
    evidence.mkdir(parents=True)
    unsigned = evidence / 'unsigned.apk'; apk = evidence / 'original.apk'
    preserved = copy_archive(Path(original['apk']), unsigned, additions={
        'lib/' + item['abi'] + '/librepack_fixture.so': Path(item['library']).read_bytes() for item in libraries})
    align_sign(unsigned, apk, key, lock, evidence)
    return {**original, 'apk': str(apk), 'sha256': sha256(apk), 'signer_sha256': [key['sha256']],
            'native_libraries': libraries, 'preserved_entries': preserved}


def run_t_a12(result, evidence, args):
    lock = load_lock(); serial = select_serial(lock, evidence, args.device); result['cell'] = read_cell(lock, evidence, serial)
    gate_path = ROOT / '.work/evidence/M1b-1.json'; gate = json.loads(gate_path.read_text())
    if gate.get('gate_progress') != 'accepted': raise PrerequisiteError('Accept M1b-1 before JNI integration')
    baseline_path = ROOT / '.work/evidence/M0-build.json'; baseline = json.loads(baseline_path.read_text())
    if baseline.get('fixture_source_sha256') != fixture_source_hash(): raise PrerequisiteError('Build current JNI-aware fixtures first')
    if result['cell']['abi'] != 'arm64-v8a' or result['cell']['api'] != 30:
        raise PrerequisiteError('First JNI runtime cell is the selected API30 arm64 phone')
    result['inputs'] = [report_reference(gate_path), report_reference(baseline_path)]
    ndk_pin = ROOT / 'config/ndk-dependency.json'
    snapshot = evidence / 'ndk-dependency.json'; write_json(snapshot, json.loads(ndk_pin.read_text()))
    result['ndk_dependency'] = {'sha256': sha256(ndk_pin), 'snapshot': str(snapshot), 'snapshot_sha256': sha256(snapshot)}
    keys = ensure_keys(lock, evidence); libraries = native_libraries(lock, evidence / 'native-build')
    originals = {}
    for identity, module in [('original', 'app'), ('other', 'other')]:
        entry = next(item for item in baseline['outputs'] if item['id'] == module + '-own')
        originals[entry['package']] = with_libraries(entry, libraries, keys[identity], lock, evidence / (module + '-native'))
    result['outputs'] = list(originals.values()); result['native_build'] = libraries
    original = originals[SELF]; other = originals[OTHER]
    for package, artifact in originals.items():
        plan = preflight(artifact, serial, args.replace_existing_and_wipe_data, lock, evidence, package)
        install(artifact, serial, plan, lock, evidence, package, result['device_mutations'])
    paths = ('direct-legacy', 'direct-current', 'reflect-legacy', 'reflect-current', 'jni-legacy', 'jni-current')
    for target in (SELF, OTHER):
        for path in paths:
            label = 'genuine-' + ('self' if target == SELF else 'other') + '-' + path
            event, _, _, _ = launch_query(original, serial, result['run_id'] + label, 'T-A12', originals[target]['signer_sha256'],
                                          target, path, lock, evidence, label)
            if event['comparison'] != 'passed': raise RuntimeError('Genuine JNI/Java oracle mismatch')
            if path.startswith('jni') and json.loads(event['response_marker']) != {'loaded_abi': 'arm64-v8a', 'process_64_bit': True}:
                raise RuntimeError('Native library was not loaded for the expected ABI')
            result['comparisons'].append({'name': label, 'result': 'passed', 'event': event})
    for mode in ('none', 'identity'):
        label = 'patched-' + mode; part = evidence / label; part.mkdir()
        artifact = build_bootstrap(Path(original['apk']), ROOT / '.work/outputs/jni' / result['run_id'] / mode,
            keys['repack'], lock, part, identity_mode=mode, probe_token=result['run_id'] + label,
            original_certificates=[Path(keys['original']['certificate']).read_bytes()] if mode == 'identity' else None,
            original_scheme=3 if mode == 'identity' else 0, signing_contracts=mode == 'identity')
        plan = preflight(artifact, serial, args.replace_existing_and_wipe_data, lock, evidence, label)
        install(artifact, serial, plan, lock, evidence, label, result['device_mutations'])
        for target in (SELF, OTHER):
            for path in paths if mode == 'identity' else ('jni-legacy', 'jni-current'):
                expected = originals[target]['signer_sha256'] if mode == 'identity' or target == OTHER else artifact['signer_sha256']
                case_label = label + '-' + ('self' if target == SELF else 'other') + '-' + path
                event, _, _, _ = launch_query(artifact, serial, result['run_id'] + case_label, 'T-A12', expected,
                                              target, path, lock, evidence, case_label)
                if event['comparison'] != 'passed': raise RuntimeError('Patched JNI/Java contract mismatch')
                if path.startswith('jni') and json.loads(event['response_marker']).get('loaded_abi') != result['cell']['abi']:
                    raise RuntimeError('Patched JNI library ABI mismatch')
                result['comparisons'].append({'name': case_label, 'result': 'passed', 'event': event})
        if mode == 'identity':
            for path in ('jni-legacy', 'jni-current'):
                case_label = 'jni-missing-' + path
                event, _, _, _ = launch_query(artifact, serial, result['run_id'] + case_label, 'T-A12', original['signer_sha256'],
                    'dev.repack.fixture.missing', path, lock, evidence, case_label, allow_failure=True)
                if event['error_class'] != 'android.content.pm.PackageManager$NameNotFoundException':
                    raise RuntimeError('JNI changed the original missing-package exception')
                result['comparisons'].append({'name': case_label, 'result': 'passed', 'event': event})
        result['outputs'].append(artifact)
    result.update(verification='passed', transformation='applied', scope='API30 arm64 JNI-to-public-Java signing calls with Java/reflection and no-A controls',
                  unsupported=['x86_64-runtime-not-run', 'native-Binder', 'native-file-integrity', 'other-API-levels'])


def run_t_a13(result, evidence, args):
    lock = load_lock(); serial = select_serial(lock, evidence, args.device); result['cell'] = read_cell(lock, evidence, serial)
    native_path = ROOT / '.work/evidence/T-A12.json'; native = json.loads(native_path.read_text())
    if native['verification'] != 'passed' or len(native['comparisons']) != 30:
        raise PrerequisiteError('Classify T-A12 before fresh Binder work')
    baseline_path = ROOT / '.work/evidence/M0-build.json'; baseline = json.loads(baseline_path.read_text())
    if baseline.get('fixture_source_sha256') != fixture_source_hash(): raise PrerequisiteError('Build current Binder-aware fixtures first')
    if result['cell']['api'] != 30: raise PrerequisiteError('Binder descriptors/transaction fixture are API30-specific')
    result['inputs'] = [report_reference(ROOT / '.work/evidence/M1b-1.json'), report_reference(native_path), report_reference(baseline_path)]
    inventory_path = ROOT / 'tests/platform/api30-binder.json'; inventory = json.loads(inventory_path.read_text())
    for item in inventory['sources']:
        if sha256(ROOT / item['path']) != item['sha256']: raise PrerequisiteError('Pinned Binder source changed')
    snapshot = evidence / 'api30-binder.json'; write_json(snapshot, inventory)
    result['platform_inventory'] = {'sha256': sha256(inventory_path), 'snapshot': str(snapshot), 'snapshot_sha256': sha256(snapshot)}
    original = next(item for item in baseline['outputs'] if item['id'] == 'app-own')
    other = next(item for item in baseline['outputs'] if item['id'] == 'other-own'); keys = ensure_keys(lock, evidence)
    plan = preflight(other, serial, args.replace_existing_and_wipe_data, lock, evidence, 'binder-other')
    install(other, serial, plan, lock, evidence, 'binder-other', result['device_mutations'])
    for deferred in (False, True):
        label = 'deferred' if deferred else 'early'; token = result['run_id'] + '-' + label
        part = evidence / label; part.mkdir()
        artifact = build_bootstrap(Path(original['apk']), ROOT / '.work/outputs/binder' / result['run_id'] / label,
            keys['repack'], lock, part, identity_mode='identity-deferred' if deferred else 'identity', probe_token=token,
            original_certificates=[Path(keys['original']['certificate']).read_bytes()], original_scheme=3,
            signing_contracts=True, package_binder=True, fixture_binder={'run_id': token, 'deferred': deferred})
        plan = preflight(artifact, serial, args.replace_existing_and_wipe_data, lock, evidence, label)
        install(artifact, serial, plan, lock, evidence, label, result['device_mutations'])
        with capture_startup(lock, serial, evidence, label) as captured:
            event, _, pid, _ = launch_query(artifact, serial, token + '-activity', 'T-A13', original['signer_sha256'],
                                           SELF, 'direct-current', lock, evidence, label)
        if event['comparison'] != 'passed': raise RuntimeError('Binder scenario broke ordinary PM startup/query')
        text = captured.read_text(errors='replace'); rows = {}
        for event in read_events(text, token):
            if event['pid'] != int(pid) or event['case_id'] != 'T-A13' or event['scenario'] != 'binder':
                raise RuntimeError('Stale/mismatched Binder observation')
            if event['event'] == 'failure': raise RuntimeError('Binder fixture failed: ' + str(event))
            path = event['query_path']
            if path in rows and rows[path] != event: raise RuntimeError('Conflicting Binder observation')
            rows[path] = event
        expected_paths = {'binder-operations', 'fresh-missing', 'raw-missing'}
        for suffix in ('legacy', 'current'):
            expected_paths.update(prefix + suffix for prefix in ('fresh-self-', 'fresh-other-', 'original-proxy-', 'wrapped-transact-', 'raw-transact-'))
            if deferred: expected_paths.add('retained-before-' + suffix)
        if set(rows) != expected_paths: raise RuntimeError('Incomplete Binder paths: ' + str(set(rows) ^ expected_paths))
        for path, event in rows.items():
            value = json.loads(event['response_marker'])
            if path == 'binder-operations':
                for key in ('alive_matches', 'ping_matches', 'as_binder_wrapper', 'matching_local_interface', 'unrelated_interface_matches',
                            'same_cached_wrapper', 'wrapper_reflexive', 'interface_reflexive', 'stable_hash', 'unlink_matches', 'unknown_transaction_matches'):
                    if value[key] is not True: raise RuntimeError('Binder forwarding/identity operation failed: ' + key)
                if value['descriptor'] != 'android.content.pm.IPackageManager' or value['death_observed'] or value['before_is_wrapper'] == deferred:
                    raise RuntimeError('Binder lifetime/ordering descriptor mismatch')
            elif path.endswith('missing'):
                if value != {'null_result': True}: raise RuntimeError('Raw/fresh missing-package contract changed')
            else:
                expected = original['signer_sha256'] if path.startswith('fresh-self-') else other['signer_sha256'] if path.startswith('fresh-other-') else artifact['signer_sha256']
                if value['null_result'] or value['signers'] != expected or event['actual_signer_sha256'] != expected:
                    raise RuntimeError('Fresh versus retained/raw signer mismatch: ' + path)
            result['comparisons'].append({'name': label + '/' + path, 'result': 'passed', 'event': event})
        publications = [item for item in tagged_events(text, 'REPACK_SHIM') if item['pid'] == int(pid)
                        and item['details'].get('operation') == 'service-cache-publication']
        if len(publications) != 1 or not publications[0]['reference_replaced']:
            raise RuntimeError('Missing actual service-cache publication')
        result['outputs'].append(artifact)
    result.update(verification='passed', transformation='applied',
        scope='API30 fresh Java ServiceManager cached-handle asInterface; early and controlled late publication; raw/retained negative controls',
        unsupported=['retained-real-stubs', 'raw-transact-parcels', 'native-libbinder', 'actual-service-death-not-triggered', 'other-API-levels'])


def gate_binder(result, evidence, args):
    children = {}; cases = {}
    for name in ('M1b-1', 'T-A12', 'T-A13'):
        path = args.reports / (name + '.json'); child = json.loads(path.read_text())
        if child['verification'] != 'passed' or (name != 'M1b-1' and child['source_sha256'] != source_hash()):
            raise PrerequisiteError(name + ' unavailable/failed/stale')
        children[name] = report_reference(path); cases[name] = child
    if any(child['cell'] != cases['T-A12']['cell'] for child in cases.values()): raise RuntimeError('JNI/Binder cells differ')
    if len(cases['T-A12']['comparisons']) != 30 or len(cases['T-A13']['comparisons']) != 28:
        raise RuntimeError('JNI/Binder controls incomplete')
    if cases['T-A13']['inputs'][1]['sha256'] != children['T-A12']['sha256']: raise RuntimeError('Binder used another JNI revision')
    for name, key, path in [('T-A12', 'ndk_dependency', ROOT / 'config/ndk-dependency.json'),
                            ('T-A13', 'platform_inventory', ROOT / 'tests/platform/api30-binder.json')]:
        dependency = cases[name][key]
        if sha256(path) != dependency['sha256'] or sha256(Path(dependency['snapshot'])) != dependency['snapshot_sha256']:
            raise PrerequisiteError(name + ' dependency/inventory changed')
    unsupported = sorted(set(cases['M1b-1']['unsupported'] + cases['T-A12']['unsupported'] + cases['T-A13']['unsupported'])
                         - {'JNI/fresh-Binder-until-M1b-2'})
    unsupported.extend(['versioned-package-queries', 'Binder-wrapper-failure-rollback-not-exercised'])
    result.update(verification='passed', gate_progress='accepted', children=children, cell=cases['T-A12']['cell'],
                  next_gate='M1b-3', scope='API30 arm64 JNI-to-Java and fresh Java package-service stubs', unsupported=unsupported)
