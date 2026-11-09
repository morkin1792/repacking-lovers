"""M4 starts with observed per-import coverage; these fixtures never redirect paths."""
import json
from pathlib import Path
import re
import shutil
import time
import zipfile
import xml.etree.ElementTree as ET

from repack.rebuild import (ROOT, PrerequisiteError, align_sign, copy_archive, ensure_keys, execute,
    fixture_source_hash, load_lock, report_reference, sha256, tool, write_json)
from repack.recon import elf_loads
from repack.recon import inspect_input
from repack.patches import patch_apk
from repack.shim import build_bootstrap
from repack.shim import manifest_editor
from repack.trust import decode_resources, rebuild_resources
from repack.verify import capture_startup, install, preflight, shell
from scripts.acceptance import launch_query, read_cell, read_events, select_serial
from scripts.contract_cases import SELF


SYMBOLS = ('open', 'open64', '__open_2', 'openat', 'openat64', '__openat_2', 'fopen', 'fopen64',
           'stat', 'stat64', 'fstat', 'fstat64', 'readlink', 'readlinkat')


def build_smoke(lock, evidence, abis=('arm64-v8a', 'x86_64')):
    dependency_path = ROOT / 'config/bytehook-dependency.json'; dependency = json.loads(dependency_path.read_text())
    for item in dependency['artifacts']:
        if sha256(ROOT / item['path']) != item['sha256']: raise PrerequisiteError('ByteHook dependency changed: ' + item['path'])
    write_json(evidence / 'bytehook-dependency.json', dependency)
    ndk_path = ROOT / 'config/ndk-dependency.json'; ndk = json.loads(ndk_path.read_text())
    for item in [*ndk['tools'].values(), *ndk['inputs']]:
        if sha256(ROOT / item['path']) != item['sha256']: raise PrerequisiteError('Native build input changed: ' + item['path'])
    write_json(evidence / 'ndk-dependency.json', ndk)
    compiler = str(ROOT / ndk['tools']['clang']['path']); reader = str(ROOT / ndk['tools']['llvm-readelf']['path'])
    research = ROOT / '.work/tools/native-research'
    additions = {}; builds = []
    triples = {'arm64-v8a': 'aarch64-linux-android', 'x86_64': 'x86_64-linux-android', 'armeabi-v7a': 'armv7a-linux-androideabi'}
    for abi in abis:
        if abi not in triples: raise PrerequisiteError('Native fixture ABI has no compiler contract')
        triple = triples[abi]
        part = evidence / abi; part.mkdir(parents=True)
        native = part / 'libraries'; native.mkdir()
        with zipfile.ZipFile(research / 'bytehook-1.1.2.aar') as archive:
            (part / 'bytehook.h').write_bytes(archive.read('prefab/modules/bytehook/include/bytehook.h'))
            (native / 'libbytehook.so').write_bytes(archive.read('jni/' + abi + '/libbytehook.so'))
        if abi.startswith('arm'):
            with zipfile.ZipFile(research / 'shadowhook-2.0.1.aar') as archive:
                (part / 'shadowhook.h').write_bytes(archive.read('prefab/modules/shadowhook/include/shadowhook.h'))
                for name in ('libshadowhook.so', 'libshadowhook_nothing.so'):
                    (native / name).write_bytes(archive.read('jni/' + abi + '/' + name))
        flags = [compiler, '--target=' + triple + '28', '-shared', '-fPIC', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                 '-Wl,-z,max-page-size=16384', '-Wl,-z,common-page-size=16384', '-Wl,--no-undefined',
                 '-I', str(part), '-I', str(ROOT / 'native/fixture')]
        callers = []
        for label in ('early', 'late'):
            name = 'librepack_io_' + label + '.so'; out = native / name
            execute([*flags, '-Wl,-soname,' + name, str(ROOT / 'native/fixture/io_caller.c'), '-ldl', '-o', str(out)], part, label + '-compile')
            table = execute([reader, '--dyn-symbols', '--wide', str(out)], part, label + '-imports').stdout
            imported = sorted(set(re.findall(r'\bUND\s+(\S+)', table)))
            imported = sorted({item.split('@')[0] for item in imported})
            missing = sorted(set(SYMBOLS) - set(imported))
            if missing: raise RuntimeError('Fixture compiler changed requested imports: ' + str(missing))
            callers.append({'library': name, 'imports': imported, 'sha256': sha256(out)})
        out = native / 'librepack_hook_smoke.so'
        execute([*flags, '-Wl,-soname,' + out.name, str(ROOT / 'native/fixture/hook_smoke.c'), '-L', str(native),
                 '-lbytehook', *(['-lshadowhook'] if abi.startswith('arm') else []), '-ldl', '-o', str(out)], part, 'hook-compile')
        files = []
        for library in sorted(native.glob('*.so')):
            metadata = elf_loads(library.read_bytes())
            minimum_alignment = 16384 if metadata['bits'] == 64 else 4096
            if any(segment['alignment'] < minimum_alignment for segment in metadata['load_segments']):
                raise RuntimeError('Native smoke library has incompatible LOAD alignment: ' + library.name)
            additions['lib/' + abi + '/' + library.name] = library.read_bytes()
            files.append({'name': library.name, 'sha256': sha256(library), 'elf': metadata})
        builds.append({'abi': abi, 'callers': callers, 'libraries': files})
    for label, filename in [('ByteHook', 'LICENSE'), ('ShadowHook', 'ShadowHook-LICENSE')]:
        additions['assets/repack/native-smoke-' + label + '-LICENSE'] = (research / filename).read_bytes()
    return additions, builds, dependency


def observe_native(result, evidence, serial, lock, label, scenario, control=None, member=None):
    token = result['run_id'] + '-' + label
    shell(lock, evidence, label + '-stop', serial, ['am', 'force-stop', SELF])
    with capture_startup(lock, serial, evidence, label + '-startup') as captured:
        command = ['am', 'start', '-W', '-n', SELF + '/.ProbeActivity', '--es', 'scenario', scenario, '--es', 'run_id', token,
                   '--es', 'case_id', result['case_id']]
        if control: command += ['--es', 'retained_control', control]
        if member: command += ['--es', 'native_member', member]
        shell(lock, evidence, label + '-launch', serial, command, timeout=20)
        actual_pid = int(shell(lock, evidence, label + '-pid', serial, ['pidof', '-s', SELF]).stdout.strip())
        for _ in range(100):
            events = read_events(captured.read_text(errors='replace'), token)
            if any(item['event'] == 'failure' or item['query_path'] == 'summary' for item in events): break
            time.sleep(.1)
    rows = read_events(captured.read_text(errors='replace'), token)
    if any(item['event'] != 'response' for item in rows): raise RuntimeError('Native fixture failed: ' + str(rows))
    by_path = {}
    for item in rows:
        if item['query_path'] in by_path or item['case_id'] != result['case_id'] or item['scenario'] != scenario:
            raise RuntimeError('Duplicate/mismatched native observation')
        by_path[item['query_path']] = item
    if 'summary' not in by_path: raise RuntimeError('Native summary absent')
    event = by_path['summary']; observation = json.loads(event['response_marker'])
    result.setdefault('native_observations', {})[label] = observation
    if observation.get('error'): raise RuntimeError('Native setup failed: ' + str(observation))
    paths = list(SYMBOLS[:8]) + ['raw-syscall', 'dlsym-open', 'preopened-fd']
    expected_paths = {'summary', 'tasks/early', 'tasks/late', 'runtime/early', 'runtime/late'}
    for stage in range(5):
        expected_paths.add('stage/' + str(stage) + '/counters')
        expected_paths.update('stage/' + str(stage) + '/' + path for path in paths)
    if set(by_path) != expected_paths or {item['pid'] for item in rows} != {actual_pid} or {item['process'] for item in rows} != {SELF}:
        raise RuntimeError('Incomplete/mismatched native observations')
    observation['pid'] = event['pid']; observation['raw_capture'] = str(captured)
    observation['stages'] = []
    for stage in range(5):
        prefix = 'stage/' + str(stage) + '/'
        value = json.loads(by_path[prefix + 'counters']['response_marker'])
        value['rows'] = [json.loads(by_path[prefix + path]['response_marker']) for path in paths]
        observation['stages'].append(value)
    observation['tasks'] = sum((json.loads(by_path['tasks/' + item]['response_marker'])['tasks'] for item in ('early', 'late')), [])
    observation['active_runtime'] = json.loads(by_path['runtime/early']['response_marker'])
    observation['runtime_after_delayed_load'] = json.loads(by_path['runtime/late']['response_marker'])
    return observation


def file_truth(path):
    data = path.read_bytes(); fingerprint = 14695981039346656037
    for value in data: fingerprint = ((fingerprint ^ value) * 1099511628211) & ((1 << 64) - 1)
    return {'bytes': len(data), 'fnv64': format(fingerprint, '016x'), 'sha256': sha256(path)}


def check_native(result, observation, artifact, original, redirect, label):
    if observation['pointer_bits'] != artifact.get('expected_pointer_bits', 64) or observation['init_status'] or observation['shadow_status'] or observation['owned_jni_loaded'] != 1:
        raise RuntimeError('Wrong native process/initialization state')
    if (observation['runtime_stage'] != 2 or observation['runtime_after_stage'] != 3
            or any(observation['runtime_import_delta'].values()) or any(observation['runtime_after_import_delta'].values())):
        raise RuntimeError('Unselected Java runtime reads entered the native caller filter')
    patched = file_truth(Path(artifact['apk'])); genuine = file_truth(Path(original['apk']))
    if (observation['java_sha256'] != patched['sha256'] or observation['java_size'] != patched['bytes']
            or observation['java_fnv64'] != patched['fnv64']):
        raise RuntimeError('Unselected Java read differs from signed host artifact')
    if redirect and (observation['retained']['sha256'] != genuine['sha256'] or observation['retained']['bytes'] != genuine['bytes']):
        raise RuntimeError('Retained input does not match verified original')
    if len(observation['stages']) != 5: raise RuntimeError('Missing native before/after stages')
    for stage, item in enumerate(observation['stages']):
        if item['stage'] != stage or len(item['rows']) != 11 or set(item['hits']) != set(SYMBOLS): raise RuntimeError('Incomplete native import stage')
        for row in item['rows']:
            redirected = redirect and ((stage == 1 and row['path'] == 'openat') or (stage in (2, 3) and row['path'] in SYMBOLS[:8]))
            expected = genuine if redirected else patched
            named = genuine if redirect and stage in (2, 3) else patched
            if (row['ok'] != 1 or row['errno'] or any(row[key] != expected[key] for key in ('bytes', 'fnv64', 'sha256'))
                    or any(row[key] != named['bytes'] for key in ('stat_size', 'stat64_size'))
                    or any(row[key] != expected['bytes'] for key in ('fd_size', 'fd64_size'))
                    or row['readlink_source'] != int(not redirected) or row['readlinkat_source'] != int(not redirected)
                    or row['readlink_retained'] != int(redirected) or row['readlinkat_retained'] != int(redirected)
                    or row['duplicate_retained'] != int(redirected) or row['duplicate_size'] != expected['bytes']
                    or row['offsets_ok'] != 1 or row['mmap_ok'] != 1 or row['mmap_errno'] or row['mmap_sha256'] != expected['sha256']):
                raise RuntimeError('Unexpected native bytes/metadata/fd target: ' + str(row))
            result['comparisons'].append({'name': label + '/' + str(stage) + '/' + row['path'], 'result': 'passed',
                'classification': 'original-bytes-with-visible-retained-fd-path' if redirected else 'real-installed-bytes-control', 'observation': row})
        expected_hits = {name: 0 if stage in (0, 4) or (stage == 1 and name != 'openat') else
                         1 if name in SYMBOLS[:8] else 22 if name in ('fstat', 'readlink') else 11 for name in SYMBOLS}
        if item['hits'] != expected_hits: raise RuntimeError('Per-import map differs: ' + str(item['hits']))
        result['comparisons'].append({'name': label + '/' + str(stage) + '/import-counters', 'result': 'passed', 'hits': item['hits']})
    if len(observation['tasks']) != 28 or any(item['status'] != 0 or item['unhook'] != 0 for item in observation['tasks']):
        raise RuntimeError('A requested import hook/unhook failed')
    result['comparisons'].append({'name': label + '/actual-symbol-publication-and-unhook', 'result': 'passed', 'tasks': observation['tasks']})
    if observation['pre_dlopen'] < 1 or observation['post_dlopen'] < 1 or observation['post_result'] != 0:
        raise RuntimeError('Delayed app-library loading was not observed')
    result['comparisons'].append({'name': label + '/delayed-dlopen', 'result': 'passed', 'constructor_hits': observation['late_constructor_hits']})
    result['comparisons'].append({'name': label + '/raw-syscall-dlsym-preopened-negative', 'result': 'passed',
        'interpretation': 'All three bypass imported open/openat; metadata hooks alone do not repair these byte reads'})


def run_native(result, evidence, args, *, redirect):
    foundation = ROOT / '.work/evidence/RELEASE-1.json'; release = json.loads(foundation.read_text())
    if release.get('gate_progress') != 'accepted': raise PrerequisiteError('Accept RELEASE-1 before native work')
    lock = load_lock(); serial = select_serial(lock, evidence, args.device); result['cell'] = read_cell(lock, evidence, serial)
    if result['cell'] != release['cell']: raise PrerequisiteError('Start native work on the accepted physical cell')
    baseline_path = ROOT / '.work/evidence/M0-build.json'; baseline = json.loads(baseline_path.read_text())
    if baseline.get('fixture_source_sha256') != fixture_source_hash(): raise PrerequisiteError('Build current native-aware fixtures first')
    original = next(item for item in baseline['outputs'] if item['id'] == 'app-own'); keys = ensure_keys(lock, evidence)
    result['inputs'] = [report_reference(foundation), report_reference(baseline_path)]
    build = evidence / 'native-build'; build.mkdir()
    additions, native_build, dependency = build_smoke(lock, build)
    result.update(native_build=native_build, native_dependency=dependency,
        native_sources=[{'path': str(path), 'sha256': sha256(path)} for path in sorted((ROOT / 'native/fixture').glob('*')) if path.is_file()])
    if redirect:
        additions['assets/repack/native-original.apk'] = Path(original['apk']).read_bytes()
        additions['assets/repack/native-original.json'] = json.dumps({'sha256': original['sha256']}).encode()
    unsigned = evidence / 'unsigned.apk'; out = ROOT / '.work/outputs/native-smoke' / result['run_id'] / 'fixture.apk'
    out.parent.mkdir(parents=True)
    preserved = copy_archive(Path(original['apk']), unsigned, additions=additions)
    key = keys['repack'] if redirect else keys['original']
    align_sign(unsigned, out, key, lock, evidence)
    artifact = {**original, 'apk': str(out), 'sha256': sha256(out), 'signer_sha256': [key['sha256']], 'preserved_entries': preserved}
    result['outputs'] = [artifact]; result['retained_original'] = original if redirect else None
    plan = preflight(artifact, serial, args.replace_existing_and_wipe_data, lock, evidence, 'native')
    install(artifact, serial, plan, lock, evidence, 'native', result['device_mutations'])
    labels = [('initial', None), ('cached', None), ('corrupt-cache', 'corrupt')] if redirect else [('smoke', None)]
    for label, corruption in labels:
        observation = observe_native(result, evidence, serial, lock, label, 'native-integrity' if redirect else 'native-smoke', corruption)
        check_native(result, observation, artifact, original, redirect, label)
        if redirect:
            state = observation['retained']['cache_state']
            if (label == 'cached' and state != 'verified') or (corruption and state != 'repaired'):
                raise RuntimeError('Original provisioning/invalidation control did not execute')
            result['comparisons'].append({'name': label + '/original-guard', 'result': 'passed', 'retained': observation['retained']})
    control, _, _, _ = launch_query(artifact, serial, result['run_id'] + '-identity-control', 'T-A12',
        artifact['signer_sha256'], SELF, 'direct-current', lock, evidence, 'identity-control')
    if control['comparison'] != 'passed': raise RuntimeError('Native fixture changed public signing identity')
    result['comparisons'].append({'name': 'ordinary-fresh-process-signing-control', 'result': 'passed', 'event': control})
    result.update(verification='passed', transformation='applied',
        scope='API30 arm64 two selected native callers; absolute read-only APK opens and size metadata after private original provisioning' if redirect else
              'API30 arm64 app-namespace imports in two owned libraries, before/after/delayed/unhook; no path redirect',
        unsupported=['raw-syscalls', 'dlsym-resolved-function-pointers', 'libc-internal-opens-through-an-openat-only-hook',
            'unselected-caller-libraries', 'x86_64-runtime-not-run', '16KB-runtime-not-run', 'other-API-levels'] +
            (['proc-fd-readlink-discloses-retained-path', 'relative-dirfd-paths', 'preopened-descriptors', 'unmeasured-descriptor-transfer-paths',
              'unmeasured-metadata-fields', 'before-original-provisioning', 'split-originals-not-yet-tested'] if redirect else ['original-byte-redirection-not-enabled']),
        delayed_constructor_imports='observed' if observation['late_constructor_hits']['open'] else 'not-observed')


def run_t_b00(result, evidence, args):
    run_native(result, evidence, args, redirect=False)


def run_t_b01(result, evidence, args):
    from repack.rebuild import source_hash
    smoke = ROOT / '.work/evidence/T-B00.json'; previous = json.loads(smoke.read_text())
    if previous['verification'] != 'passed' or previous['source_sha256'] != source_hash():
        raise PrerequisiteError('Classify current import smoke before redirecting bytes')
    run_native(result, evidence, args, redirect=True)
    result['inputs'].append(report_reference(smoke))


def run_t_b02(result, evidence, args):
    from repack.rebuild import environment, source_hash
    from scripts.selected_cases import build_selected_fixture
    previous = ROOT / '.work/evidence/T-B01.json'; parent = json.loads(previous.read_text())
    if parent['verification'] != 'passed' or parent['source_sha256'] != source_hash():
        raise PrerequisiteError('Classify current scoped original-byte reads before runtime coexistence')
    lock = load_lock(); serial = select_serial(lock, evidence, args.device); result['cell'] = read_cell(lock, evidence, serial)
    if result['cell'] != parent['cell']: raise PrerequisiteError('Native coexistence uses another cell')
    baseline_path = ROOT / '.work/evidence/M0-build.json'; baseline = json.loads(baseline_path.read_text())
    if baseline.get('fixture_source_sha256') != fixture_source_hash(): raise PrerequisiteError('Build current coexistence fixtures first')
    result['inputs'] = [report_reference(previous), report_reference(baseline_path)]
    inventory = ROOT / 'tests/platform/api30-native-runtime.json'; flags = ROOT / '.work/inputs/api30-hiddenapi-flags.csv'
    pinned = json.loads(inventory.read_text())
    if sha256(flags) != pinned['flags_sha256'] or len(pinned['members']) != 6: raise PrerequisiteError('Fresh ApkAssets inventory changed')
    write_json(evidence / 'api30-native-runtime.json', pinned)
    result['platform_inventory'] = {'path': str(inventory), 'sha256': sha256(inventory)}
    keys = ensure_keys(lock, evidence)
    selected = build_selected_fixture(baseline, keys, lock, evidence / 'fixture')
    # Add an original marker and an independent tiny DEX to the genuine base before retaining it.
    toy = evidence / 'toy'; toy.mkdir(); classes = toy / 'classes'; classes.mkdir(); dex = toy / 'dex'; dex.mkdir()
    execute([tool(lock, 'javac'), '--release', '8', '-classpath', lock['android_jar'], '-d', str(classes),
             str(ROOT / 'native/fixture/LazyPatchProbe.java')], toy, 'javac', env=environment(lock))
    program = toy / 'program.jar'
    with zipfile.ZipFile(program, 'w') as jar:
        for path in classes.rglob('*.class'): jar.write(path, str(path.relative_to(classes)))
    execute([tool(lock, 'd8'), '--release', '--min-api', '28', '--lib', lock['android_jar'], '--output', str(dex), str(program)],
            toy, 'd8', env=environment(lock))
    unsigned = toy / 'base-unsigned.apk'; original_signed = toy / 'base-original.apk'
    copy_archive(selected / 'base.apk', unsigned, additions={'classes2.dex': (dex / 'classes.dex').read_bytes(),
        'assets/repack-runtime-marker.txt': b'original-zip'})
    align_sign(unsigned, original_signed, keys['original'], lock, toy)
    shutil.copyfile(original_signed, selected / 'base.apk')
    source = inspect_input(str(selected), serial, lock, evidence / 'original-selected')
    original_base = next(item for item in source['members'] if not item.get('split'))
    result['original_selected'] = source
    native = evidence / 'native-build'; native.mkdir(); additions, builds, dependency = build_smoke(lock, native)
    result.update(native_build=builds, native_dependency=dependency)
    if source['abis'] != ['arm64-v8a']: raise RuntimeError('Unexpected genuine fixture ABI selection')
    result['outputs'] = []; result['native_observations'] = {}; result['resource_transforms'] = []
    for patched in (False, True):
        label = 'patched' if patched else 'control'; part = evidence / label; part.mkdir()
        base_path = Path(original_base['apk'])
        if patched:
            decoded = part / 'decoded'; decode_resources(base_path, decoded, lock, part)
            matches = []
            for values in (decoded / 'res/values').glob('*.xml'):
                tree = ET.parse(values); changed = False
                for node in tree.getroot().findall('string'):
                    if node.get('name') == 'repack_runtime_marker':
                        if node.text != 'original-resource': raise RuntimeError('Unexpected original resource marker')
                        node.text = 'patched-resource'; matches.append(str(values)); changed = True
                if changed: tree.write(values, encoding='utf-8', xml_declaration=True)
            if len(matches) != 1: raise RuntimeError('Resource fixture marker is ambiguous/missing')
            transformed = rebuild_resources(base_path, decoded, part / 'resource-patched.apk', lock, part)
            result['resource_transforms'].append(transformed); base_path = Path(transformed['unsigned_apk'])
        base_additions = {name: value for name, value in additions.items() if name.startswith('assets/')}
        base_additions['assets/repack/native-original.apk'] = Path(original_base['apk']).read_bytes()
        base_additions['assets/repack/native-original.json'] = json.dumps({'sha256': original_base['sha256'], 'runtime_probe': True}).encode()
        merged_unsigned = part / 'merged-unsigned.apk'; merged_signed = part / 'merged.apk'
        copy_archive(base_path, merged_unsigned,
            replacements={'assets/repack-runtime-marker.txt': b'patched-zip'} if patched else {}, additions=base_additions)
        align_sign(merged_unsigned, merged_signed, keys['repack'], lock, part)
        if patched:
            java_part = part / 'java'; java_part.mkdir()
            java = patch_apk(merged_signed, part / 'shadow', keys['repack'], lock, java_part)
            if len(java['patches']) != 1 or java['patches'][0]['class'] != 'Ldev/repack/fixture/common/LazyPatchProbe;':
                raise RuntimeError('Coexistence Java patch selected an unexpected contract')
            result['java_shadow'] = java; merged_signed = Path(java['apk'])
        helper_part = part / 'helper'; helper_part.mkdir()
        helper = build_bootstrap(merged_signed, part / 'helper-output', keys['repack'], lock, helper_part,
            identity_mode='identity', probe_token=result['run_id'] + '-' + label,
            original_certificates=[Path(item['der']).read_bytes() for item in original_base['signing']['certificates']],
            historical_certificates=[Path(item['der']).read_bytes() for item in original_base['signing']['history']],
            original_scheme=original_base['signing']['scheme_version'], signing_contracts=True, package_binder=True,
            identity_input_sha256=original_base['sha256'])
        output = ROOT / '.work/outputs/native-coexistence' / result['run_id'] / label; output.mkdir(parents=True)
        shutil.copyfile(helper['apk'], output / 'base.apk')
        preserved_nonbase = []
        for index, member in enumerate(source['members']):
            if not member.get('split'): continue
            item_part = part / ('member-' + str(index)); item_part.mkdir()
            native_additions = {name: value for name, value in additions.items() if name.startswith('lib/arm64-v8a/')} if member['split'] == 'config.arm64_v8a' else {}
            staged_unsigned = item_part / 'unsigned.apk'; staged = item_part / 'signed.apk'
            preserved = copy_archive(Path(member['apk']), staged_unsigned, additions=native_additions)
            align_sign(staged_unsigned, staged, keys['repack'], lock, item_part)
            with zipfile.ZipFile(staged) as archive:
                import hashlib
                for entry in preserved:
                    if hashlib.sha256(archive.read(entry['entry'])).hexdigest() != entry['sha256'] or archive.getinfo(entry['entry']).compress_type != entry['compression']:
                        raise RuntimeError('Native injection changed original split payloads')
            shutil.copyfile(staged, output / ('split_' + member['split'] + '.apk'))
            preserved_nonbase.append({'split': member['split'], 'entries': preserved})
        artifact = inspect_input(str(output), serial, lock, part / 'patched-selected', allow_patched=True)
        if artifact['abis'] != source['abis']: raise RuntimeError('Native hook injection changed selected ABI set')
        artifact['base_transform'] = helper; artifact['preserved_nonbase'] = preserved_nonbase
        result['outputs'].append(artifact)
        plan = preflight(artifact, serial, args.replace_existing_and_wipe_data, lock, evidence, label)
        install(artifact, serial, plan, lock, evidence, label, result['device_mutations'])
        observed = observe_native(result, evidence, serial, lock, label, 'native-integrity')
        base_artifact = {'apk': artifact['base'], 'sha256': sha256(Path(artifact['base']))}
        check_native(result, observed, base_artifact, original_base, True, label)
        wanted_resource = 'patched-resource' if patched else 'original-resource'
        wanted_zip = 'patched-zip' if patched else 'original-zip'
        for phase in ('active_runtime', 'runtime_after_delayed_load'):
            runtime = observed[phase]
            if (runtime['requested'] is not True or runtime['resource'] != wanted_resource or runtime['class_accepts'] is not patched
                    or runtime['class_unrelated'] != 'preserved-method' or runtime['zip_asset'] != wanted_zip
                    or runtime['retained_zip_asset'] != 'original-zip' or runtime['fresh_apkassets']['value'] != wanted_resource
                    or runtime['retained_apkassets']['value'] != 'original-resource' or runtime['fresh_apkassets']['path'] == observed['retained']['path']
                    or runtime['retained_apkassets']['path'] != observed['retained']['path']
                    or runtime['signer_sha256'] != source['signer_sha256']):
                raise RuntimeError('Original integrity bytes and patched runtime did not coexist: ' + str(runtime))
            if runtime['splits'] != {'parent': 'parent', 'child': 'child', 'lazy_asset': 'child-lazy-asset',
                                     'density_resource': 'density-config', 'native_abi': 'arm64-v8a', 'split_count': 4}:
                raise RuntimeError('Lazy split/resource/native load changed under integrity hooks')
            result['comparisons'].append({'name': label + '/' + phase, 'result': 'passed', 'runtime': runtime})
    result.update(verification='passed', transformation='applied', scope='API30 arm64 original base-byte reads in two native callers coexist with A, lazy class shadow, patched string/ZIP, fresh ApkAssets and selected feature/resource/native loads',
        unsupported=parent['unsupported'] + ['shared-Java-file-integrity-readers-uncovered', 'on-demand-not-installed-features-not-tested'])


def native_member(apk, additions, key, lock, evidence):
    """Owned fixture only: load STORED aligned libraries directly from the APK."""
    from repack.rebuild import environment
    evidence.mkdir(parents=True)
    with zipfile.ZipFile(apk) as archive: xml = archive.read('AndroidManifest.xml')
    source = evidence / 'manifest.axml'; source.write_bytes(xml); changed = evidence / 'changed.axml'
    jar, editor = manifest_editor(lock, evidence)
    execute([tool(lock, 'java'), '-classpath', str(editor) + ':' + str(jar), 'ManifestEdit',
             'fixture-extract-false', str(source), str(changed)], evidence, 'no-extraction', env=environment(lock))
    unsigned = evidence / 'unsigned.apk'; signed = evidence / 'signed.apk'
    preserved = copy_archive(Path(apk), unsigned, replacements={'AndroidManifest.xml': changed.read_bytes()}, additions=additions)
    align_sign(unsigned, signed, key, lock, evidence)
    execute([tool(lock, 'zipalign'), '-c', '-P', '16', '-v', '4', str(signed)], evidence, 'verify-alignment')
    return signed, preserved


def run_t_b03(result, evidence, args):
    from repack.rebuild import source_hash
    previous = ROOT / '.work/evidence/T-B02.json'; parent = json.loads(previous.read_text())
    if parent['verification'] != 'passed' or parent['source_sha256'] != source_hash():
        raise PrerequisiteError('Classify current patched-runtime coexistence before native packaging')
    lock = load_lock(); serial = select_serial(lock, evidence, args.device); result['cell'] = read_cell(lock, evidence, serial)
    if result['cell'] != parent['cell']: raise PrerequisiteError('Native packaging uses another cell')
    baseline_path = ROOT / '.work/evidence/M0-build.json'; baseline = json.loads(baseline_path.read_text())
    if baseline.get('fixture_source_sha256') != fixture_source_hash(): raise PrerequisiteError('Build current native member-selection fixture first')
    keys = ensure_keys(lock, evidence); result['inputs'] = [report_reference(previous), report_reference(baseline_path)]
    supported = shell(lock, evidence, 'device-abis', serial, ['getprop', 'ro.product.cpu.abilist']).stdout.strip().split(',')
    result['device_abis'] = supported; result['outputs'] = []; result['native_observations'] = {}
    # A genuine 32-bit-only app is measured before adding the same-ABI hook components.
    if 'armeabi-v7a' not in supported: raise PrerequisiteError('Recorded phone lacks the required ARM32 runtime cell')
    build32 = evidence / 'build32'; build32.mkdir(); additions32, binaries32, dependency = build_smoke(lock, build32, ('armeabi-v7a',))
    result['native32_build'] = binaries32; result['native_dependency'] = dependency
    ndk = json.loads((ROOT / 'config/ndk-dependency.json').read_text()); compiler = str(ROOT / ndk['tools']['clang']['path'])
    fixture32 = build32 / 'librepack_fixture.so'
    execute([compiler, '--target=armv7a-linux-androideabi28', '-shared', '-fPIC', '-O2', '-Wall', '-Wextra', '-Werror',
             '-Wl,-z,max-page-size=16384', '-Wl,-z,common-page-size=16384', '-DREPACK_ABI="armeabi-v7a"',
             str(ROOT / 'tests/fixtures/identity/app/src/main/cpp/signing_probe.c'), '-o', str(fixture32)], build32, 'original-jni32')
    pure = next(item for item in baseline['outputs'] if item['id'] == 'app-own')
    original32, _ = native_member(Path(pure['apk']), {'lib/armeabi-v7a/librepack_fixture.so': fixture32.read_bytes()},
                                 keys['original'], lock, evidence / 'original32')
    truth32 = inspect_input(str(original32), serial, lock, evidence / 'original32-inventory')
    result['genuine32'] = truth32
    if truth32['abis'] != ['armeabi-v7a'] or truth32['effective_abi'] != 'armeabi-v7a': raise RuntimeError('Genuine fixture is not ARM32-only')
    plan = preflight(truth32, serial, args.replace_existing_and_wipe_data, lock, evidence, 'original32')
    install(truth32, serial, plan, lock, evidence, 'original32', result['device_mutations'])
    event, _, _, _ = launch_query(truth32, serial, result['run_id'] + '-original32', 'T-A12', truth32['signer_sha256'],
                                SELF, 'jni-current', lock, evidence, 'original32-jni')
    if event['comparison'] != 'passed' or json.loads(event['response_marker']) != {'loaded_abi': 'armeabi-v7a', 'process_64_bit': False}:
        raise RuntimeError('Original 32-bit process/JNI oracle failed')
    result['comparisons'].append({'name': 'genuine-32bit-only-process', 'result': 'passed', 'event': event})
    additions32['assets/repack/native-original.apk'] = original32.read_bytes()
    additions32['assets/repack/native-original.json'] = json.dumps({'sha256': sha256(original32)}).encode()
    patched32, preserved32 = native_member(original32, additions32, keys['repack'], lock, evidence / 'patched32')
    artifact32 = inspect_input(str(patched32), serial, lock, evidence / 'patched32-inventory')
    if artifact32['abis'] != truth32['abis'] or artifact32['effective_abi'] != 'armeabi-v7a': raise RuntimeError('Hook injection changed ARM32 selection')
    if any(member['extract_native_libs'] for member in artifact32['members']): raise RuntimeError('ARM32 APK unexpectedly extracts libraries')
    result['outputs'].append(artifact32); result['preserved32'] = preserved32
    plan = preflight(artifact32, serial, args.replace_existing_and_wipe_data, lock, evidence, 'patched32')
    install(artifact32, serial, plan, lock, evidence, 'patched32', result['device_mutations'])
    observed32 = observe_native(result, evidence, serial, lock, 'patched32', 'native-integrity')
    check_native(result, observed32, {'apk': str(patched32), 'expected_pointer_bits': 32},
                 {'apk': str(original32)}, True, 'patched32')
    result['comparisons'].append({'name': '32bit-selection-preserved-with-apk-mapped-hooks', 'result': 'passed',
        'input_abis': truth32['abis'], 'output_abis': artifact32['abis'], 'pointer_bits': observed32['pointer_bits']})
    # Every selected original is retained, including the APK containing the hook libraries.
    source = parent['original_selected']; original_by_id = {item.get('split') or 'base': item for item in source['members']}
    for item in source['members']:
        if sha256(Path(item['apk'])) != item['sha256']: raise PrerequisiteError('Original selected member changed')
    build64 = evidence / 'build64'; build64.mkdir(); additions64, binaries64, _ = build_smoke(lock, build64, ('arm64-v8a',))
    result['native64_build'] = binaries64
    selected = ROOT / '.work/outputs/native-packaging' / result['run_id'] / 'selected'; selected.mkdir(parents=True)
    member_config = []; retained = {}
    for index, item in enumerate(source['members']):
        member = item.get('split') or 'base'; name = 'repack/native-original-members/' + str(index) + '.apk'
        retained['assets/' + name] = Path(item['apk']).read_bytes()
        member_config.append({'member': member, 'sha256': item['sha256'], 'asset': name})
    result['selected_preservation'] = []
    for index, item in enumerate(source['members']):
        member = item.get('split') or 'base'; additions = {}
        if member == 'base':
            additions = {name: value for name, value in additions64.items() if name.startswith('assets/')}
            additions.update(retained); additions['assets/repack/native-original.json'] = json.dumps({'members': member_config}).encode()
        elif member == 'config.arm64_v8a':
            additions = {name: value for name, value in additions64.items() if name.startswith('lib/arm64-v8a/')}
        staged, preserved = native_member(Path(item['apk']), additions, keys['repack'], lock, evidence / ('selected-' + str(index)))
        shutil.copyfile(staged, selected / ('base.apk' if member == 'base' else 'split_' + member + '.apk'))
        result['selected_preservation'].append({'member': member, 'entries': preserved})
    artifact = inspect_input(str(selected), serial, lock, evidence / 'selected-inventory')
    if artifact['abis'] != source['abis'] or artifact['effective_abi'] != 'arm64-v8a': raise RuntimeError('Selected hook ABI differs from genuine input')
    if any(item['extract_native_libs'] for item in artifact['members']): raise RuntimeError('Selected APKs unexpectedly extract libraries')
    result['outputs'].append(artifact)
    plan = preflight(artifact, serial, args.replace_existing_and_wipe_data, lock, evidence, 'selected')
    install(artifact, serial, plan, lock, evidence, 'selected', result['device_mutations'])
    for item in artifact['members']:
        member = item.get('split') or 'base'; original = original_by_id[member]
        observed = observe_native(result, evidence, serial, lock, 'member-' + member, 'native-integrity', member=member)
        check_native(result, observed, item, original, True, 'member-' + member)
        if observed['retained']['member'] != member: raise RuntimeError('Retained split mapping selected another member')
        result['comparisons'].append({'name': member + '/original-member-binding', 'result': 'passed',
            'original_sha256': original['sha256'], 'patched_sha256': item['sha256'], 'actual_sha256': observed['retained']['sha256']})
    result.update(verification='passed', transformation='applied', scope='API30 ARM32 stays ARM32; ARM64 selected base/ABI/density/features original reads; STORED 16KB ZIP alignment with extractNativeLibs=false; 4KB device runtime',
        unsupported=['16KB-runtime-not-run', 'x86_64-runtime-not-run', 'unmeasured-ABIs-and-API-levels', 'proc-fd-path-concealment',
            'relative-dirfd-and-preopened-redirection', 'unselected-callers', 'no-production-B-loader-or-public-flag-yet'])


def observe_public_native(result, evidence, serial, lock, label):
    token = result['run_id'] + '-' + label
    shell(lock, evidence, label + '-stop', serial, ['am', 'force-stop', SELF])
    with capture_startup(lock, serial, evidence, label) as captured:
        shell(lock, evidence, label + '-launch', serial, ['am', 'start', '-W', '-n', SELF + '/.ProbeActivity',
            '--es', 'scenario', 'native-public', '--es', 'case_id', 'T-B04', '--es', 'run_id', token], timeout=30)
        pid = int(shell(lock, evidence, label + '-pid', serial, ['pidof', '-s', SELF]).stdout.strip())
        for _ in range(100):
            rows = read_events(captured.read_text(errors='replace'), token)
            if any(item['event'] == 'failure' or item['query_path'] == 'public-complete' for item in rows): break
            time.sleep(.1)
    rows = read_events(captured.read_text(errors='replace'), token); values = {}
    for row in rows:
        if row['pid'] != pid or row['process'] != SELF or row['case_id'] != 'T-B04' or row['scenario'] != 'native-public':
            raise RuntimeError('Mismatched public-native observation')
        if row['event'] != 'response' or row['query_path'] in values: raise RuntimeError('Public native fixture failed: ' + str(row))
        values[row['query_path']] = json.loads(row['response_marker'])
    expected = {'public-initial', 'public-complete'} | {prefix + name for prefix in ('public-read/', 'public-runtime/')
        for name in ('librepack_io_early.so', 'librepack_io_late.so')}
    if set(values) != expected: raise RuntimeError('Incomplete public-native fixture observations')
    return values, captured.read_text(errors='replace'), pid


def run_t_b04(result, evidence, args):
    from repack.rebuild import environment, source_hash
    from repack.report import load_artifact
    from scripts.cli_cases import cli
    from scripts.acceptance import tagged_events
    previous = ROOT / '.work/evidence/T-B03.json'; parent = json.loads(previous.read_text())
    if parent['verification'] != 'passed' or parent['source_sha256'] != source_hash():
        raise PrerequisiteError('Classify current native ABI packaging before the persistent public module')
    lock = load_lock(); serial = select_serial(lock, evidence, args.device); result['cell'] = read_cell(lock, evidence, serial)
    if result['cell'] != parent['cell']: raise PrerequisiteError('Public native module uses another cell')
    result['inputs'] = [report_reference(previous)]; keys = ensure_keys(lock, evidence)
    ca = ROOT / '.work/keys/mitmproxy/mitmproxy-ca-cert.pem'; key = Path(keys['repack']['path'])
    native_selection = 'native-base-bytes:librepack_io_early.so,librepack_io_late.so'
    coexistence = json.loads((ROOT / '.work/evidence/T-B02.json').read_text())
    sources = {'armeabi-v7a': parent['genuine32'], 'arm64-v8a': coexistence['original_selected']}
    result['outputs'] = []; result['public_native_observations'] = {}
    for abi, source in sources.items():
        part = evidence / abi; part.mkdir(); binaries = part / 'binaries'; binaries.mkdir()
        additions, _, _ = build_smoke(lock, binaries, (abi,))
        pin = json.loads((ROOT / 'config/ndk-dependency.json').read_text()); compiler = str(ROOT / pin['tools']['clang']['path'])
        observer = part / 'librepack_observe.so'; triple = 'armv7a-linux-androideabi' if abi == 'armeabi-v7a' else 'aarch64-linux-android'
        execute([compiler, '--target=' + triple + '28', '-shared', '-fPIC', '-O2', '-Wall', '-Wextra', '-Werror',
            '-Wl,-soname,librepack_observe.so', '-Wl,-z,max-page-size=16384', '-Wl,-z,common-page-size=16384',
            str(ROOT / 'native/fixture/public_observer.c'), '-ldl', '-o', str(observer)], part, 'observer-compile')
        own = {'lib/' + abi + '/librepack_observe.so': observer.read_bytes()}
        own.update({name: value for name, value in additions.items() if name.endswith(('/librepack_io_early.so', '/librepack_io_late.so'))})
        inputs = part / 'inputs'; inputs.mkdir()
        for index, member in enumerate(source['members']):
            role = member.get('split') or 'base'; extra = {}
            if role == 'base': extra['assets/repack/native-public.json'] = json.dumps({'runtime_probe': abi == 'arm64-v8a'}).encode()
            if (abi == 'armeabi-v7a' and role == 'base') or (abi == 'arm64-v8a' and role == 'config.arm64_v8a'): extra.update(own)
            staged, _ = native_member(Path(member['apk']), extra, keys['original'], lock, part / ('input-' + str(index)))
            shutil.copyfile(staged, inputs / ('base.apk' if role == 'base' else 'split_' + role + '.apk'))
        original = inspect_input(str(inputs), serial, lock, part / 'input-inventory')
        original_base = next(item for item in original['members'] if not item.get('split'))
        result.setdefault('public_native_inputs', {})[abi] = original
        # Only the ARM64 profile needs A for the fresh hidden ApkAssets runtime fixture.
        for enabled in (False, True):
            label = abi + ('-enabled' if enabled else '-control'); destination = ROOT / '.work/outputs/native-public' / result['run_id'] / label
            output = destination / 'patched.apk' if abi == 'armeabi-v7a' else destination
            arguments = ['patch', inputs, '--out', output, '--key', key, '--ca', ca, '--device', serial]
            if abi == 'arm64-v8a': arguments += ['--antitamper']
            if enabled: arguments += ['--integrity', native_selection]
            child = cli(result, evidence, label + '-patch', arguments, lock)
            manifest = Path(child['artifact_manifest']); document, artifact = load_artifact(manifest)
            from repack.verify import artifact_members
            artifacts = artifact_members(artifact)
            # load_artifact yields bound output members with absolute local APK paths.
            cli(result, evidence, label + '-verify', ['verify', manifest, '--device', serial, '--replace-existing-and-wipe-data'], lock)
            values, text, pid = observe_public_native(result, evidence, serial, lock, label)
            result['public_native_observations'][label] = {'values': values, 'pid': pid, 'artifact_manifest': str(manifest)}
            initial = values['public-initial']
            if bool(initial.get('armed')) != enabled: raise RuntimeError('Public native module opt-in state differs')
            base_output = next(item for item in artifacts if not item.get('split'))
            expected = file_truth(Path(original_base['apk'] if enabled else base_output['apk']))
            for caller in ('librepack_io_early.so', 'librepack_io_late.so'):
                observed = values['public-read/' + caller]
                if (observed['sha256'] != expected['sha256'] or observed['bytes'] != expected['bytes']
                        or observed['constructor'] != {'bytes': expected['bytes'], 'fnv64': expected['fnv64']}):
                    raise RuntimeError('Public imported/constructor bytes differ: ' + str(observed))
                if enabled:
                    state = observed['state']
                    if (not state['armed'] or state['pid'] != pid or state['pointer_bits'] != (32 if abi == 'armeabi-v7a' else 64)
                            or state['registered_tasks'] != 28 or state['hits']['open'] < 2 or state['original_sha256'] != original_base['sha256']):
                        raise RuntimeError('Persistent native state/hits/input binding mismatch')
                result['comparisons'].append({'name': label + '/' + caller, 'result': 'passed', 'observation': observed})
                runtime = values['public-runtime/' + caller]
                if enabled and abi == 'arm64-v8a':
                    if (not runtime['requested'] or not runtime['class_accepts'] or runtime['class_unrelated'] != 'preserved-method'
                            or runtime['resource'] != 'original-resource' or runtime['zip_asset'] != 'original-zip'
                            or runtime['fresh_apkassets']['value'] != 'original-resource' or runtime['signer_sha256'] != original['signer_sha256']
                            or runtime['splits']['split_count'] != 4 or runtime['splits']['native_abi'] != 'arm64-v8a'):
                        raise RuntimeError('Public A/Java/native/split runtime composition failed')
                    result['comparisons'].append({'name': label + '/runtime/' + caller, 'result': 'passed', 'runtime': runtime})
            if enabled:
                native = [item for item in tagged_events(text, 'REPACK_SHIM') if item['pid'] == pid and item['details'].get('capability') == 'integrity']
                complete = [item for item in native if item['event'] == 'complete' and item['details'].get('published')]
                if len(complete) != 1 or any(item['event'] == 'failure' for item in native): raise RuntimeError('Persistent native setup did not complete once')
                lines = [line for line in text.splitlines() if '"pid":' + str(pid) + ',' in line]
                setup = next(index for index, line in enumerate(lines) if 'REPACK_SHIM' in line and '"capability":"integrity"' in line and '"event":"complete"' in line)
                factory = next(index for index, line in enumerate(lines) if 'REPACK_FIXTURE' in line and '"factory-constructor"' in line)
                if setup >= factory: raise RuntimeError('Original factory ran before native original provisioning/publication')
                result['comparisons'].append({'name': label + '/before-original-factory', 'result': 'passed', 'event': complete[0]})
                output_native = inspect_input(str(output), serial, lock, part / 'output-native-inventory', allow_patched=True)
                if output_native['abis'] != original['abis'] or output_native['effective_abi'] != abi: raise RuntimeError('Public native packaging changed input ABI selection')
                result['comparisons'].append({'name': label + '/ABI-preserved', 'result': 'passed', 'abis': output_native['abis']})
            result['outputs'].append({'manifest': str(manifest), 'sha256': sha256(manifest)})
        paths_before = shell(lock, evidence, abi + '-negative-before', serial, ['pm', 'path', SELF]).stdout
        for label, value, expected_status, reason in [('reserved', 'native-base-bytes:libopenjdk.so', 4, 'cannot be selected'),
                ('missing', 'native-base-bytes:librepack_missing.so', 4, 'absent or ambiguous'),
                ('no-import', 'native-base-bytes:librepack_fixture.so', 4, 'no supported file-opening'),
                ('malformed', 'native-base-bytes:../libcaller.so', 1, 'literal library basenames')]:
            out = ROOT / '.work/outputs/native-public' / result['run_id'] / (abi + '-' + label)
            if abi == 'armeabi-v7a': out = out.with_suffix('.apk')
            cli(result, evidence, abi + '-' + label, ['patch', inputs, '--out', out, '--key', key, '--ca', ca,
                '--device', serial, '--integrity', value], lock, expected=expected_status, reason=reason)
            if out.exists(): raise RuntimeError('Rejected native operation published an output')
            result['comparisons'].append({'name': abi + '/' + label + '-refused', 'result': 'passed'})
        if shell(lock, evidence, abi + '-negative-after', serial, ['pm', 'path', SELF]).stdout != paths_before:
            raise RuntimeError('Rejected native patch operation changed installed state')
    result.update(verification='passed', transformation='applied', scope='Public native-base-bytes opt-in on API30 ARM32/ARM64, original provisioning before original factory, imported constructor/read hashes, ABI-preserving APK-mapped libraries and ARM64 A/Java/split composition',
        unsupported=['raw-syscalls', 'dlsym-pointers', 'preopened-descriptors', 'relative-dirfd-paths', 'proc-fd-path-disclosure',
            'same-caller-mixed-runtime/integrity-reads', 'unselected-callers', '16KB-runtime-not-run', 'other-API/ABI-cells', 'real-target-runtime'])


def gate_native(result, evidence, args):
    from repack.rebuild import source_hash
    children = {}; reports = {}
    for name in ('T-B00', 'T-B01', 'T-B02', 'T-B03', 'T-B04', 'T-A03', 'T-P12'):
        path = (args.reports / (name + '.json')).resolve(); reference = report_reference(path)
        child = json.loads(Path(reference['path']).read_text())
        if child['verification'] != 'passed' or child['source_sha256'] != source_hash(): raise PrerequisiteError(name + ' unavailable/failed/stale')
        children[name] = reference; reports[name] = child
    if any(item['cell'] != reports['T-B00']['cell'] for item in reports.values()): raise RuntimeError('Native/default regression cells differ')
    if [len(reports[name]['comparisons']) for name in reports] != [64, 193, 130, 385, 22, 10, 10]:
        raise RuntimeError('Native or default regression control coverage incomplete')
    for child, parent in [('T-B01', 'T-B00'), ('T-B02', 'T-B01'), ('T-B03', 'T-B02'), ('T-B04', 'T-B03')]:
        if not any(item.get('sha256') == children[parent]['sha256'] for item in reports[child]['inputs']):
            raise RuntimeError('Native case used another parent revision: ' + child)
    dependency = json.loads((ROOT / 'config/bytehook-dependency.json').read_text())
    if any(reports[name]['native_dependency'] != dependency for name in ('T-B00', 'T-B01', 'T-B02', 'T-B03')):
        raise PrerequisiteError('Native dependency pin differs between cases')
    result.update(verification='passed', gate_progress='accepted', children=children, cell=reports['T-B00']['cell'],
        scope='Opt-in native-base-bytes for one/two named app native callers, API30 ARM32/ARM64; original base provisioned before original factory; tested app namespace and 4KB runtime only',
        prototype_scope=reports['T-B03']['scope'], public_scope=reports['T-B04']['scope'],
        unsupported=sorted(set(reports['T-B04']['unsupported'] + ['unmeasured-metadata-fields', 'public-split-original-redirection',
            'isolated-process-storage', 'unvalidated-loader-namespaces'])), next_gate='M5 selected input containers')
