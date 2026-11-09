"""Selected split fixtures and validation; container selection belongs to M5."""
import json
from pathlib import Path
import shutil
import zipfile

from repack.rebuild import (ROOT, PrerequisiteError, align_sign, copy_archive, ensure_keys, environment, execute,
                            fixture_source_hash, load_lock, report_reference, sha256, tool, write_json)
from repack.recon import inspect_apk, inspect_input, validate_selected
from repack.shim import build_bootstrap, manifest_editor
from repack.verify import install, preflight, shell
from scripts.acceptance import launch_query, read_cell, select_serial


def fixture_member(manifest, additions, output, key, lock, evidence):
    output.mkdir(parents=True); evidence.mkdir(parents=True)
    xml = output / 'AndroidManifest.xml'; xml.write_text(manifest)
    linked = output / 'linked.apk'
    execute([tool(lock, 'aapt2'), 'link', '-I', lock['android_jar'], '--manifest', str(xml),
             '--min-sdk-version', '28', '--target-sdk-version', '35', '-o', str(linked)], evidence, 'link')
    unsigned = output / 'unsigned.apk'; copy_archive(linked, unsigned, additions=additions)
    apk = output / 'member.apk'; align_sign(unsigned, apk, key, lock, evidence)
    return apk


def feature_manifest(split, *, package='dev.repack.fixture.identity', version=1, dependency=None):
    uses = '<uses-split android:name="' + dependency + '" />' if dependency else ''
    return ('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="' + package + '" '
            'android:versionCode="' + str(version) + '" split="' + split + '" android:isFeatureSplit="true">'
            + uses + '<application android:hasCode="true" /></manifest>')


def build_selected_fixture(baseline, keys, lock, evidence):
    evidence.mkdir(parents=True)
    output = evidence / 'build'; output.mkdir(); selected = evidence / 'selected'; selected.mkdir()
    original = next(item for item in baseline['outputs'] if item['id'] == 'app-own')
    resources = output / 'res'; shutil.copytree(ROOT / 'tests/fixtures/identity/common/res', resources)
    for qualifier, value in [('values', 'density-base'), ('values-xxhdpi', 'density-config')]:
        folder = resources / qualifier; folder.mkdir(exist_ok=True)
        (folder / 'strings.xml').write_text('<resources><string name="repack_density_value">' + value + '</string></resources>')
    manifest = (ROOT / 'tests/fixtures/identity/app/AndroidManifest.xml').read_text().replace(
        'android:versionCode="1"', 'android:versionCode="1" android:requiredSplitTypes="base__abi,base__density"')
    xml = output / 'AndroidManifest.xml'; xml.write_text(manifest)
    compiled = output / 'resources.zip'; linked = output / 'base-linked.apk'; density = output / 'density-linked.apk'
    execute([tool(lock, 'aapt2'), 'compile', '--dir', str(resources), '-o', str(compiled)], evidence, 'compile-base-resources')
    execute([tool(lock, 'aapt2'), 'link', '-I', lock['android_jar'], '--manifest', str(xml), '--min-sdk-version', '28',
             '--target-sdk-version', '35', '--split', str(density) + ':xxhdpi', '-o', str(linked), str(compiled)], evidence, 'link-base-density')
    with zipfile.ZipFile(original['apk']) as archive:
        dex = {name: archive.read(name) for name in archive.namelist() if name.startswith('classes') and name.endswith('.dex')}
    unsigned = output / 'base-unsigned.apk'; copy_archive(linked, unsigned, additions=dex)
    signed_base = output / 'base.apk'; align_sign(unsigned, signed_base, keys['original'], lock, evidence)
    shutil.copyfile(signed_base, selected / 'base.apk')
    jar, editor = manifest_editor(lock, evidence)
    with zipfile.ZipFile(density) as archive: density_xml = output / 'density.axml'; density_xml.write_bytes(archive.read('AndroidManifest.xml'))
    updated = output / 'density-updated.axml'
    execute([tool(lock, 'java'), '-classpath', str(editor) + ':' + str(jar), 'ManifestEdit', 'split-types',
             str(density_xml), str(updated), 'base__density'], evidence, 'density-type', env=environment(lock))
    density_unsigned = output / 'density-unsigned.apk'; copy_archive(density, density_unsigned, {'AndroidManifest.xml': updated.read_bytes()})
    signed_density = output / 'density.apk'; align_sign(density_unsigned, signed_density, keys['original'], lock, evidence)
    shutil.copyfile(signed_density, selected / 'split_config.xxhdpi.apk')

    native_report = json.loads((ROOT / '.work/evidence/T-A12.json').read_text())
    library = next(item for item in native_report['native_build'] if item['abi'] == 'arm64-v8a')
    if sha256(Path(library['library'])) != library['sha256']: raise PrerequisiteError('Accepted JNI fixture library changed')
    native_manifest = ('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="dev.repack.fixture.identity" '
        'android:versionCode="1" split="config.arm64_v8a" android:splitTypes="base__abi">'
        '<application android:hasCode="false" android:extractNativeLibs="true" /></manifest>')
    native = fixture_member(native_manifest, {'lib/arm64-v8a/librepack_fixture.so': Path(library['library']).read_bytes()},
                            output / 'native', keys['original'], lock, evidence / 'native')
    shutil.copyfile(native, selected / 'split_config.arm64_v8a.apk')
    sources = output / 'java'; sources.mkdir(); classes = output / 'classes'; classes.mkdir()
    files = []
    for name in ('Parent', 'Child'):
        path = sources / ('Split' + name + '.java')
        path.write_text('package dev.repack.fixture.split; public final class Split' + name
                        + ' { public static String marker() { return "' + name.lower() + '"; } }')
        files.append(str(path))
    execute([tool(lock, 'javac'), '--release', '8', '-d', str(classes), *files], evidence, 'feature-javac', env=environment(lock))
    for name in ('Parent', 'Child'):
        part = output / name; part.mkdir(); dex = part / 'dex'; dex.mkdir()
        classfile = classes / ('dev/repack/fixture/split/Split' + name + '.class')
        program = part / 'program.jar'
        with zipfile.ZipFile(program, 'w') as archive: archive.write(classfile, str(classfile.relative_to(classes)))
        execute([tool(lock, 'd8'), '--release', '--min-api', '28', '--lib', lock['android_jar'], '--output', str(dex), str(program)],
                evidence, 'feature-' + name + '-d8', env=environment(lock))
        additions = {'classes.dex': (dex / 'classes.dex').read_bytes()}
        if name == 'Child': additions['assets/repack-feature-child.txt'] = b'child-lazy-asset'
        manifest = feature_manifest('feature.' + name.lower(), dependency='feature.parent' if name == 'Child' else None)
        apk = fixture_member(manifest, additions, part / 'member', keys['original'], lock, evidence / name)
        shutil.copyfile(apk, selected / ('split_feature.' + name.lower() + '.apk'))
    return selected


def repack_fixture_set(source, keys, lock, evidence):
    evidence.mkdir(parents=True); selected = evidence / 'selected'; selected.mkdir()
    base = next(item for item in source['members'] if not item.get('split'))
    signing = base['signing']; part = evidence / 'base'; part.mkdir()
    patched = build_bootstrap(Path(base['apk']), part / 'output', keys['repack'], lock, part,
        identity_mode='identity', probe_token=evidence.parent.name,
        original_certificates=[Path(item['der']).read_bytes() for item in signing['certificates']],
        historical_certificates=[Path(item['der']).read_bytes() for item in signing['history']],
        original_scheme=signing['scheme_version'], signing_contracts=True, package_binder=True)
    shutil.copyfile(patched['apk'], selected / 'base.apk')
    preserved = []
    for index, member in enumerate(source['members']):
        if not member.get('split'): continue
        part = evidence / ('member-' + str(index)); part.mkdir()
        unsigned = part / 'unsigned.apk'; signed = part / 'signed.apk'
        entries = copy_archive(Path(member['apk']), unsigned); align_sign(unsigned, signed, keys['repack'], lock, part)
        with zipfile.ZipFile(signed) as archive:
            for entry in entries:
                import hashlib
                if hashlib.sha256(archive.read(entry['entry'])).hexdigest() != entry['sha256'] or archive.getinfo(entry['entry']).compress_type != entry['compression']:
                    raise RuntimeError('Unedited selected-member bytes/compression changed')
        shutil.copyfile(signed, selected / ('split_' + member['split'] + '.apk')); preserved.append({'split': member['split'], 'entries': entries})
    members = []
    for index, apk in enumerate(sorted(selected.glob('*.apk'))):
        members.append(inspect_apk(apk, source['metadata_api'], lock, evidence / ('output-' + str(index)),
                                   inherited_min_sdk=base.get('min_sdk') if apk.name != 'base.apk' else None, allow_patched=True))
    result = validate_selected(members, source['api'], source['device_abis'])
    result['preserved_nonbase'] = preserved; result['base_transform'] = patched
    return result


def run_t_p10(result, evidence, args):
    lock = load_lock(); serial = select_serial(lock, evidence, args.device); result['cell'] = read_cell(lock, evidence, serial)
    parent = ROOT / '.work/evidence/M1b-2.json'
    if json.loads(parent.read_text()).get('gate_progress') != 'accepted': raise PrerequisiteError('Accept M1b-2 first')
    build_path = ROOT / '.work/evidence/M0-build.json'; baseline = json.loads(build_path.read_text())
    if baseline.get('fixture_source_sha256') != fixture_source_hash(): raise PrerequisiteError('Rebuild current split-aware fixtures first')
    result['inputs'] = [report_reference(parent), report_reference(build_path), report_reference(ROOT / '.work/evidence/T-A12.json')]
    keys = ensure_keys(lock, evidence); selected = build_selected_fixture(baseline, keys, lock, evidence / 'fixture')
    source = inspect_input(str(selected), serial, lock, evidence / 'original-inventory')
    if len(source['members']) != 5: raise RuntimeError('Fixture is not the expected selected set')
    patched = repack_fixture_set(source, keys, lock, evidence / 'repacked')
    for label, artifact in [('genuine', source), ('repacked', patched)]:
        plan = preflight(artifact, serial, args.replace_existing_and_wipe_data, lock, evidence, label)
        install(artifact, serial, plan, lock, evidence, label, result['device_mutations'])
        for path in ('direct-legacy', 'direct-current'):
            name = label + '-' + path
            event, _, _, _ = launch_query(artifact, serial, result['run_id'] + name, 'T-P10', source['signer_sha256'],
                                          source['package'], path, lock, evidence, name)
            expected = {'parent': 'parent', 'child': 'child', 'lazy_asset': 'child-lazy-asset',
                        'density_resource': 'density-config', 'native_abi': 'arm64-v8a', 'split_count': 4}
            if event['comparison'] != 'passed' or json.loads(event['response_marker']) != expected:
                raise RuntimeError('Selected DEX/resource/asset/native runtime oracle failed')
            result['comparisons'].append({'name': name, 'result': 'passed', 'event': event})
        if plan.get('existing_installer') != 'com.android.shell': raise RuntimeError('Selected-set installer setup is not the measured known value')
        actual_installer = shell(lock, evidence, label + '-installer-after', serial, ['pm', 'list', 'packages', '-i', source['package']]).stdout
        if 'installer=com.android.shell' not in actual_installer: raise RuntimeError('install-multiple did not preserve installer of record')
    compile_ = shell(lock, evidence, 'compile-selected', serial, ['cmd', 'package', 'compile', '-f', '-m', 'speed', source['package']])
    if 'Success' not in compile_.stdout: raise RuntimeError('Selected-set compilation did not report Success')
    event, _, _, _ = launch_query(patched, serial, result['run_id'] + '-compiled', 'T-P10', source['signer_sha256'],
                                  source['package'], 'direct-current', lock, evidence, 'compiled')
    if event['comparison'] != 'passed' or json.loads(event['response_marker']) != expected: raise RuntimeError('Compiled selected set changed behavior')
    result['comparisons'].append({'name': 'compiled-repacked-set', 'result': 'passed', 'event': event})
    result['outputs'] = [source, patched]

    def rejected(label, directory):
        before = shell(lock, evidence, label + '-before', serial, ['pm', 'path', source['package']]).stdout
        try: inspect_input(str(directory), serial, lock, evidence / (label + '-inspection'))
        except PrerequisiteError: raise
        except (ValueError, RuntimeError) as error:
            reasons = {'missing-base': 'exactly one base', 'missing-feature-parent': 'Missing/invalid split dependency',
                       'missing-native-type': 'Missing required split types', 'missing-density-type': 'Missing required split types',
                       'duplicate-split': 'Duplicate/conflicting split IDs', 'wrong-signer': 'different signers',
                       'wrong-version': 'different package/version', 'wrong-package': 'different package/version',
                       'prepatched-input': 'Previously patched input', 'corrupt-signed-member': 'signature-all exited 1'}
            if reasons[label] not in str(error): raise RuntimeError('Invalid input failed for an unexpected reason: ' + str(error)) from error
            if label == 'corrupt-signed-member':
                failures = list((evidence / (label + '-inspection')).rglob('signature-all.stderr.log'))
                if not any('DOES NOT VERIFY' in path.read_text() for path in failures): raise RuntimeError('Corruption was not rejected by signature verification')
            after = shell(lock, evidence, label + '-after', serial, ['pm', 'path', source['package']]).stdout
            if before != after: raise RuntimeError('Rejected input changed installed member inventory')
            result['comparisons'].append({'name': label, 'result': 'passed', 'rejection': str(error), 'installed_paths_unchanged': True})
        else: raise RuntimeError('Invalid selected set was accepted: ' + label)

    def subset(label, omit=()):
        directory = evidence / label; directory.mkdir()
        for member in source['members']:
            if (member.get('split') or 'base') not in omit: shutil.copyfile(member['apk'], directory / Path(member['apk']).name)
        return directory

    for label, omit in [('missing-base', ['base']), ('missing-feature-parent', ['feature.parent']),
                         ('missing-native-type', ['config.arm64_v8a']), ('missing-density-type', ['config.xxhdpi'])]:
        rejected(label, subset(label, omit))
    duplicate = subset('duplicate-split'); shutil.copyfile(selected / 'split_feature.child.apk', duplicate / 'duplicate.apk'); rejected('duplicate-split', duplicate)
    wrong_signer = subset('wrong-signer', ['feature.child']); part = evidence / 'wrong-signer-build'; part.mkdir()
    unsigned = part / 'unsigned.apk'; signed = part / 'signed.apk'; copy_archive(selected / 'split_feature.child.apk', unsigned)
    align_sign(unsigned, signed, keys['other'], lock, part); shutil.copyfile(signed, wrong_signer / 'wrong-signer.apk'); rejected('wrong-signer', wrong_signer)
    with zipfile.ZipFile(selected / 'split_feature.child.apk') as archive:
        payload = {name: archive.read(name) for name in archive.namelist() if name == 'classes.dex' or name.startswith('assets/')}
    for label, kwargs in [('wrong-version', {'version': 2}), ('wrong-package', {'package': 'dev.repack.fixture.other'})]:
        directory = subset(label, ['feature.child'])
        apk = fixture_member(feature_manifest('feature.child', dependency='feature.parent', **kwargs), payload,
                             evidence / (label + '-build'), keys['original'], lock, evidence / (label + '-logs'))
        shutil.copyfile(apk, directory / 'changed.apk'); rejected(label, directory)
    rejected('prepatched-input', evidence / 'repacked/selected')
    corrupt = subset('corrupt-signed-member'); base = corrupt / 'base.apk'
    with zipfile.ZipFile(base) as archive: offset = archive.getinfo('classes.dex').header_offset
    import struct
    with base.open('r+b') as stream:
        stream.seek(offset + 26); name_size, extra_size = struct.unpack('<HH', stream.read(4))
        stream.seek(offset + 30 + name_size + extra_size + 120); value = stream.read(1)
        stream.seek(-1, 1); stream.write(bytes([value[0] ^ 1]))
    rejected('corrupt-signed-member', corrupt)
    result.update(verification='passed', transformation='applied', scope='API30 selected five-member set, dependent feature DEX, lazy asset, density resource, native ABI and signer/installer consistency',
                  unsupported=['container-selection', 'unavailable-dynamic-features', 'isolated-split-loaders', 'other-API-levels'])
