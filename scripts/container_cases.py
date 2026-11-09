"""M5 genuine multi-device bundletool fixture and explicit selected XAPK controls."""
import copy
import json
from pathlib import Path
import shutil
import struct
import zlib
import zipfile

from repack.containers import bundletool, device_spec
from repack.rebuild import (ROOT, PrerequisiteError, environment, execute, ensure_keys, load_lock,
    report_reference, sha256, source_hash, tool, write_json)
from repack.recon import inspect_input
from repack.report import load_artifact
from repack.verify import shell
from scripts.acceptance import launch_query, read_cell, select_serial
from scripts.cli_cases import cli
from scripts.selected_cases import build_selected_fixture


def build_apks(baseline, keys, lock, evidence):
    evidence.mkdir(parents=True)
    jar, pin = bundletool()
    resources = evidence / 'res'; shutil.copytree(ROOT / 'tests/fixtures/identity/common/res', resources)
    def chunk(kind, data): return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data))
    for density, colour in [('mdpi', b'\xff\0\0\xff'), ('xxhdpi', b'\0\xff\0\xff')]:
        folder = resources / ('drawable-' + density); folder.mkdir()
        png = b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 6, 0, 0, 0))
        (folder / 'container_density.png').write_bytes(png + chunk(b'IDAT', zlib.compress(b'\0' + colour)) + chunk(b'IEND', b''))
    manifest = evidence / 'AndroidManifest.xml'; shutil.copyfile(ROOT / 'tests/fixtures/identity/app/AndroidManifest.xml', manifest)
    compiled = evidence / 'resources.zip'; linked = evidence / 'linked.apk'; proto = evidence / 'proto.apk'
    execute([tool(lock, 'aapt2'), 'compile', '--dir', str(resources), '-o', str(compiled)], evidence, 'compile')
    execute([tool(lock, 'aapt2'), 'link', '-I', lock['android_jar'], '--manifest', str(manifest),
        '--min-sdk-version', '28', '--target-sdk-version', '35', '-o', str(linked), str(compiled)], evidence, 'link')
    execute([tool(lock, 'aapt2'), 'convert', '--output-format', 'proto', '-o', str(proto), str(linked)], evidence, 'convert')
    native = json.loads((ROOT / '.work/evidence/T-A12.json').read_text())['native_build']
    original = next(row for row in baseline['outputs'] if row['id'] == 'app-own')
    module = evidence / 'base.zip'
    with zipfile.ZipFile(module, 'w') as output:
        with zipfile.ZipFile(proto) as source:
            for name in source.namelist():
                output.writestr('manifest/AndroidManifest.xml' if name == 'AndroidManifest.xml' else name, source.read(name))
        with zipfile.ZipFile(original['apk']) as source:
            for name in source.namelist():
                if name.startswith('classes') and name.endswith('.dex'): output.writestr('dex/' + name, source.read(name))
        for abi in ('arm64-v8a', 'x86_64'):
            entry = next(row for row in native if row['abi'] == abi)
            if sha256(Path(entry['library'])) != entry['sha256']: raise PrerequisiteError('JNI fixture changed')
            output.write(entry['library'], 'lib/' + abi + '/librepack_fixture.so')
    bundle = evidence / 'fixture.aab'; apks = evidence / 'multi-device.apks'
    execute([tool(lock, 'java'), '-jar', str(jar), 'build-bundle', '--modules=' + str(module), '--output=' + str(bundle)],
        evidence, 'build-bundle', env=environment(lock), timeout=120)
    key = keys['original']
    execute([tool(lock, 'java'), '-jar', str(jar), 'build-apks', '--bundle=' + str(bundle), '--output=' + str(apks),
        '--aapt2=' + tool(lock, 'aapt2'), '--ks=' + key['path'], '--ks-key-alias=' + key['alias'],
        '--ks-pass=file:' + key['password_file']], evidence, 'build-apks', env=environment(lock), timeout=180)
    return apks


def xapk(path, files, metadata, extras=None):
    with zipfile.ZipFile(path, 'w') as output:
        output.writestr('manifest.json', json.dumps(metadata))
        for name, source in files.items(): output.write(source, name)
        for name, data in (extras or {}).items(): output.writestr(name, data)


def run_t_i50(result, evidence, args):
    lock = load_lock(); serial = select_serial(lock, evidence, args.device)
    result['cell'] = read_cell(lock, evidence, serial)
    foundation = report_reference(ROOT / '.work/evidence/RELEASE-1.json')
    if json.loads(Path(foundation['path']).read_text()).get('gate_progress') != 'accepted': raise PrerequisiteError('Accept RELEASE-1 first')
    result['inputs'] = [foundation, report_reference(ROOT / '.work/evidence/M4.json')]
    baseline = json.loads((ROOT / '.work/evidence/M0-build.json').read_text()); keys = ensure_keys(lock, evidence)
    def passed(name, **values): result['comparisons'].append({'name': name, 'result': 'passed', **values})
    spec, spec_path, origin = device_spec(serial, None, lock, evidence)
    passed('actual-device-spec', api=spec['sdkVersion'], abis=spec['supportedAbis'], density=spec['screenDensity'], provenance=origin)
    apks = build_apks(baseline, keys, lock, evidence / 'bundle-fixture')
    selected = inspect_input(str(apks), None, lock, evidence / 'apks-selected', device_spec=spec_path)
    container = selected['container']; selected_names = {row['path'] for row in container['selected']}
    all_names = {row['path'] for row in container['inventory'] if row['path'].endswith('.apk')}
    if (not selected_names < all_names or selected['abis'] != ['arm64-v8a']
            or not any('x86_64' in name for name in all_names - selected_names)):
        raise RuntimeError('Multi-device APKS was not reduced to the actual device subset')
    passed('apks-compatible-subset', selected=sorted(selected_names), archive=sorted(all_names))
    offline = copy.deepcopy(spec); offline.update(supportedAbis=['x86_64'], screenDensity=160, sdkVersion=35)
    offline_path = evidence / 'offline-spec.json'; write_json(offline_path, offline)
    other = inspect_input(str(apks), None, lock, evidence / 'offline-selected', device_spec=offline_path)
    if other['abis'] != ['x86_64'] or other['metadata_api'] != 35 or other['api'] != 35:
        raise RuntimeError('Offline spec did not govern ABI and signer API inventory')
    passed('offline-targeting', selected=other['container']['selected'], metadata_api=other['metadata_api'], runtime='not-run')
    explicit = build_selected_fixture(baseline, keys, lock, evidence / 'xapk-fixture')
    inventory = inspect_input(str(explicit), serial, lock, evidence / 'xapk-fixture-inventory')
    files = {Path(row['apk']).name: Path(row['apk']) for row in inventory['members']}
    metadata = {'xapk_version': 2, 'package_name': inventory['package'], 'version_code': inventory['version_code'],
        'split_apks': [{'file': Path(row['apk']).name, 'id': row.get('split') or 'base'} for row in inventory['members']]}
    archive = evidence / 'selected.xapk'; xapk(archive, files, metadata)
    via_xapk = inspect_input(str(archive), None, lock, evidence / 'xapk-selected', device_spec=spec_path)
    if len(via_xapk['members']) != 5 or {row['sha256'] for row in via_xapk['members']} != {row['sha256'] for row in inventory['members']}:
        raise RuntimeError('XAPK selection changed or lost a selected split')
    passed('xapk-explicit-subset', members=via_xapk['container']['selected'], dependencies=via_xapk['dependencies'])
    paths_before = shell(lock, evidence, 'negative-before', serial, ['pm', 'path', inventory['package']]).stdout
    outputs = ROOT / '.work/outputs/containers' / result['run_id']; outputs.mkdir(parents=True)
    ca = ROOT / '.work/keys/mitmproxy/mitmproxy-ca-cert.pem'; key = Path(keys['repack']['path'])
    bads = []
    for label, mutation in [('wrong-package', {'package_name': 'wrong.package'}), ('wrong-version', {'version_code': 99}),
            ('expansion', {'expansions': [{'file': 'main.obb'}]}), ('wrong-id', {'split_apks': [{**row, 'id': 'wrong'} for row in metadata['split_apks']]})]:
        value = copy.deepcopy(metadata); value.update(mutation); target = evidence / (label + '.xapk'); xapk(target, files, value)
        bads.append((label, target, 4 if label == 'expansion' else 1))
    for label, extras, subset in [('traversal', {'../escape': b'bad'}, files), ('unlisted', {'other.apk': b'bad'}, files),
            ('missing', {}, {name: file for index, (name, file) in enumerate(files.items()) if index})]:
        target = evidence / (label + '.xapk'); xapk(target, subset, metadata, extras); bads.append((label, target, 1 if label == 'traversal' else 4))
    bad_apks = evidence / 'missing-toc.apks'
    with zipfile.ZipFile(bad_apks, 'w') as output: output.writestr('base.apk', b'invalid')
    bads.append(('missing-toc', bad_apks, 1))
    for label, target, status in bads:
        out = outputs / label
        cli(result, evidence, 'refuse-' + label, ['patch', target, '--device-spec', spec_path, '--out', out,
            '--key', key, '--ca', ca], lock, expected=status)
        if out.exists(): raise RuntimeError('Invalid container published output')
        passed('refuse-' + label)
    cli(result, evidence, 'missing-target', ['triage', apks], lock, expected=3)
    passed('refuse-missing-target')
    if shell(lock, evidence, 'negative-after', serial, ['pm', 'path', inventory['package']]).stdout != paths_before:
        raise RuntimeError('Invalid containers changed installed package state')
    passed('negative-device-state-preserved')
    for label, source in [('apks', apks), ('xapk', archive)]:
        out = outputs / label
        cli(result, evidence, 'patch-' + label, ['patch', source, '--device', serial, '--out', out,
            '--key', key, '--ca', ca, '--antitamper'], lock)
        manifest = out / 'manifest.json'; document, artifact = load_artifact(manifest)
        cli(result, evidence, 'install-' + label, ['verify', manifest, '--device', serial,
            '--replace-existing-and-wipe-data'], lock)
        scenario = 'direct-current'
        if document['semantic']['input_container']['sha256'] != sha256(source):
            raise RuntimeError('Signed artifact omitted original container binding')
        case = 'T-A03' if label == 'apks' else 'T-P10'
        event, _, _, _ = launch_query(artifact, serial, result['run_id'] + '-' + label, case,
            [keys['original']['sha256']], inventory['package'], scenario, lock, evidence, label + '-query')
        if event['comparison'] != 'passed': raise RuntimeError('Patched container identity runtime failed')
        if label == 'xapk' and json.loads(event['response_marker']).get('native_abi') != 'arm64-v8a':
            raise RuntimeError('XAPK lazy feature/native path failed')
        passed(label + '-public-runtime', event=event, input_members=document['semantic']['input_members'])
        result['outputs'].append({'manifest': str(manifest), 'sha256': sha256(manifest)})
    if sha256(apks) != container['sha256'] or sha256(archive) != via_xapk['container']['sha256']:
        raise RuntimeError('Input archives changed')
    passed('archives-preserved')
    result.update(verification='passed', transformation='applied', bundletool=bundletool()[1],
        scope='Bundletool install-time APKS subset and explicit selected version-2 XAPK; physical API30 ARM64, offline x86_64/API35 selection only',
        unsupported=['XAPK multi-ABI/density targeting', 'expansion/asset delivery', 'offline runtime', 'all on-demand features'])


def gate_containers(result, evidence, args):
    reference = report_reference((args.reports / 'T-I50.json').resolve()); child = json.loads(Path(reference['path']).read_text())
    if child['verification'] != 'passed' or child['source_sha256'] != source_hash(): raise PrerequisiteError('T-I50 failed or stale')
    expected = {'actual-device-spec', 'apks-compatible-subset', 'offline-targeting', 'xapk-explicit-subset',
        'refuse-wrong-package', 'refuse-wrong-version', 'refuse-expansion', 'refuse-wrong-id', 'refuse-traversal',
        'refuse-unlisted', 'refuse-missing', 'refuse-missing-toc', 'refuse-missing-target', 'negative-device-state-preserved',
        'apks-public-runtime', 'xapk-public-runtime', 'archives-preserved'}
    if ({row['name'] for row in child['comparisons']} != expected or len(child['comparisons']) != len(expected)
            or any(row['result'] != 'passed' for row in child['comparisons'])): raise RuntimeError('Container controls incomplete')
    if child['bundletool'] != bundletool()[1]: raise PrerequisiteError('Container dependency pin changed')
    for row in child['inputs']:
        if sha256(Path(row['path'])) != row['sha256']: raise RuntimeError('Container foundation evidence changed')
    for row in child.get('cli_reports', []):
        if sha256(Path(row['path'])) != row['sha256']: raise RuntimeError('Container CLI child report changed')
    result.update(verification='passed', gate_progress='accepted', cell=child['cell'], children={'T-I50': reference},
        scope=child['scope'], unsupported=child['unsupported'], next_gate='M6')
