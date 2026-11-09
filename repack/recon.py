"""Read-only APK, selected-set and targeted container inventory."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import re
import ssl
import struct
import zipfile

from .rebuild import ROOT, PrerequisiteError, environment, execute, sha256, signer_records, tool, write_json
from .shim import manifest_editor
from .verify import adb, shell


def certificate_blocks(text: str) -> list[bytes]:
    return [ssl.PEM_cert_to_DER_cert(block) for block in re.findall(
        r'-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\r\n\s]+?-----END CERTIFICATE-----', text)]


def apk_signer_output(text: str) -> str:
    """Source-stamp certificates authenticate distribution, not the APK signer."""
    return re.split(r'^Source Stamp Signer certificate DN:', text, maxsplit=1, flags=re.M)[0]


def signing_metadata(apk: Path, api: int | None, lock: dict, evidence: Path, *, inherited_min_sdk: int | None = None) -> dict:
    inherited = ['--min-sdk-version', str(inherited_min_sdk)] if inherited_min_sdk is not None else []
    generic = execute([tool(lock, 'apksigner'), 'verify', '--verbose', '--print-certs-pem', *inherited, str(apk)],
                      evidence, 'signature-all', env=environment(lock)).stdout
    selected = generic
    if api is not None:
        selected = execute([tool(lock, 'apksigner'), 'verify', '--verbose', '--min-sdk-version', str(api),
                            '--max-sdk-version', str(api), '--print-certs-pem', str(apk)],
                           evidence, 'signature-selected-api', env=environment(lock)).stdout
    selected = apk_signer_output(selected)
    generic = apk_signer_output(generic)
    printed = signer_records(selected); blocks = certificate_blocks(selected)
    if not blocks or [hashlib.sha256(value).hexdigest() for value in blocks] != [row['sha256'] for row in printed]:
        raise RuntimeError('Verified current signer PEM/digest output is ambiguous')
    if api is None and any(row['min_sdk'] is not None for row in printed):
        raise PrerequisiteError('Choose a metadata API for SDK-range-specific signer output')
    current = [value for row, value in zip(printed, blocks)
               if row['min_sdk'] is None or row['min_sdk'] <= api <= row['max_sdk']]
    actual = [hashlib.sha256(value).hexdigest() for value in current]
    if not actual or len(set(actual)) != len(actual): raise RuntimeError('Ambiguous selected-platform signer set')
    lineage = execute([tool(lock, 'apksigner'), 'lineage', '--in', str(apk), '--print-certs-pem'],
                      evidence, 'signature-lineage', env=environment(lock), check=False)
    history = []
    if lineage.returncode == 0:
        full = certificate_blocks(lineage.stdout)
        digests = [hashlib.sha256(value).hexdigest() for value in full]
        printed = re.findall(r'certificate SHA-256 digest:\s*([0-9a-f]{64})', lineage.stdout)
        if not full or digests != printed or len(actual) != 1 or digests.count(actual[0]) != 1:
            raise RuntimeError('Verified rotation lineage PEM/digest output is ambiguous')
        history = full[:digests.index(actual[0]) + 1]
        if len(history) == 1: history = []
    else:
        error = lineage.stderr + lineage.stdout
        absent = 'The provided APK does not contain a valid lineage.' in error
        no_v3 = ('The provided APK does not contain a valid V3 nor V3.1 signature block.' in error
                 and not re.search(r'^Verified using v3(?:\.1)? scheme[^:]*:\s*true$', generic, re.M))
        if not absent and not no_v3: raise RuntimeError('Unable to classify signing lineage; retain the tool error')
    schemes = {name: value == 'true' for name, value in re.findall(r'^Verified using (v[0-9.]+) scheme[^:]*:\s*(true|false)$', selected, re.M)}
    scheme = 3 if schemes.get('v3') or schemes.get('v3.1') else 2 if schemes.get('v2') else 1 if schemes.get('v1') else None
    if scheme is None: raise RuntimeError('Verified signing scheme is not represented')
    def store(values):
        result = []
        for value in values:
            digest = hashlib.sha256(value).hexdigest(); path = evidence / ('certificate-' + digest + '.der'); path.write_bytes(value)
            result.append({'sha256': digest, 'der': str(path)})
        return result
    return {'api': api, 'signer_sha256': sorted(actual), 'certificates': store(current), 'history': store(history),
            'scheme_version': scheme, 'verified_schemes': schemes,
            'verification_min_sdk': inherited_min_sdk,
            'verified_api_range_signer_sha256': sorted({hashlib.sha256(value).hexdigest() for value in certificate_blocks(generic)}),
            'verified_api_ranges': signer_records(generic)}


def elf_loads(data: bytes) -> dict:
    if len(data) < 64 or data[:4] != b'\x7fELF' or data[4] not in (1, 2) or data[5] not in (1, 2):
        raise RuntimeError('Native member is not a supported ELF file')
    endian = '<' if data[5] == 1 else '>'; bits = 64 if data[4] == 2 else 32
    machine = struct.unpack_from(endian + 'H', data, 18)[0]
    if bits == 64:
        offset = struct.unpack_from(endian + 'Q', data, 32)[0]; size, count = struct.unpack_from(endian + 'HH', data, 54)
        format_ = endian + 'IIQQQQQQ'
    else:
        offset = struct.unpack_from(endian + 'I', data, 28)[0]; size, count = struct.unpack_from(endian + 'HH', data, 42)
        format_ = endian + 'IIIIIIII'
    if size < struct.calcsize(format_) or offset + size * count > len(data): raise RuntimeError('Truncated ELF program headers')
    loads, segments = [], []
    for index in range(count):
        row = struct.unpack_from(format_, data, offset + index * size)
        if row[0] == 1:
            position, address, length = (row[2], row[3], row[5]) if bits == 64 else (row[1], row[2], row[4])
            if position + length > len(data): raise RuntimeError('Truncated ELF load segment')
            loads.append(row[-1]); segments.append({'offset': position, 'address': address, 'alignment': row[-1]})
    if not loads: raise RuntimeError('ELF has no loadable segments')
    return {'bits': bits, 'machine': machine, 'load_alignments': loads, 'load_segments': segments,
            'compatible_16k': all(item['alignment'] >= 16384 and item['offset'] % 16384 == item['address'] % 16384 for item in segments)}


def manifest_metadata(payload: bytes, lock: dict, evidence: Path) -> dict:
    evidence.mkdir(parents=True, exist_ok=True)
    manifest = evidence / 'AndroidManifest.xml'; manifest.write_bytes(payload)
    jar, classes = manifest_editor(lock, evidence)
    output = execute([tool(lock, 'java'), '-classpath', str(classes) + ':' + str(jar), 'ManifestEdit', 'inventory', str(manifest)],
                     evidence, 'manifest-inventory', env=environment(lock)).stdout
    rows = [line[9:] for line in output.splitlines() if line.startswith('metadata=')]
    if len(rows) != 1: raise RuntimeError('Ambiguous binary manifest inventory')
    metadata = json.loads(base64.b64decode(rows[0]))
    low = metadata['version_code']; major = metadata.get('version_code_major') or 0
    if not isinstance(low, int) or not isinstance(major, int): raise RuntimeError('Manifest version is not an integer')
    metadata['version_code'] = ((major & 0xffffffff) << 32) | (low & 0xffffffff)
    return metadata


def inspect_apk(apk: Path, api: int | None, lock: dict, evidence: Path, *, metadata_hint=None, inherited_min_sdk=None, allow_patched=False) -> dict:
    evidence.mkdir(parents=True)
    with zipfile.ZipFile(apk) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)): raise RuntimeError('Duplicate APK ZIP entries')
        if 'AndroidManifest.xml' not in names: raise RuntimeError('APK lacks a manifest')
        previously_patched = any(name in names for name in ('assets/repack/marker.json', 'assets/repack/artifact.json', 'assets/repack/java-patches.json'))
        if previously_patched and not allow_patched:
            raise RuntimeError('Previously patched input')
        metadata = dict(metadata_hint) if metadata_hint is not None else manifest_metadata(archive.read('AndroidManifest.xml'), lock, evidence)
        natives = []
        for item in archive.infolist():
            match = re.fullmatch(r'lib/([^/]+)/([^/]+\.so)', item.filename)
            if match:
                payload = archive.read(item.filename)
                elf = elf_loads(payload)
                expected = {'arm64-v8a': (64, 183), 'armeabi-v7a': (32, 40), 'armeabi': (32, 40),
                            'x86': (32, 3), 'x86_64': (64, 62), 'riscv64': (64, 243)}.get(match[1])
                if expected is None or (elf['bits'], elf['machine']) != expected: raise RuntimeError('Native ABI label/ELF machine mismatch')
                natives.append({'entry': item.filename, 'abi': match[1], 'sha256': hashlib.sha256(payload).hexdigest(),
                                'compression': item.compress_type, **elf})
        dex = sorted(name for name in names if re.fullmatch(r'classes(?:[2-9]|[1-9][0-9]+)?\.dex', name))
        dex.sort(key=lambda name: 1 if name == 'classes.dex' else int(name[7:-4]))
        if dex and dex != ['classes.dex'] + [f'classes{index}.dex' for index in range(2, len(dex) + 1)]:
            raise RuntimeError('Non-contiguous DEX inventory')
        marker = [name for name in names if name.endswith('/libpairipcore.so')]
    signing = signing_metadata(apk, api, lock, evidence, inherited_min_sdk=inherited_min_sdk)
    return {'apk': str(apk.resolve()), 'sha256': sha256(apk), **metadata, 'signing': signing,
            'native_libraries': natives, 'abis': sorted({item['abi'] for item in natives}), 'dex': dex,
            'pairip_native_markers': marker, 'previously_patched': previously_patched}


def validate_selected(members: list[dict], api: int | None = None, abi: str | list[str] | None = None) -> dict:
    bases = [item for item in members if not item.get('split')]
    if len(bases) != 1: raise RuntimeError('Selected set must contain exactly one base APK')
    base = bases[0]; names = {item.get('split') or 'base' for item in members}
    if len(names) != len(members): raise RuntimeError('Duplicate/conflicting split IDs')
    by_name = {item.get('split') or 'base': item for item in members}
    if base.get('isFeatureSplit') or base.get('configForSplit'): raise RuntimeError('Base APK cannot be a feature/config split')
    for item in members:
        if item['package'] != base['package'] or item['version_code'] != base['version_code']:
            raise RuntimeError('Selected members have different package/version')
        if item['signing']['signer_sha256'] != base['signing']['signer_sha256'] or item['signing']['verified_api_range_signer_sha256'] != base['signing']['verified_api_range_signer_sha256']:
            raise RuntimeError('Selected members have different signers')
        for sdk in ('min_sdk', 'target_sdk'):
            if item.get(sdk) is not None and not isinstance(item[sdk], int): raise RuntimeError('Unresolved SDK targeting')
        if api is not None and item.get('min_sdk') is not None and api < item['min_sdk']:
            raise PrerequisiteError('Selected device API is below a member minimum')
    dependencies = {}
    types = set()
    for item in members:
        name = item.get('split') or 'base'; required = list(item.get('uses_split') or [])
        for dep in required:
            if dep in by_name and not by_name[dep].get('isFeatureSplit'): raise RuntimeError('uses-split must reference a feature')
        config_for = item.get('configForSplit')
        if config_for and config_for != 'base' and config_for in by_name and not by_name[config_for].get('isFeatureSplit'):
            raise RuntimeError('Config target is not a feature')
        if item.get('isFeatureSplit') and config_for: raise RuntimeError('Feature cannot be a config split')
        if item.get('configForSplit'): required.append(item['configForSplit'])
        if name != 'base': required.append('base')
        if any(not isinstance(dep, str) or dep not in names or dep == name for dep in required):
            raise RuntimeError('Missing/invalid split dependency: ' + name)
        dependencies[name] = required
        types.update(value for value in (item.get('splitTypes') or '').split(',') if value)
    required_types = {value for item in members for value in (item.get('requiredSplitTypes') or '').split(',') if value}
    if not required_types <= types: raise RuntimeError('Missing required split types: ' + ','.join(sorted(required_types - types)))
    visiting, visited = set(), set()
    def visit(name):
        if name in visiting: raise RuntimeError('Cyclic split dependencies')
        if name in visited: return
        visiting.add(name)
        for dep in dependencies[name]: visit(dep)
        visiting.remove(name); visited.add(name)
    for name in names: visit(name)
    abis = sorted({value for item in members for value in item['abis']})
    supported = [abi] if isinstance(abi, str) else abi
    effective = next((value for value in (supported or []) if value in abis), None)
    if supported is not None and abis and effective is None: raise PrerequisiteError('Selected native APKs do not include a supported device ABI')
    return {'package': base['package'], 'version_code': base['version_code'], 'base': base['apk'],
            'members': [base] + sorted((item for item in members if item is not base), key=lambda item: item['split']),
            'dependencies': dependencies, 'required_split_types': sorted(required_types), 'abis': abis,
            'signer_sha256': base['signing']['signer_sha256'], 'effective_abi': effective, 'selection': 'already-selected-members'}


def inspect_input(input_ref: str, serial: str | None, lock: dict, evidence: Path, *, allow_patched=False, device_spec=None, _target_spec=None) -> dict:
    evidence.mkdir(parents=True)
    path = Path(input_ref)
    if path.is_file() and path.suffix.lower() in (".apks", ".xapk"):
        from .containers import select_container, validate_snapshot, validate_xapk
        container = select_container(path, serial, device_spec, lock, evidence / "container")
        result = inspect_input(container["selected_directory"], serial, lock, evidence / "selected",
                               allow_patched=allow_patched, _target_spec=container["device_spec"])
        validate_xapk(container, result["members"]); validate_snapshot(container)
        result.update(input_ref=input_ref, input_form=container["kind"], container=container)
        write_json(evidence / "inventory.json", result)
        return result
    if device_spec is not None:
        raise ValueError("--device-spec is supported only for .apks/.xapk input")
    api = abi = None; device_abis = None
    provenance = {'installer': None, 'initiating': None, 'originating': None, 'source': 'file-only-unknown'}
    if serial:
        api = int(shell(lock, evidence, 'input-api', serial, ['getprop', 'ro.build.version.sdk']).stdout.strip())
        abi = shell(lock, evidence, 'input-abi', serial, ['getprop', 'ro.product.cpu.abi']).stdout.strip()
        device_abis = shell(lock, evidence, 'input-abilist', serial, ['getprop', 'ro.product.cpu.abilist']).stdout.strip().split(',')
        if not all(device_abis): device_abis = [abi]
    if _target_spec is not None:
        if serial and (api != _target_spec['sdkVersion'] or device_abis != _target_spec['supportedAbis']):
            raise PrerequisiteError('Device spec and current API/ABI changed during selection')
        api = _target_spec['sdkVersion']; device_abis = _target_spec['supportedAbis']; abi = device_abis[0]
    if input_ref.startswith('pkg:'):
        package = input_ref[4:]
        if not serial or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*', package):
            raise ValueError('Device pull needs an explicit serial and valid pkg:name')
        paths = [line[8:] for line in shell(lock, evidence, 'input-paths', serial, ['pm', 'path', package]).stdout.splitlines() if line.startswith('package:')]
        if not paths or len(set(paths)) != len(paths): raise PrerequisiteError('Installed package/member inventory unavailable')
        files = []
        for index, path in enumerate(paths):
            target = evidence / (f'{index:03d}-' + Path(path).name)
            adb(lock, evidence, 'input-pull-' + str(index), ['pull', path, str(target)], serial=serial); files.append(target)
        again = [line[8:] for line in shell(lock, evidence, 'input-paths-after', serial, ['pm', 'path', package]).stdout.splitlines() if line.startswith('package:')]
        if paths != again: raise PrerequisiteError('Installed member inventory changed during pull')
        installer = shell(lock, evidence, 'input-installer', serial, ['pm', 'list', 'packages', '-i', package]).stdout
        match = re.search(r'package:' + re.escape(package) + r'\s+installer=(\S+)', installer)
        provenance.update(installer=match[1] if match and match[1] != 'null' else None, source='pm-list-packages-i',
                          installed_paths=paths, serial=serial, initiating_status='not-run', originating_status='not-run')
    else:
        path = Path(input_ref)
        if path.is_dir(): files = sorted(item for item in path.iterdir() if item.is_file() and item.suffix.lower() == '.apk')
        elif path.is_file() and path.suffix.lower() == '.apk': files = [path]
        else: raise ValueError('Input must be an APK, selected APK directory, or pkg:name')
        if not files: raise ValueError('Selected directory contains no APK members')
    snapshots = []
    for index, path in enumerate(files):
        digest = sha256(path)
        with zipfile.ZipFile(path) as archive: metadata = manifest_metadata(archive.read('AndroidManifest.xml'), lock, evidence / ('manifest-' + str(index)))
        snapshots.append((path, digest, metadata))
    bases = [metadata for path, digest, metadata in snapshots if not metadata.get('split')]
    if len(bases) != 1: raise RuntimeError('Selected set must contain exactly one base APK')
    inherited_min_sdk = bases[0].get('min_sdk') or 1
    if api is not None and api < inherited_min_sdk: raise PrerequisiteError('Selected device API is below the base minimum')
    metadata_api = api if api is not None else max(inherited_min_sdk, lock.get('release_target', {}).get('api') or inherited_min_sdk)
    members = []
    for index, (path, digest, metadata) in enumerate(snapshots):
        member = inspect_apk(path, metadata_api, lock, evidence / ('member-' + str(index)), metadata_hint=metadata,
                             inherited_min_sdk=inherited_min_sdk if metadata.get('split') else None, allow_patched=allow_patched)
        if member['sha256'] != digest: raise PrerequisiteError('APK changed during read-only inventory')
        members.append(member)
    result = validate_selected(members, api, device_abis)
    if input_ref.startswith('pkg:') and result['package'] != input_ref[4:]: raise RuntimeError('Pulled package differs from requested package')
    result.update(input_ref=input_ref, api=api, metadata_api=metadata_api, abi=abi, device_abis=device_abis, provenance=provenance,
                  input_form='installed-selected-set' if input_ref.startswith('pkg:') else 'selected-directory' if len(files) > 1 else 'apk')
    write_json(evidence / 'inventory.json', result)
    return result


def triage(input_ref: str, serial: str | None, lock: dict, evidence: Path, *, allow_patched=False, device_spec=None) -> dict:
    from .patches import dex_tool, extract_dex, find_candidates, inspect_dex
    result = inspect_input(input_ref, serial, lock, evidence / 'input', allow_patched=allow_patched, device_spec=device_spec)
    command = dex_tool(lock, evidence); references = []; pairip = []; definitions = {}; collisions = []
    tls_surfaces = []
    stacks = {'react-native': {'classes': 0, 'native_members': []}, 'flutter': {'classes': 0, 'native_members': []},
              'trustkit': {'classes': 0, 'native_members': []}, 'okhttp': {'classes': 0, 'native_members': []}}
    prefixes = {'react-native': 'Lcom/facebook/react/', 'flutter': 'Lio/flutter/',
                'trustkit': 'Lcom/datatheorem/android/trustkit/', 'okhttp': 'Lokhttp3/'}
    library_prefixes = ('Landroid/', 'Landroidx/', 'Ljava/', 'Ljavax/', 'Lkotlin/', 'Lkotlinx/', 'Lokhttp3/', 'Lokio/',
                        'Lcom/google/', 'Lcom/facebook/', 'Lcom/datatheorem/')
    app_prefix = 'L' + result['package'].replace('.', '/') + '/'
    for index, member in enumerate(result['members']):
        member_id = member.get('split') or 'base'
        for native in member['native_libraries']:
            name = native['entry'].rsplit('/', 1)[-1]
            from .tls_surfaces import runtime_hints
            with zipfile.ZipFile(member['apk']) as native_archive:
                hints = runtime_hints(native_archive.read(native['entry']), native['entry'])
            tls_surfaces.extend({'member':member_id,'entry':native['entry'],'sha256':native['sha256'],**hint} for hint in hints)
            if name in ('libflutter.so', 'libapp.so'): stacks['flutter']['native_members'].append({'member': member_id, **native})
            if name.startswith(('libreactnative', 'libhermes', 'libjscexecutor', 'libjsc')):
                stacks['react-native']['native_members'].append({'member': member_id, **native})
            if name == 'libpairipcore.so': pairip.append({'kind': 'native-member', 'member': member_id, 'entry': native['entry'], 'sha256': native['sha256']})
        if not member['dex']: continue
        part = evidence / ('dex-' + str(index)); part.mkdir()
        directory = part / 'original-dex'; extract_dex(Path(member['apk']), directory, allow_patched=allow_patched)
        inventory = inspect_dex(directory, command, result['metadata_api'] or 30, part)
        write_json(part / 'candidates.json', find_candidates(inventory))
        for descriptor, cls in inventory['classes'].items():
            definitions.setdefault(descriptor, []).append(member_id)
            if descriptor.startswith(('Ldev/repack/shim/', 'Lorg/lsposed/hiddenapibypass/')): collisions.append({'member': member_id, 'class': descriptor})
            if descriptor.startswith('Lcom/pairip/'):
                pairip.append({'kind': 'class-definition', 'member': member_id, 'dex': cls['dex'], 'class': descriptor})
            for name, prefix in prefixes.items():
                if descriptor.startswith(prefix): stacks[name]['classes'] += 1
            for method in cls['methods']:
                if descriptor.startswith(('Ldev/repack/shim/', 'Lorg/lsposed/hiddenapibypass/')): continue
                selected = [ref for ref in method['references'] if
                    ('->getPackageInfo(' in ref or '->hasSigningCertificate(' in ref or '->checkSignatures(' in ref)
                    or ref.startswith(('Landroid/content/pm/PackageInfo;->signatures:', 'Landroid/content/pm/PackageInfo;->signingInfo:'))
                    or ref.startswith('Landroid/content/pm/SigningInfo;->')]
                if not selected: continue
                flags = [value for value in method.get('literals', []) if value in (0x40, 0x08000000, 0x08000040)]
                attribution = 'app-package' if descriptor.startswith(app_prefix) else 'known-library' if descriptor.startswith(library_prefixes) else 'unknown-after-packaging-or-obfuscation'
                references.append({'member': member_id, 'dex': cls['dex'], 'class': descriptor, 'method': method['descriptor'],
                    'references': selected, 'flag_constants': flags, 'attribution': attribution,
                    'nearby_package_name_call': any('->getPackageName()Ljava/lang/String;' in ref for ref in method['references']),
                    'interpretation': 'advisory-reference; no self-check/dataflow/enforcement proof'})
    result['triage'] = {'signing_references': references, 'antitamper_decision': 'explicit-opt-in',
        'native_tls_surfaces': tls_surfaces,
        'pairip': {'markers': pairip, 'enforcement': 'unknown', 'limit': 'L-PAIRIP'},
        'stacks': {name: {**value, 'interpretation': 'bundled-static-evidence; active-path-not-proven'} for name, value in stacks.items()},
        'helper_class_collisions': collisions,
        'cross_member_duplicate_classes': {name: places for name, places in definitions.items() if len(places) > 1}}
    write_json(evidence / 'triage.json', result)
    return result
