"""Explicit third-party reFlutter replacement for one measured original engine."""
import hashlib
import json
import struct
from .rebuild import ROOT, PrerequisiteError, sha256
from .recon import elf_loads


class NativeTlsUnsupported(ValueError):
    pass


def dependencies():
    path = ROOT / 'config/flutter-dependency.json'; pin = json.loads(path.read_text())
    for row in (pin['replacement'], pin['upstream_license'], *pin['source_contracts']):
        file = ROOT / row['path']
        if not file.is_file() or sha256(file) != row['sha256']:
            raise PrerequisiteError('Pinned reFlutter input missing/changed: ' + row['path'])
    return pin


def aot_snapshots(data: bytes, expected: str):
    if len(data) < 64 or data[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', data, 18)[0] != 183:
        raise NativeTlsUnsupported('AOT snapshot requires a little-endian ARM64 ELF')
    phoff, shoff = struct.unpack_from('<QQ', data, 32)
    phsize, phcount, shsize, shcount = struct.unpack_from('<HHHH', data, 54)
    if (phsize != 56 or shsize != 64 or not phcount or not shcount
            or phoff + phcount * phsize > len(data) or shoff + shcount * shsize > len(data)):
        raise NativeTlsUnsupported('AOT ELF tables are truncated or unsupported')
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * shsize) for i in range(shcount)]
    segments = [struct.unpack_from('<IIQQQQQQ', data, phoff + i * phsize) for i in range(phcount)]
    wanted = {'_kDartVmSnapshotData', '_kDartIsolateSnapshotData'}; found = {}
    for section in sections:
        if section[1] != 11: continue
        if section[6] >= len(sections) or section[9] != 24 or section[5] % 24:
            raise NativeTlsUnsupported('AOT dynamic symbol table is unsupported')
        strings = sections[section[6]]
        if strings[4] + strings[5] > len(data) or section[4] + section[5] > len(data):
            raise NativeTlsUnsupported('AOT symbols or strings are truncated')
        names = data[strings[4]:strings[4] + strings[5]]
        for offset in range(section[4], section[4] + section[5], 24):
            name_index, info, _, index, value, size = struct.unpack_from('<IBBHQQ', data, offset)
            if name_index >= len(names): raise NativeTlsUnsupported('AOT symbol name is out of bounds')
            name = names[name_index:].split(b'\0', 1)[0].decode('ascii', errors='replace')
            if name not in wanted: continue
            positions = [p[2] + value - p[3] for p in segments if p[0] == 1 and p[3] <= value and value + 52 <= p[3] + p[5]]
            if name in found or not index or info & 15 != 1 or size < 52 or len(positions) != 1:
                raise NativeTlsUnsupported('AOT snapshot symbols are absent or ambiguous')
            position = positions[0]
            header = data[position:position + 52]
            if (len(header) != 52 or header[:4] != b'\xf5\xf5\xdc\xdc'
                    or struct.unpack_from('<Q', header, 12)[0] != 3 or header[20:] != expected.encode('ascii')):
                raise NativeTlsUnsupported('AOT snapshot header/hash differs from the pinned full-AOT format')
            found[name] = {'file_offset': position, 'size': size, 'snapshot_hash': expected}
    if set(found) != wanted: raise NativeTlsUnsupported('AOT snapshot data symbols are missing')
    return found


def patch_engine(original: bytes, abi: str, libapp: bytes, *, function='ssl_crypto_x509_session_verify_cert_chain'):
    pin = dependencies()
    if function != 'ssl_crypto_x509_session_verify_cert_chain':
        raise NativeTlsUnsupported('Only the pinned boolean chain-verification contract is supported')
    if abi != pin['abi'] or hashlib.sha256(original).hexdigest() != pin['original_engine_sha256']:
        raise NativeTlsUnsupported('Unknown Flutter engine hash/ABI; no replacement selected')
    snapshots = aot_snapshots(libapp, pin['snapshot_hash'])
    old_elf = elf_loads(original)
    data = (ROOT / pin['replacement']['path']).read_bytes(); new_elf = elf_loads(data)
    if (old_elf['machine'], old_elf['bits']) != (183, 64) or (new_elf['machine'], new_elf['bits']) != (183, 64):
        raise NativeTlsUnsupported('Pinned native ELF machine differs')
    edit = pin['route_edit']; old = edit['old_ascii'].encode('ascii'); new = edit['new_ascii'].encode('ascii')
    if len(old) != len(new) or data.count(old) != edit['required_matches']:
        raise NativeTlsUnsupported('Fixed loopback route marker is absent or ambiguous')
    edited = data.replace(old, new)
    changes = [index for index, (left, right) in enumerate(zip(data, edited)) if left != right]
    return edited, {'mode': pin['mode'], 'engine_revision': pin['engine_revision'], 'abi': abi,
        'original_sha256': hashlib.sha256(original).hexdigest(), 'released_replacement_sha256': pin['replacement']['sha256'],
        'patched_sha256': hashlib.sha256(edited).hexdigest(), 'snapshot_hash': pin['snapshot_hash'], 'aot_snapshots': snapshots,
        'function_contract': {'function': function, 'return_type': 'bool', 'accept': True,
                              'scope': 'upstream boolean contract; measured whole-engine TLS evidence is separate'},
        'route': pin['endpoint'], 'route_edit_offsets': changes, 'replacement_elf': new_elf,
        'license': 'reFlutter GPL-3.0; Flutter/BoringSSL upstream notices also apply',
        'limitations': pin['limits'], 'runtime_verification': 'not-run'}


def plan(source: dict, mode: str):
    import zipfile
    if mode == 'offline-arm64':
        return offline_plan(source)
    if mode != 'reflutter-3.10.6-arm64': raise NativeTlsUnsupported('Unknown native TLS mode')
    pin = dependencies()
    if source['metadata_api'] != pin['runtime_api'] or source.get('effective_abi') != pin['abi']:
        raise NativeTlsUnsupported('Native TLS mode requires the measured API30/ARM64 target')
    found = {}
    for member in source['members']:
        with zipfile.ZipFile(member['apk']) as archive:
            for name in ('libflutter.so', 'libapp.so'):
                entry = 'lib/' + pin['abi'] + '/' + name
                if entry in archive.namelist():
                    if name in found: raise NativeTlsUnsupported('Native TLS engine/AOT member is ambiguous')
                    found[name] = {'member': member.get('split') or 'base', 'entry': entry, 'data': archive.read(entry)}
    if set(found) != {'libflutter.so', 'libapp.so'}: raise NativeTlsUnsupported('Native TLS engine or AOT member is missing')
    output, transform = patch_engine(found['libflutter.so']['data'], pin['abi'], found['libapp.so']['data'])
    transform.update(member=found['libflutter.so']['member'], entry=found['libflutter.so']['entry'],
        input_aot_sha256=hashlib.sha256(found['libapp.so']['data']).hexdigest(),
        dependency_pin_sha256=sha256(ROOT / 'config/flutter-dependency.json'))
    return output, transform


def offline_plan(source):
    import zipfile
    from .elf_tls import patch_library, ElfTlsUnsupported
    if source.get('effective_abi') != 'arm64-v8a':
        raise NativeTlsUnsupported('Offline native TLS requires an existing selected ARM64 ABI')
    replacements = {}; libraries = []; skipped = []
    for member in source['members']:
        member_id = member.get('split') or 'base'
        with zipfile.ZipFile(member['apk']) as archive:
            for native in member['native_libraries']:
                if native['abi'] != 'arm64-v8a': continue
                entry = native['entry']; data = archive.read(entry)
                signals = [s for s in (b'ssl_client\0', b'SSL_CTX_set_verify\0', b'SSL_set_custom_verify\0',
                                       b'SSL_CTX_set_custom_verify\0', b'X509_verify_cert\0', b'SSL_get_verify_result\0') if s in data]
                if not signals: continue
                try: output, transform = patch_library(data, entry.rsplit('/', 1)[-1])
                except ElfTlsUnsupported as error:
                    skipped.append({'member': member_id, 'entry': entry, 'input_sha256': hashlib.sha256(data).hexdigest(),
                                    'status': 'unsupported', 'reason': str(error)})
                    continue
                key = (member_id, entry)
                if key in replacements: raise NativeTlsUnsupported('Duplicate native member/entry')
                replacements[key] = output; libraries.append({**transform, 'member': member_id, 'entry': entry})
    if not libraries: raise NativeTlsUnsupported('No supported offline native TLS implementation; no native bytes changed')
    return replacements, {'mode': 'offline-arm64', 'abi': 'arm64-v8a', 'libraries': libraries, 'unsupported': skipped,
        'runtime_verification': 'not-run', 'scope': 'App-owned ARM64 TLS exports and bounded BoringSSL table verifier; no native routing or external/system patch'}
