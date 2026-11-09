"""Opt-in, named-caller native base-byte reads on the measured API30 ARM cells."""
import json
from pathlib import Path
import re
import zipfile

from .rebuild import ROOT, PrerequisiteError, execute, sha256, write_json
from .recon import elf_loads


class IntegrityUnsupported(ValueError):
    pass


OPEN_IMPORTS = {'open', 'open64', '__open_2', 'openat', 'openat64', '__openat_2', 'fopen', 'fopen64'}
RESERVED = {'libc.so', 'libdl.so', 'libart.so', 'libandroidfw.so', 'libopenjdk.so', 'libziparchive.so',
            'libbytehook.so', 'libshadowhook.so', 'libshadowhook_nothing.so', 'librepack_integrity.so'}


def callers(value):
    if not isinstance(value, str) or not value.startswith('native-base-bytes:'):
        raise ValueError('--integrity requires native-base-bytes:libCaller.so[,libOther.so]')
    names = value[len('native-base-bytes:'):].split(',')
    if not 1 <= len(names) <= 2 or len(set(names)) != len(names) or any(
            len(name) > 128 or not re.fullmatch(r'lib[A-Za-z0-9_.-]+\.so', name) for name in names):
        raise ValueError('Native integrity requires one or two distinct literal library basenames')
    if set(names) & RESERVED: raise IntegrityUnsupported('Platform, backend and helper libraries cannot be selected as integrity callers')
    return sorted(names)


def dependencies():
    pin = json.loads((ROOT / 'config/bytehook-dependency.json').read_text())
    for item in pin['artifacts']:
        path = ROOT / item['path']
        if not path.is_file() or sha256(path) != item['sha256']: raise PrerequisiteError('Pinned native dependency missing/changed: ' + item['path'])
    ndk = json.loads((ROOT / 'config/ndk-dependency.json').read_text())
    for item in [*ndk['tools'].values(), *ndk['inputs']]:
        path = ROOT / item['path']
        if not path.is_file() or sha256(path) != item['sha256']: raise PrerequisiteError('Pinned NDK input missing/changed: ' + item['path'])
    return pin, ndk


def plan(source, selection, device, evidence):
    names = callers(selection)
    if not device: raise PrerequisiteError('--integrity requires --device for the tested API/ABI selection')
    if source['metadata_api'] != 30: raise IntegrityUnsupported('Native base-byte mapping is accepted only on API30')
    abi = source.get('effective_abi')
    if abi not in ('arm64-v8a', 'armeabi-v7a'): raise IntegrityUnsupported('Native integrity needs an existing tested ARM ABI; no ABI is added')
    base = next(item for item in source['members'] if not item.get('split'))
    if Path(base['apk']).stat().st_size > 1073741824: raise IntegrityUnsupported('Native original storage is limited to one GiB per base APK')
    pin, ndk = dependencies(); evidence.mkdir(parents=True)
    reader = str(ROOT / ndk['tools']['llvm-readelf']['path']); chosen = []; entries = []
    for name in names:
        matches = [(member, native) for member in source['members'] for native in member['native_libraries']
                   if native['abi'] == abi and native['entry'].rsplit('/', 1)[-1] == name]
        if len(matches) != 1: raise IntegrityUnsupported('Native integrity caller is absent or ambiguous: ' + name)
        member, native = matches[0]
        if member.get('isFeatureSplit') or member.get('configForSplit') not in (None, 'base'):
            raise IntegrityUnsupported('Isolated feature-library namespaces are not accepted integrity callers')
        path = evidence / name
        with zipfile.ZipFile(member['apk']) as archive: path.write_bytes(archive.read(native['entry']))
        if sha256(path) != native['sha256']: raise PrerequisiteError('Caller changed during native planning')
        table = execute([reader, '--dyn-symbols', '--wide', str(path)], evidence, name + '-imports').stdout
        imported = sorted({item.split('@')[0] for item in re.findall(r'\bUND\s+(\S+)', table)})
        if not OPEN_IMPORTS.intersection(imported): raise IntegrityUnsupported('Selected caller has no supported file-opening imports: ' + name)
        chosen.append(member.get('split') or 'base')
        entries.append({'library': name, 'member': member.get('split') or 'base', 'sha256': native['sha256'], 'imports': imported})
    collisions = [native['entry'] for member in source['members'] for native in member['native_libraries']
                  if native['abi'] == abi and native['entry'].rsplit('/', 1)[-1] in
                  {'libbytehook.so', 'libshadowhook.so', 'libshadowhook_nothing.so', 'librepack_integrity.so'}]
    if collisions: raise IntegrityUnsupported('Existing native backend/helper names conflict with isolated injection')
    result = {'mode': 'native-base-bytes', 'callers': names, 'abi': abi, 'member': chosen[0], 'caller_inventory': entries,
        'dependency_pin_sha256': sha256(ROOT / 'config/bytehook-dependency.json'), 'ndk_pin_sha256': sha256(ROOT / 'config/ndk-dependency.json'),
        'input_base_sha256': base['sha256'], 'bytehook_version': pin['bytehook_version'], 'shadowhook_version': pin['shadowhook_version'],
        'scope': 'Absolute read-only base APK opens in explicitly named native import callers; source/data paths supplied before original factory construction',
        'limitations': ['raw-syscalls', 'dlsym-pointers', 'preopened-descriptors', 'relative-dirfd-paths',
            'proc-fd-path-disclosure', 'unmeasured-metadata-fields', 'mixed-integrity/runtime-reads-in-the-same-caller',
            'unselected-callers', 'split-original-redirects', 'isolated-process-storage', 'unvalidated-classloader-namespaces',
            'other-API/ABI/page-size-cells']}
    write_json(evidence / 'plan.json', result); return result


def build(spec, evidence):
    pin, ndk = dependencies(); evidence.mkdir(parents=True)
    abi = spec['abi']; triple = {'arm64-v8a': 'aarch64-linux-android', 'armeabi-v7a': 'armv7a-linux-androideabi'}[abi]
    by_name = {Path(item['path']).name: ROOT / item['path'] for item in pin['artifacts']}
    directory = evidence / 'libraries'; directory.mkdir()
    with zipfile.ZipFile(by_name['bytehook-1.1.2.aar']) as archive:
        (evidence / 'bytehook.h').write_bytes(archive.read('prefab/modules/bytehook/include/bytehook.h'))
        (directory / 'libbytehook.so').write_bytes(archive.read('jni/' + abi + '/libbytehook.so'))
    with zipfile.ZipFile(by_name['shadowhook-2.0.1.aar']) as archive:
        (evidence / 'shadowhook.h').write_bytes(archive.read('prefab/modules/shadowhook/include/shadowhook.h'))
        for name in ('libshadowhook.so', 'libshadowhook_nothing.so'):
            (directory / name).write_bytes(archive.read('jni/' + abi + '/' + name))
    out = directory / 'librepack_integrity.so'; compiler = str(ROOT / ndk['tools']['clang']['path'])
    execute([compiler, '--target=' + triple + '28', '-shared', '-fPIC', '-O2', '-Wall', '-Wextra', '-Werror',
        '-Wl,-soname,librepack_integrity.so', '-Wl,-z,max-page-size=16384', '-Wl,-z,common-page-size=16384', '-Wl,--no-undefined',
        '-I', str(evidence), '-I', str(ROOT / 'native/core'), str(ROOT / 'native/core/persistent.c'),
        '-L', str(directory), '-lbytehook', '-lshadowhook', '-ldl', '-o', str(out)], evidence, 'native-module-compile')
    additions = {}; libraries = []
    for path in sorted(directory.glob('*.so')):
        metadata = elf_loads(path.read_bytes())
        if metadata['bits'] != (64 if abi == 'arm64-v8a' else 32): raise RuntimeError('Native module ELF bitness mismatch')
        if abi == 'arm64-v8a' and not metadata['compatible_16k']: raise RuntimeError('Native ARM64 module/dependency lacks 16KB ELF compatibility')
        additions['lib/' + abi + '/' + path.name] = path.read_bytes()
        libraries.append({'name': path.name, 'sha256': sha256(path), 'elf': metadata})
    notices = {'assets/repack/native/LICENSE.ByteHook': by_name['LICENSE'].read_bytes(),
               'assets/repack/native/LICENSE.ShadowHook': by_name['ShadowHook-LICENSE'].read_bytes()}
    report = {'abi': abi, 'libraries': libraries, 'source_files': [
        {'path': str(path.relative_to(ROOT)), 'sha256': sha256(path)} for path in sorted((ROOT / 'native/core').iterdir()) if path.is_file()],
        'dependencies': pin, 'ndk_pin_sha256': sha256(ROOT / 'config/ndk-dependency.json')}
    write_json(evidence / 'build.json', report); return additions, notices, report
