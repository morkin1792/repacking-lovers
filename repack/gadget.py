"""Explicit script-mode Gadget for the owned raw-APK syscall fixture only."""
import hashlib
import json
import zipfile
from .rebuild import ROOT, PrerequisiteError, sha256
from .report import canonical


class GadgetUnsupported(ValueError):
    pass


def dependencies():
    pin = json.loads((ROOT / 'config/gadget-dependency.json').read_text())
    for key in ('library', 'license', 'script'):
        row = pin[key]; path = ROOT / row['path']
        if not path.is_file() or sha256(path) != row['sha256']:
            raise PrerequisiteError('Pinned Gadget input missing/changed: ' + row['path'])
    return pin


def plan(source, mode):
    if mode != 'raw-apk-fixture': raise GadgetUnsupported('Unknown Gadget mode')
    if source['package'] != 'dev.repack.fixture.identity' or source['api'] != 30 or source['effective_abi'] != 'arm64-v8a':
        raise GadgetUnsupported('Gadget mode is measured only for the owned API30 ARM64 raw-APK fixture')
    pin = dependencies(); found = []
    for member in source['members']:
        with zipfile.ZipFile(member['apk']) as archive:
            name = 'lib/arm64-v8a/' + pin['fixture_library']['name']
            if name in archive.namelist(): found.append(hashlib.sha256(archive.read(name)).hexdigest())
    if found != [pin['fixture_library']['sha256']]: raise GadgetUnsupported('Owned Gadget fixture native library is absent/ambiguous/changed')
    library = (ROOT / pin['library']['path']).read_bytes(); script = (ROOT / pin['script']['path']).read_bytes()
    config = {'version': pin['version'], 'library_sha256': pin['library']['sha256'], 'script_sha256': pin['script']['sha256']}
    additions = {'assets/repack/gadget/librepack_gadget.so': library, 'assets/repack/gadget/hook.js': script,
        'assets/repack/gadget/config.json': canonical(config), 'assets/repack/gadget/COPYING': (ROOT / pin['license']['path']).read_bytes()}
    transform = {'mode': mode, **config, 'interaction': 'script', 'listener': False, 'preload': pin['fixture_library']['name'],
        'fixture_library_sha256': pin['fixture_library']['sha256'], 'dependency_pin_sha256': sha256(ROOT / 'config/gadget-dependency.json'),
        'runtime_verification': 'not-run', 'limitations': ['owned-fixture-only', 'detectable-in-maps', 'isolated/other-processes-unmeasured',
            'other-API/ABI/page-cells-unsupported', 'no-generic-RASP-guarantee', 'module-observer-crashes-on-this-cell']}
    return additions, transform
