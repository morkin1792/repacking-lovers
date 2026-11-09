"""Bounded container selection; bundletool owns APKS targeting, XAPK is explicit-only."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import select
import shutil
import socket
import socketserver
import threading
import zipfile

from .report import unique_object
from .rebuild import ROOT, PrerequisiteError, environment, execute, sha256, tool, write_json


class ContainerUnsupported(ValueError):
    pass


def bundletool() -> tuple[Path, dict]:
    pin = json.loads((ROOT / 'config/bundletool-dependency.json').read_text())
    jar = ROOT / pin['path']
    if not jar.is_file() or sha256(jar) != pin['sha256']:
        raise PrerequisiteError('Pinned bundletool is missing or changed')
    return jar, pin


def validate_spec(value: dict) -> dict:
    if (not isinstance(value, dict) or type(value.get('sdkVersion')) is not int
            or not 21 <= value['sdkVersion'] <= 100
            or type(value.get('screenDensity')) is not int or not 1 <= value['screenDensity'] <= 2000):
        raise ValueError('Device spec requires integer sdkVersion >=21 and screenDensity')
    for field in ('supportedAbis', 'supportedLocales'):
        rows = value.get(field)
        if (not isinstance(rows, list) or not rows or len(rows) > 100
                or any(not isinstance(row, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', row) for row in rows)
                or len(rows) != len(set(rows))):
            raise ValueError('Invalid device spec ' + field)
    return value


@contextmanager
def ddmlib_environment(lock: dict):
    """ddmlib uses localhost; relay only this child to the existing remote ADB server."""
    env = environment(lock)
    address = lock.get('adb_server_socket') or env.get('ADB_SERVER_SOCKET')
    if not address:
        yield env
        return
    match = re.fullmatch(r'tcp:([^:]+):(\d+)', address)
    if not match:
        raise PrerequisiteError('Container device probe requires a TCP ADB server socket')
    destination = (match[1], int(match[2])); stopping = threading.Event()

    class Relay(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                with socket.create_connection(destination, timeout=10) as remote:
                    self.request.settimeout(10)
                    while not stopping.is_set():
                        readable, _, _ = select.select([remote, self.request], [], [], .2)
                        for incoming in readable:
                            data = incoming.recv(65536)
                            if not data: return
                            (self.request if incoming is remote else remote).sendall(data)
            except (OSError, ValueError):
                return

    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True

    with Server(('127.0.0.1', 0), Relay) as server:
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        env['ADB_SERVER_SOCKET'] = 'tcp:127.0.0.1:' + str(port)
        env['ANDROID_ADB_SERVER_PORT'] = str(port)
        try: yield env
        finally:
            stopping.set(); server.shutdown(); thread.join(timeout=2)


def device_spec(serial: str | None, provided: Path | None, lock: dict, evidence: Path) -> tuple[dict, Path, dict]:
    if bool(serial) == bool(provided):
        raise PrerequisiteError('Container selection needs exactly one of --device or --device-spec')
    output = evidence / 'device-spec.json'
    if provided:
        payload = Path(provided).read_bytes()
        if len(payload) > 1024 * 1024: raise ValueError('Device spec is too large')
        value = validate_spec(json.loads(payload, object_pairs_hook=unique_object)); output.write_bytes(payload)
        origin = {'kind': 'operator-supplied-offline', 'path': str(Path(provided).resolve()),
                  'sha256': hashlib.sha256(payload).hexdigest(), 'runtime_claim': 'not-run'}
    else:
        jar, pin = bundletool()
        with ddmlib_environment(lock) as env:
            execute([tool(lock, 'java'), '-jar', str(jar), 'get-device-spec', '--adb=' + tool(lock, 'adb'),
                     '--device-id=' + serial, '--output=' + str(output)], evidence, 'device-spec', env=env, timeout=60)
        value = validate_spec(json.loads(output.read_text()))
        origin = {'kind': 'connected-device', 'serial': serial, 'bundletool_sha256': pin['sha256']}
    return value, output, origin


def archive_inventory(archive: zipfile.ZipFile) -> list[dict]:
    infos = archive.infolist(); seen = set(); total = 0; rows = []
    if not infos or len(infos) > 20000: raise ValueError('Container entry count exceeds supported bounds')
    for item in infos:
        name = item.filename; path = PurePosixPath(name)
        if (not name or '\\' in name or '\x00' in name or path.is_absolute()
                or any(part in ('', '.', '..') for part in name.rstrip('/').split('/'))
                or ':' in name or name in seen or (item.external_attr >> 16) & 0o170000 == 0o120000):
            raise ValueError('Unsafe or duplicate container entry: ' + repr(name))
        if item.flag_bits & 1: raise ContainerUnsupported('Encrypted containers are unsupported')
        seen.add(name); total += item.file_size
        if item.file_size > 1024**3 or total > 2 * 1024**3:
            raise ContainerUnsupported('Container expanded size exceeds 2 GiB / 1 GiB per member')
        digest = None
        if not item.is_dir():
            hasher = hashlib.sha256()
            with archive.open(item) as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b''): hasher.update(block)
            digest = hasher.hexdigest()
        rows.append({'path': name, 'size': item.file_size, 'sha256': digest})
    return rows


def select_container(path: Path, serial: str | None, provided: Path | None, lock: dict, evidence: Path) -> dict:
    evidence.mkdir(parents=True)
    if path.stat().st_size > 2 * 1024**3: raise ContainerUnsupported('Container exceeds 2 GiB')
    before = sha256(path); snapshot = evidence / ('input' + path.suffix.lower())
    shutil.copyfile(path, snapshot)
    if sha256(snapshot) != before or sha256(path) != before:
        raise PrerequisiteError('Container changed while snapshotting')
    with zipfile.ZipFile(snapshot) as archive:
        inventory = archive_inventory(archive); by_name = {row['path']: row for row in inventory}
        if any(row['path'].lower().endswith('.obb') or row['path'].startswith(('asset-slices/', 'assetpacks/')) for row in inventory):
            raise ContainerUnsupported('Expansion files and Play asset packs require an unsupported delivery path')
        spec, spec_path, provenance = device_spec(serial, provided, lock, evidence)
        selected = evidence / 'selected'; selected.mkdir()
        metadata = None; pin = None
        if path.suffix.lower() == '.apks':
            if 'toc.pb' not in by_name: raise ValueError('APKS container lacks toc.pb')
            jar, pin = bundletool(); extracted = evidence / 'bundletool-selected'
            execute([tool(lock, 'java'), '-jar', str(jar), 'extract-apks', '--apks=' + str(snapshot),
                     '--device-spec=' + str(spec_path), '--output-dir=' + str(extracted)],
                    evidence, 'extract-apks', env=environment(lock), timeout=120)
            available = [row for row in inventory if row['path'].lower().endswith('.apk')]
            choices = []
            for file in sorted(extracted.rglob('*.apk')):
                digest = sha256(file); matches = [row for row in available if row['sha256'] == digest]
                if len(matches) != 1: raise ValueError('Selected APK cannot be uniquely joined to the archive inventory')
                choices.append(matches[0]['path'])
        else:
            if 'manifest.json' not in by_name: raise ContainerUnsupported('XAPK requires explicit version-2 manifest.json metadata')
            if by_name['manifest.json']['size'] > 1024 * 1024: raise ValueError('XAPK metadata is too large')
            metadata = json.loads(archive.read('manifest.json'), object_pairs_hook=unique_object)
            if metadata.get('xapk_version') != 2: raise ContainerUnsupported('Only version-2 XAPK metadata is supported')
            if metadata.get('expansions'): raise ContainerUnsupported('XAPK expansion delivery is unsupported')
            rows = metadata.get('split_apks')
            if not isinstance(rows, list) or not rows or any(not isinstance(row, dict) or not isinstance(row.get('file'), str) or not isinstance(row.get('id'), str) for row in rows):
                raise ValueError('XAPK split_apks must explicitly list file and split id')
            choices = [row['file'] for row in rows]
            if set(choices) != {row['path'] for row in inventory if row['path'].lower().endswith('.apk')}:
                raise ContainerUnsupported('XAPK must describe one complete selected set; unlisted or missing APKs are unsupported')
        if not choices or len(choices) != len(set(choices)): raise ValueError('Empty or duplicate selected APK members')
        picked = []
        for index, name in enumerate(choices):
            if name not in by_name or not name.endswith('.apk'): raise ValueError('Invalid selected APK member')
            target = selected / (str(index).zfill(3) + '.apk')
            with archive.open(name) as source, target.open('xb') as output: shutil.copyfileobj(source, output)
            if sha256(target) != by_name[name]['sha256']: raise RuntimeError('Container member changed during extraction')
            picked.append({**by_name[name], 'apk': str(target.resolve())})
    result = {'kind': path.suffix.lower()[1:], 'original': str(path.resolve()), 'sha256': before,
              'inventory': inventory, 'selected': picked, 'selected_directory': str(selected),
              'device_spec': spec, 'targeting': provenance, 'xapk_metadata': metadata,
              'bundletool': pin, 'selection': 'bundletool-install-time' if pin else 'explicit-selected-xapk-only'}
    validate_snapshot(result)
    write_json(evidence / 'container.json', result)
    return result


def validate_snapshot(container: dict) -> None:
    if sha256(Path(container['original'])) != container['sha256']:
        raise PrerequisiteError('Original container changed during processing')
    if container.get('bundletool') and bundletool()[1] != container['bundletool']:
        raise PrerequisiteError('Bundletool dependency pin changed during processing')
    targeting = container['targeting']
    if targeting['kind'] == 'operator-supplied-offline' and sha256(Path(targeting['path'])) != targeting['sha256']:
        raise PrerequisiteError('Offline device spec changed during processing')


def validate_xapk(container: dict, members: list[dict]) -> None:
    metadata = container['xapk_metadata']
    if metadata is None: return
    base = next(row for row in members if not row.get('split'))
    if metadata.get('package_name') != base['package'] or str(metadata.get('version_code')) != str(base['version_code']):
        raise ValueError('XAPK package/version metadata conflicts with signed APK manifests')
    declared = {row['file']: row['id'] for row in metadata['split_apks']}
    for selected, actual in zip(container['selected'], members):
        if declared[selected['path']] != (actual.get('split') or 'base'):
            raise ValueError('XAPK split id conflicts with signed APK manifest')
    abis = {abi for row in members for abi in row['abis']}
    if len(abis) > 1: raise ContainerUnsupported('Multi-ABI XAPK targeting is ambiguous; supply a selected set')
    densities = {match[1] for row in members if (match := re.search(r'(?:^|[._])(ldpi|mdpi|tvdpi|hdpi|xhdpi|xxhdpi|xxxhdpi)(?:$|[._])', row.get('split') or ''))}
    if len(densities) > 1: raise ContainerUnsupported('Multi-density XAPK targeting is ambiguous; supply a selected set')
