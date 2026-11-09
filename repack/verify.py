"""Fixture-scoped device preflight and install actions, shared by the active gates."""
from pathlib import Path
from contextlib import contextmanager
import socket
import hashlib
import json
import sys
import subprocess
import time
import re
import shlex
import struct
import zipfile

from .rebuild import PrerequisiteError, badging, environment, execute, sha256, signer_digests, tool, write_json

FIXTURE_PACKAGES = {'dev.repack.fixture.identity', 'dev.repack.fixture.other'}


@contextmanager
def capture_startup(lock: dict, serial: str, evidence: Path, label: str):
    """Retain the full live log stream before large startup probes rotate logd's ring."""
    evidence.chmod(0o700)
    timestamp = shell(lock, evidence, label + '-time', serial, ['date', '+%m-%d %H:%M:%S.000']).stdout.strip()
    path = evidence / (label + '-full.log')
    command = [tool(lock, 'adb'), '-s', serial, 'logcat', '-v', 'threadtime', '-T', timestamp]
    with path.open('w') as output, (evidence / (label + '-stderr.log')).open('w') as error:
        path.chmod(0o600)
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output, stderr=error,
                                   env=environment(lock), start_new_session=True)
        def guard(suffix):
            marker = evidence.name + '-' + label + '-' + suffix
            shell(lock, evidence, label + '-guard-' + suffix, serial, ['log', '-t', 'REPACK_RUNNER', marker])
            for _ in range(30):
                if marker in path.read_text(errors='replace'): return
                if process.poll() is not None: break
                time.sleep(0.1)
            raise RuntimeError('Live log capture did not observe its guard: ' + marker)
        try:
            guard('start')
            yield path
            guard('end')
        finally:
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=3)
            write_json(evidence / (label + '-capture.json'), {'argv': command, 'owned_client_pid': process.pid,
                       'exit_status': process.returncode, 'full_log': str(path), 'server_stop_requested': False})


def reverse_service(lock: dict, serial: str, service: str, evidence: Path, label: str) -> str:
    """ADB smart-socket request; preserve explicit destination rejected by CLI's port check."""
    server = environment(lock).get('ADB_SERVER_SOCKET', 'tcp:localhost:5037')
    match = re.fullmatch(r'tcp:([^:]+):([0-9]+)', server)
    if not match:
        raise PrerequisiteError('Explicit TCP ADB server required for reverse lifecycle')
    def exact(connection, size):
        data = b''
        while len(data) < size:
            chunk = connection.recv(size - len(data))
            if not chunk:
                raise RuntimeError('ADB smart socket closed early')
            data += chunk
        return data
    def status(connection):
        value = exact(connection, 4)
        if value == b'FAIL':
            raise RuntimeError(exact(connection, int(exact(connection, 4), 16)).decode())
        if value != b'OKAY':
            raise RuntimeError('Invalid ADB response ' + repr(value))
    requests = ['host:transport:' + serial, 'reverse:' + service]
    record = {'server': server, 'requests': requests, 'verification': 'not-run'}
    try:
        with socket.create_connection((match[1], int(match[2])), timeout=8) as connection:
            for request in requests:
                data = request.encode()
                connection.sendall(f'{len(data):04x}'.encode() + data)
                status(connection)
            status(connection)  # reverse service's own operation result
            response = b''
            if service.startswith('forward:'):
                response = exact(connection, int(exact(connection, 4), 16))
        record.update(verification='passed', response=response.decode())
        return response.decode()
    except Exception as error:
        record.update(verification='failed', error_class=type(error).__name__, error=str(error))
        raise
    finally:
        write_json(evidence / (label + '-smart-socket.json'), record)


@contextmanager
def owned_reverse(lock: dict, serial: str, device_port: int, host: str, host_port: int,
                  evidence: Path, label: str, mutations: list, cleanup: list):
    # Keep the phone listener on loopback. The ADB server may be outside the workspace.
    source = 'tcp:' + str(device_port)
    destination = 'tcp:' + host + ':' + str(host_port)
    before = adb(lock, evidence, label + '-before', ['reverse', '--list'], serial=serial).stdout
    if any(len(parts := line.split()) == 3 and parts[1] == source for line in before.splitlines()):
        raise PrerequisiteError('Existing reverse mapping owns ' + source)
    reverse_service(lock, serial, 'forward:norebind:tcp:localhost:' + str(device_port) + ';' + destination,
                    evidence, label + '-create')
    mutations.append({'action': 'reverse-create', 'serial': serial, 'source': source,
                      'destination': destination, 'listener': '127.0.0.1', 'owned': True})
    try:
        listeners = shell(lock, evidence, label + '-listeners', serial, ['ss', '-ltn'], check=False).stdout
        if not any('127.0.0.1:' + str(device_port) in line.split() for line in listeners.splitlines()):
            raise RuntimeError('Owned reverse listener not observed on phone loopback')
        yield
    finally:
        original_error = sys.exc_info()[1]
        try:
            current = adb(lock, evidence, label + '-cleanup-list', ['reverse', '--list'], serial=serial).stdout
            rows = [line.split() for line in current.splitlines()]
            if any(len(row) == 3 and row[1:] == [source, destination] for row in rows):
                reverse_service(lock, serial, 'killforward:' + source, evidence, label + '-remove')
                after = adb(lock, evidence, label + '-after', ['reverse', '--list'], serial=serial).stdout
                remaining = [line.split() for line in after.splitlines()]
                if any(len(row) == 3 and row[1] == source for row in remaining):
                    raise RuntimeError('Owned reverse mapping remains after cleanup')
                prior = {tuple(line.split()) for line in before.splitlines()}
                if not prior.issubset({tuple(row) for row in remaining}):
                    raise RuntimeError('Unrelated reverse mapping changed during test')
                cleanup.append({'action': 'reverse-remove', 'source': source, 'verification': 'passed',
                                'unrelated_mappings_preserved': True})
            else:
                cleanup.append({'action': 'reverse-remove', 'source': source, 'verification': 'skipped',
                                'reason': 'Mapping no longer matches this run; unrelated mappings preserved'})
        except Exception as cleanup_error:
            cleanup.append({'action': 'reverse-remove', 'source': source, 'destination': destination,
                            'serial': serial, 'verification': 'inconclusive', 'pending': True,
                            'error_class': type(cleanup_error).__name__, 'error': str(cleanup_error)})
            if original_error is None: raise


def adb(lock: dict, evidence: Path, label: str, args: list[str], *, serial=None, check=True, timeout=120):
    command = [tool(lock, 'adb')] + (['-s', serial] if serial else []) + args
    completed = execute(command, evidence, label, env=environment(lock), check=False, timeout=timeout)
    if check and completed.returncode:
        message = completed.stdout + '\n' + completed.stderr
        if re.search(r'cannot connect to daemon|cannot start server on remote host|error: device .*(?:not found|offline|unauthorized)|error: no devices/emulators found', message):
            raise PrerequisiteError('Configured ADB device/server unavailable; see ' + str(evidence / (label + '.stderr.log')))
        raise RuntimeError(f'{label} exited {completed.returncode}; see {evidence / (label + ".stderr.log")}')
    return completed


def shell(lock: dict, evidence: Path, label: str, serial: str, args: list[str], check=True, timeout=120):
    return adb(lock, evidence, label, ['shell', shlex.join(args)], serial=serial, check=check, timeout=timeout)


def uid_packages(output: str, expected_uid: int) -> list[str]:
    """Android may append uid:N to --uid results even without the -U flag."""
    packages = []
    for line in output.splitlines():
        if not line.startswith('package:'): continue
        match = re.fullmatch(r'package:([A-Za-z_][A-Za-z0-9_.]*)(?:\s+uid:(\d+))?', line.strip())
        if not match or (match[2] is not None and int(match[2]) != int(expected_uid)):
            raise PrerequisiteError('Shared/unknown UID inventory format or UID mismatch')
        packages.append(match[1])
    return packages


def artifact_members(artifact: dict) -> list[dict]:
    members = artifact.get('members')
    if members is None: return [artifact]
    if not isinstance(members, list) or not members: raise RuntimeError('Artifact has no selected members')
    return members


def artifact_fingerprint(artifact: dict) -> str:
    if 'members' not in artifact: return artifact['sha256']
    values = sorted(({'split': item.get('split'), 'sha256': item['sha256']} for item in artifact_members(artifact)),
                    key=lambda item: item['split'] or '')
    content = {'package': artifact['package'], 'version_code': artifact['version_code'], 'members': values}
    return hashlib.sha256(json.dumps(content, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def preflight(artifact: dict, serial: str, replace_existing: bool, lock: dict,
              evidence: Path, label: str, *, requested_package: str | None = None) -> dict:
    package = artifact['package']
    if requested_package is not None and requested_package != package: raise ValueError('Requested package differs from artifact')
    if package not in FIXTURE_PACKAGES and requested_package != package:
        raise PrerequisiteError('Only inventoried fixture packages may be installed by these gates')
    members = artifact_members(artifact)
    bases = [item for item in members if not item.get('split')]
    if len(bases) != 1: raise RuntimeError('Artifact has no unique base')
    base = bases[0]
    if any(sha256(Path(item['apk'])) != item['sha256'] for item in members): raise RuntimeError('Artifact member hash changed before preflight')
    api = int(shell(lock, evidence, label + '-api', serial, ['getprop', 'ro.build.version.sdk']).stdout.strip())
    base_metadata, text = badging(Path(base['apk']), lock, evidence, label + '-base-badging')
    match = re.search(r"targetSdkVersion:'(\d+)'", text)
    target = int(match[1]) if match else 1
    minimum = re.search(r"(?:minSdkVersion|sdkVersion):'(\d+)'", text)
    inherited_minimum = int(minimum[1]) if minimum else 1
    if artifact['version_code'] != base_metadata['version_code']: raise RuntimeError('Artifact version differs from actual base')
    signatures = artifact['signer_sha256']
    for index, member in enumerate(members):
        apk = Path(member['apk'])
        if sha256(apk) != member['sha256']: raise RuntimeError('Artifact member hash changed before preflight')
        metadata, _ = badging(apk, lock, evidence, label + '-member-' + str(index))
        verified = signer_digests(apk, lock, evidence, label + '-signers-' + str(index), api=api)
        if metadata['package'] != package or metadata['version_code'] != base_metadata['version_code'] or verified != signatures:
            raise RuntimeError('Artifact member package/version/signers differ from manifest')
        with zipfile.ZipFile(apk) as archive, apk.open('rb') as stream:
            if target >= 30 and 'resources.arsc' in archive.namelist():
                item = archive.getinfo('resources.arsc'); stream.seek(item.header_offset + 26)
                name_size, extra_size = struct.unpack('<HH', stream.read(4))
                offset = item.header_offset + 30 + name_size + extra_size
                if item.compress_type != zipfile.ZIP_STORED or offset % 4:
                    raise RuntimeError('target30+ resources.arsc must be STORED and four-byte aligned')
    if 'members' in artifact:
        from .recon import validate_selected
        # Verify actual manifest dependencies, not just sidecar assertions. Read already-selected
        # members individually, so neighboring intermediate APKs are never installed implicitly.
        from .recon import inspect_apk
        inspected = [inspect_apk(Path(item['apk']), api, lock, evidence / (label + '-selected-' + str(index)),
                                 inherited_min_sdk=inherited_minimum if item.get('split') else None, allow_patched=True)
                     for index, item in enumerate(members)]
        supported = shell(lock, evidence, label + '-abis', serial, ['getprop', 'ro.product.cpu.abilist']).stdout.strip().split(',')
        validate_selected(inspected, api, supported)
        if sorted((item.get('split') or '', item['sha256']) for item in inspected) != sorted((item.get('split') or '', item['sha256']) for item in members):
            raise RuntimeError('Artifact member split IDs differ from actual manifest')
    user = int(shell(lock, evidence, label + '-user', serial, ['am', 'get-current-user']).stdout.strip())
    current = shell(lock, evidence, label + '-paths', serial, ['pm', 'path', '--user', str(user), package], check=False)
    paths = [line[8:] for line in current.stdout.splitlines() if line.startswith('package:')]
    plan = {'serial': serial, 'package': package, 'user': user, 'api': api, 'artifact_sha256': artifact_fingerprint(artifact),
            'version_code': base_metadata['version_code'], 'existing_paths': paths, 'replace': False,
            'replacement_authorized': replace_existing, 'requested_package': requested_package,
            'members': [{'apk': item['apk'], 'sha256': item['sha256']} for item in members]}
    if paths:
        installer_text = shell(lock, evidence, label + '-installer', serial,
                               ['pm', 'list', 'packages', '-i', '--user', str(user), package]).stdout
        match = re.search(r'package:' + re.escape(package) + r'\s+installer=(\S+)', installer_text)
        plan['existing_installer'] = match[1] if match and match[1] != 'null' else None
        previous_members = []
        for index, path in enumerate(paths):
            previous_apk = evidence / (label + '-previous-' + str(index) + '.apk')
            adb(lock, evidence, label + '-pull-' + str(index), ['pull', path, str(previous_apk)], serial=serial)
            previous_signers = signer_digests(previous_apk, lock, evidence, label + '-previous-signers-' + str(index), api=api)
            previous, _ = badging(previous_apk, lock, evidence, label + '-previous-badging-' + str(index))
            if previous['package'] != package or previous['version_code'] > base_metadata['version_code']:
                raise PrerequisiteError('Existing fixture version/package is incompatible')
            previous_members.append({'path': path, 'sha256': sha256(previous_apk), 'signer_sha256': previous_signers})
        previous_signers = previous_members[0]['signer_sha256']
        if any(item['signer_sha256'] != previous_signers for item in previous_members): raise RuntimeError('Installed members have inconsistent signers')
        plan.update(existing_sha256=previous_members[0]['sha256'], existing_signers=previous_signers, existing_members=previous_members)
        if previous_signers != signatures:
            if not replace_existing: raise PrerequisiteError('Existing fixture signer differs; explicit wipe authorization required')
            plan['replace'] = True
            if package not in FIXTURE_PACKAGES:
                system = shell(lock, evidence, label + '-system-package', serial,
                               ['pm', 'list', 'packages', '-s', '--user', str(user), package]).stdout.splitlines()
                if 'package:' + package in system: raise PrerequisiteError('System-package replacement is unsupported')
                uid_text = shell(lock, evidence, label + '-uid', serial,
                                 ['pm', 'list', 'packages', '-U', '--user', str(user), package]).stdout
                uid_match = re.search(r'package:' + re.escape(package) + r'\s+uid:(\d+)', uid_text)
                if not uid_match: raise PrerequisiteError('Installed UID unavailable before replacement')
                siblings = shell(lock, evidence, label + '-uid-packages', serial,
                                 ['pm', 'list', 'packages', '--uid', uid_match[1], '--user', str(user)]).stdout.splitlines()
                packages = uid_packages('\n'.join(siblings), int(uid_match[1]))
                if packages != [package]: raise PrerequisiteError('Shared/unknown UID replacement is unsupported')
                users = shell(lock, evidence, label + '-users', serial, ['pm', 'list', 'users']).stdout
                user_ids = [int(value) for value in re.findall(r'UserInfo\{(\d+):', users)]
                if user not in user_ids: raise PrerequisiteError('User scope inventory unavailable before replacement')
                for other_user in user_ids:
                    if other_user == user: continue
                    observed = shell(lock, evidence, label + '-other-user-' + str(other_user), serial,
                                     ['pm', 'path', '--user', str(other_user), package], check=False)
                    if observed.returncode != 0 or 'Exception' in observed.stdout + observed.stderr or 'package:' in observed.stdout:
                        raise PrerequisiteError('Cannot replace a user app installed/unknown in another Android user')
                plan['replacement_users'] = [user]
    return plan


def install(artifact: dict, serial: str, plan: dict, lock: dict,
            evidence: Path, label: str, mutations: list) -> None:
    package = artifact['package']; members = artifact_members(artifact)
    if ((package not in FIXTURE_PACKAGES and plan.get('requested_package') != package) or plan['serial'] != serial or plan['package'] != package
            or artifact_fingerprint(artifact) != plan['artifact_sha256']
            or any(sha256(Path(item['apk'])) != item['sha256'] for item in members)
            or [{'apk': item['apk'], 'sha256': item['sha256']} for item in members] != plan['members']):
        raise RuntimeError('Install does not match its preflight')
    fresh = shell(lock, evidence, label + '-recheck', serial,
                  ['pm', 'path', '--user', str(plan['user']), package], check=False)
    paths = [line[8:] for line in fresh.stdout.splitlines() if line.startswith('package:')]
    if paths != plan['existing_paths']: raise PrerequisiteError('Installed fixture changed since preflight')
    if plan['replace']:
        if not plan['replacement_authorized']: raise PrerequisiteError('Replacement was not authorized')
        adb(lock, evidence, label + '-uninstall', ['uninstall', package], serial=serial)
        mutations.append({'action': 'uninstall', 'package': package, 'data_loss': True})
    installer = ['-i', plan['existing_installer']] if plan.get('existing_installer') else []
    verb = 'install-multiple' if len(members) > 1 else 'install'
    response = adb(lock, evidence, label + '-install',
                   [verb, '-r', '--user', str(plan['user']), *installer, *[item['apk'] for item in members]], serial=serial, check=False)
    state = shell(lock, evidence, label + '-post-install', serial,
                  ['pm', 'path', '--user', str(plan['user']), package], check=False)
    after = [line[8:] for line in state.stdout.splitlines() if line.startswith('package:')]
    success = response.returncode == 0 and 'Success' in response.stdout
    mutations.append({'action': verb if success else 'install-failed', 'package': package,
                      'artifact_sha256': plan['artifact_sha256'], 'installer_argument': plan.get('existing_installer'),
                      'installed_paths_after': after, 'exit_status': response.returncode})
    if not success: raise RuntimeError('Installer did not report Success; post-failure state retained')
    if len(after) != len(members): raise RuntimeError('Installed member count differs after Success')


def verify_artifact(manifest: Path, serial: str, lock: dict, evidence: Path, *, proxy=None, replace_existing=False, mutations=None) -> dict:
    from .pipeline import validate_toolchain
    from .report import load_artifact
    validate_toolchain(lock, device=True)
    document, artifact = load_artifact(manifest)
    configuration = document['semantic']['configuration']
    if proxy is not None and proxy != configuration['proxy']:
        raise ValueError('--proxy asserts the baked endpoint; it cannot override the artifact')
    api = int(shell(lock, evidence, 'verify-api', serial, ['getprop', 'ro.build.version.sdk']).stdout.strip())
    if configuration['antitamper_selected'] and api != document['semantic']['original_identity']['metadata_api']:
        raise PrerequisiteError('Identity artifact was built for a different runtime API; no install attempted')
    native_tls = configuration.get('native_tls')
    dart_pinning = configuration.get('dart_pinning')
    gadget = configuration.get('gadget')
    if gadget and api != 30:
        raise PrerequisiteError('Gadget artifact requires its measured API30 runtime; no install attempted')
    if native_tls and api != 30:
        raise PrerequisiteError('Native TLS artifact requires its measured API30 runtime; no install attempted')
    if dart_pinning and api != 30:
        raise PrerequisiteError('Dart pinning artifact requires its measured API30 runtime; no install attempted')
    if native_tls or gadget or dart_pinning:
        supported = shell(lock, evidence, 'verify-native-tls-abis', serial, ['getprop', 'ro.product.cpu.abilist']).stdout.strip().split(',')
        pages = shell(lock, evidence, 'verify-native-tls-pages', serial, ['getconf', 'PAGE_SIZE']).stdout.strip()
        if not supported or supported[0] != 'arm64-v8a' or pages != '4096':
            raise PrerequisiteError('Native TLS artifact requires the measured ARM64/4KB runtime; no install attempted')
    plan = preflight(artifact, serial, replace_existing, lock, evidence, 'verify', requested_package=artifact['package'])
    if mutations is None: mutations = []
    install(artifact, serial, plan, lock, evidence, 'verify', mutations)
    return {'verification': 'passed', 'scope': 'artifact hashes/marker/signatures and authorized installation',
            'runtime_verification': 'not-run', 'artifact_manifest': str(manifest), 'plan': plan, 'device_mutations': mutations}
