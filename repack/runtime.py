"""Read-only assessment of bounded, artifact-bound action evidence."""
import datetime as dt
import json
import math
from pathlib import Path
import re

from .rebuild import PrerequisiteError, sha256, write_json
from .report import canonical, load_artifact, unique_object
from .verify import artifact_fingerprint


ADAPTERS = {'fixture-https-v1', 'manual-https-v1'}


def validate_packet(packet):
    required = {'schema_version', 'adapter', 'serial', 'package', 'artifact_sha256', 'action', 'process', 'endpoint', 'token', 'references'}
    if (not isinstance(packet, dict) or set(packet) != required or type(packet['schema_version']) is not int
            or packet['schema_version'] != 1 or packet['adapter'] not in ADAPTERS): raise ValueError('Unsupported runtime evidence packet schema')
    if not re.fullmatch(r'[0-9a-f]{64}', packet['artifact_sha256']): raise ValueError('Runtime evidence artifact fingerprint is invalid')
    process = packet['process']; action = packet['action']; endpoint = packet['endpoint']
    if (not isinstance(process, dict) or set(process) != {'pid', 'name'} or type(process['pid']) is not int
            or process['pid'] <= 0 or process['name'] != packet['package']): raise ValueError('Runtime evidence process identity is invalid')
    if not isinstance(action, dict) or set(action) != {'name', 'trigger', 'component', 'start_epoch_s', 'end_epoch_s'}:
        raise ValueError('Runtime evidence action fields are invalid')
    if not isinstance(action['name'], str) or not 1 <= len(action['name']) <= 160: raise ValueError('Runtime evidence action name is invalid')
    start, end = action['start_epoch_s'], action['end_epoch_s']
    if (type(start) not in (int, float) or type(end) not in (int, float) or not math.isfinite(start) or not math.isfinite(end)
            or start <= 0 or not start <= end <= start + 3600): raise ValueError('Runtime evidence capture window is invalid')
    if (not isinstance(endpoint, dict) or set(endpoint) != {'scheme', 'host', 'port', 'method', 'path'}
            or endpoint['scheme'] != 'https' or not isinstance(endpoint['host'], str)
            or not re.fullmatch(r'[A-Za-z0-9.-]{1,253}', endpoint['host'])
            or type(endpoint['port']) is not int or not 1 <= endpoint['port'] <= 65535
            or not isinstance(endpoint['method'], str) or not re.fullmatch(r'[A-Z]{3,12}', endpoint['method'])
            or not isinstance(endpoint['path'], str) or not endpoint['path'].startswith('/')
            or len(endpoint['path']) > 4096 or any(c in endpoint['path'] for c in '\r\n?#')):
        raise ValueError('Runtime evidence HTTPS endpoint is invalid')
    if packet['adapter'] == 'fixture-https-v1':
        token = packet['token']
        if (packet['package'] != 'dev.repack.fixture.identity' or not isinstance(token, str)
                or not re.fullmatch(r'[A-Za-z0-9_-]{8,120}', token) or endpoint['path'] != '/repack/' + token
                or endpoint['host'] != '127.0.0.1' or endpoint['method'] != 'GET'
                or action['trigger'] != 'adb-am-broadcast'
                or action['component'] != packet['package'] + '/dev.repack.fixture.common.NetworkReceiver'):
            raise ValueError('Fixture adapter accepts only its owned marked NetworkReceiver action')
    elif action['trigger'] != 'manual': raise ValueError('Manual adapter requires a recorded manual trigger')
    if not isinstance(packet['references'], dict) or set(packet['references']) != {'proxy_log', 'app_log'}:
        raise ValueError('Runtime evidence needs separate proxy_log and app_log references')
    return packet


def read_packet(path: Path):
    if path.stat().st_size > 1024 * 1024: raise ValueError('Runtime packet exceeds one MiB')
    packet = validate_packet(json.loads(path.read_text(), object_pairs_hook=unique_object)); root = path.resolve().parent
    payloads = {}
    for name, row in packet['references'].items():
        if not isinstance(row, dict) or set(row) != {'path', 'sha256'} or not isinstance(row['path'], str):
            raise ValueError('Runtime evidence reference is invalid')
        relative = Path(row['path']); target = (root / relative).resolve()
        if relative.is_absolute() or not target.is_relative_to(root) or target.stat().st_size > 16 * 1024 * 1024:
            raise ValueError('Runtime evidence reference escapes its packet or exceeds16MiB')
        if not re.fullmatch(r'[0-9a-f]{64}', row['sha256']) or sha256(target) != row['sha256']:
            raise ValueError('Runtime evidence reference hash mismatch')
        payloads[name] = target.read_text()
    proxy = []
    for line in payloads['proxy_log'].splitlines():
        if line.strip():
            row = json.loads(line, object_pairs_hook=unique_object)
            if not isinstance(row, dict): raise ValueError('Proxy evidence line must be an object')
            proxy.append(row)
    app = []
    for line in payloads['app_log'].splitlines():
        match = re.search(r'REPACK_FIXTURE\s*:\s*(\{.*\})\s*$', line)
        if match: app.append(json.loads(match[1], object_pairs_hook=unique_object))
    return packet, proxy, app


def assess(packet, proxy, app):
    validate_packet(packet); endpoint = packet['endpoint']; action = packet['action']; token = packet['token']
    matched = []
    for row in proxy:
        timestamp = row.get('timestamp_start')
        if (row.get('kind') == 'http' and row.get('tls') is True and row.get('scheme') == 'https'
                and all(row.get(key) == endpoint[key] for key in ('host', 'port', 'method', 'path'))
                and type(row.get('port')) is int and type(timestamp) in (int, float) and math.isfinite(timestamp)
                and action['start_epoch_s'] <= timestamp <= action['end_epoch_s']):
            matched.append(row)
    verdict = 'inconclusive'; reason = 'missing-matching-decrypted-HTTPS-request'
    observations = {'proxy_rows': len(proxy), 'matched_decrypted_requests': len(matched), 'app_rows': len(app),
                    'correlated_app_events': 0, 'adapter': packet['adapter']}
    if packet['adapter'] == 'manual-https-v1':
        reason = 'manual-capture-has-no-automatic-process/response-attribution' if matched else reason
    else:
        events = [row for row in app if row.get('run_id') == token]
        observations['correlated_app_events'] = len(events)
        if any(type(row.get('pid')) is not int or type(row.get('schema_version')) is not int or row.get('schema_version') != 1
               or row.get('pid') != packet['process']['pid'] or row.get('process') != packet['process']['name']
               or row.get('package') != packet['package'] for row in events): reason = 'app-process-mismatch'
        elif len({canonical(row) for row in events}) > 1:
            verdict, reason = 'failed', 'conflicting-app-observations'
        elif events:
            event = events[0]
            if event.get('event') == 'failure': verdict, reason = 'failed', 'app-request-failed'
            elif event.get('event') == 'response':
                try: body = json.loads(event.get('response_marker') or 'null', object_pairs_hook=unique_object)
                except (ValueError, TypeError): body = None
                if body != {'token': token, 'via': 'proxy'}: verdict, reason = 'failed', 'app-response-marker-mismatch'
                elif matched: verdict, reason = 'passed', 'paired-decrypted-request-and-app-response'
            else: reason = 'missing-app-response'
        elif matched: reason = 'missing-app-response'
    normalized = dict(endpoint)
    if packet['adapter'] == 'fixture-https-v1': normalized['path'] = '/repack/{token}'
    semantic = {'artifact_sha256': packet['artifact_sha256'], 'adapter': packet['adapter'], 'package': packet['package'],
        'action': {'name': action['name'], 'trigger': action['trigger'], 'component': action['component']}, 'endpoint': normalized,
        'runtime_verification': verdict, 'reason': reason, 'matched_decrypted_requests': len(matched)}
    return {'verification': verdict, 'runtime_verification': verdict, 'reason': reason, 'observations': observations,
            'semantic': semantic, 'scope': 'Read-only assessment of the recorded artifact/action/window; manual captures cannot establish automatic process/response attribution'}


def verify_runtime(manifest: Path, packet_path: Path, serial: str, lock: dict, evidence: Path, *, proxy=None):
    from .pipeline import validate_toolchain
    from .recon import inspect_input
    validate_toolchain(lock, device=True)
    packet, traffic, events = read_packet(packet_path); document, artifact = load_artifact(manifest)
    if packet['serial'] != serial or packet['package'] != artifact['package'] or packet['artifact_sha256'] != artifact_fingerprint(artifact):
        raise ValueError('Runtime evidence serial/package/artifact fingerprint mismatch')
    if proxy is not None and proxy != document['semantic']['configuration']['proxy']:
        raise ValueError('--proxy asserts the baked endpoint; it cannot override the artifact')
    installed = inspect_input('pkg:' + artifact['package'], serial, lock, evidence / 'installed-runtime-snapshot', allow_patched=True)
    actual = sorted((row.get('split') or '', row['sha256']) for row in installed['members'])
    expected = sorted((row.get('split') or '', row['sha256']) for row in (artifact.get('members') or [artifact]))
    if actual != expected: raise PrerequisiteError('Installed APK bytes differ from runtime evidence artifact; no install was attempted')
    result = assess(packet, traffic, events)
    result.update(artifact_manifest=str(manifest.resolve()), runtime_evidence={'path': str(packet_path.resolve()), 'sha256': sha256(packet_path),
        'references': packet['references'], 'action': packet['action'], 'process': packet['process'], 'endpoint': packet['endpoint']},
        installed_snapshot={'api': installed['api'], 'device_abis': installed['device_abis'], 'members': [{'split': row.get('split'), 'sha256': row['sha256']} for row in installed['members']]},
        installed_snapshot_verified=True, device_mutations=[])
    write_json(evidence / 'runtime-assessment.json', result)
    return result
