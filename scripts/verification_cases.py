"""M8 observed action packets, strict pairing/refusals and private human review."""
import copy
import json
from pathlib import Path
import shutil
import time

from repack.rebuild import (ROOT, PrerequisiteError, ensure_keys, fixture_source_hash, load_lock,
    report_reference, sha256, source_hash, write_json)
from repack.report import load_artifact
from repack.runtime import assess, read_packet
from repack.verify import artifact_fingerprint, capture_startup, install, owned_reverse, preflight, shell
from scripts.acceptance import read_cell, read_events, select_serial
from scripts.cli_cases import cli
from scripts.contract_cases import SELF
from scripts.routing_cases import oracle, rows


def bundle(directory, packet, traffic, app_text):
    directory.mkdir(parents=True)
    proxy = directory / 'proxy.jsonl'; app = directory / 'app.log'
    proxy.write_text(''.join(json.dumps(row, sort_keys=True) + '\n' for row in traffic)); app.write_text(app_text)
    value = copy.deepcopy(packet); value['references'] = {'proxy_log': {'path': proxy.name, 'sha256': sha256(proxy)},
        'app_log': {'path': app.name, 'sha256': sha256(app)}}
    path = directory / 'packet.json'; write_json(path, value); return path


def run_t_v80(result, evidence, args):
    lock = load_lock(); serial = select_serial(lock, evidence, args.device); result['cell'] = read_cell(lock, evidence, serial)
    result['inputs'] = [report_reference(ROOT / '.work/evidence/M7.json')]
    baseline = json.loads((ROOT / '.work/evidence/M0-build.json').read_text())
    if baseline['fixture_source_sha256'] != fixture_source_hash(): raise PrerequisiteError('Build current original fixtures first')
    keys = ensure_keys(lock, evidence); own = next(row for row in baseline['outputs'] if row['id'] == 'app-own')
    outputs = ROOT / '.work/outputs/runtime' / result['run_id']; outputs.mkdir(parents=True)
    output = outputs / 'fixture.apk'; key = Path(keys['repack']['path']); ca = ROOT / '.work/keys/mitmproxy/mitmproxy-ca-cert.pem'
    cli(result, evidence, 'build', ['patch', own['apk'], '--out', output, '--key', key, '--ca', ca, '--device', serial], lock)
    manifest = output.with_suffix('.artifact.json'); document, artifact = load_artifact(manifest)
    cli(result, evidence, 'install', ['verify', manifest, '--device', serial, '--replace-existing-and-wipe-data'], lock)
    result['comparisons'].append({'name': 'current-public-artifact', 'result': 'passed', 'manifest': str(manifest)})
    captured = []; reports = []
    capture_log = evidence / 'proxy-metadata.jsonl'
    with oracle(evidence / 'proxy', args.proxy_bind, capture=capture_log) as (_, _):
        with owned_reverse(lock, serial, 8080, args.proxy_bind, 8080, evidence, 'capture', result['device_mutations'], result['cleanup']):
            for label in ('first', 'second'):
                token = result['run_id'] + '-' + label
                config = {'run_id': token, 'case_id': 'T-V80', 'url': 'https://127.0.0.1:18443/repack/' + token, 'expected_via': 'proxy'}
                begin = time.time() - .1
                with capture_startup(lock, serial, evidence, label + '-startup') as log:
                    shell(lock, evidence, label + '-trigger', serial, ['am', 'broadcast', '-n', SELF + '/dev.repack.fixture.common.NetworkReceiver',
                        '--es', 'network_json', json.dumps(config, separators=(',', ':'))])
                    for _ in range(100):
                        app_text = log.read_text(errors='replace'); events = read_events(app_text, token)
                        if events: break
                        time.sleep(.1)
                    pid = shell(lock, evidence, label + '-pid', serial, ['pidof', '-s', SELF]).stdout.strip()
                end = time.time() + .1
                if len(events) != 1 or events[0]['pid'] != int(pid): raise RuntimeError('Observed M8 action event/PID is missing or ambiguous')
                packet = {'schema_version': 1, 'adapter': 'fixture-https-v1', 'serial': serial, 'package': SELF,
                    'artifact_sha256': artifact_fingerprint(artifact), 'token': token, 'process': {'pid': int(pid), 'name': SELF},
                    'action': {'name': 'controlled-fixture-HTTPS', 'trigger': 'adb-am-broadcast',
                        'component': SELF + '/dev.repack.fixture.common.NetworkReceiver', 'start_epoch_s': begin, 'end_epoch_s': end},
                    'endpoint': {'scheme': 'https', 'host': '127.0.0.1', 'port': 18443, 'method': 'GET', 'path': '/repack/' + token}, 'references': {}}
                traffic = rows(capture_log)
                if not any(row['kind'] == 'connect' for row in traffic): raise RuntimeError('Passive capture did not record actual CONNECT independently of decrypted HTTP')
                app_only = '\n'.join(line for line in app_text.splitlines() if 'REPACK_FIXTURE' in line and token in line) + '\n'
                path = bundle(evidence / ('packet-' + label), packet, traffic, app_only)
                review = outputs / (label + '.md')
                child = cli(result, evidence, label + '-assess', ['verify', manifest, '--device', serial, '--runtime-evidence', path, '--review', review], lock)
                if child['runtime_verification'] != 'passed' or child['device_mutations'] or not child['installed_snapshot_verified']:
                    raise RuntimeError('Read-only paired runtime assessment failed or mutated device')
                captured.append((packet, traffic, app_only, path)); reports.append(child)
                result['comparisons'].append({'name': label + '-observed-runtime', 'result': 'passed', 'packet': str(path), 'report': result['cli_reports'][-1]})
    if reports[0]['semantic'] != reports[1]['semantic']: raise RuntimeError('Equivalent action semantics retained token/PID/time noise')
    result['comparisons'].append({'name': 'equivalent-semantics', 'result': 'passed', 'semantic': reports[0]['semantic']})
    packet, traffic, app_text, positive_path = captured[0]
    original_events = read_events(app_text, packet['token'])
    matched = [row for row in traffic if row.get('kind') == 'http' and row.get('path') == packet['endpoint']['path']]
    if len(matched) != 1: raise RuntimeError('Missing unique real positive traffic observation')
    before = shell(lock, evidence, 'assessment-paths-before', serial, ['pm', 'path', SELF]).stdout
    negatives = []
    negatives.append(('missing-traffic', packet, [], app_text, 'inconclusive'))
    altered = copy.deepcopy(matched); altered[0]['host'] = 'unrelated.repack.test'; negatives.append(('unrelated', packet, altered, app_text, 'inconclusive'))
    negatives.append(('CONNECT-only', packet, [row for row in traffic if row['kind'] == 'connect'], app_text, 'inconclusive'))
    altered = copy.deepcopy(matched); altered[0].update(tls=False, scheme='http'); negatives.append(('cleartext-only', packet, altered, app_text, 'inconclusive'))
    altered = copy.deepcopy(matched); altered[0]['timestamp_start'] = packet['action']['start_epoch_s'] - 10; negatives.append(('stale-proxy', packet, altered, app_text, 'inconclusive'))
    altered_packet = copy.deepcopy(packet); altered_packet['process']['pid'] += 1; negatives.append(('wrong-PID', altered_packet, matched, app_text, 'inconclusive'))
    altered_event = copy.deepcopy(original_events[0]); altered_event['response_marker'] = json.dumps({'token': 'different-token', 'via': 'proxy'}); altered_event['comparison'] = 'passed'
    negatives.append(('forged-comparison', packet, matched, 'REPACK_FIXTURE: ' + json.dumps(altered_event), 'failed'))
    altered_event = copy.deepcopy(original_events[0]); altered_event.update(event='failure', response_marker=None, error_class='fixture.ControlledFailure')
    negatives.append(('app-failure', packet, matched, 'REPACK_FIXTURE: ' + json.dumps(altered_event), 'failed'))
    negatives.append(('conflicting-events', packet, matched, app_text + '\nREPACK_FIXTURE: ' + json.dumps(altered_event), 'failed'))
    altered_packet = copy.deepcopy(packet); altered_packet['adapter'] = 'manual-https-v1'; altered_packet['action']['trigger'] = 'manual'
    negatives.append(('manual-unattributed', altered_packet, matched, app_text, 'inconclusive'))
    assessment_children = list(reports)
    for label, value, proxy_rows, app, expected in negatives:
        path = bundle(evidence / ('negative-' + label), value, proxy_rows, app)
        child = cli(result, evidence, label, ['verify', manifest, '--device', serial, '--runtime-evidence', path], lock, expected=1 if expected == 'failed' else 0)
        if child['runtime_verification'] != expected or child['device_mutations']: raise RuntimeError('Invalid/missing evidence became runtime success or mutated device: ' + label)
        assessment_children.append(child)
        result['comparisons'].append({'name': label + '-no-false-pass', 'result': 'passed', 'verdict': child['runtime_verification'], 'reason': child['reason']})
    tamper = bundle(evidence / 'tampered-reference', packet, matched, app_text)
    with (tamper.parent / 'proxy.jsonl').open('a') as stream: stream.write('{}\n')
    escape = bundle(evidence / 'escape-reference', packet, matched, app_text); value = json.loads(escape.read_text()); value['references']['proxy_log']['path'] = '../outside'; write_json(escape, value)
    fingerprint = bundle(evidence / 'wrong-artifact', packet, matched, app_text); value = json.loads(fingerprint.read_text()); value['artifact_sha256'] = '0' * 64; write_json(fingerprint, value)
    forged = outputs / 'forged.artifact.json'; value = copy.deepcopy(document); value['runtime_verification'] = 'passed'; write_json(forged, value)
    for label, input_manifest, path, reason in [('tampered-reference', manifest, tamper, 'hash mismatch'),
            ('escaping-reference', manifest, escape, 'escapes'), ('wrong-artifact', manifest, fingerprint, 'fingerprint mismatch'),
            ('forged-artifact-status', forged, positive_path, 'runtime verdicts require separate')]:
        child = cli(result, evidence, label, ['verify', input_manifest, '--device', serial, '--runtime-evidence', path], lock, expected=1, reason=reason)
        if child['device_mutations']: raise RuntimeError('Malformed runtime packet mutated the device')
        result['comparisons'].append({'name': label + '-refused', 'result': 'passed'})
    if shell(lock, evidence, 'assessment-paths-after', serial, ['pm', 'path', SELF]).stdout != before:
        raise RuntimeError('Read-only runtime assessment changed installed paths')
    result['comparisons'].append({'name': 'runtime-assessments-read-only', 'result': 'passed'})
    review = (outputs / 'first.md').read_text()
    if packet['token'] in review or 'response_marker' in review or '"via"' in review or 'proxy.jsonl' in review:
        raise RuntimeError('Human review copied a private payload or raw capture')
    result['comparisons'].append({'name': 'human-review-private-payloads-omitted', 'result': 'passed', 'path': str(outputs / 'first.md')})
    # A valid old capture cannot authorize an assessment against different installed APK bytes.
    plan = preflight(own, serial, args.replace_existing_and_wipe_data, lock, evidence, 'different-installed')
    install(own, serial, plan, lock, evidence, 'different-installed', result['device_mutations'])
    different_before = shell(lock, evidence, 'different-before', serial, ['pm', 'path', SELF]).stdout
    child = cli(result, evidence, 'different-installed-runtime', ['verify', manifest, '--device', serial, '--runtime-evidence', positive_path], lock,
        expected=3, reason='Installed APK bytes differ')
    if child['device_mutations'] or shell(lock, evidence, 'different-after', serial, ['pm', 'path', SELF]).stdout != different_before:
        raise RuntimeError('Installed-byte mismatch performed an installation')
    result['comparisons'].append({'name': 'installed-byte-mismatch-refused', 'result': 'passed'})
    cli(result, evidence, 'restore-fixture', ['verify', manifest, '--device', serial, '--replace-existing-and-wipe-data'], lock)
    result.update(verification='passed', transformation='applied', scope='Read-only artifact/action HTTPS evidence assessment with owned NetworkReceiver auto pairing; manual captures remain inconclusive; private Markdown review',
        runtime_packets=[{'path': str(row[3]), 'sha256': sha256(row[3])} for row in captured], outputs=[{'manifest': str(manifest), 'sha256': sha256(manifest)}],
        unsupported=['automatic-real-app-action-attribution', 'generic-Burp/Caido-export-parsing', 'uncovered-client-stacks', 'current-runtime-claim-from-historical-capture'])


def gate_verification(result, evidence, args):
    reference = report_reference((args.reports / 'T-V80.json').resolve()); child = json.loads(Path(reference['path']).read_text())
    if child['verification'] != 'passed' or child['source_sha256'] != source_hash(): raise PrerequisiteError('T-V80 failed/stale')
    if len(child['comparisons']) != 21 or any(row['result'] != 'passed' for row in child['comparisons']): raise RuntimeError('Runtime evidence controls incomplete')
    for row in [*child['inputs'], *child['cli_reports'], *child['runtime_packets']]:
        if sha256(Path(row['path'])) != row['sha256']: raise RuntimeError('Runtime evidence child reference changed')
    for row in child['runtime_packets']: read_packet(Path(row['path']))
    for row in child['outputs']:
        if sha256(Path(row['manifest'])) != row['sha256']: raise RuntimeError('Runtime artifact manifest changed')
        load_artifact(Path(row['manifest']))
    result.update(verification='passed', gate_progress='accepted', cell=child['cell'], children={'T-V80': reference},
        scope=child['scope'], unsupported=child['unsupported'], next_gate='final Midway artifact/preflight and authorized runtime test')
