"""M1b-3 public CLI/schema composition and evidence controls."""
import copy
import json
from pathlib import Path
import shutil
import sys
import time

from repack.rebuild import (ROOT, PrerequisiteError, align_sign, copy_archive, ensure_keys, environment, execute,
                            fixture_source_hash, load_lock, report_reference, sha256, source_hash, write_json)
from repack.recon import signing_metadata
from repack.report import load_artifact
from repack.verify import capture_startup, install, owned_reverse, preflight, shell
from scripts.acceptance import launch_query, read_cell, read_events, select_serial
from scripts.cache_cases import launch as state_query
from scripts.contract_cases import sign_profile
from scripts.routing_cases import compare_response, oracle
from scripts.selected_cases import build_selected_fixture
from scripts.trust_cases import https_config


def cli(result, evidence, label, arguments, lock, expected=0, reason=None):
    command = [sys.executable, '-m', 'repack', *map(str, arguments)]
    completed = execute(command, evidence, label, env=environment(lock), check=False, timeout=300)
    if completed.returncode != expected or (reason and reason not in completed.stdout + completed.stderr):
        raise RuntimeError('Public CLI failed for an unexpected reason: ' + label)
    paths = [Path(line[9:]) for line in completed.stdout.splitlines() if line.startswith('EVIDENCE ')]
    child = None
    if paths:
        if len(paths) != 1: raise RuntimeError('Ambiguous public CLI evidence path')
        child = json.loads(paths[0].read_text())
        if child['command']['exit_status'] != expected: raise RuntimeError('CLI exit/report mismatch')
        result.setdefault('cli_reports', []).append({'path': str(paths[0]), 'sha256': sha256(paths[0]), 'label': label})
        result['device_mutations'].extend(child['device_mutations'])
    return child


def run_t_p12(result, evidence, args):
    lock = load_lock(); serial = select_serial(lock, evidence, args.device); result['cell'] = read_cell(lock, evidence, serial)
    previous = ROOT / '.work/evidence/T-P11.json'
    if json.loads(previous.read_text())['verification'] != 'passed': raise PrerequisiteError('Classify install lifecycle first')
    baseline_path = ROOT / '.work/evidence/M0-build.json'; baseline = json.loads(baseline_path.read_text())
    if baseline.get('fixture_source_sha256') != fixture_source_hash(): raise PrerequisiteError('Build current fixture sources first')
    result['inputs'] = [report_reference(ROOT / '.work/evidence/T-P10.json'), report_reference(previous), report_reference(baseline_path)]
    keys = ensure_keys(lock, evidence); key = Path(keys['repack']['path']); ca = ROOT / '.work/keys/mitmproxy/mitmproxy-ca-cert.pem'
    own = next(item for item in baseline['outputs'] if item['id'] == 'app-own')
    outputs = ROOT / '.work/outputs/public-cases' / result['run_id']; outputs.mkdir(parents=True)
    cli(result, evidence, 'installed-triage', ['triage', 'pkg:dev.repack.fixture.identity', '--device', serial], lock)
    inventory = result['cli_reports'][-1]; inspected = json.loads(Path(inventory['path']).read_text())['inventory']
    if not inspected['provenance']['installed_paths'] or inspected['package'] != own['package']:
        raise RuntimeError('Public triage did not capture selected installed members/provenance')
    result['comparisons'].append({'name': 'installed-selected-triage', 'result': 'passed', 'member_count': len(inspected['members']), 'provenance': inspected['provenance']})
    documents = []
    for label in ('trust-one', 'trust-two'):
        cli(result, evidence, label, ['patch', own['apk'], '--out', outputs / (label + '.apk'), '--key', key, '--trust-only', '--ca', ca], lock)
        document, _ = load_artifact(outputs / (label + '.artifact.json')); documents.append(document)
    if documents[0]['semantic'] != documents[1]['semantic'] or documents[0]['semantic']['configuration']['proxy'] is not None:
        raise RuntimeError('Semantic reports changed across equivalent builds / trust-only routing was enabled')
    result['comparisons'].append({'name': 'semantic-diff-and-trust-only', 'result': 'passed', 'semantic': documents[0]['semantic']})
    cli(result, evidence, 'default-no-a', ['patch', own['apk'], '--out', outputs / 'default.apk', '--key', key, '--ca', ca, '--device', serial], lock)
    default_path = outputs / 'default.artifact.json'; default, default_artifact = load_artifact(default_path)
    config = default['semantic']['configuration']
    if config['antitamper_selected'] or config['antitamper_requested'] or config['proxy'] != {'host': '127.0.0.1', 'port': 8080}:
        raise RuntimeError('Default patch silently changed A/proxy policy')
    cli(result, evidence, 'verify-default', ['verify', default_path, '--device', serial, '--replace-existing-and-wipe-data'], lock)
    event, _, _, _ = launch_query(default_artifact, serial, result['run_id'] + '-default', 'T-P12', [keys['repack']['sha256']],
        own['package'], 'direct-current', lock, evidence, 'default-query')
    if event['comparison'] != 'passed': raise RuntimeError('Default no-A control did not expose real installed signer')
    result['comparisons'].append({'name': 'default-antitamper-opt-in', 'result': 'passed', 'event': event})

    selected = build_selected_fixture(baseline, keys, lock, evidence / 'selected-fixture')
    request = https_config(result, 'combined-https')
    unsigned = evidence / 'network-base-unsigned.apk'; signed = evidence / 'network-base.apk'; part = evidence / 'network-base-sign'; part.mkdir()
    copy_archive(selected / 'base.apk', unsigned, additions={'assets/repack-fixture-request.json': json.dumps(request).encode()})
    align_sign(unsigned, signed, keys['original'], lock, part); shutil.copyfile(signed, selected / 'base.apk')
    original_base_sha = sha256(selected / 'base.apk')
    cli(result, evidence, 'combined-build', ['patch', selected, '--out', outputs / 'combined', '--key', key, '--antitamper', '--ca', ca, '--device', serial], lock)
    combined_path = outputs / 'combined/manifest.json'; combined, artifact = load_artifact(combined_path)
    if len(artifact['members']) != 5 or not combined['semantic']['configuration']['antitamper_selected']:
        raise RuntimeError('Combined public artifact omitted identity or selected members')
    cli(result, evidence, 'verify-combined', ['verify', combined_path, '--device', serial, '--proxy', '127.0.0.1:8080', '--replace-existing-and-wipe-data'], lock)
    expected_signers = combined['semantic']['original_identity']['signer_sha256']
    with oracle(evidence / 'proxy', args.proxy_bind) as (_, logfile):
        with owned_reverse(lock, serial, 8080, args.proxy_bind, 8080, evidence, 'combined', result['device_mutations'], result['cleanup']):
            with capture_startup(lock, serial, evidence, 'combined-startup') as captured:
                event, _, pid, _ = launch_query(artifact, serial, result['run_id'] + '-combined-identity', 'T-P10', expected_signers,
                    own['package'], 'direct-current', lock, evidence, 'combined-query')
                for _ in range(60):
                    network = read_events(captured.read_text(errors='replace'), request['run_id'])
                    if network: break
                    time.sleep(.1)
            network = read_events(captured.read_text(errors='replace'), request['run_id'])
            if not network or any(item != network[0] for item in network[1:]) or network[0]['pid'] != int(pid):
                raise RuntimeError('Combined startup network observation was missing/stale')
            compare_response(result, request, network[0], logfile, 'proxy', tls=True)
            if event['comparison'] != 'passed' or json.loads(event['response_marker']) != {
                    'parent': 'parent', 'child': 'child', 'lazy_asset': 'child-lazy-asset', 'density_resource': 'density-config',
                    'native_abi': 'arm64-v8a', 'split_count': 4}: raise RuntimeError('Combined split/resource/native/identity runtime failed')
            result['comparisons'].append({'name': 'combined-selected-runtime', 'result': 'passed', 'event': event})
            rows, _, _ = state_query(result, evidence, artifact, serial, lock, 'original-input-binding')
            if rows['state']['input_sha256'] != original_base_sha: raise RuntimeError('Identity metadata was bound to a transformed intermediate instead of original bytes')
            result['comparisons'].append({'name': 'original-input-hash-binding', 'result': 'passed', 'state': rows['state']})
    paths_before = shell(lock, evidence, 'negative-before', serial, ['pm', 'path', own['package']]).stdout
    bad = outputs / 'changed'; shutil.copytree(outputs / 'combined', bad)
    with (bad / 'base.apk').open('ab') as stream: stream.write(b'changed-output')
    cli(result, evidence, 'verify-changed', ['verify', bad / 'manifest.json', '--device', serial, '--replace-existing-and-wipe-data'], lock,
        expected=1, reason='Artifact output hash mismatch')
    cli(result, evidence, 'verify-proxy-mismatch', ['verify', combined_path, '--device', serial, '--proxy', '127.0.0.1:18080', '--replace-existing-and-wipe-data'], lock,
        expected=1, reason='cannot override the artifact')
    if shell(lock, evidence, 'negative-after', serial, ['pm', 'path', own['package']]).stdout != paths_before:
        raise RuntimeError('Invalid verify changed installed state')
    result['comparisons'].append({'name': 'modified-output-and-endpoint-refusal', 'result': 'passed', 'installed_paths_unchanged': True})
    cli(result, evidence, 'prepatched-refusal', ['patch', outputs / 'combined', '--out', outputs / 'double', '--key', key, '--ca', ca], lock,
        expected=1, reason='Previously patched input')
    cli(result, evidence, 'dex-only-unsupported', ['patch', own['apk'], '--out', outputs / 'unsupported.apk', '--key', key, '--dex-only'], lock,
        expected=4, reason='DEX-only bootstrap/runtime trust is not implemented')
    cli(result, evidence, 'conflicting-flags', ['patch', own['apk'], '--out', outputs / 'conflict.apk', '--key', key, '--trust-only', '--proxy', '127.0.0.1:8080'], lock,
        expected=1, reason='changes trust alone')
    missing_key = outputs / 'not-generated.p12'
    cli(result, evidence, 'missing-key', ['patch', own['apk'], '--out', outputs / 'missing-key.apk', '--key', missing_key, '--ca', ca], lock,
        expected=3, reason='no replacement key was generated')
    cli(result, evidence, 'removed-flag', ['patch', own['apk'], '--out', outputs / 'removed-flag.apk', '--key', key, '--force-proxy'], lock,
        expected=2, reason='unrecognized arguments')
    if missing_key.exists() or any((outputs / name).exists() for name in ('double', 'unsupported.apk', 'conflict.apk', 'missing-key.apk', 'removed-flag.apk')):
        raise RuntimeError('Rejected public operation published output or generated a key')
    result['comparisons'].append({'name': 'prepatched-unimplemented-conflict-key-surface-controls', 'result': 'passed'})

    rotated = sign_profile(own, ['other'], lock, keys, evidence / 'v31-source', rotated=True, rotation_min_sdk=33)
    views = {}
    for api in (30, 35):
        part = evidence / ('v31-api' + str(api)); part.mkdir(); metadata = signing_metadata(Path(rotated['apk']), api, lock, part)
        expected = keys['original' if api == 30 else 'other']['sha256']
        if metadata['signer_sha256'] != [expected] or len(metadata['history']) != (0 if api == 30 else 2):
            raise RuntimeError('SDK-specific v3.1 signer/history extraction is wrong')
        views[str(api)] = metadata
    api30 = {**rotated, 'signer_sha256': views['30']['signer_sha256']}
    plan = preflight(api30, serial, args.replace_existing_and_wipe_data, lock, evidence, 'v31-genuine')
    install(api30, serial, plan, lock, evidence, 'v31-genuine', result['device_mutations'])
    event, _, _, _ = launch_query(api30, serial, result['run_id'] + '-v31', 'T-P12', views['30']['signer_sha256'],
                                  own['package'], 'direct-current', lock, evidence, 'v31-genuine-query')
    if event['comparison'] != 'passed': raise RuntimeError('Actual API30 signer differs from SDK-specific host view')
    result['comparisons'].append({'name': 'v31-host-views-and-actual-api30', 'result': 'passed', 'views': views, 'event': event,
                                  'api35_runtime': 'not-run'})
    tests = execute([sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_artifacts.py'], evidence, 'artifact-unit-controls')
    if 'Ran 7 tests' not in tests.stdout + tests.stderr: raise RuntimeError('Artifact negative controls did not run completely')
    result['comparisons'].append({'name': 'artifact-schema-controls', 'result': 'passed', 'count': 7})
    result.update(verification='passed', transformation='applied', outputs=[str(default_path), str(combined_path)],
                  scope='Public APK/selected-set CLI, immutable marker/hash manifests, integrated API30 identity/routing/trust and refusal controls',
                  unsupported=['dex-only-mode', 'generic-app-runtime-verifier-until-M8', 'api35-runtime', 'containers-until-M5'])


def gate_integration(result, evidence, args):
    children = {}; cases = {}
    for name in ('M1b-2', 'T-P10', 'T-P11', 'T-P12'):
        path = args.reports / (name + '.json'); child = json.loads(path.read_text())
        if child['verification'] != 'passed' or (name != 'M1b-2' and child['source_sha256'] != source_hash()):
            raise PrerequisiteError(name + ' unavailable/failed/stale')
        children[name] = report_reference(path); cases[name] = child
    if any(child['cell'] != cases['T-P10']['cell'] for child in cases.values()): raise RuntimeError('Integration cells differ')
    if [len(cases[name]['comparisons']) for name in ('T-P10', 'T-P11', 'T-P12')] != [15, 8, 10]:
        raise RuntimeError('Integration controls incomplete')
    if cases['T-P11']['inputs'][0]['sha256'] != children['T-P10']['sha256'] or any(
            cases['T-P12']['inputs'][index]['sha256'] != children[name]['sha256'] for index, name in enumerate(('T-P10', 'T-P11'))):
        raise RuntimeError('Integration cases used different selected-set/lifecycle revisions')
    unsupported = sorted(set(cases['M1b-2']['unsupported'] + sum((cases[name]['unsupported'] for name in ('T-P10', 'T-P11', 'T-P12')), [])))
    result.update(verification='passed', gate_progress='accepted', children=children, cell=cases['T-P10']['cell'],
                  next_gate='M1b-4', scope='API30 selected-set, install/key lifecycle and integrated public artifact CLI', unsupported=unsupported)
