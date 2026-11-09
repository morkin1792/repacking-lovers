"""Controlled late publication, process-local cache clear and same-key update evidence."""
import base64
import json
from pathlib import Path
import time

from repack.rebuild import (ROOT, PrerequisiteError, align_sign, copy_archive, ensure_keys, fixture_source_hash,
                            load_lock, report_reference, sha256, source_hash)
from repack.shim import build_bootstrap
from repack.verify import capture_startup, install, preflight, shell
from scripts.acceptance import read_cell, read_events, select_serial, tagged_events
from scripts.contract_cases import SELF, OTHER, sign_profile


def launch(result, evidence, artifact, serial, lock, label, *, sentinel=None):
    token = result['run_id'] + '-' + label
    shell(lock, evidence, label + '-stop', serial, ['am', 'force-stop', SELF])
    with capture_startup(lock, serial, evidence, label) as captured:
        command = ['am', 'start', '-W', '-n', SELF + '/.ProbeActivity', '--es', 'scenario', 'cache-state',
                   '--es', 'run_id', token, '--es', 'case_id', result['case_id']]
        if sentinel is not None: command += ['--es', 'sentinel_write', sentinel]
        shell(lock, evidence, label + '-launch', serial, command, check=False, timeout=10)
        pid = int(shell(lock, evidence, label + '-pid', serial, ['pidof', '-s', SELF]).stdout.strip())
        for _ in range(60):
            events = read_events(captured.read_text(errors='replace'), token)
            if any(item['query_path'] == 'state' for item in events): break
            time.sleep(.1)
    text = captured.read_text(errors='replace'); rows = {}
    for item in read_events(text, token):
        if item['pid'] != pid or item['case_id'] != result['case_id'] or item['scenario'] != 'cache':
            raise RuntimeError('Mismatched cache observation')
        path = item['query_path']
        if item['event'] == 'failure': raise RuntimeError('Cache fixture failed: ' + str(item))
        value = json.loads(item['response_marker'])
        if path in rows and rows[path] != value: raise RuntimeError('Conflicting cache observation')
        rows[path] = value
    if 'state' not in rows: raise RuntimeError('Cache fixture state absent')
    shim = [item for item in tagged_events(text, 'REPACK_SHIM') if item['pid'] == pid]
    return rows, shim, pid


def run_t_a11(result, evidence, args):
    lock = load_lock(); serial = select_serial(lock, evidence, args.device)
    result['cell'] = read_cell(lock, evidence, serial)
    if result['cell']['api'] != 30: raise PrerequisiteError('Cache descriptors and adapter are tested for API30 only')
    gate_path = ROOT / '.work/evidence/M1a.json'
    if json.loads(gate_path.read_text()).get('gate_progress') != 'accepted': raise PrerequisiteError('Accept M1a first')
    build_path = ROOT / '.work/evidence/M0-build.json'; build = json.loads(build_path.read_text())
    if build.get('fixture_source_sha256') != fixture_source_hash(): raise PrerequisiteError('Rebuild current cache fixtures first')
    original = next(item for item in build['outputs'] if item['id'] == 'app-own')
    other = next(item for item in build['outputs'] if item['id'] == 'other-own')
    result['inputs'] = [report_reference(gate_path), report_reference(build_path)]
    nonce = shell(lock, evidence, 'package-info-cache-nonce', serial, ['getprop', 'cache_key.package_info']).stdout.strip()
    result['package_info_cache_nonce_observed'] = nonce
    keys = ensure_keys(lock, evidence); certificate = Path(keys['original']['certificate']).read_bytes()
    output = ROOT / '.work/outputs/cache-controls' / result['run_id']
    for clear in (False, True):
        label = 'clear' if clear else 'no-clear'; part = evidence / label; part.mkdir()
        token = result['run_id'] + '-' + label
        artifact = build_bootstrap(Path(original['apk']), output / label, keys['repack'], lock, part,
            identity_mode='identity-deferred', probe_token=token, original_certificates=[certificate],
            original_scheme=3, signing_contracts=True, fixture_cache={'run_id': token, 'clear': clear,
                'original_certificate': base64.b64encode(certificate).decode()})
        for name, entry in [(label, artifact), (label + '-other', other)]:
            plan = preflight(entry, serial, args.replace_existing_and_wipe_data, lock, evidence, name)
            install(entry, serial, plan, lock, evidence, name, result['device_mutations'])
        rows, shim, pid = launch(result, evidence, artifact, serial, lock, label)
        if set(rows) != {'before', 'publication', 'after', 'state'}: raise RuntimeError('Incomplete cache stage observations')
        before, publication, after = (rows[name] for name in ('before', 'publication', 'after'))
        def expect(info, signer):
            if info['signers'] != signer: raise RuntimeError('Cache signer mismatch: ' + str(info))
        for field in ('current', 'legacy'): expect(before[field], [keys['repack']['sha256']])
        expect(before['other'], other['signer_sha256'])
        if before['counters']['self_queries'] != 0 or before['counters']['published']:
            raise RuntimeError('Identity was published before deliberate cache prewarming')
        if not publication['published'] or publication['cache_clear_count'] != int(clear):
            raise RuntimeError('Late publication/one-shot clear failed')
        cached = before['repeated_same_object']
        wanted = original['signer_sha256'] if clear or not cached else artifact['signer_sha256']
        for field in ('current', 'repeat', 'legacy', 'new_context'): expect(after[field], wanted)
        expect(after['new_flags'], original['signer_sha256']); expect(after['no_flags'], [])
        expect(after['retained'], artifact['signer_sha256']); expect(after['retained_legacy'], artifact['signer_sha256'])
        expect(after['other'], other['signer_sha256'])
        if after['after_first']['self_queries'] != after['after_repeat']['self_queries'] and cached:
            raise RuntimeError('Repeated cache lookup unexpectedly recomputed')
        if not after['existing_manager_predicate'] or not after['new_manager_predicate']:
            raise RuntimeError('Existing/new manager mPM path missed proxy')
        completed = [item for item in shim if item['details'].get('metadata_source') == 'embedded-host-verified-certificates']
        if len(completed) != 1 or completed[0]['details']['existing_managers'] < 1:
            raise RuntimeError('Pre-existing manager was not observed and patched')
        fields = ('uid', 'source_dir', 'version_code')
        if any(after['current'][key] != before['current'][key] for key in fields):
            raise RuntimeError('Cache transformation changed installed fields')
        result['comparisons'].append({'name': label, 'result': 'passed', 'prewarmed_cache_observed': cached,
            'rows': rows, 'publication': completed[0], 'pid': pid,
            'retained_result_gap': 'Already-returned PackageInfo retains real signer; it is never mutated'})
        result['outputs'].append(artifact)

    # A changed original input/certificate is re-patched with the same persistent operator key.
    # Same-version -r is an ordinary compatible Android update and must preserve app-private data.
    sources = [original, sign_profile(original, ['other'], lock, keys, evidence / 'changed-original')]
    previous_uid = None; previous_pid = None; sentinel = result['run_id'] + '-private-sentinel'
    updates = []
    for index, (source, key_name) in enumerate(zip(sources, ('original', 'other'))):
        label = 'update-' + str(index); part = evidence / label; part.mkdir()
        artifact = build_bootstrap(Path(source['apk']), output / label, keys['repack'], lock, part,
            identity_mode='identity', probe_token=result['run_id'] + '-' + label,
            original_certificates=[Path(keys[key_name]['certificate']).read_bytes()], original_scheme=3, signing_contracts=True)
        plan = preflight(artifact, serial, False, lock, evidence, label)
        if plan['replace']: raise RuntimeError('Compatible update planned an uninstall')
        install(artifact, serial, plan, lock, evidence, label, result['device_mutations'])
        rows, shim, pid = launch(result, evidence, artifact, serial, lock, label, sentinel=sentinel if index == 0 else None)
        state = rows['state']
        if state['sentinel'] != sentinel or state['signers'] != source['signer_sha256'] or state['input_sha256'] != source['sha256']:
            raise RuntimeError('Compatible update lost data or reused stale input/signing metadata')
        if index and (state['uid'] != previous_uid or pid == previous_pid): raise RuntimeError('Update UID/process lifetime mismatch')
        previous_uid, previous_pid = state['uid'], pid
        updates.append({'state': state, 'plan': plan, 'pid': pid, 'artifact': artifact})
    if sources[0]['sha256'] == sources[1]['sha256']: raise RuntimeError('Update input did not actually change')
    result['comparisons'].append({'name': 'compatible-update-input-invalidation', 'result': 'passed', 'updates': updates})
    result.update(verification='passed', transformation='applied',
        scope='API30 prewarmed package/flags/current-user cache; existing/new mPM references; retained-object gap; compatible same-key update',
        unsupported=['typed-long-public-overload-absent-on-API30', 'cross-user-keys', 'already-returned-results', 'unobserved-contexts'])
    if not any(item.get('prewarmed_cache_observed') for item in result['comparisons']):
        result['unsupported'].append('prewarmed-cache-hit-repair-not-observed')


def gate_contracts(result, evidence, args):
    children = {}; cases = {}
    for name in ('M1a', 'T-A10', 'T-A11'):
        path = args.reports / (name + '.json'); child = json.loads(path.read_text())
        if child['verification'] != 'passed' or (name != 'M1a' and child['source_sha256'] != source_hash()):
            raise PrerequisiteError(name + ' unavailable/failed/stale')
        children[name] = report_reference(path); cases[name] = child
    if any(child['cell'] != cases['T-A10']['cell'] for child in cases.values()): raise RuntimeError('Signing contract cells differ')
    if len(cases['T-A10']['comparisons']) != 362 or len(cases['T-A10']['profiles']) != 7 or len(cases['T-A11']['comparisons']) != 3:
        raise RuntimeError('Signing contract/cache controls incomplete')
    if any(item['result'] != 'passed' for name in ('T-A10', 'T-A11') for item in cases[name]['comparisons']):
        raise RuntimeError('Signing contract/cache comparison failed')
    unsupported = ['shared-UIDs', 'cross-user', 'other-API-levels', 'already-returned-results', 'unobserved-contexts', 'JNI/fresh-Binder-until-M1b-2']
    unsupported.extend(item for item in cases['T-A11']['unsupported'] if item not in unsupported)
    result.update(verification='passed', gate_progress='accepted', children=children, cell=cases['T-A10']['cell'],
        next_gate='M1b-2', metadata_adapter='public-parcel-api30',
        scope='API30 tested predicates, comparisons, signing flag/list contracts, multi-signer/rotation and cache/update controls',
        unsupported=unsupported)
