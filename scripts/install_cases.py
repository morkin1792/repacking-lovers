"""R-INSTALL/key lifecycle on the two owned fixtures only."""
import copy
import json
from pathlib import Path
import zipfile

from repack.rebuild import (ROOT, PrerequisiteError, align_sign, copy_archive, ensure_keys, environment, execute,
                            fixture_source_hash, load_lock, report_reference, sha256, tool)
from repack.recon import inspect_input
from repack.shim import manifest_editor
from repack.verify import adb, artifact_members, install, preflight, shell
from scripts.acceptance import read_cell, select_serial
from scripts.cache_cases import launch
from scripts.selected_cases import build_selected_fixture, repack_fixture_set

SELF = 'dev.repack.fixture.identity'


def changed_member(artifact, keys, lock, evidence, *, test_only=False):
    evidence.mkdir(parents=True); result = copy.deepcopy(artifact)
    member = next(item for item in result['members'] if not item.get('split')) if test_only else next(item for item in result['members'] if item.get('split') == 'feature.child')
    unsigned = evidence / 'unsigned.apk'; replacements = {}; additions = {}
    if test_only:
        with zipfile.ZipFile(member['apk']) as archive:
            manifest = evidence / 'manifest.axml'; manifest.write_bytes(archive.read('AndroidManifest.xml'))
        updated = evidence / 'updated.axml'; jar, editor = manifest_editor(lock, evidence)
        execute([tool(lock, 'java'), '-classpath', str(editor) + ':' + str(jar), 'ManifestEdit', 'fixture-test-only',
                 str(manifest), str(updated)], evidence, 'fixture-test-only', env=environment(lock))
        replacements['AndroidManifest.xml'] = updated.read_bytes()
    else: additions['assets/repack-fixture-update.txt'] = b'compatible-feature-update'
    copy_archive(Path(member['apk']), unsigned, replacements, additions)
    apk = evidence / 'changed.apk'; align_sign(unsigned, apk, keys['original' if test_only else 'repack'], lock, evidence)
    member.update(apk=str(apk), sha256=sha256(apk))
    if test_only: result['base'] = str(apk)
    return result


def run_t_p11(result, evidence, args):
    lock = load_lock(); serial = select_serial(lock, evidence, args.device); result['cell'] = read_cell(lock, evidence, serial)
    if not args.replace_existing_and_wipe_data: raise PrerequisiteError('This fixture lifecycle needs explicit fixture wipe authorization')
    prior_path = ROOT / '.work/evidence/T-P10.json'; prior = json.loads(prior_path.read_text())
    if prior['verification'] != 'passed': raise PrerequisiteError('Accept selected-set runtime controls first')
    build_path = ROOT / '.work/evidence/M0-build.json'; baseline = json.loads(build_path.read_text())
    if baseline.get('fixture_source_sha256') != fixture_source_hash(): raise PrerequisiteError('Build current generic-state fixtures first')
    result['inputs'] = [report_reference(prior_path), report_reference(build_path), report_reference(ROOT / '.work/evidence/M1b-2.json')]
    keys = ensure_keys(lock, evidence); key_before = sha256(Path(keys['repack']['path']))
    selected = build_selected_fixture(baseline, keys, lock, evidence / 'fixture')
    genuine = inspect_input(str(selected), serial, lock, evidence / 'genuine-inventory')
    patched = repack_fixture_set(genuine, keys, lock, evidence / 'patched')
    update = changed_member(patched, keys, lock, evidence / 'compatible-update')
    response = adb(lock, evidence, 'clear-owned-fixture', ['uninstall', SELF], serial=serial)
    if 'Success' not in response.stdout: raise RuntimeError('Owned fixture initial cleanup did not succeed')
    result['device_mutations'].append({'action': 'uninstall', 'package': SELF, 'data_loss': True, 'reason': 'explicit-owned-fixture-absent-control'})
    plan = preflight(patched, serial, False, lock, evidence, 'absent')
    if plan['existing_paths'] or plan['replace']: raise RuntimeError('Absent control was not absent')
    install(patched, serial, plan, lock, evidence, 'absent', result['device_mutations'])
    sentinel = result['run_id'] + '-private-data'
    rows, _, first_pid = launch(result, evidence, patched, serial, lock, 'absent-state', sentinel=sentinel)
    first = rows['state']
    if first['sentinel'] != sentinel or first['signers'] != genuine['signer_sha256']: raise RuntimeError('Absent install/sentinel/public identity failed')
    result['comparisons'].append({'name': 'absent-install', 'result': 'passed', 'plan': plan, 'state': first})
    # A controlled known installer is setup evidence, never invented provenance for user APKs.
    response = adb(lock, evidence, 'known-installer-seed', ['install-multiple', '-r', '-i', 'com.android.shell',
                   *[item['apk'] for item in artifact_members(patched)]], serial=serial)
    if 'Success' not in response.stdout: raise RuntimeError('Owned known-installer setup failed')
    result['device_mutations'].append({'action': 'fixture-installer-seed', 'package': SELF, 'installer': 'com.android.shell'})
    plan = preflight(update, serial, False, lock, evidence, 'compatible')
    if plan['replace'] or plan['existing_installer'] != 'com.android.shell': raise RuntimeError('Compatible update selected uninstall/wrong installer')
    install(update, serial, plan, lock, evidence, 'compatible', result['device_mutations'])
    rows, _, second_pid = launch(result, evidence, update, serial, lock, 'compatible-state'); second = rows['state']
    if (second['sentinel'] != sentinel or second['uid'] != first['uid'] or first_pid == second_pid
            or second['installer_legacy'] != 'com.android.shell' or second['installer_installing'] != 'com.android.shell'):
        raise RuntimeError('Compatible update lost data/UID or known installer')
    result['comparisons'].append({'name': 'compatible-update', 'result': 'passed', 'plan': plan, 'state': second,
                                  'changed_member_sha256': next(item['sha256'] for item in update['members'] if item.get('split') == 'feature.child')})

    before = shell(lock, evidence, 'mismatch-before', serial, ['pm', 'path', SELF]).stdout
    mutation_count = len(result['device_mutations'])
    try: preflight(genuine, serial, False, lock, evidence, 'mismatch-no-authorization')
    except PrerequisiteError as error:
        if 'signer differs' not in str(error): raise
    else: raise RuntimeError('Unapproved signer mismatch was accepted')
    after = shell(lock, evidence, 'mismatch-after', serial, ['pm', 'path', SELF]).stdout
    rows, _, _ = launch(result, evidence, update, serial, lock, 'mismatch-state')
    if before != after or len(result['device_mutations']) != mutation_count or rows['state']['sentinel'] != sentinel:
        raise RuntimeError('Unapproved mismatch changed package/data')
    result['comparisons'].append({'name': 'mismatched-signer-refusal', 'result': 'passed', 'state': rows['state']})
    plan = preflight(genuine, serial, True, lock, evidence, 'authorized-replacement')
    if not plan['replace']: raise RuntimeError('Different signer did not select explicit replacement')
    install(genuine, serial, plan, lock, evidence, 'authorized-replacement', result['device_mutations'])
    rows, _, _ = launch(result, evidence, genuine, serial, lock, 'replacement-state'); replaced = rows['state']
    if replaced['sentinel'] != 'absent' or replaced['signers'] != genuine['signer_sha256'] or replaced['input_sha256'] is not None:
        raise RuntimeError('Replacement did not show expected data loss/genuine installation')
    result['comparisons'].append({'name': 'explicit-replacement-data-loss', 'result': 'passed', 'plan': plan, 'state': replaced})
    failure_sentinel = result['run_id'] + '-before-failure'
    rows, _, _ = launch(result, evidence, genuine, serial, lock, 'before-failure-state', sentinel=failure_sentinel)
    failures_before = rows['state']; paths_before = shell(lock, evidence, 'failed-install-before', serial, ['pm', 'path', SELF]).stdout
    test_only = changed_member(genuine, keys, lock, evidence / 'test-only', test_only=True)
    plan = preflight(test_only, serial, False, lock, evidence, 'platform-failure')
    try: install(test_only, serial, plan, lock, evidence, 'platform-failure', result['device_mutations'])
    except RuntimeError as error:
        if 'Installer did not report Success' not in str(error): raise
    else: raise RuntimeError('Platform accepted testOnly APK without -t; negative control is invalid')
    output = (evidence / 'platform-failure-install.stderr.log').read_text() + (evidence / 'platform-failure-install.stdout.log').read_text()
    if 'INSTALL_FAILED_TEST_ONLY' not in output: raise RuntimeError('Platform failure had an unexpected cause')
    rows, _, _ = launch(result, evidence, genuine, serial, lock, 'after-failure-state')
    paths_after = shell(lock, evidence, 'failed-install-after', serial, ['pm', 'path', SELF]).stdout
    if paths_before != paths_after or rows['state']['sentinel'] != failure_sentinel or rows['state']['uid'] != failures_before['uid']:
        raise RuntimeError('Failed compatible install changed previous package/data')
    result['comparisons'].append({'name': 'platform-install-failure-state', 'result': 'passed', 'state': rows['state'], 'failure': 'INSTALL_FAILED_TEST_ONLY'})
    for label in ('missing-member', 'changed-member'):
        candidate = copy.deepcopy(patched); item = candidate['members'][-1]
        if label == 'missing-member': item['apk'] = str(evidence / 'not-present.apk')
        else:
            corrupt = evidence / 'changed-member.apk'; corrupt.write_bytes(Path(item['apk']).read_bytes() + b'changed'); item['apk'] = str(corrupt)
        count_before = len(result['device_mutations'])
        try: preflight(candidate, serial, True, lock, evidence, label)
        except FileNotFoundError:
            if label != 'missing-member': raise
        except RuntimeError as error:
            if label != 'changed-member' or 'hash changed' not in str(error): raise
        else: raise RuntimeError('Bad member passed preflight')
        rows, _, _ = launch(result, evidence, genuine, serial, lock, label + '-state')
        if len(result['device_mutations']) != count_before or rows['state']['sentinel'] != failure_sentinel:
            raise RuntimeError('Bad preflight member reached uninstall/data loss')
        result['comparisons'].append({'name': label + '-before-uninstall', 'result': 'passed', 'state': rows['state']})
    if sha256(Path(keys['repack']['path'])) != key_before: raise RuntimeError('Persistent operator fixture key changed')
    result['comparisons'].append({'name': 'persistent-signing-key', 'result': 'passed', 'signer_sha256': keys['repack']['sha256']})
    result.update(verification='passed', transformation='applied', outputs=[genuine, patched, update, test_only],
                  scope='Owned selected-set install/key lifecycle, known installer, private sentinel and measured failure state',
                  unsupported=['recovery-guarantee', 'other-Android-users', 'user-app-replacement-without-explicit-approval'])
