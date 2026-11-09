"""Bounded, deterministic plain-repack/startup experiments; no model dependency.

Rules recognize configurations, not arbitrary security-check implementations.
Every hypothesis is rebuilt from one immutable baseline and tested on-device.
"""
from __future__ import annotations

import itertools
import json
from pathlib import Path
import re
import subprocess
import time
import zipfile

from .pipeline import resolve_key, validate_toolchain
from .rebuild import (ROOT, PrerequisiteError, align_sign, copy_archive, environment,
                      execute, sha256, tool, write_json)
from .recon import inspect_input
from .shim import manifest_editor
from .startup_analysis import discover_signer_payloads, rewrite_signer_payloads
from .trust import decode_resources, rebuild_resources
from .verify import capture_startup, install, preflight, shell


def classify_log(raw: str, package: str) -> dict:
    """Attribute Java/native crashes and ANRs to this package, including services."""
    escaped = re.escape(package)
    own = re.compile(r'Process:\s*' + escaped + r'(?::[\w.]+)?,\s*PID:\s*(\d+)')
    crashes = []
    for block in re.split(r'(?=FATAL EXCEPTION:)', raw)[1:]:
        match = own.search(block)
        if not match: continue
        # Stop at the next fatal; unrelated processes never qualify by PID alone.
        phase = ('application-init' if re.search(r'Unable to (?:create|instantiate) application', block, re.I)
                 else 'service-init' if re.search(r'Unable to (?:create|instantiate) service', block, re.I)
                 else 'java-background')
        causes = re.findall(r'(?:Caused by: )?((?:java|android|kotlin)\.[\w.$]+(?:Exception|Error)(?::[^\n]*)?)', block)
        frames = re.findall(r'\bat ([\w.$]+\([^\n]+\))', block)
        crashes.append({'phase': phase, 'pid': int(match[1]), 'causes': causes[:8], 'frames': frames[:12]})
    native = bool(re.search(r'>>>\s*' + escaped + r'(?::[\w.]+)?\s*<<<', raw))
    anr = bool(re.search(r'\bANR in ' + escaped + r'(?::[\w.]+)?(?:\s|$)', raw))
    phase = crashes[0]['phase'] if crashes else 'native-crash' if native else 'anr' if anr else None
    return {'failure_phase': phase, 'java_crashes': crashes, 'native_crash': native, 'anr': anr}


def next_hypothesis(axes: list[dict], attempts: list[dict]) -> tuple[str, ...] | None:
    """Small best-first subset search. Failures guide ordering, never certify a fix."""
    tried = {tuple(row['selected']) for row in attempts}
    possible = [tuple(a['id'] for a in subset) for n in range(len(axes) + 1)
                for subset in itertools.combinations(axes, n)]
    pending = [value for value in possible if value not in tried]
    if not pending: return None
    if not attempts: return ()
    last = attempts[-1]; selected = set(last['selected'])
    phase = last.get('observation', {}).get('failure_phase')
    desired = 'signer-payload' if phase == 'application-init' else 'package-visibility'
    ids = {a['id'] for a in axes if a['kind'] == desired}
    # Prefer adding one relevant change to the current partial result; retain all
    # combinations for cases where classification is incomplete or misleading.
    def priority(value):
        changed = set(value) ^ selected
        addition = set(value) - selected
        return (0 if addition & ids else 1, len(changed), len(value), value)
    return min(pending, key=priority)


def search(axes: list[dict], trial, max_trials: int, checkpoint) -> dict:
    if not 1 <= max_trials <= 32: raise ValueError('Trial budget must be 1..32')
    if len(axes) > 6 or len({a['id'] for a in axes}) != len(axes):
        raise ValueError('Search supports at most six uniquely identified repair axes')
    attempts = []; winner = None
    while len(attempts) < max_trials:
        selected = next_hypothesis(axes, attempts)
        if selected is None: break
        row = {'trial': len(attempts) + 1, 'selected': list(selected),
               'rationale': 'Plain resource rebuild baseline' if not selected else
               'Next untried combination selected by the previous failure phase'}
        attempts.append(row); checkpoint({'status': 'running', 'attempts': attempts, 'winner': None})
        # Infrastructure errors propagate; a disconnected device is not an app failure.
        row.update(trial(selected, len(attempts)))
        if row['observation']['startup_liveness'] == 'passed':
            confirmation = trial(selected, len(attempts), confirm=row)
            row['confirmation'] = confirmation
            if (confirmation['observation']['startup_liveness'] == 'passed'
                    and confirmation['artifact'] == row['artifact']):
                winner = len(attempts); checkpoint({'status': 'passed', 'attempts': attempts, 'winner': winner}); break
            row['observation'] = {**row['observation'], 'startup_liveness': 'failed', 'failure_phase': 'confirmation-failed'}
        checkpoint({'status': 'running', 'attempts': attempts, 'winner': winner})
    result = {'status': 'passed' if winner else 'exhausted', 'attempts': attempts, 'winner': winner,
              'untried_combinations': 2 ** len(axes) - len(attempts), 'trial_budget': max_trials,
              'functional_verification': 'not-run'}
    checkpoint(result)
    return result


def _manifest_command(lock: dict, evidence: Path) -> list[str]:
    jar, _ = manifest_editor(lock, evidence)
    classes = evidence / 'startup-manifest-classes'; classes.mkdir()
    execute([tool(lock, 'javac'), '--release', '8', '-cp', str(jar), '-d', str(classes),
             str(ROOT / 'tools/StartupManifest.java')], evidence, 'startup-manifest-compile', env=environment(lock))
    return [tool(lock, 'java'), '-cp', str(classes) + ':' + str(jar), 'StartupManifest']


def _installed_hashes(artifact: dict, serial: str, lock: dict, evidence: Path, label: str) -> None:
    state = shell(lock, evidence, label + '-paths', serial, ['pm', 'path', artifact['package']], timeout=20)
    paths = [line[8:] for line in state.stdout.splitlines() if line.startswith('package:')]
    digests = []
    for i, path in enumerate(paths):
        result = shell(lock, evidence, label + '-hash-' + str(i), serial, ['sha256sum', path], timeout=30)
        digests.append(result.stdout.split()[0])
    if sorted(digests) != sorted(m['sha256'] for m in artifact['members']):
        raise RuntimeError('Installed APK set differs from trial artifact')


def window_focus(text: str) -> list[str]:
    focus = [line.strip() for line in text.splitlines() if 'mCurrentFocus=' in line]
    if not focus: raise PrerequisiteError('Window focus field unavailable; startup oracle is inconclusive')
    return focus


def observe_startup(artifact: dict, serial: str, lock: dict, evidence: Path, seconds: int, user: int) -> dict:
    """Cold launch, own-package liveness, target crash/ANR oracle, no UI actions."""
    package = artifact['package']; evidence.mkdir()
    _installed_hashes(artifact, serial, lock, evidence, 'installed')
    resolve = shell(lock, evidence, 'launcher', serial,
        ['cmd', 'package', 'resolve-activity', '--brief', '--user', str(user), '-a', 'android.intent.action.MAIN',
         '-c', 'android.intent.category.LAUNCHER', package], timeout=20).stdout
    components = [line.strip() for line in resolve.splitlines() if line.strip().startswith(package + '/')]
    if len(components) != 1: raise PrerequisiteError('No unique launcher activity for startup observation')
    samples = []; log_path = None; launch = None
    try:
        with capture_startup(lock, serial, evidence, 'startup') as log_path:
            shell(lock, evidence, 'cold-stop', serial, ['am', 'force-stop', '--user', str(user), package], timeout=20)
            shell(lock, evidence, 'wake', serial, ['input', 'keyevent', 'KEYCODE_WAKEUP'], timeout=15)
            launch = shell(lock, evidence, 'launch', serial,
                           ['am', 'start', '-W', '--user', str(user), '-n', components[0]], check=False, timeout=30)
            start = time.monotonic()
            for point in range(5, seconds + 1, 5):
                while time.monotonic() - start < point: time.sleep(.2)
                pid = shell(lock, evidence, f't{point}-pid', serial, ['pidof', package], check=False, timeout=15)
                if pid.returncode not in (0, 1) or pid.stderr.strip(): raise PrerequisiteError('Device PID probe failed')
                window = shell(lock, evidence, f't{point}-window', serial, ['dumpsys', 'window'], timeout=20).stdout
                focus = window_focus(window)
                samples.append({'second': point, 'pid': pid.stdout.strip(), 'focus': focus})
                raw = log_path.read_text(errors='replace').split(evidence.name + '-startup-start', 1)[-1]
                classified = classify_log(raw, package)
                if classified['failure_phase'] or not pid.stdout.strip(): break
            # Final screen/UI evidence can show a maintenance/login/error page even
            # when the narrow startup oracle passes. Preserve it for human review.
            screen = evidence / 'screen.png'
            with screen.open('wb') as image:
                captured = subprocess.run([tool(lock, 'adb'), '-s', serial, 'exec-out', 'screencap', '-p'],
                    stdout=image, stderr=subprocess.PIPE, env=environment(lock), timeout=20)
            screen.chmod(0o600)
            write_json(evidence / 'screen.json', {'path': str(screen), 'sha256': sha256(screen),
                'exit_status': captured.returncode, 'stderr': captured.stderr.decode(errors='replace')})
            shell(lock, evidence, 'ui-dump', serial, ['uiautomator', 'dump', '/dev/tty'], check=False, timeout=20)
    finally:
        shell(lock, evidence, 'stop-after-observation', serial,
              ['am', 'force-stop', '--user', str(user), package], check=False, timeout=20)
    raw = log_path.read_text(errors='replace').split(evidence.name + '-startup-start', 1)[-1]
    classified = classify_log(raw, package)
    stable = bool(samples and samples[0]['pid']) and len({s['pid'] for s in samples}) == 1
    foreground = bool(samples) and all(any(package + '/' in f and 'Application Error' not in f for f in s['focus']) for s in samples)
    duration = bool(samples) and samples[-1]['second'] == seconds
    launch_ok = launch.returncode == 0 and not re.search(r'(?m)^Error(?: type \d+)?:', launch.stdout + launch.stderr)
    passed = stable and foreground and duration and launch_ok and not classified['failure_phase']
    if not classified['failure_phase'] and not passed:
        classified['failure_phase'] = 'process-exit' if not stable else 'not-foreground' if not foreground else 'launch-failed'
    _installed_hashes(artifact, serial, lock, evidence, 'installed-after')
    result = {**classified, 'startup_liveness': 'passed' if passed else 'failed', 'samples': samples,
        'process_stable': stable, 'foreground_all_samples': foreground, 'observation_seconds': seconds,
        'artifact_hashes_verified': True, 'functional_verification': 'not-run',
        'log': {'path': str(log_path), 'sha256': sha256(log_path)},
        'interpretation': 'Foreground process survived the bounded window; login/service behavior is unverified'}
    write_json(evidence / 'observation.json', result)
    return result


def startup(input_ref: str, options: dict, lock: dict, evidence: Path, mutations: list) -> dict:
    """Run a standalone repair search, retaining all trial outputs and decisions."""
    if not options['replace_existing_and_wipe_data']:
        raise PrerequisiteError('Startup trials clear target app data; --replace-existing-and-wipe-data is required')
    seconds = options.get('observe_seconds', 60); max_trials = options.get('max_trials', 8)
    if not 15 <= seconds <= 300 or seconds % 5: raise ValueError('Observation must be 15..300 seconds, in steps of five')
    if not 1 <= max_trials <= 32: raise ValueError('Trial budget must be 1..32')
    validate_toolchain(lock, device=True)
    out = Path(options['out']).resolve(); out.mkdir(parents=True, exist_ok=False)
    out.chmod(0o700)
    serial = options['device']; key = resolve_key(Path(options['key']), lock, evidence)
    inventory = inspect_input(input_ref, serial, lock, evidence / 'input')
    write_json(out / 'input.json', inventory)
    members = inventory['members']; base = next(m for m in members if not m.get('split'))
    axes = []; analyses = []
    for index, member in enumerate(members):
        with zipfile.ZipFile(member['apk']) as archive:
            has_dex = 'classes.dex' in archive.namelist()
        if not has_dex: continue
        analysis = discover_signer_payloads(Path(member['apk']), inventory['signer_sha256'],
                                           inventory['api'], lock, evidence / f'analysis-{index}')
        analyses.append({'member': member['sha256'], **analysis})
        for candidate in analysis['candidates']:
            axes.append({'id': f'signer-{index}-{candidate["id"]}', 'kind': 'signer-payload',
                         'member_sha256': member['sha256'], 'candidate': candidate})
    command = _manifest_command(lock, evidence)
    with zipfile.ZipFile(base['apk']) as archive: original_manifest = archive.read('AndroidManifest.xml')
    manifest_in = evidence / 'original.axml'; manifest_in.write_bytes(original_manifest)
    inventory_text = execute([*command, 'inspect', str(manifest_in)], evidence, 'visibility-inventory', env=environment(lock)).stdout
    match = re.fullmatch(r'query_all_packages=(\d+)\s*', inventory_text)
    if not match: raise RuntimeError('Malformed permission inventory')
    if int(match[1]): axes.append({'id': 'narrow-package-visibility', 'kind': 'package-visibility',
        'permission': 'android.permission.QUERY_ALL_PACKAGES', 'preserves_explicit_queries': True,
        'tradeoff': 'Changes installed-package enumeration; app functionality requires separate testing'})
    if len(axes) > 6: raise PrerequisiteError('More than six candidate axes; analysis retained, no installation attempted')
    prepared = {}; build_dir = evidence / 'baseline'; build_dir.mkdir()
    # Cache the expensive resource round trip once. Every hypothesis starts here.
    decode_resources(Path(base['apk']), build_dir / 'decoded', lock, build_dir)
    rebuilt = rebuild_resources(Path(base['apk']), build_dir / 'decoded', build_dir / 'rebuilt.apk', lock, build_dir)
    for member in members:
        prepared[member['sha256']] = Path(rebuilt['unsigned_apk']) if not member.get('split') else Path(member['apk'])
    write_json(out / 'analysis.json', {'axes': axes, 'dex': analyses, 'resource_rebuild': rebuilt,
        'strategy': 'bounded-subset-search', 'model_dependency': False})
    summary = {'schema_version': 1, 'package': inventory['package'], 'input_signer_sha256': inventory['signer_sha256'],
        'test_signer_sha256': key['sha256'], 'evidence': str(evidence), 'axes': axes,
        'scope': 'Plain resource rebuild and startup compatibility', 'pinning_changes': False,
        'routing_changes': False, 'embedded_ca': False, 'functional_verification': 'not-run'}
    def checkpoint(state): write_json(out / 'startup-search.json', {**summary, **state})
    cache = {}
    def trial(selected, number, confirm=None):
        trial_dir = out / f'trial-{number:02d}'; logs = evidence / (f'trial-{number:02d}' + ('-confirm' if confirm else ''))
        logs.mkdir()
        if confirm is None:
            trial_dir.mkdir(); outputs = []
            chosen = [a for a in axes if a['id'] in selected]
            print('STARTUP trial', number, list(selected) or ['plain-rebuild'], flush=True)
            for index, member in enumerate(members):
                if sha256(Path(member['apk'])) != member['sha256']: raise RuntimeError('Input APK changed during search')
                changes = [a for a in chosen if a.get('member_sha256') == member['sha256']]
                visibility = not member.get('split') and 'narrow-package-visibility' in selected
                signature = (member['sha256'], tuple(a['id'] for a in changes), visibility)
                if signature not in cache:
                    part = logs / str(index); part.mkdir(); replacements = {}; current = prepared[member['sha256']]
                    with zipfile.ZipFile(current) as archive:
                        for dex in sorted({a['candidate']['dex'] for a in changes}):
                            replacements[dex] = rewrite_signer_payloads(archive.read(dex),
                                [a['candidate'] for a in changes if a['candidate']['dex'] == dex], key['sha256'])
                        if visibility:
                            before = part / 'before.axml'; before.write_bytes(archive.read('AndroidManifest.xml'))
                            after = part / 'after.axml'
                            execute([*command, 'remove', str(before), str(after)], part, 'visibility-edit', env=environment(lock))
                            replacements['AndroidManifest.xml'] = after.read_bytes()
                    unsigned = part / 'unsigned.apk'; copy_archive(current, unsigned, replacements=replacements)
                    apk = trial_dir / f'{index:03d}.apk'; align_sign(unsigned, apk, key, lock, part)
                    cache[signature] = {'apk': str(apk), 'sha256': sha256(apk), 'split': member.get('split')}
                outputs.append(dict(cache[signature]))
            artifact = {'package': inventory['package'], 'version_code': inventory['version_code'],
                        'signer_sha256': [key['sha256']], 'members': outputs}
            artifact_path = trial_dir / 'artifact.json'; write_json(artifact_path, artifact)
            plan = preflight(artifact, serial, True, lock, logs, 'startup', requested_package=inventory['package'])
            install(artifact, serial, plan, lock, logs, 'startup', mutations)
            response = shell(lock, logs, 'clear-trial-data', serial,
                             ['pm', 'clear', '--user', str(plan['user']), inventory['package']], timeout=30)
            if response.stdout.strip() != 'Success': raise RuntimeError('Target app data clear did not report Success')
            mutations.append({'action': 'clear-app-data', 'package': inventory['package'], 'user': plan['user'], 'trial': number})
        else:
            artifact_path = Path(confirm['artifact'])
            if sha256(artifact_path) != confirm['artifact_manifest_sha256']:
                raise RuntimeError('Artifact manifest changed before confirmation')
            artifact = json.loads(artifact_path.read_text())
            plan = {'user': confirm['user']}
            print('STARTUP confirming trial', number, flush=True)
        observation = observe_startup(artifact, serial, lock, logs / 'observe', seconds, plan['user'])
        print('STARTUP outcome', number, observation['startup_liveness'], observation['failure_phase'] or '', flush=True)
        return {'artifact': str(artifact_path), 'artifact_manifest_sha256': sha256(artifact_path),
                'user': plan['user'], 'observation': observation}
    try:
        searched = search(axes, trial, max_trials, checkpoint)
    except (Exception, KeyboardInterrupt) as error:
        previous = json.loads((out / 'startup-search.json').read_text()) if (out / 'startup-search.json').exists() else summary
        write_json(out / 'startup-search.json', {**previous, 'status': 'interrupted', 'error': str(error) or 'Operator interruption',
            'error_class': type(error).__name__, 'functional_verification': 'not-run'})
        raise
    return {'startup_verification': searched['status'], 'manifest': str(out / 'startup-search.json'),
            'trials': len(searched['attempts']), 'winner': searched['winner'], 'functional_verification': 'not-run'}
