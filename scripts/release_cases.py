"""Join existing evidence for explicitly declared cells; never infer missing runtime coverage."""
import json
from pathlib import Path

from repack.pipeline import validate_toolchain
from repack.rebuild import ROOT, PrerequisiteError, load_lock, report_reference, sha256, source_hash, write_json
from scripts.acceptance import read_cell, select_serial


PACKETS = ('M0', 'BOOTSTRAP', 'M1b-5', 'M2', 'M3', 'M1a', 'M1b-1', 'M1b-2', 'M1b-3')


def packet(path, *, current=True, gate=True):
    reference = report_reference(path.resolve()); child = json.loads(Path(reference['path']).read_text())
    if child['verification'] != 'passed' or (gate and child.get('gate_progress') != 'accepted'):
        raise PrerequisiteError(path.name + ' not accepted')
    if current and child['source_sha256'] != source_hash(): raise PrerequisiteError(path.name + ' source is stale')
    for item in child.get('children', {}).values():
        if sha256(Path(item['path'])) != item['sha256']: raise RuntimeError('Changed child evidence: ' + item['path'])
    return child, reference


def run_t_a15(result, evidence, args):
    lock = load_lock(); serial = select_serial(lock, evidence, args.device); cell = read_cell(lock, evidence, serial)
    matrix_path = ROOT / 'config/support-matrix.json'; matrix = json.loads(matrix_path.read_text())
    if matrix['schema_version'] != 1 or len(matrix['release_cells']) != 1:
        raise PrerequisiteError('This runner joins one explicitly declared physical release cell')
    declared = matrix['release_cells'][0]
    if set(declared) != set('id serial api target_sdk min_sdk abi page_size user fingerprint execution access_mode metadata_adapter'.split()):
        raise PrerequisiteError('Release matrix lacks an exact cell declaration')
    if (declared['execution'] != 'physical-device-ordinary-adb-shell'
            or declared['access_mode'] != 'process-local-bypass' or declared['metadata_adapter'] != 'public-parcel-api30'):
        raise PrerequisiteError('Release cell declares an untested execution/access/adapter mode')
    for key, value in declared.items():
        if key in ('execution', 'access_mode', 'metadata_adapter'): continue
        if cell.get(key) != value: raise PrerequisiteError('Release cell changed: ' + key)
    if cell['ro_debuggable'] != '0' or cell['build_type'] != 'user' or not cell['shell_id'].startswith('uid=2000('):
        raise PrerequisiteError('Declared release requires ordinary non-root execution')
    # All packets are rerun with frozen source before this join, including the composed HTTPS CLI case.
    reports = {}; children = {}
    for name in (*PACKETS, 'T-A14'):
        reports[name], children[name] = packet(ROOT / '.work/evidence' / (name + '.json'), gate=name != 'T-A14')
        if reports[name]['cell'] != cell: raise RuntimeError('Release packet belongs to another cell: ' + name)
    process = reports['T-A14']
    if len(process['comparisons']) != 143 or len(process['observations']) != 11:
        raise RuntimeError('Process/restart/provider/rollback observations incomplete')
    if any(item['result'] != 'passed' for item in process['comparisons']): raise RuntimeError('Process comparison failed')
    tools = validate_toolchain(lock, device=True)
    engine = lock['resource_engine']
    for item in (engine, engine['compiler']):
        if sha256(Path(item['path'])) != item['sha256']: raise PrerequisiteError('Resource engine/compiler changed')
    snapshot = evidence / 'support-matrix.json'; write_json(snapshot, matrix)
    lock_snapshot = evidence / 'implementation-lock.json'; write_json(lock_snapshot, lock)
    result.update(verification='passed', cell=cell, children=children, toolchain=tools,
        matrix={'path': str(snapshot), 'sha256': sha256(snapshot), 'source_sha256': sha256(matrix_path)},
        lock={'path': str(lock_snapshot), 'sha256': sha256(lock_snapshot)},
        release_cells=matrix['release_cells'], excluded_cells=matrix['excluded_cells'], firmware_claim=matrix['firmware_claim'],
        scope='Declared API30/target35 physical arm64 4KB cell only; current-source identity, selected-set install, composed HTTPS and named Java pinning regressions',
        comparisons=[{'name': name, 'result': 'passed'} for name in children])


def gate_process(result, evidence, args):
    children = {}; reports = {}
    for name in ('M1b-3', 'T-A14', 'T-A15'):
        reports[name], children[name] = packet(args.reports / (name + '.json'), gate=name == 'M1b-3')
    if reports['T-A15']['children']['T-A14'] != children['T-A14']:
        raise RuntimeError('Matrix joined another process packet')
    if any(item['cell'] != reports['T-A14']['cell'] for item in reports.values()): raise RuntimeError('Process cells differ')
    unsupported = sorted(set(reports['M1b-3']['unsupported'] + reports['T-A14']['unsupported'])
                         - {'Binder-wrapper-failure-rollback-not-exercised'})
    result.update(verification='passed', gate_progress='accepted', cell=reports['T-A14']['cell'], children=children,
        scope=reports['T-A15']['scope'], release_cells=reports['T-A15']['release_cells'],
        excluded_cells=reports['T-A15']['excluded_cells'], unsupported=unsupported, next_gate='RELEASE-1')


def gate_release(result, evidence, args):
    children = {}; reports = {}
    for name in (*PACKETS, 'M1b-4'):
        reports[name], children[name] = packet(args.reports / (name + '.json'))
    matrix, matrix_ref = packet(args.reports / 'T-A15.json', gate=False)
    if reports['M1b-4']['children']['T-A15'] != matrix_ref: raise RuntimeError('Process gate used another release matrix')
    for name in PACKETS:
        if matrix['children'][name] != children[name]: raise RuntimeError('Matrix used another packet: ' + name)
    if any(item['cell'] != matrix['cell'] for item in reports.values()): raise RuntimeError('Release cell mismatch')
    lock = load_lock(); validate_toolchain(lock, device=True)
    if json.loads(Path(matrix['lock']['path']).read_text()) != lock: raise PrerequisiteError('Tool/access/device lock changed since matrix')
    if sha256(ROOT / 'config/support-matrix.json') != matrix['matrix']['source_sha256']:
        raise PrerequisiteError('Declared support matrix changed')
    result.update(verification='passed', gate_progress='accepted', cell=matrix['cell'], children=children,
        matrix=matrix_ref, release_cells=matrix['release_cells'], excluded_cells=matrix['excluded_cells'],
        firmware_claim=matrix['firmware_claim'],
        capabilities={'identity': reports['M1b-4']['scope'], 'routing': 'Implicit HTTP(S) startup routes on named Java clients; no OS-transition persistence claim',
            'trust': reports['M2']['scope'], 'java_pinning': reports['M3']['scope'],
            'selected_sets_and_install': reports['M1b-3']['scope']},
        unsupported=sorted(set(reports['M1b-4']['unsupported'] + ['OS-proxy-transition-persistence', 'off-USB-mobile-data',
            'explicit-direct-sockets', 'unmatched/native-network-stacks', 'fully-inlined-pinning-boundaries',
            'API36-CT', 'runtime-NSC', 'real-target-runtime', 'factory-stock-firmware-provenance'])),
        next_gate='M4 smoke experiment')
