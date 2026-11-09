"""The three M1b-5 fixture cases and their owned local oracles."""
from contextlib import contextmanager
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import threading
import time

from repack.rebuild import (ROOT, PrerequisiteError, ensure_keys, fixture_source_hash, load_lock,
                            report_reference, sha256, source_hash, write_json)
from repack.shim import build_bootstrap, parse_proxy
from repack.verify import adb, install, owned_reverse, preflight, shell
from scripts.acceptance import read_cell, read_events, select_serial, tagged_events

MITM_VERSION = '12.3.1'
MITM_WHEEL_SHA256 = '87afb808ac8d55383dbe6aa30eadeb0fedaeffd26210e7e23c25c9cd43bdb36a'


def inputs(result, evidence, args):
    lock = load_lock()
    serial = select_serial(lock, evidence, args.device)
    result['cell'] = read_cell(lock, evidence, serial)
    bootstrap = ROOT / '.work/evidence/BOOTSTRAP.json'
    if json.loads(bootstrap.read_text()).get('gate_progress') != 'accepted':
        raise PrerequisiteError('Accept BOOTSTRAP first')
    baseline = ROOT / '.work/evidence/M0-build.json'
    build = json.loads(baseline.read_text())
    if build['verification'] != 'passed' or build.get('fixture_source_sha256') != fixture_source_hash():
        raise PrerequisiteError('Build current network fixtures first')
    result['inputs'] = [report_reference(bootstrap), report_reference(baseline)]
    keys = ensure_keys(lock, evidence)
    own = next(x for x in build['outputs'] if x['id'] == 'app-own')
    other = next(x for x in build['outputs'] if x['id'] == 'other-own')
    if sha256(Path(own['apk'])) != own['sha256'] or sha256(Path(other['apk'])) != other['sha256']:
        raise RuntimeError('Fixture artifact changed')
    return lock, serial, keys, own, other


@contextmanager
def oracle(evidence, bind, port=8080, *, confdir=None, capture=None):
    executable = ROOT / ('.work/tools/mitmproxy-' + MITM_VERSION + '/bin/mitmdump')
    wheel = ROOT / ('.work/tools/wheels/mitmproxy-' + MITM_VERSION + '-py3-none-any.whl')
    if not executable.exists() or not wheel.exists() or sha256(wheel) != MITM_WHEEL_SHA256:
        raise PrerequisiteError('Pinned project-local mitmproxy installation missing/changed')
    evidence.mkdir(parents=True)
    # Refuse to collide with a process owned by the operator or another run.
    with socket.socket() as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind((bind, port))
    command = [str(executable), '--listen-host', bind, '-p', str(port), '-s', str(ROOT / 'scripts/mitm_oracle.py'),
               '--set', 'connection_strategy=lazy', '--set', 'upstream_cert=false',
               '--set', 'confdir=' + str(confdir or ROOT / '.work/keys/mitmproxy')]
    env = os.environ.copy()
    if capture is not None:
        command.extend(['-s', str(ROOT / 'scripts/mitm_capture.py')])
        env['REPACK_CAPTURE_LOG'] = str(capture)
        env.pop('REPACK_IDENTIFYING_HEADER', None)
    env['REPACK_ORACLE_LOG'] = str(evidence / 'requests.jsonl')
    write_json(evidence / 'proxy-command.json', {'argv': command, 'wheel_sha256': sha256(wheel),
               'version': MITM_VERSION, 'addon_sha256': sha256(ROOT / 'scripts/mitm_oracle.py')})
    metadata = subprocess.run([str(executable.parent / 'python'), '-c',
        'import importlib.metadata as m,json;print(json.dumps({d.metadata["Name"]:d.version for d in m.distributions()},sort_keys=True))'],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, check=True, timeout=10)
    packages = json.loads(metadata.stdout)
    if packages.get('mitmproxy') != MITM_VERSION:
        raise PrerequisiteError('Installed mitmproxy version differs from pinned wheel')
    write_json(evidence / 'installed-packages.json', packages)
    with (evidence / 'stdout.log').open('w') as stdout, (evidence / 'stderr.log').open('w') as stderr:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                   env=env, start_new_session=True)
        try:
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError('Owned mitmproxy exited; see ' + str(evidence))
                try:
                    with socket.create_connection((bind, port), timeout=0.1): pass
                    break
                except OSError: time.sleep(0.1)
            else: raise RuntimeError('Owned mitmproxy startup timed out')
            yield process, evidence / 'requests.jsonl'
        finally:
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(timeout=3)
            write_json(evidence / 'proxy-exit.json', {'pid': process.pid, 'exit_status': process.returncode,
                                                     'owned_process_stopped': True})


@contextmanager
def origin(evidence, bind, port=18081, *, tls=None):
    evidence.mkdir(parents=True)
    logfile = evidence / 'requests.jsonl'
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            token = self.path.removeprefix('/repack/')
            with logfile.open('a') as stream:
                stream.write(json.dumps({'token': token, 'path': self.path}) + '\n')
            body = json.dumps({'token': token, 'via': 'origin'}).encode()
            self.send_response(200); self.send_header('Content-Length', str(len(body)))
            self.send_header('Content-Type', 'application/json'); self.end_headers(); self.wfile.write(body)
        def log_message(self, format, *args):
            with (evidence / 'access.log').open('a') as stream: stream.write(format % args + '\n')
    server = http.server.ThreadingHTTPServer((bind, port), Handler)
    if tls is not None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(tls['certificate'], tls['key'])
        server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try: yield logfile
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=3)


def rows(path):
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def request_config(result, label, *, via='proxy', direct=False):
    token = result['run_id'] + '-' + label
    return {'run_id': token, 'case_id': result['case_id'], 'url': 'http://127.0.0.1:18081/repack/' + token,
            'expected_via': via, 'direct_socket': direct}


def build_route(result, evidence, label, own, keys, lock, proxy, config=None):
    part = evidence / label; part.mkdir()
    artifact = build_bootstrap(Path(own['apk']), ROOT / '.work/outputs/routing' / result['run_id'] / label,
                               keys['repack'], lock, part, proxy=proxy, fixture_request=config)
    result['outputs'].append(artifact)
    return artifact


def install_fixture(result, evidence, label, artifact, serial, lock, args):
    plan = preflight(artifact, serial, args.replace_existing_and_wipe_data, lock, evidence, label)
    install(artifact, serial, plan, lock, evidence, label, result['device_mutations'])


def observe(artifact, config, serial, lock, evidence, label, *, fresh=True, baked=False):
    package = artifact['package']
    if fresh: shell(lock, evidence, label + '-stop', serial, ['am', 'force-stop', package])
    timestamp = shell(lock, evidence, label + '-time', serial, ['date', '+%m-%d %H:%M:%S.000']).stdout.strip()
    if fresh:
        # A real Activity keeps the fixture foreground; signing output is a separate observation.
        argv = ['am', 'start', '-W', '-n', package + '/.ProbeActivity']
        extras = {'run_id': config['run_id'] + '-identity', 'case_id': config['case_id'], 'scenario': 'identity',
                  'query_path': 'direct-current', 'query_package': package,
                  'expected_signer_sha256': ','.join(artifact['signer_sha256'])}
        for name, value in extras.items(): argv.extend(['--es', name, value])
        shell(lock, evidence, label + '-launch', serial, argv, check=False, timeout=5)
    pid = shell(lock, evidence, label + '-pid', serial, ['pidof', '-s', package]).stdout.strip()
    if not pid: raise RuntimeError('Fixture process unavailable')
    if not baked:
        shell(lock, evidence, label + '-request', serial,
              ['am', 'broadcast', '-n', package + '/dev.repack.fixture.common.NetworkReceiver',
               '--es', 'network_json', json.dumps(config, separators=(',', ':'))])
    for attempt in range(60):
        text = shell(lock, evidence, label + '-logs', serial,
                     ['logcat', '-d', '-v', 'threadtime', '--pid=' + pid, '-T', timestamp]).stdout
        events = read_events(text, config['run_id'])
        if events: break
        time.sleep(0.15)
    if (not events or any(item != events[0] for item in events[1:]) or events[0]['pid'] != int(pid)
            or events[0]['case_id'] != config['case_id'] or events[0]['process'] != package
            or events[0]['package'] != package or events[0]['scenario'] != 'routing'):
        raise RuntimeError('Missing/ambiguous fresh network observation: ' + label)
    write_json(evidence / (label + '-observed.json'), {'event': events[0], 'pid': int(pid),
                'artifact_sha256': artifact['sha256'], 'launch_time': timestamp,
                'identical_observation_count': len(events)})
    return events[0], text


def compare_response(result, config, event, logfile, via, *, tls=False):
    matched = [row for row in rows(logfile) if row['token'] == config['run_id']]
    body = json.loads(event['response_marker']) if event['response_marker'] else None
    if (event['event'] != 'response' or event['comparison'] != 'passed' or not matched
            or body != {'token': config['run_id'], 'via': via}
            or (via == 'proxy' and any(row['tls'] != tls for row in matched))):
        raise RuntimeError('Independent request/response oracle failed: ' + config['run_id'])
    result['comparisons'].append({'name': config['run_id'], 'result': 'passed', 'via': via,
                                   'event': event, 'oracle': str(logfile), 'requests': matched})


def run_t_n10(result, evidence, args):
    lock, serial, keys, own, _ = inputs(result, evidence, args)
    malformed = ['http://127.0.0.1:8080', 'host', 'host:0', 'host:65536', '::1:8080',
                 'host:abc', 'a b:80', 'host:80/path', 'user@host:80', '999.1.1.1:80']
    for value in malformed:
        try: parse_proxy(value)
        except ValueError: pass
        else: raise RuntimeError('Malformed proxy accepted: ' + value)
    result['comparisons'].append({'name': 'malformed-endpoints-before-build', 'rejected': malformed, 'result': 'passed'})
    with oracle(evidence / 'proxy', args.proxy_bind) as (_, logfile):
        for label, endpoint in [('default', '127.0.0.1:8080'), ('explicit', '127.0.0.1:18080')]:
            proxy = parse_proxy(endpoint); config = request_config(result, label)
            artifact = build_route(result, evidence, label, own, keys, lock, proxy, config)
            with owned_reverse(lock, serial, proxy['port'], args.proxy_bind, 8080, evidence, label,
                               result['device_mutations'], result['cleanup']):
                install_fixture(result, evidence, label, artifact, serial, lock, args)
                event, text = observe(artifact, config, serial, lock, evidence, label, baked=True)
                compare_response(result, config, event, logfile, 'proxy')
                lines = text.splitlines()
                route = next((i for i, line in enumerate(lines) if 'REPACK_SHIM' in line
                              and '"reason":"startup"' in line and '"published":true' in line), None)
                first = next((i for i, line in enumerate(lines) if '"application-network-start"' in line), None)
                if route is None or first is None or route >= first:
                    raise RuntimeError('Routing publication did not precede first Application request')
                events = tagged_events(text, 'REPACK_SHIM')
                if not any(item['endpoint'] == proxy and item['reference_replaced'] for item in events):
                    raise RuntimeError('Observed endpoint differs from baked configuration')
                result['comparisons'].append({'name': label + '-before-Application-network', 'result': 'passed',
                                               'client': 'HttpURLConnection-created-in-Application.onCreate', 'endpoint': proxy})
    result.update(verification='passed', transformation='applied', routing_scope='startup-implicit-HttpURLConnection-HTTP')


def run_t_n11(result, evidence, args):
    lock, serial, _, _, _ = inputs(result, evidence, args)
    # Explicitly retain the unsupported transition instead of silently changing a daily-driver setting.
    settings = shell(lock, evidence, 'global-proxy-snapshot', serial, ['settings', 'list', 'global']).stdout
    values = [line.partition('=')[2] for line in settings.splitlines() if line.startswith('http_proxy=')]
    result.update(verification='not-run', routing_scope='startup-only',
                  transition={'verification': 'not-run', 'reason': 'Operator phone: global proxy mutation not selected',
                              'setting_present': bool(values), 'prior_value': values[0] if values else None},
                  saved_selector_trial={'verification': 'not-run', 'reason': 'No observed OS reset; optional bypass experiment not opened'},
                  receiver={'verification': 'not-run', 'reason': 'Registration alone does not prove persistence'})


def run_t_n12(result, evidence, args):
    lock, serial, keys, own, other = inputs(result, evidence, args)
    proxy = parse_proxy('127.0.0.1:8080')
    artifact = build_route(result, evidence, 'route', own, keys, lock, proxy)
    install_fixture(result, evidence, 'route', artifact, serial, lock, args)
    install_fixture(result, evidence, 'other', other, serial, lock, args)
    selection = request_config(result, 'second-app-selector-before'); selection['selector_probe'] = True
    before_selection, _ = observe(other, selection, serial, lock, evidence, 'second-app-selector-before')
    if before_selection['event'] != 'marker' or before_selection['comparison'] != 'passed':
        raise RuntimeError('Second app baseline selector observation missing')
    with origin(evidence / 'origin', args.proxy_bind) as origin_log:
        with owned_reverse(lock, serial, 18081, args.proxy_bind, 18081, evidence, 'origin',
                           result['device_mutations'], result['cleanup']):
            calibration = request_config(result, 'calibrate', via='origin', direct=True)
            event, _ = observe(artifact, calibration, serial, lock, evidence, 'calibrate')
            compare_response(result, calibration, event, origin_log, 'origin')
            selection = request_config(result, 'second-app-selector-after'); selection['selector_probe'] = True
            after_selection, _ = observe(other, selection, serial, lock, evidence, 'second-app-selector-after')
            if (after_selection['event'] != 'marker' or after_selection['comparison'] != 'passed'
                    or json.loads(before_selection['response_marker']) != json.loads(after_selection['response_marker'])):
                raise RuntimeError('Second app selector/properties changed after shim publication')
            result['comparisons'].append({'name': 'second-app-selection-unchanged', 'result': 'passed',
                'before': before_selection, 'after': after_selection,
                'scope': 'Public ProxySelector and properties; existing operator proxy preserved'})
            ordinary = request_config(result, 'second-app', via='origin', direct=True)
            event, _ = observe(other, ordinary, serial, lock, evidence, 'second-app')
            compare_response(result, ordinary, event, origin_log, 'origin')
            with owned_reverse(lock, serial, 8080, args.proxy_bind, 8080, evidence, 'proxy',
                               result['device_mutations'], result['cleanup']):
                try:
                    with owned_reverse(lock, serial, 8080, args.proxy_bind, 18082, evidence, 'conflict',
                                       result['device_mutations'], result['cleanup']):
                        raise RuntimeError('Conflicting reverse was accepted')
                except PrerequisiteError as error:
                    if 'Existing reverse mapping' not in str(error): raise
                result['comparisons'].append({'name': 'conflicting-reverse-refused', 'result': 'passed'})
                with oracle(evidence / 'proxy-before', args.proxy_bind) as (_, log):
                    before = request_config(result, 'before')
                    event, _ = observe(artifact, before, serial, lock, evidence, 'before')
                    compare_response(result, before, event, log, 'proxy')
                down = request_config(result, 'proxy-down')
                event, _ = observe(artifact, down, serial, lock, evidence, 'proxy-down')
                hits = [row for row in rows(origin_log) if row['token'] == down['run_id']]
                if event['event'] != 'failure' or not event['error_class'] or hits:
                    raise RuntimeError('Proxy-down covered request reached origin or did not fail')
                result['comparisons'].append({'name': 'fresh-client-proxy-down', 'result': 'passed',
                    'event': event, 'origin_hits': hits, 'oracle': str(origin_log), 'scope': 'HttpURLConnection-HTTP'})
                uncovered = request_config(result, 'uncovered', via='origin', direct=True)
                event, _ = observe(artifact, uncovered, serial, lock, evidence, 'uncovered')
                compare_response(result, uncovered, event, origin_log, 'origin')
                with oracle(evidence / 'proxy-restored', args.proxy_bind) as (_, log):
                    restored = request_config(result, 'proxy-restored')
                    event, _ = observe(artifact, restored, serial, lock, evidence, 'proxy-restored')
                    compare_response(result, restored, event, log, 'proxy')
    # Reconnect only after releasing our mappings, and only with no unrelated reverse mappings.
    remaining = adb(lock, evidence, 'reconnect-mappings', ['reverse', '--list'], serial=serial).stdout
    reconnect = 'not-run'
    if not remaining.strip():
        adb(lock, evidence, 'reconnect', ['reconnect'], serial=serial, timeout=10)
        result['device_mutations'].append({'action': 'adb-reconnect', 'serial': serial, 'prior_reverse_mappings': []})
        for attempt in range(40):
            devices = adb(lock, evidence, 'reconnect-devices', ['devices']).stdout.splitlines()
            if any(line.split() == [serial, 'device'] for line in devices): break
            time.sleep(0.25)
        else: raise RuntimeError('Selected ADB transport did not recover')
        if read_cell(lock, evidence / 'reconnected', serial) != result['cell']:
            raise RuntimeError('Device cell changed after reconnect')
        with owned_reverse(lock, serial, 8080, args.proxy_bind, 8080, evidence, 'reconnected-proxy',
                           result['device_mutations'], result['cleanup']):
            with oracle(evidence / 'proxy-reconnected', args.proxy_bind) as (_, log):
                restored = request_config(result, 'adb-reconnected')
                event, _ = observe(artifact, restored, serial, lock, evidence, 'adb-reconnected')
                compare_response(result, restored, event, log, 'proxy')
        reconnect = 'passed'
    result.update(verification='passed', transformation='applied', routing_scope='startup-implicit-HttpURLConnection-HTTP',
                  adb_reconnect=reconnect,
                  optional_transports={'wireless_adb': 'not-run', 'remote_mobile_data': 'not-run',
                                       'physical_usb_disconnect': 'not-run'})


def gate_routing(result, evidence, args):
    children = {}
    reports = {}
    for name in ('T-N10', 'T-N11', 'T-N12'):
        path = args.reports / (name + '.json')
        child = json.loads(path.read_text())
        if child['source_sha256'] != source_hash():
            raise PrerequisiteError(name + ' source revision is stale')
        if name != 'T-N11' and child['verification'] != 'passed':
            raise PrerequisiteError(name + ' not accepted')
        children[name] = report_reference(path); reports[name] = child
    if any(child['cell'] != reports['T-N10']['cell'] for child in reports.values()):
        raise RuntimeError('Routing cases used different cells')
    if (reports['T-N11']['routing_scope'] != 'startup-only' or len(reports['T-N10']['comparisons']) != 5
            or len(reports['T-N12']['comparisons']) != (9 if reports['T-N12']['adb_reconnect'] == 'passed' else 8)):
        raise RuntimeError('Routing observations incomplete or unsupported gate scope')
    result.update(verification='passed', gate_progress='accepted', children=children,
                  cell=reports['T-N10']['cell'], routing_scope='startup-implicit-HttpURLConnection-HTTP',
                  unsupported=['OS-proxy-transition-persistence', 'off-USB-mobile-data', 'explicit-direct-sockets',
                               'HTTPS-until-M2', 'other-network-stacks'], next_gate='M2')
