"""M2 resource screening and controlled HTTPS trust-policy cases."""
import copy
import json
from pathlib import Path
import re
import shutil
import xml.etree.ElementTree as ET
import zipfile

from repack.rebuild import (ROOT, PrerequisiteError, align_sign, badging, ensure_keys, environment,
                            execute, fixture_source_hash, load_lock, report_reference, sha256, source_hash, tool, write_json)
from repack.shim import build_bootstrap, parse_proxy
from repack.trust import (ANDROID, apply_trust, decode_resources, public_ca, rebuild_resources, resource_engine)
from repack.verify import install, owned_reverse, preflight, shell
from scripts.acceptance import read_cell, select_serial
from scripts.routing_cases import (compare_response, install_fixture, observe, oracle, origin, request_config, rows)


def pki(lock, evidence):
    python = ROOT / '.work/tools/mitmproxy-12.3.1/bin/python'
    if not python.exists(): raise PrerequisiteError('Pinned proxy environment required for fixture PKI generation')
    completed = execute([str(python), str(ROOT / 'scripts/fixture_pki.py')], evidence, 'fixture-pki', timeout=20)
    return json.loads(completed.stdout)


def prerequisites(result, evidence, args):
    lock = load_lock(); serial = select_serial(lock, evidence, args.device)
    result['cell'] = read_cell(lock, evidence, serial)
    gate = ROOT / '.work/evidence/M1b-5.json'
    routing = json.loads(gate.read_text())
    if routing.get('gate_progress') != 'accepted' or routing['cell'] != result['cell']:
        raise PrerequisiteError('Accept routing on the selected cell first')
    result['inputs'].append(report_reference(gate))
    return lock, serial, ensure_keys(lock, evidence)


def sign_resource(unsigned, key, lock, evidence, output):
    align_sign(Path(unsigned), output, key, lock, evidence)
    info, _ = badging(output, lock, evidence, 'signed-resource-badging')
    return {**info, 'apk': str(output), 'sha256': sha256(output), 'signer_sha256': [key['sha256']]}


def fixture_variant(own, variant, tls, keys, lock, evidence, output):
    """Build NSC variants with SDK aapt2, independently of the engine under test."""
    evidence.mkdir(parents=True); output.mkdir(parents=True)
    fixture = ROOT / 'tests/fixtures/identity'
    res = output / 'res'; shutil.copytree(fixture / 'common/res', res)
    # Stock aapt2 legitimately generates private $ names from inline animated-vector XML.
    # Decoding these names then rebuilding with an unpatched SDK compiler was the real
    # Midway failure; keep that shape in every resource-engine fixture.
    drawable = res / 'drawable'; drawable.mkdir()
    (drawable / 'repack_inline_vector.xml').write_text('''<animated-vector
        xmlns:android="http://schemas.android.com/apk/res/android"
        xmlns:aapt="http://schemas.android.com/aapt">
      <aapt:attr name="android:drawable"><vector android:width="24dp" android:height="24dp"
          android:viewportWidth="24" android:viewportHeight="24">
        <path android:name="fixture" android:fillColor="#ff000000" android:pathData="M0,0 L24,0 L24,24 Z" />
      </vector></aapt:attr>
      <target android:name="fixture"><aapt:attr name="android:animation">
        <objectAnimator android:duration="50" android:propertyName="fillAlpha"
            android:valueFrom="0" android:valueTo="1" android:valueType="floatType" />
      </aapt:attr></target>
    </animated-vector>''')
    manifest = ET.parse(fixture / 'app/AndroidManifest.xml')
    application = manifest.getroot().find('application')
    if variant == 'absent': application.attrib.pop(ANDROID + 'networkSecurityConfig')
    else:
        raw = res / 'raw'; raw.mkdir(exist_ok=True)
        shutil.copyfile(tls['ca'], raw / 'fixture_origin_ca.pem')
        root = ET.Element('network-security-config')
        base = ET.SubElement(root, 'base-config', {'cleartextTrafficPermitted': 'false'})
        ET.SubElement(ET.SubElement(base, 'trust-anchors'), 'certificates', {'src': 'system'})
        domain = ET.SubElement(root, 'domain-config', {'cleartextTrafficPermitted': 'true'})
        ET.SubElement(domain, 'domain', {'includeSubdomains': 'false'}).text = '127.0.0.1'
        ET.SubElement(ET.SubElement(domain, 'trust-anchors'), 'certificates', {'src': '@raw/fixture_origin_ca'})
        pins = ET.SubElement(domain, 'pin-set')
        ET.SubElement(pins, 'pin', {'digest': 'SHA-256'}).text = tls['origin-good']['spki_sha256_base64']
        parent = ET.SubElement(root, 'domain-config', {'cleartextTrafficPermitted': 'false'})
        ET.SubElement(parent, 'domain', {'includeSubdomains': 'true'}).text = 'pinned.repack.test'
        ET.SubElement(ET.SubElement(parent, 'trust-anchors'), 'certificates', {'src': '@raw/fixture_origin_ca'})
        ET.SubElement(ET.SubElement(parent, 'pin-set'), 'pin', {'digest': 'SHA-256'}).text = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
        child = ET.SubElement(parent, 'domain-config')
        ET.SubElement(child, 'domain', {'includeSubdomains': 'false'}).text = 'deep.pinned.repack.test'
        ET.SubElement(ET.SubElement(child, 'trust-anchors'), 'certificates', {'src': '@raw/fixture_origin_ca'})
        directory = res / ('xml-v' + str(lock['cell']['api']) if variant == 'qualified' else 'xml')
        directory.mkdir(exist_ok=True)
        ET.ElementTree(root).write(directory / 'network_security_config.xml', encoding='utf-8', xml_declaration=True)
    manifest_path = output / 'AndroidManifest.xml'; manifest.write(manifest_path, encoding='utf-8', xml_declaration=True)
    compiled = output / 'resources.zip'; linked = output / 'linked.apk'
    execute([tool(lock, 'aapt2'), 'compile', '--dir', str(res), '-o', str(compiled)], evidence, 'fixture-res-compile')
    execute([tool(lock, 'aapt2'), 'link', '-I', lock['android_jar'], '--manifest', str(manifest_path),
             '--min-sdk-version', '28', '--target-sdk-version', '35', '-o', str(linked), str(compiled)],
             evidence, 'fixture-res-link')
    unsigned = output / 'unsigned.apk'
    with zipfile.ZipFile(linked) as resource, zipfile.ZipFile(own['apk']) as original, zipfile.ZipFile(unsigned, 'w') as target:
        for item in resource.infolist(): target.writestr(copy.copy(item), resource.read(item.filename))
        for item in original.infolist():
            if item.filename.startswith(('res/', 'META-INF/')) or item.filename in ('resources.arsc', 'AndroidManifest.xml'): continue
            target.writestr(copy.copy(item), original.read(item.filename))
    artifact = sign_resource(unsigned, keys['original'], lock, evidence, output / 'original.apk')
    artifact['variant'] = variant
    artifact.update(fixture_source_sha256=fixture_source_hash(), fixture_pki_ca_sha256=tls['ca_sha256'])
    return artifact


def count_stages(rows):
    counts = {}
    for stage in ('rebuild', 'insertion', 'install', 'launch', 'https'):
        states = [row['stages'][stage] for row in rows]
        count = {name: states.count(name) for name in ('passed', 'failed', 'inconclusive', 'not-run')}
        count['selected'] = len(states); count['attempted'] = count['passed'] + count['failed'] + count['inconclusive']
        count['pass_rate'] = count['passed'] / count['attempted'] if count['attempted'] else None
        counts[stage] = count
    return counts


def run_t_t19(result, evidence, args):
    lock, serial, keys = prerequisites(result, evidence, args)
    baseline_path = ROOT / '.work/evidence/M0-build.json'
    baseline = json.loads(baseline_path.read_text())
    if baseline['verification'] != 'passed' or baseline.get('fixture_source_sha256') != fixture_source_hash():
        raise PrerequisiteError('Build current original fixtures first')
    result['inputs'].append(report_reference(baseline_path))
    own = next(item for item in baseline['outputs'] if item['id'] == 'app-own')
    if sha256(Path(own['apk'])) != own['sha256']: raise RuntimeError('Original fixture changed')
    tls = pki(lock, evidence); result['fixture_pki'] = tls
    engine = resource_engine(lock, evidence)
    lock['resource_engine'] = engine; write_json(ROOT / 'config/implementation-lock.json', lock)
    result['corpus'] = []
    for variant in ('absent', 'existing', 'qualified'):
        part = evidence / variant
        original = fixture_variant(own, variant, tls, keys, lock, part / 'fixture',
                                   ROOT / '.work/outputs/trust-fixtures' / result['run_id'] / variant)
        result['outputs'].append(original)
        row = {'input_id': 'nsc-' + variant, 'members': [original], 'engine': engine,
               'stages': {stage: 'not-run' for stage in ('rebuild', 'insertion', 'install', 'launch', 'https')},
               'logs': [str(part)], 'fallback_reason': None}
        result['corpus'].append(row)
        try:
            decode_resources(Path(original['apk']), part / 'decoded', lock, part)
            rebuilt = rebuild_resources(Path(original['apk']), part / 'decoded', part / 'unsigned.apk', lock, part)
            artifact = sign_resource(rebuilt['unsigned_apk'], keys['repack'], lock, part, part / 'rebuilt.apk')
            row.update(rebuilt=artifact, preserved_entries=rebuilt['preserved_entries'])
            row['stages']['rebuild'] = 'passed'
        except Exception as error:
            row['stages']['rebuild'] = 'failed'; row.update(error_class=type(error).__name__, error=str(error))
    # Only the user's named target is selected. Split validation opens later; never screen its base alone.
    inventory = ROOT / '.work/targets/midway/original/inventory.json'
    if inventory.exists():
        selected = json.loads(inventory.read_text())
        result['corpus'].append({'input_id': 'br.com.midway-installed-set', 'inventory': str(inventory),
            'inventory_sha256': sha256(inventory), 'engine': engine, 'members': selected,
            'stages': {stage: 'not-run' for stage in ('rebuild', 'insertion', 'install', 'launch', 'https')},
            'prerequisite_failures': ['Selected split-set validation opens at M1b-3; base-only screening excluded'], 'logs': []})
    result['stage_counts'] = count_stages(result['corpus'])
    if any(row['stages']['rebuild'] != 'passed' for row in result['corpus'][:3]):
        raise RuntimeError('Required resource fixture rebuild failed; retain failure before ARSCLib fallback trial')
    result.update(verification='passed', transformation='applied', engine=engine)


def screened(result, evidence, args):
    lock, serial, keys = prerequisites(result, evidence, args)
    index = ROOT / '.work/evidence/T-T19.json'; screen = json.loads(index.read_text())
    if screen['verification'] != 'passed' or screen['cell'] != result['cell']:
        raise PrerequisiteError('Resource screening must pass on this cell')
    if any(item.get('fixture_source_sha256') != fixture_source_hash() for item in screen['outputs']):
        raise PrerequisiteError('Screened fixture sources changed')
    for item in screen['outputs']:
        if sha256(Path(item['apk'])) != item['sha256']: raise RuntimeError('Screened fixture changed')
    result['inputs'].append(report_reference(index))
    return lock, serial, keys, screen


def trusted_route(result, evidence, original, ca, keys, lock, label):
    part = evidence / label; part.mkdir()
    trust = apply_trust(Path(original['apk']), ca, part / 'trust', lock)
    signed = sign_resource(trust['unsigned_apk'], keys['repack'], lock, part, part / 'trusted.apk')
    artifact = build_bootstrap(Path(signed['apk']), ROOT / '.work/outputs/trust-routing' / result['run_id'] / label,
                               keys['repack'], lock, part, proxy=parse_proxy('127.0.0.1:8080'))
    artifact.update(trust=trust, variant=original['variant'])
    result['outputs'].append(artifact)
    return artifact


def https_config(result, label, host='127.0.0.1', *, direct=False):
    config = request_config(result, label, via='origin' if direct else 'proxy')
    config['url'] = 'https://' + host + ':18081/repack/' + config['run_id']
    config['explicit_direct'] = direct
    return config


def require_tls_failure(result, config, event, logfile, label):
    hits = [row for row in rows(logfile) if row['token'] == config['run_id']]
    if event['event'] != 'failure' or event['error_class'] not in (
            'javax.net.ssl.SSLHandshakeException', 'javax.net.ssl.SSLPeerUnverifiedException') or hits:
        raise RuntimeError('Expected TLS validation failure missing: ' + label)
    result['comparisons'].append({'name': label, 'result': 'passed', 'negative_control': True,
                                  'event': event, 'decrypted_or_origin_requests': hits, 'oracle': str(logfile)})


def wrong_ca_control(result, evidence, args, lock, serial, artifact, expected_ca):
    """Same accepted endpoint/artifact; change only the proxy's signing CA."""
    install_fixture(result, evidence, 'restore-trust', artifact, serial, lock, args)
    with oracle(evidence / 'wrong-ca-proxy', args.proxy_bind,
                confdir=ROOT / '.work/keys/mitmproxy-wrong-ca') as (_, logfile):
        wrong, _ = public_ca(ROOT / '.work/keys/mitmproxy-wrong-ca/mitmproxy-ca-cert.pem')
        if wrong == expected_ca: raise RuntimeError('Wrong-CA control shares trusted root')
        result['wrong_ca_sha256'] = wrong
        result['trusted_ca_sha256'] = expected_ca
        with owned_reverse(lock, serial, 8080, args.proxy_bind, 8080, evidence, 'wrong-ca',
                           result['device_mutations'], result['cleanup']):
            config = https_config(result, 'wrong-ca')
            event, _ = observe(artifact, config, serial, lock, evidence, 'wrong-ca')
            require_tls_failure(result, config, event, logfile, 'wrong-ca')


def run_t_t21_ca(result, evidence, args):
    lock, serial, keys, screen = screened(result, evidence, args)
    index = ROOT / '.work/evidence/T-T20.json'; t20 = json.loads(index.read_text())
    if t20['verification'] != 'passed' or t20['cell'] != result['cell']:
        raise PrerequisiteError('An observed HTTPS insertion artifact is required for isolation')
    result['inputs'].append(report_reference(index))
    artifact = next(item for item in t20['outputs'] if item['variant'] == 'qualified')
    if sha256(Path(artifact['apk'])) != artifact['sha256']: raise RuntimeError('Trust output changed')
    wrong_ca_control(result, evidence, args, lock, serial, artifact, t20['ca_sha256'])
    result.update(verification='passed', scope='Isolated wrong-CA diagnostic only; full T-T21 remains required')


def run_t_t20(result, evidence, args):
    lock, serial, keys, screen = screened(result, evidence, args)
    ca = ROOT / '.work/keys/mitmproxy/mitmproxy-ca-cert.pem'
    fingerprint, der = public_ca(ca); result['ca_sha256'] = fingerprint
    result['corpus'] = []
    with oracle(evidence / 'proxy', args.proxy_bind) as (_, logfile):
        with owned_reverse(lock, serial, 8080, args.proxy_bind, 8080, evidence, 'https-proxy',
                           result['device_mutations'], result['cleanup']):
            for original in screen['outputs']:
                label = original['variant']
                artifact = trusted_route(result, evidence, original, ca, keys, lock, label)
                with zipfile.ZipFile(artifact['apk']) as archive:
                    raw = [name for name in archive.namelist() if re.fullmatch(r'res/raw/repack_ca_?\.der', name)]
                    if len(raw) != 1 or archive.read(raw[0]) != der: raise RuntimeError('Embedded public CA differs')
                    for name in archive.namelist():
                        if name.endswith(('.pem', '.der')) and b'PRIVATE KEY' in archive.read(name):
                            raise RuntimeError('Private key material embedded')
                install_fixture(result, evidence, label, artifact, serial, lock, args)
                config = https_config(result, label)
                event, _ = observe(artifact, config, serial, lock, evidence, label)
                compare_response(result, config, event, logfile, 'proxy', tls=True)
                result['corpus'].append({'input_id': label, 'members': [original], 'output_sha256': artifact['sha256'],
                    'engine': artifact['trust']['engine'], 'stages': {'rebuild': 'passed', 'insertion': 'passed',
                    'install': 'passed', 'launch': 'passed', 'https': 'passed'}, 'logs': [str(evidence / label)]})
    result.update(verification='passed', transformation='applied', stage_counts=count_stages(result['corpus']))


def run_t_t21(result, evidence, args):
    lock, serial, keys, screen = screened(result, evidence, args)
    t20_path = ROOT / '.work/evidence/T-T20.json'; t20 = json.loads(t20_path.read_text())
    if t20['verification'] != 'passed' or t20['source_sha256'] != source_hash():
        raise PrerequisiteError('Accept current HTTPS insertion controls first')
    result['inputs'].append(report_reference(t20_path))
    original = next(item for item in screen['outputs'] if item['variant'] == 'qualified')
    artifact = next(item for item in t20['outputs'] if item['variant'] == 'qualified')
    if sha256(Path(artifact['apk'])) != artifact['sha256']: raise RuntimeError('Trust output changed')
    install_fixture(result, evidence, 'trusted', artifact, serial, lock, args)
    tls = screen['fixture_pki']
    with oracle(evidence / 'proxy', args.proxy_bind) as (_, logfile):
        with owned_reverse(lock, serial, 8080, args.proxy_bind, 8080, evidence, 'trusted-proxy',
                           result['device_mutations'], result['cleanup']):
            for label, host in [('domain-own-anchors', 'pinned.repack.test'), ('nested-own-anchors', 'deep.pinned.repack.test')]:
                config = https_config(result, label, host)
                event, _ = observe(artifact, config, serial, lock, evidence, label)
                compare_response(result, config, event, logfile, 'proxy', tls=True)
            # The original app's valid private anchor and matching pin remain usable without the proxy.
            for label, certificate, failure in [('original-trust', tls['origin-good'], False),
                                                  ('original-pin-wrong-key', tls['origin-wrong-pin'], True)]:
                with origin(evidence / label, args.proxy_bind, tls=certificate) as origin_log:
                    with owned_reverse(lock, serial, 18081, args.proxy_bind, 18081, evidence, label,
                                       result['device_mutations'], result['cleanup']):
                        config = https_config(result, label, direct=True)
                        event, _ = observe(artifact, config, serial, lock, evidence, label)
                        if failure: require_tls_failure(result, config, event, origin_log, label)
                        else: compare_response(result, config, event, origin_log, 'origin')
            # Routing without the embedded anchor still rejects the same proxy's chain.
            part = evidence / 'without-anchor'; part.mkdir()
            untrusted = build_bootstrap(Path(original['apk']), ROOT / '.work/outputs/trust-routing' / result['run_id'] / 'without-anchor',
                                        keys['repack'], lock, part, proxy=parse_proxy('127.0.0.1:8080'))
            install_fixture(result, evidence, 'without-anchor', untrusted, serial, lock, args)
            config = https_config(result, 'without-anchor')
            event, _ = observe(untrusted, config, serial, lock, evidence, 'without-anchor')
            require_tls_failure(result, config, event, logfile, 'without-anchor')
            baseline = json.loads((ROOT / '.work/evidence/M0-build.json').read_text())
            other = next(item for item in baseline['outputs'] if item['id'] == 'other-own')
            if sha256(Path(other['apk'])) != other['sha256']: raise RuntimeError('Second fixture changed')
            part = evidence / 'second-app'; part.mkdir()
            second = build_bootstrap(Path(other['apk']), ROOT / '.work/outputs/trust-routing' / result['run_id'] / 'second-app',
                                    keys['other'], lock, part, proxy=parse_proxy('127.0.0.1:8080'))
            install_fixture(result, evidence, 'second-app', second, serial, lock, args)
            config = https_config(result, 'second-app-no-anchor')
            event, _ = observe(second, config, serial, lock, evidence, 'second-app-no-anchor')
            require_tls_failure(result, config, event, logfile, 'second-app-no-anchor')
    wrong_ca_control(result, evidence, args, lock, serial, artifact, t20['ca_sha256'])
    # Every original pin and explicit anchor must remain in each decoded qualifier.
    for policy in artifact['trust']['policies']:
        before = ET.fromstring(policy['original_xml']); after = ET.fromstring(policy['modified_xml'])
        if [ET.tostring(item) for item in before.iter('pin-set')] != [ET.tostring(item) for item in after.iter('pin-set')]:
            raise RuntimeError('Original declarative pin set changed')
        old = [dict(item.attrib) for item in before.iter('certificates')]
        new = [dict(item.attrib) for item in after.iter('certificates') if item.get('src') != artifact['trust']['ca_resource']]
        if old != new: raise RuntimeError('Original trust anchors changed')
    result['comparisons'].append({'name': 'original-policies-retained-all-qualifiers', 'result': 'passed'})
    result.update(verification='passed', transformation='applied', ca_sha256=t20['ca_sha256'])


def gate_trust(result, evidence, args):
    children = {}; reports = {}
    for name in ('T-T19', 'T-T20', 'T-T21'):
        index = args.reports / (name + '.json'); child = json.loads(index.read_text())
        if child['verification'] != 'passed' or child['source_sha256'] != source_hash():
            raise PrerequisiteError(name + ' unavailable/failed/stale')
        children[name] = report_reference(index); reports[name] = child
    if any(child['cell'] != reports['T-T19']['cell'] for child in reports.values()):
        raise RuntimeError('Trust cases differ in selected device cell')
    if len(reports['T-T20']['comparisons']) != 3 or len(reports['T-T21']['comparisons']) != 8:
        raise RuntimeError('Trust controls incomplete')
    result.update(verification='passed', gate_progress='accepted', children=children,
                  cell=reports['T-T19']['cell'], trust_mode='resource-nsc', next_gate='M3',
                  scope='Owned API' + str(reports['T-T19']['cell']['api']) + ' NSC absent/existing/qualified; nested anchors and declarative pins',
                  unsupported=['programmatic-pins-until-M3', 'real-target-runtime', 'API36-CT', 'runtime-NSC'])
