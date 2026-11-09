"""M3: actual pinned clients, conservative shadow selection, and refusal controls."""
import copy
import json
import re
from pathlib import Path
import zipfile

from repack.rebuild import (ROOT, PrerequisiteError, copy_archive, ensure_keys, environment, execute,
                            load_lock, report_reference, sha256, source_hash, tool, write_json)
from repack.patches import (UnsupportedJavaPatch, dex_counts, dex_tool, java_dependencies, patch_apk)
from repack.shim import build_bootstrap, parse_proxy
from repack.trust import apply_trust, public_ca
from repack.verify import owned_reverse, shell
from scripts.acceptance import read_cell, select_serial
from scripts.routing_cases import compare_response, install_fixture, observe, oracle, rows
from scripts.trust_cases import https_config, require_tls_failure, sign_resource

CLIENTS = ('okhttp', 'trust-manager', 'inherited-trust-manager', 'hostname-verifier', 'inherited-hostname-verifier')


def prerequisites(result, evidence, args):
    lock = load_lock(); serial = select_serial(lock, evidence, args.device)
    result['cell'] = read_cell(lock, evidence, serial)
    index = ROOT / '.work/evidence/M2.json'; gate = json.loads(index.read_text())
    if gate.get('gate_progress') != 'accepted' or gate['cell'] != result['cell']:
        raise PrerequisiteError('Accept M2 on the selected cell first')
    accepted = gate['children']['T-T20']
    if sha256(Path(accepted['path'])) != accepted['sha256']: raise RuntimeError('Accepted HTTPS evidence changed')
    trust = json.loads(Path(accepted['path']).read_text())
    ca = ROOT / '.work/keys/mitmproxy/mitmproxy-ca-cert.pem'
    if public_ca(ca)[0] != trust['ca_sha256']: raise PrerequisiteError('Accepted proxy CA changed')
    result['inputs'] = [report_reference(index)]
    result['dependencies'] = java_dependencies('http-fixture') + java_dependencies('smali')
    return lock, serial, ensure_keys(lock, evidence), ca


def build_fixture(result, evidence, lock, keys, variant):
    part = evidence / ('build-' + variant); part.mkdir()
    out = ROOT / '.work/outputs/pinning-fixtures' / result['run_id'] / variant; out.mkdir(parents=True)
    base = ROOT / 'tests/fixtures/identity'
    compiled = out / 'resources.zip'; linked = out / 'linked.apk'
    execute([tool(lock, 'aapt2'), 'compile', '--dir', str(base / 'common/res'), '-o', str(compiled)], part, 'aapt-compile')
    execute([tool(lock, 'aapt2'), 'link', '-I', lock['android_jar'], '--manifest', str(base / 'app/AndroidManifest.xml'),
             '--min-sdk-version', '28', '--target-sdk-version', '35', '-o', str(linked), str(compiled)], part, 'aapt-link')
    classes = out / 'classes'; classes.mkdir(); dex = out / 'dex'; dex.mkdir()
    deps = [item['path'] for item in java_dependencies('http-fixture')]
    sources = sorted((base / 'common/src').rglob('*.java')) + sorted((base / 'app/src').rglob('*.java'))
    sources += sorted((ROOT / 'tests/fixtures/pinning/src').rglob('*.java'))
    execute([tool(lock, 'javac'), '--release', '8', '-classpath', ':'.join([lock['android_jar'], *deps]),
             '-d', str(classes), *map(str, sources)], part, 'javac', env=environment(lock))
    program = out / 'program.jar'
    with zipfile.ZipFile(program, 'w') as archive:
        for path in sorted(classes.rglob('*.class')): archive.write(path, str(path.relative_to(classes)))
    if variant in ('renamed', 'optimized'):
        rules = out / 'r8.pro'
        rules.write_text('''-keep class dev.repack.fixture.common.** { *; }
-keep class dev.repack.fixture.identity.** { *; }
-keep,allowoptimization class dev.repack.fixture.pinning.JavaPinProbe { public static java.lang.String perform(java.net.URL, java.lang.String); }
-keep interface kotlin.jvm.functions.** { *; }
-dontwarn org.codehaus.mojo.animal_sniffer.IgnoreJRERequirement
-dontwarn org.conscrypt.**
-dontwarn org.openjsse.**
-dontwarn org.bouncycastle.**
''')
        if variant == 'renamed':
            with rules.open('a') as stream:
                stream.write('-keep,allowobfuscation class dev.repack.fixture.pinning.JavaPinProbe$* { *; }\n'
                             '-keep,allowobfuscation class okhttp3.CertificatePinner { *; }\n')
        # Consume the library's own narrowly scoped shrinker rules as well.
        with zipfile.ZipFile(deps[0]) as jar:
            embedded = [name for name in jar.namelist() if name.startswith('META-INF/proguard/') and name.endswith('.pro')]
            with rules.open('a') as stream:
                for name in embedded: stream.write('\n' + jar.read(name).decode() + '\n')
        mapping = out / 'mapping.txt'
        with rules.open('a') as stream: stream.write('-printmapping ' + str(mapping) + '\n')
        execute([tool(lock, 'java'), '-cp', str(Path(tool(lock, 'd8')).parent / 'lib/d8.jar'),
                 'com.android.tools.r8.R8', '--release', '--min-api', '28', '--lib', lock['android_jar'],
                 '--pg-conf', str(rules), '--output', str(dex), str(program), *deps], part, 'r8', env=environment(lock))
    else:
        execute([tool(lock, 'd8'), '--release', '--min-api', '28', '--lib', lock['android_jar'],
                 '--output', str(dex), str(program), *deps], part, 'd8', env=environment(lock))
    dex_paths = sorted(dex.glob('classes*.dex'))
    if len(dex_paths) != 1: raise PrerequisiteError('Controlled Java fixture unexpectedly needs multidex')
    if variant == 'near-limit':
        command = dex_tool(lock, part)
        execute([*command, 'filler', str(lock['cell']['api']), str(dex / 'classes2.dex')], part, 'near-limit-filler')
        if dex_counts(dex / 'classes2.dex')['methods'] != 65530: raise RuntimeError('Near-limit fixture has wrong reference count')
    unsigned = out / 'unsigned.apk'
    with zipfile.ZipFile(linked) as resources, zipfile.ZipFile(unsigned, 'w') as target:
        for item in resources.infolist(): target.writestr(copy.copy(item), resources.read(item.filename))
        for path in sorted(dex.glob('classes*.dex')): target.write(path, path.name, compress_type=zipfile.ZIP_STORED)
    artifact = sign_resource(unsigned, keys['original'], lock, part, out / 'original.apk')
    artifact.update(variant=variant, dex_counts={path.name: dex_counts(path) for path in sorted(dex.glob('classes*.dex'))})
    return artifact


def prepare_route(result, evidence, lock, keys, ca, original, label):
    part = evidence / label; part.mkdir()
    trust = apply_trust(Path(original['apk']), ca, part / 'trust', lock)
    signed = sign_resource(trust['unsigned_apk'], keys['repack'], lock, part, part / 'trusted.apk')
    artifact = build_bootstrap(Path(signed['apk']), ROOT / '.work/outputs/pinning' / result['run_id'] / label,
                               keys['repack'], lock, part, proxy=parse_proxy('127.0.0.1:8080'))
    artifact['variant'] = original['variant']
    return artifact


def client_config(result, label, client):
    config = https_config(result, label); config['client'] = client
    return config


def run_t_u30(result, evidence, args):
    lock, serial, keys, ca = prerequisites(result, evidence, args)
    original = build_fixture(result, evidence, lock, keys, 'unoptimized')
    prepared = prepare_route(result, evidence, lock, keys, ca, original, 'prepared')
    result['outputs'] = [original, prepared]
    with oracle(evidence / 'proxy', args.proxy_bind) as (_, logfile):
        with owned_reverse(lock, serial, 8080, args.proxy_bind, 8080, evidence, 'proxy',
                           result['device_mutations'], result['cleanup']):
            install_fixture(result, evidence, 'control', prepared, serial, lock, args)
            config = client_config(result, 'trust-route-control', 'okhttp-unpinned')
            event, _ = observe(prepared, config, serial, lock, evidence, 'trust-route-control')
            compare_response(result, config, event, logfile, 'proxy', tls=True)
            for client in CLIENTS:
                config = client_config(result, 'original-' + client, client)
                event, _ = observe(prepared, config, serial, lock, evidence, 'original-' + client)
                require_tls_failure(result, config, event, logfile, 'original-' + client)
            part = evidence / 'shadow'; part.mkdir()
            artifact = patch_apk(Path(prepared['apk']), ROOT / '.work/outputs/pinning' / result['run_id'] / 'shadow', keys['repack'], lock, part)
            result['outputs'].append(artifact)
            if len(artifact['patches']) != 5: raise RuntimeError('Expected exactly five complete class/method patches')
            install_fixture(result, evidence, 'patched', artifact, serial, lock, args)
            for client in CLIENTS:
                config = client_config(result, 'patched-' + client, client)
                event, logs = observe(artifact, config, serial, lock, evidence, 'patched-' + client)
                compare_response(result, config, event, logfile, 'proxy', tls=True)
                markers = [item['class'] + '->' + item['method'] for item in artifact['patches']]
                if not any('REPACK_PATCH' in line and any(marker in line for marker in markers) for line in logs.splitlines()):
                    raise RuntimeError('No actual shadow-method execution marker: ' + client)
                if 'VerifyError' in logs or 'ClassNotFoundException' in logs: raise RuntimeError('Shadow class verification failed')
    result.update(verification='passed', transformation='applied', packaging='shadow',
                  scope='OkHttp4.12.0 and named direct/inherited fixture X509TrustManager/HostnameVerifier paths')


def run_t_u31(result, evidence, args):
    lock, serial, keys, ca = prerequisites(result, evidence, args)
    for variant in ('renamed', 'near-limit', 'optimized'):
        original = build_fixture(result, evidence, lock, keys, variant)
        prepared = prepare_route(result, evidence, lock, keys, ca, original, variant + '-prepared')
        result['outputs'].extend([original, prepared])
        part = evidence / (variant + '-shadow'); part.mkdir()
        artifact = patch_apk(Path(prepared['apk']), ROOT / '.work/outputs/pinning' / result['run_id'] / (variant + '-shadow'),
                             keys['repack'], lock, part)
        artifact['variant'] = variant; result['outputs'].append(artifact)
        if variant != 'optimized' and len(artifact['patches']) != 5:
            raise RuntimeError('Expected five pinning-method matches: ' + variant)
        if variant == 'renamed':
            if any(item['class'].startswith(('Ldev/repack/fixture/pinning/', 'Lokhttp3/CertificatePinner;')) for item in artifact['patches']):
                raise RuntimeError('R8 fixture did not actually rename pinning classes')
        elif variant == 'near-limit':
            if not any(entry['counts']['methods'] == 65530 for entry in artifact['dex_mapping']):
                raise RuntimeError('Near-limit original DEX preservation not measured')
        with oracle(evidence / (variant + '-proxy'), args.proxy_bind) as (_, logfile):
            with owned_reverse(lock, serial, 8080, args.proxy_bind, 8080, evidence, variant + '-proxy',
                               result['device_mutations'], result['cleanup']):
                install_fixture(result, evidence, variant + '-control', prepared, serial, lock, args)
                config = client_config(result, variant + '-unpatched', 'okhttp')
                event, _ = observe(prepared, config, serial, lock, evidence, variant + '-unpatched')
                require_tls_failure(result, config, event, logfile, variant + '-unpatched')
                install_fixture(result, evidence, variant + '-patched', artifact, serial, lock, args)
                for client in CLIENTS:
                    config = client_config(result, variant + '-' + client, client)
                    event, logs = observe(artifact, config, serial, lock, evidence, variant + '-' + client)
                    if variant == 'optimized' and event['event'] == 'failure':
                        require_tls_failure(result, config, event, logfile, variant + '-unsupported-' + client)
                        result['comparisons'][-1]['coverage'] = 'unsupported-optimized-boundary'
                    else:
                        compare_response(result, config, event, logfile, 'proxy', tls=True)
                        if 'REPACK_PATCH' not in logs: raise RuntimeError('Actual patched-method selection missing')
                compilation = shell(lock, evidence, variant + '-compile', serial,
                                    ['cmd', 'package', 'compile', '-m', 'speed', '-f', artifact['package']])
                if 'Success' not in compilation.stdout: raise RuntimeError('Shadow APK compilation failed')
                config = client_config(result, variant + '-compiled', 'okhttp')
                event, logs = observe(artifact, config, serial, lock, evidence, variant + '-compiled')
                compare_response(result, config, event, logfile, 'proxy', tls=True)
                if 'REPACK_PATCH' not in logs or 'VerifyError' in logs: raise RuntimeError('Compiled shadow definition was not used')
                if variant == 'optimized':
                    config = client_config(result, variant + '-inlined-pinner', 'inlined-pinner')
                    event, _ = observe(artifact, config, serial, lock, evidence, variant + '-inlined-pinner')
                    require_tls_failure(result, config, event, logfile, 'fully-inlined-guard-not-bypassed')
                    mapping = Path(original['apk']).parent / 'mapping.txt'
                    inline = [line for line in mapping.read_text().splitlines() if 'inlineGuard(' in line and '-> perform' in line]
                    if not inline: raise RuntimeError('R8 did not actually inline the guard into the request method')
                    result['comparisons'][-1].update(coverage='unsupported-optimized-boundary', r8_inline_mapping=inline)
    result.update(verification='passed', transformation='applied', packaging='shadow',
                  scope='Named R8-renamed fixture with retained method boundaries; near-limit original DEX')


def strip_selected_methods(text, selected):
    """Ignore only selected bodies while comparing canonical full-class disassembly."""
    lines = text.splitlines(keepends=True); output = []; skipping = False
    for line in lines:
        if line.startswith('.method '):
            descriptor = line.strip().split()[-1]
            skipping = descriptor in selected
            if skipping: output.append(line); continue
        if skipping:
            if line.startswith('.end method'): skipping = False; output.append(line)
        else: output.append(line)
    if skipping: raise RuntimeError('Incomplete disassembled method')
    return ''.join(output)


def run_t_u32(result, evidence, args):
    lock, serial, keys, ca = prerequisites(result, evidence, args)
    index = ROOT / '.work/evidence/T-U30.json'; baseline = json.loads(index.read_text())
    if baseline['verification'] != 'passed' or baseline['cell'] != result['cell']:
        raise PrerequisiteError('Unoptimized Java acceptance must pass first')
    result['inputs'].append(report_reference(index))
    original, prepared, patched = baseline['outputs']
    for artifact in (original, prepared, patched):
        if sha256(Path(artifact['apk'])) != artifact['sha256']: raise RuntimeError('Java fixture changed')
    rejected = patched['rejected']
    for name in ('unrelated(', 'checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;Z)Ljava/lang/String;'):
        if not any(item['method'].startswith(name) for item in rejected): raise RuntimeError('False-positive control absent')
    if sum(item['reason'] == 'native-or-abstract' for item in rejected) < 2:
        raise RuntimeError('Native/abstract refusal controls missing')
    result['comparisons'].append({'name': 'ambiguous-return-native-abstract-unrelated-refused', 'result': 'passed', 'rejected': rejected})
    try:
        patch_apk(Path(patched['apk']), evidence / 'prepatched-output', keys['repack'], lock, evidence)
    except ValueError as error:
        if 'Previously Java-patched' not in str(error): raise
    else: raise RuntimeError('Prepatched input was accepted')
    result['comparisons'].append({'name': 'prepatched-refused', 'result': 'passed'})
    decoy_logs = evidence / 'decoy'; decoy_logs.mkdir()
    command = dex_tool(lock, decoy_logs); decoy = decoy_logs / 'decoy.dex'
    execute([*command, 'decoy', str(lock['cell']['api']), str(decoy)], decoy_logs, 'build-decoy')
    baseline_fixtures = json.loads((ROOT / '.work/evidence/M0-build.json').read_text())
    result['inputs'].append(report_reference(ROOT / '.work/evidence/M0-build.json'))
    plain = next(item for item in baseline_fixtures['outputs'] if item['id'] == 'app-own')
    if sha256(Path(plain['apk'])) != plain['sha256']: raise RuntimeError('Decoy baseline changed')
    decoy_apk = decoy_logs / 'input.apk'
    copy_archive(Path(plain['apk']), decoy_apk, additions={'classes2.dex': decoy.read_bytes()})
    try: patch_apk(decoy_apk, decoy_logs / 'output', keys['repack'], lock, evidence)
    except UnsupportedJavaPatch:
        result['comparisons'].append({'name': 'string-only-input-unsupported', 'result': 'passed',
                                     'requested_transform': 'unsupported', 'input_sha256': sha256(decoy_apk),
                                     'baseline_sha256': plain['sha256'], 'output_apk': None})
    else: raise RuntimeError('String-only decoy input was patched')
    # Independent canonical disassembly checks every unedited member of the complete copied class.
    dependencies = java_dependencies('smali'); classpath = ':'.join(item['path'] for item in dependencies)
    owners = sorted({item['class'] for item in patched['patches']})
    directory = Path(patched['apk']).parent
    for label, dex in [('original', directory / 'original-dex/classes.dex'), ('shadow', directory / 'classes.dex')]:
        execute([tool(lock, 'java'), '-cp', classpath, 'com.android.tools.smali.baksmali.Main', 'disassemble',
                 '--api', str(lock['cell']['api']), '--classes', ','.join(owners), '--accessor-comments', 'false', '-j', '2',
                 '-o', str(evidence / (label + '-smali')), str(dex)], evidence, label + '-disassemble')
    for owner in owners:
        path = owner[1:-1] + '.smali'
        selected = {item['method'] for item in patched['patches'] if item['class'] == owner}
        before = strip_selected_methods((evidence / 'original-smali' / path).read_text(), selected)
        after = strip_selected_methods((evidence / 'shadow-smali' / path).read_text(), selected)
        if before != after: raise RuntimeError('Unedited complete-class members changed: ' + owner)
    result['comparisons'].append({'name': 'complete-class-unedited-members-identical', 'result': 'passed', 'classes': owners})
    # A Java patch alone is not an HTTPS success when the default TLS manager lacks the CA.
    part = evidence / 'missing-trust'; part.mkdir()
    route = build_bootstrap(Path(original['apk']), ROOT / '.work/outputs/pinning' / result['run_id'] / 'no-trust-route',
                            keys['repack'], lock, part, proxy=parse_proxy('127.0.0.1:8080'))
    shadow_logs = evidence / 'no-trust-shadow'; shadow_logs.mkdir()
    no_trust = patch_apk(Path(route['apk']), ROOT / '.work/outputs/pinning' / result['run_id'] / 'no-trust-shadow',
                         keys['repack'], lock, shadow_logs)
    result['outputs'] = [no_trust]
    with oracle(evidence / 'proxy', args.proxy_bind) as (_, logfile):
        with owned_reverse(lock, serial, 8080, args.proxy_bind, 8080, evidence, 'proxy',
                           result['device_mutations'], result['cleanup']):
            install_fixture(result, evidence, 'no-trust', no_trust, serial, lock, args)
            config = client_config(result, 'missing-trust', 'okhttp')
            event, _ = observe(no_trust, config, serial, lock, evidence, 'missing-trust')
            require_tls_failure(result, config, event, logfile, 'missing-trust-not-interception-success')
    malformed = evidence / 'malformed-resources.apk'
    with zipfile.ZipFile(malformed, 'w') as archive: archive.writestr('AndroidManifest.xml', b'invalid binary XML')
    try: apply_trust(malformed, ca, evidence / 'resource-failure', lock)
    except Exception as error:
        if not isinstance(error, RuntimeError) or 'resource-decode exited' not in str(error): raise
        result['comparisons'].append({'name': 'resource-failure-retained', 'result': 'passed',
            'requested_transform': 'failed', 'error_class': type(error).__name__, 'error': str(error)})
    else: raise RuntimeError('Malformed resource input accepted')
    if (evidence / 'resource-failure/unsigned.apk').exists(): raise RuntimeError('Failed trust transform emitted an APK')
    result.update(verification='passed', transformation='applied', scope='Named refusal controls; no false HTTPS acceptance')


def gate_pinning(result, evidence, args):
    children = {}; reports = {}
    for name in ('T-U30', 'T-U31', 'T-U32'):
        index = args.reports / (name + '.json'); child = json.loads(index.read_text())
        if child['verification'] != 'passed' or child['source_sha256'] != source_hash():
            raise PrerequisiteError(name + ' unavailable/failed/stale')
        children[name] = report_reference(index); reports[name] = child
    if any(child['cell'] != reports['T-U30']['cell'] for child in reports.values()): raise RuntimeError('Java cases differ in cell')
    if [len(reports[name]['comparisons']) for name in reports] != [11, 22, 6]:
        raise RuntimeError('Java fixture coverage incomplete')
    if reports['T-U32']['inputs'][1]['sha256'] != children['T-U30']['sha256']:
        raise RuntimeError('Refusal/preservation cases used another T-U30 artifact revision')
    result.update(verification='passed', gate_progress='accepted', children=children, cell=reports['T-U30']['cell'],
                  packaging='shadow', scope='OkHttp4.12.0 and named direct/inherited Java pinning fixtures, named R8 and near-limit cases',
                  unsupported=['fully-inlined-pinning-boundaries', 'unmatched-libraries', 'native-pinning', 'real-target-runtime'],
                  next_gate='remaining-M1a-identity')
