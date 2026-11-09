"""Pinned real-library host checks for Java APK patch extensions.

The generated DEX is translated back for JVM execution as a host semantic check;
this does not substitute for Android ART/device acceptance. No target app runs.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tarfile
import urllib.request
import zipfile

from repack.rebuild import (ROOT, PrerequisiteError, align_sign, copy_archive, ensure_keys,
                            environment, execute, load_lock, report, sha256, tool, write_json)
from repack.patches import patch_apk, java_dependencies, inspect_dex

FIXTURES = ROOT / 'tests/fixtures/pinning_extensions'
DEPENDENCIES = ROOT / 'config/pinning-fixture-dependencies.json'


def dependencies(fetch=False):
    pins = json.loads(DEPENDENCIES.read_text()); result = {}
    for row in pins['artifacts']:
        path = ROOT / row['path']
        if not path.is_file() and fetch:
            data = urllib.request.urlopen(row['url'], timeout=180).read()
            if hashlib.sha256(data).hexdigest() != row['sha256']: raise RuntimeError('Test dependency download changed: ' + row['name'])
            path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
        if not path.is_file() or sha256(path) != row['sha256']:
            raise PrerequisiteError('Missing/changed pinned test dependency: ' + row['name'] + '; run scripts.pinning_extension_cases --fetch-dependencies')
        result[row['name']] = path
    return result


def jar_directory(directory, output):
    with zipfile.ZipFile(output, 'w') as archive:
        for path in sorted(directory.rglob('*.class')): archive.write(path, path.relative_to(directory).as_posix())


def tools_for_host(pins, evidence):
    jre = evidence / 'fixture-jre'; jre.mkdir()
    with tarfile.open(pins['fixture-jre17.tar.gz']) as archive: archive.extractall(jre, filter='data')
    java = next(jre.glob('*/bin/java'))
    libs = evidence / 'dex2jar-lib'; libs.mkdir()
    with zipfile.ZipFile(pins['dex-tools-v2.4.zip']) as archive:
        for name in archive.namelist():
            if '/lib/' in name and name.endswith('.jar'): (libs / Path(name).name).write_bytes(archive.read(name))
    return java, ':'.join(str(p) for p in sorted(libs.glob('*.jar')))


CASES = ('okhttp', 'ct', 'interceptor', 'plugins', 'conscrypt')


def host_cases(fetch=False, cases=CASES):
    if not cases or any(c not in CASES for c in cases) or len(set(cases)) != len(cases): raise ValueError('Unknown/duplicate fixture case')
    pins = dependencies(fetch); result, evidence = report('PINNING-EXTENSIONS-real-library-host')
    lock = load_lock(); env = environment(lock); keys = ensure_keys(lock, evidence)
    java, d2j_cp = tools_for_host(pins, evidence)
    fixtures = evidence / 'fixtures'; fixtures.mkdir()
    stubs = fixtures / 'stubs'; stubs.mkdir()
    execute([tool(lock, 'javac'), '--release', '8', '-cp', lock['android_jar'], '-d', str(stubs),
             *map(str, sorted((FIXTURES / 'stubs').rglob('*.java')))], evidence, 'stub-javac', env=env)
    stub_jar = fixtures / 'stubs.jar'; jar_directory(stubs, stub_jar)
    http = [a['path'] for a in java_dependencies('http-fixture')]
    harness = fixtures / 'harness'; harness.mkdir()
    execute([tool(lock, 'javac'), '--release', '8', '-cp', ':'.join([str(stub_jar), *http]),
             '-d', str(harness), str(FIXTURES / 'HostHarness.java')], evidence, 'harness-javac', env=env)
    execute([tool(lock, 'javac'), '--release', '8', '-cp', d2j_cp, '-d', str(harness),
             str(FIXTURES / 'FixtureFrames.java')], evidence, 'frame-tool-javac', env=env)
    kotlin_cp = ':'.join(str(p) for name, p in pins.items() if name.startswith(('kotlin-', 'trove4j-'))) + ':' + ':'.join(http)
    observations = {}
    try:
        for mode in cases:
            part = evidence / mode; part.mkdir(); program = part / 'program.jar'
            if mode in ('okhttp', 'ct', 'conscrypt'):
                source = pins[{'okhttp': 'okhttp-3.14.9.jar', 'ct': 'ct-2.8.4.jar', 'conscrypt': 'conscrypt-2.5.2.jar'}[mode]]
                # D8 input is the real library's class files; original JAR remains
                # on the JVM classpath for resources/native provider binaries.
                with zipfile.ZipFile(source) as old, zipfile.ZipFile(program, 'w') as out:
                    for item in old.infolist():
                        if item.filename.endswith('.class') and not item.filename.startswith('META-INF/'):
                            out.writestr(item.filename, old.read(item.filename))
            elif mode == 'interceptor':
                classes = part / 'classes'; classes.mkdir()
                execute([tool(lock, 'javac'), '--release', '8', '-cp', ':'.join(http), '-d', str(classes),
                         *map(str, (FIXTURES / 'fallback').rglob('*.java'))], part, 'fixture-javac', env=env)
                jar_directory(classes, program)
            else:
                sources = []
                for name in ('http_certificate_pinning', 'ssl_pinning_plugin'):
                    with tarfile.open(pins[name + '.tar.gz']) as archive:
                        members = [m for m in archive.getmembers() if m.isfile() and m.name.startswith('android/')
                                   and m.name.endswith(('HttpCertificatePinningPlugin.kt', 'SslPinningPlugin.kt'))]
                        if len(members) != 1: raise RuntimeError('Unexpected pinned plugin source layout')
                        path = part / Path(members[0].name).name; path.write_bytes(archive.extractfile(members[0]).read()); sources.append(path)
                execute([str(java), '-cp', kotlin_cp, 'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler', '-no-stdlib', '-no-reflect',
                         '-jvm-target', '1.8', '-classpath', ':'.join([str(stub_jar), lock['android_jar'], *http]),
                         '-d', str(program), *map(str, sources)], part, 'plugin-kotlinc', env=env)
            runtime = [str(program), str(harness), str(stub_jar)]
            runtime += ([str(pins['okio-1.17.2.jar'])] + [p for p in http if 'okhttp-4.' not in p and 'okio-jvm-' not in p]) if mode == 'okhttp' else http
            if mode == 'conscrypt': runtime.append(str(pins['conscrypt-2.5.2.jar']))
            arguments = [mode, 'baseline', keys['original']['certificate'], keys['original']['path'], keys['original']['password_file']]
            vm = [str(java), '-Xverify:all', '--add-opens=java.base/java.net=ALL-UNNAMED', '--add-opens=java.base/sun.nio.ch=ALL-UNNAMED']
            baseline = execute([*vm, '-cp', ':'.join(runtime), 'HostHarness', *arguments], part, 'baseline', env=env, timeout=45)
            if f'PINNING_EXTENSION_PASS {mode} baseline' not in baseline.stdout: raise RuntimeError('Missing original-library oracle')
            dex = part / 'dex'; dex.mkdir()
            execute([tool(lock, 'd8'), '--release', '--min-api', '28', '--lib', lock['android_jar'],
                     '--classpath', str(stub_jar), '--output', str(dex), str(program)], part, 'd8', env=env)
            manifest = part / 'AndroidManifest.xml'
            manifest.write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="dev.repack.fixture.extensions" android:versionCode="1"><uses-sdk android:minSdkVersion="28" android:targetSdkVersion="35"/><application android:label="Pin extension fixture"/></manifest>')
            linked = part / 'linked.apk'
            execute([tool(lock, 'aapt2'), 'link', '-I', lock['android_jar'], '--manifest', str(manifest), '-o', str(linked)], part, 'aapt-link', env=env)
            unsigned = part / 'original-unsigned.apk'
            copy_archive(linked, unsigned, additions={p.name: p.read_bytes() for p in dex.glob('classes*.dex')})
            original = part / 'original.apk'; align_sign(unsigned, original, keys['original'], lock, part)
            patch_logs = part / 'patch-logs'; patch_logs.mkdir()
            patched = patch_apk(original, part / 'patched', keys['repack'], lock, patch_logs)
            shadow_command = json.loads((patch_logs / 'dex-shadow.command.json').read_text())['argv']
            if mode == 'conscrypt':
                audit = part / 'side-effect-audit'; audit.mkdir()
                prefix = shadow_command[:shadow_command.index('shadow')]
                inspected = inspect_dex(part / 'patched', prefix, lock['cell']['api'], audit)
                for target in patched['patches']:
                    callback = next(m for m in inspected['classes'][target['class']]['methods'] if m['descriptor'] == target['method'])
                    refs = callback['references']
                    if (any('->checkServerTrusted(' in ref for ref in refs)
                            or not any('->checkClientTrusted(' in ref for ref in refs)
                            or not any('->onPeerCertificatesReceived(' in ref for ref in refs)
                            or not any('->decodeX509CertificateChain(' in ref for ref in refs)):
                        raise RuntimeError('Conscrypt callback side-effect contract was not preserved')
            shadow = part / 'patched/classes.dex'; translated = part / 'translated.jar'
            execute([str(java), '-cp', d2j_cp, 'com.googlecode.dex2jar.tools.Dex2jarCmd', '-f', '-o', str(translated), str(shadow)],
                    part, 'dex2jar', env=env, timeout=90)
            if list(part.glob('*error.zip')): raise RuntimeError('DEX translation had method errors')
            verified_jar = part / 'translated-frames.jar'
            execute([str(java), '-cp', ':'.join([str(harness), d2j_cp, *runtime]), 'FixtureFrames', str(translated), str(verified_jar)],
                    part, 'frames', env=env, timeout=45)
            if mode == 'plugins':
                # D8 generates Runnable/SAM helpers that do not exist in the
                # upstream class JAR. They remain in the preserved original DEX
                # on Android; supply precisely those classes to the host adapter.
                originals_jar = part / 'original-dex.jar'
                execute([str(java), '-cp', d2j_cp, 'com.googlecode.dex2jar.tools.Dex2jarCmd', '-f', '-o', str(originals_jar), str(original)],
                        part, 'original-dex2jar', env=env, timeout=90)
                if list(part.glob('*error.zip')): raise RuntimeError('Original fixture DEX translation had method errors')
                helpers = part / 'desugared-helpers.jar'; helper_frames = part / 'desugared-helpers-frames.jar'
                with zipfile.ZipFile(program) as upstream, zipfile.ZipFile(originals_jar) as converted, zipfile.ZipFile(helpers, 'w') as output:
                    names = set(upstream.namelist())
                    for item in converted.infolist():
                        if item.filename.endswith('.class') and item.filename not in names:
                            output.writestr(item.filename, converted.read(item.filename))
                execute([str(java), '-cp', ':'.join([str(harness), d2j_cp, str(helpers), *runtime]),
                         'FixtureFrames', str(helpers), str(helper_frames)], part, 'helper-frames', env=env, timeout=45)
                runtime.insert(0, str(helper_frames))
            arguments[1] = 'patched'
            after = execute([*vm, '-cp', ':'.join([str(verified_jar), *runtime]), 'HostHarness', *arguments], part, 'patched-runtime', env=env, timeout=45)
            if f'PINNING_EXTENSION_PASS {mode} patched' not in after.stdout: raise RuntimeError('Missing rewritten-library oracle')
            observations[mode] = {'verification': 'passed', 'original_apk': {'path': str(original), 'sha256': sha256(original)},
                'patched_apk': {'path': patched['apk'], 'sha256': patched['sha256']},
                'replacements': [{'class': row['class'], 'method': row['method'], 'kind': row['kind'], 'replacement': row['replacement']} for row in patched['patches']],
                'original_dex_preserved': True, 'evidence': str(part)}
            if mode == cases[0]:
                first = patched['patches'][0]
                first_row = first['class'] + '\t' + first['method']
                wrong = 'return-false' if first['method'].endswith(')V') else 'return-void'
                for label, content, error in [
                    ('missing-contract', first_row + '\n', 'explicit replacement'),
                    ('unknown-contract', first_row + '\tguess\n', 'explicit replacement'),
                    ('wrong-type', first_row + '\t' + wrong + '\n', 'contract mismatch'),
                    ('duplicate', first_row + '\t' + first['replacement'] + '\n' + first_row + '\t' + first['replacement'] + '\n', 'Duplicate requested method')]:
                    selection = part / (label + '.tsv'); selection.write_text(content)
                    output = part / (label + '.dex'); argv = [*shadow_command[:-2], str(selection), str(output)]
                    refused = execute(argv, part, label, env=env, check=False)
                    if refused.returncode == 0 or error not in refused.stderr or output.exists():
                        raise RuntimeError('Malformed selection was not refused: ' + label)
            write_json(part / 'result.json', observations[mode]); print('PASS', mode, observations[mode]['replacements'], flush=True)
        result.update(verification='passed', cases=observations, android_runtime_verification='not-run',
            scope='Real Java libraries compiled to DEX, APK shadow rewrite, dex2jar/JVM semantics; scheduling adapters and interceptor fallback are fixtures')
    except Exception as error:
        result.update(verification='failed', error=str(error), error_class=type(error).__name__, cases=observations, android_runtime_verification='not-run')
        raise
    finally:
        write_json(evidence / 'report.json', result)
        suffix = '' if tuple(cases) == CASES else '-' + '-'.join(cases)
        write_json(ROOT / ('.work/evidence/PINNING-EXTENSIONS-host' + suffix + '.json'), {**result, 'evidence_refs': [str(evidence / 'report.json')]})
        print('EVIDENCE', evidence / 'report.json', flush=True)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--fetch-dependencies', action='store_true')
    parser.add_argument('--case', action='append', choices=CASES)
    args = parser.parse_args(); host_cases(args.fetch_dependencies, tuple(args.case) if args.case else CASES)
