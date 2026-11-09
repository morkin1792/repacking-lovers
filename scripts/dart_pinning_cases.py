"""Owned Flutter fixture for callback and post-handshake Dart certificate pins."""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import time
import uuid
import zipfile

from repack.rebuild import ROOT, align_sign, copy_archive, ensure_keys, environment, execute, load_lock, report, sha256, tool, write_json
from repack.native_tls import dependencies
from repack.elf_tls import patch_library
from repack.verify import shell, adb, preflight, install, capture_startup, owned_reverse
from repack.startup import _installed_hashes
from scripts.pinning_extension_cases import jar_directory
from scripts.routing_cases import origin

PACKAGE = 'dev.repack.fixture.dartpins'


def build_original(lock, keys, evidence):
    evidence.mkdir(); pin = dependencies(); sdk = ROOT / '.work/tools/flutter-3.10.6'
    project = evidence / 'project'; (project / 'lib').mkdir(parents=True); (project / 'assets').mkdir()
    for name in ('pubspec.yaml', 'pubspec.lock'): shutil.copyfile(ROOT / 'native/flutter' / name, project / name)
    with (project / 'pubspec.yaml').open('a') as out: out.write('\nflutter:\n  assets:\n    - assets/origin-ca.pem\n')
    shutil.copyfile(ROOT / 'tests/fixtures/dart_pinning/main.dart', project / 'lib/main.dart')
    shutil.copyfile(ROOT / '.work/keys/fixture-tls/origin-ca.pem', project / 'assets/origin-ca.pem')
    env = environment(lock); env.update(FLUTTER_SUPPRESS_ANALYTICS='true', DART_SUPPRESS_ANALYTICS='true')
    for label, arguments in [('pub-get', ['pub', 'get', '--offline']), ('assemble', ['assemble', '--output=build/native-bundle',
            '-dTargetFile=lib/main.dart', '-dTargetPlatform=android-arm64', '-dBuildMode=release', '-dDartObfuscation=false',
            '-dTrackWidgetCreation=false', '-dTreeShakeIcons=false', 'android_aot_bundle_release_android-arm64'])]:
        command = [str(sdk / 'bin/flutter'), '--no-version-check', *arguments]
        done = subprocess.run(command, cwd=project, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=180)
        write_json(evidence / (label + '.command.json'), {'argv': command, 'cwd': str(project), 'exit_status': done.returncode})
        (evidence / (label + '.stdout.log')).write_text(done.stdout); (evidence / (label + '.stderr.log')).write_text(done.stderr)
        if done.returncode: raise RuntimeError('Flutter fixture build failed: ' + label)
    output = project / 'build/native-bundle'; app = output / 'arm64-v8a/app.so'
    flutter_jar = sdk / 'bin/cache/artifacts/engine/android-arm64-release/flutter.jar'; jars = [flutter_jar]
    for row in pin['dependencies']:
        path = ROOT / row.get('classes_path', row['path'])
        if sha256(path) != row.get('classes_sha256', row['sha256']): raise RuntimeError('Flutter fixture dependency changed')
        jars.append(path)
    source = evidence / 'NativeTlsActivity.java'
    java = (ROOT / 'native/flutter/NativeTlsActivity.java').read_text().replace('dev.repack.fixture.identity', PACKAGE)
    java = java.replace('getIntent().getStringExtra("url")))', 'getIntent().getStringExtra("url"), getIntent().getStringExtra("mode")))')
    java = java.replace('result.put("pid", Process.myPid());', 'result.put("pid", Process.myPid()); result.put("uid", Process.myUid()); result.put("target_sdk", getApplicationInfo().targetSdkVersion);')
    source.write_text(java); classes = evidence / 'classes'; classes.mkdir(); dex = evidence / 'dex'; dex.mkdir()
    execute([tool(lock, 'javac'), '--release', '8', '-cp', ':'.join(map(str, [Path(lock['android_jar']), *jars])), '-d', str(classes), str(source)], evidence, 'javac', env=env)
    own = evidence / 'own.jar'; jar_directory(classes, own)
    execute([tool(lock, 'd8'), '--release', '--min-api', '28', '--lib', lock['android_jar'], '--output', str(dex), str(own), *map(str,jars)], evidence, 'd8', env=env)
    manifest = evidence / 'AndroidManifest.xml'; manifest.write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="' + PACKAGE + '" android:versionCode="1"><uses-sdk android:minSdkVersion="28" android:targetSdkVersion="35"/><uses-permission android:name="android.permission.INTERNET"/><application android:extractNativeLibs="true" android:label="Owned Dart pin fixture"><activity android:name=".NativeTlsActivity" android:exported="true"/><meta-data android:name="flutterEmbedding" android:value="2"/></application></manifest>')
    linked = evidence / 'linked.apk'; execute([tool(lock,'aapt2'),'link','-I',lock['android_jar'],'--manifest',str(manifest),'-o',str(linked)],evidence,'link',env=env)
    additions = {p.name:p.read_bytes() for p in dex.glob('classes*.dex')}
    additions['lib/arm64-v8a/libapp.so'] = app.read_bytes()
    with zipfile.ZipFile(flutter_jar) as archive: additions['lib/arm64-v8a/libflutter.so'] = archive.read('lib/arm64-v8a/libflutter.so')
    for path in (output / 'flutter_assets').rglob('*'):
        if path.is_file(): additions['assets/flutter_assets/' + path.relative_to(output / 'flutter_assets').as_posix()] = path.read_bytes()
    copy_archive(linked,evidence/'unsigned.apk',additions=additions)
    original=evidence/'original.apk'; align_sign(evidence/'unsigned.apk',original,keys['repack'],lock,evidence)
    return original, app, additions['lib/arm64-v8a/libflutter.so']


def main(args):
    lock=load_lock(); result,evidence=report('DART-PINNING-build');keys=ensure_keys(lock,evidence)
    original,app,engine=build_original(lock,keys,evidence/'build')
    result.update(verification='passed',original_apk=str(original),original_sha256=sha256(original),app=str(app),app_sha256=sha256(app),engine_sha256=__import__('hashlib').sha256(engine).hexdigest())
    write_json(evidence/'report.json',result);write_json(ROOT/'.work/evidence/DART-PINNING-build.json',{**result,'evidence_refs':[str(evidence/'report.json')]})
    print('BUILT',evidence,flush=True)
    if args.build_only: return
    from repack.dart_pinning import analyze
    native_engine,native_transform=patch_library(engine,'libflutter.so')
    dart_app,dart_transform=analyze(app.read_bytes(),evidence/'dart-analysis')
    variants={'original':original}
    for name, replacements in [('native',{'lib/arm64-v8a/libflutter.so':native_engine}),
            ('dart',{'lib/arm64-v8a/libapp.so':dart_app}),
            ('both',{'lib/arm64-v8a/libflutter.so':native_engine,'lib/arm64-v8a/libapp.so':dart_app})]:
        part=evidence/name;part.mkdir();copy_archive(original,part/'unsigned.apk',replacements=replacements)
        variants[name]=part/'fixture.apk';align_sign(part/'unsigned.apk',variants[name],keys['repack'],lock,part)
    write_json(evidence/'native-transform.json',native_transform);write_json(evidence/'dart-transform.json',dart_transform)
    serial=args.device or lock['cell']['serial'];latest=None
    result.update(verification='not-run',observations=[],native_transform=native_transform,dart_transform=dart_transform)
    existing=shell(lock,evidence,'initial-fixture-paths',serial,['pm','path',PACKAGE],check=False)
    if 'package:' in existing.stdout: raise RuntimeError('Refusing ownership of an existing Dart fixture package')
    before=shell(lock,evidence,'global-before',serial,['settings','get','global','http_proxy']).stdout
    try:
        tls_dir=evidence/'tls';tls_dir.mkdir(mode=0o700)
        execute(['openssl','req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=localhost',
                 '-keyout',str(tls_dir/'leaf.key'),'-out',str(tls_dir/'leaf.csr')],tls_dir,'keygen')
        (tls_dir/'extensions').write_text('basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n')
        execute(['openssl','x509','-req','-in',str(tls_dir/'leaf.csr'),'-CA',str(ROOT/'.work/keys/fixture-tls/origin-ca.pem'),
                 '-CAkey',str(ROOT/'.work/keys/fixture-tls/origin-ca.key'),'-set_serial','0x'+uuid.uuid4().hex,
                 '-days','2','-extfile',str(tls_dir/'extensions'),'-out',str(tls_dir/'leaf.pem')],tls_dir,'issue')
        (tls_dir/'leaf.key').chmod(0o600)
        tls={'certificate':str(tls_dir/'leaf.pem'),'key':str(tls_dir/'leaf.key')}
        with origin(evidence/'origin',args.bind,18443,tls=tls):
            with owned_reverse(lock,serial,18443,args.bind,18443,evidence,'origin',result['device_mutations'],result['cleanup']):
                for index,(name,mode,accept) in enumerate([('original','callback',False),('native','callback',True),
                        ('original','post',False),('native','post',False),('dart','post',True),('both','post',True)]):
                    apk=variants[name];artifact={'package':PACKAGE,'version_code':1,'apk':str(apk),'sha256':sha256(apk),'signer_sha256':[keys['repack']['sha256']]}
                    part=evidence/('case-'+str(index));part.mkdir()
                    if latest:_installed_hashes({**latest,'members':[latest]},serial,lock,part,'owned-before-update')
                    plan=preflight(artifact,serial,False,lock,part,'fixture',requested_package=PACKAGE)
                    install(artifact,serial,plan,lock,part,'fixture',result['device_mutations']);latest=artifact
                    _installed_hashes({**artifact,'members':[artifact]},serial,lock,part,'installed')
                    token=uuid.uuid4().hex;observed=None
                    with capture_startup(lock,serial,part,'fixture') as log:
                        shell(lock,part,'stop',serial,['am','force-stop',PACKAGE])
                        shell(lock,part,'launch',serial,['am','start','-n',PACKAGE+'/.NativeTlsActivity','--es','token',token,
                            '--es','url','https://localhost:18443/repack/'+token,'--es','mode',mode],timeout=30)
                        for _ in range(250):
                            for line in log.read_text(errors='replace').splitlines():
                                if 'REPACK_NATIVE' not in line or token not in line or '{' not in line:continue
                                try:row=json.loads(line[line.index('{'):])
                                except ValueError:continue
                                if row.get('token')==token:observed=row
                            if observed:break
                            time.sleep(.1)
                    if not observed:raise RuntimeError('Missing Dart result '+name+'/'+mode)
                    observed.update(variant=name,apk_sha256=artifact['sha256'],evidence=str(part));result['observations'].append(observed)
                    write_json(part/'result.json',observed);print('DART',json.dumps(observed),flush=True)
                    if ((observed['status']=='response')!=accept or observed.get('unrelated')!=42 or observed.get('feature_negative_control') is not False
                            or observed.get('uid',0)<10000 or observed.get('target_sdk')!=35):raise RuntimeError('Dart result/control failed '+name+'/'+mode)
                    if accept and (observed.get('http_status')!=200 or token not in observed.get('body','')):raise RuntimeError('Missing marked Dart HTTP response')
                    if not accept and mode=='post' and 'pin mismatch' not in observed.get('error',''):raise RuntimeError('Post-handshake pin control failed')
                    if not accept and mode=='callback' and 'CERTIFICATE_VERIFY_FAILED' not in observed.get('error',''):raise RuntimeError('Dart TLS rejection control failed')
        result['verification']='passed'
    except BaseException as error:
        result.update(verification='failed',error_class=type(error).__name__,error=str(error));raise
    finally:
        if latest:
            try:
                _installed_hashes({**latest,'members':[latest]},serial,lock,evidence,'cleanup-owned')
                shell(lock,evidence,'cleanup-stop',serial,['am','force-stop',PACKAGE]);removed=adb(lock,evidence,'cleanup-uninstall',['uninstall',PACKAGE],serial=serial)
                if 'Success' not in removed.stdout:raise RuntimeError('Owned Dart fixture removal failed')
                result['cleanup'].append({'action':'remove-owned-fixture','verification':'passed'})
            except Exception as error:result['cleanup'].append({'action':'remove-owned-fixture','verification':'inconclusive','error':str(error)});result['verification']='failed'
        result['operator_global_proxy_preserved']=shell(lock,evidence,'global-after',serial,['settings','get','global','http_proxy']).stdout==before
        if not result['operator_global_proxy_preserved']:result['verification']='failed'
        write_json(evidence/'report.json',result);write_json(ROOT/'.work/evidence/DART-PINNING-android.json',{**result,'evidence_refs':[str(evidence/'report.json')]})
        print('EVIDENCE',evidence/'report.json',flush=True)
    if result['verification']!='passed':raise RuntimeError('Dart verification or cleanup did not pass')


if __name__ == '__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--device');parser.add_argument('--bind',default='127.0.0.1')
    parser.add_argument('--build-only',action='store_true')
    main(parser.parse_args())
