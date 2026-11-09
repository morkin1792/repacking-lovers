"""Public CLI composition and ordinary-app runtime proof for the new TLS modes."""
import argparse
import json
from pathlib import Path
import re
import sys
import time
import uuid
import zipfile

from repack.rebuild import ROOT, environment, execute, load_lock, report, sha256, write_json
from repack.report import load_artifact
from repack.verify import shell, adb, preflight, install, capture_startup, owned_reverse
from repack.startup import _installed_hashes
from scripts.routing_cases import origin


def main(args):
    lock=load_lock();serial=args.device or lock['cell']['serial'];result,evidence=report('PINNING-EXPANSION-public')
    result.update(observations=[],artifacts={},scope='Public CLI host/signing composition and owned API30 target35 Android fixtures; no operator app was replaced')
    expansion=json.loads(args.expansion_report.read_text());dart=json.loads(args.dart_report.read_text())
    expansion_apk=Path(expansion['artifacts']['original']['apk']);dart_apk=Path(dart['original_apk'])
    if sha256(expansion_apk)!=expansion['artifacts']['original']['sha256'] or sha256(dart_apk)!=dart['original_sha256']:
        raise RuntimeError('Fixture input binding changed')
    packages={'expansion':'dev.repack.fixture.expansion','dart':'dev.repack.fixture.dartpins'}
    owned={};artifacts={};before=shell(lock,evidence,'global-before',serial,['settings','get','global','http_proxy']).stdout
    for name,package in packages.items():
        state=shell(lock,evidence,'initial-'+name,serial,['pm','path',package],check=False)
        if 'package:' in state.stdout:raise RuntimeError('Fixture package exists; refusing to claim ownership')
    try:
        for name,source,flags in [('expansion',expansion_apk,['--native-tls','offline-arm64','--relax-hostname']),
                ('dart',dart_apk,['--native-tls','offline-arm64','--dart-pinning']),('default',dart_apk,[])]:
            output=evidence/(name+'.apk')
            execute([sys.executable,'-m','repack','patch',str(source),'--out',str(output),'--key',str(ROOT/'.work/keys/repack.p12'),
                     '--ca',str(ROOT/'.work/keys/fixture-tls/origin-ca.pem'),'--device',serial,*flags],evidence,'build-'+name,env=environment(lock),timeout=240)
            manifest=output.with_suffix('.artifact.json');document,artifact=load_artifact(manifest)
            result['artifacts'][name]={'manifest':str(manifest),'manifest_sha256':sha256(manifest),'configuration':document['semantic']['configuration']}
            artifacts[name]=artifact
            if name=='default':
                with zipfile.ZipFile(source) as original,zipfile.ZipFile(output) as rebuilt:
                    for entry in ('lib/arm64-v8a/libapp.so','lib/arm64-v8a/libflutter.so'):
                        if rebuilt.read(entry)!=original.read(entry):raise RuntimeError('Default patch silently enabled a native/Dart mode')
        cases=[('expansion','hostname',{'case':'hostname','patched':True}),
               ('expansion','cronet',{'case':'cronet','patched':True}),
               ('expansion','openssl3',{'case':'native','patched':True,'library':'libfixture_ossl3.so'}),
               ('expansion','openssl34',{'case':'native','patched':True,'library':'libfixture_ossl34.so'}),
               ('dart','callback',{'mode':'callback'}),('dart','post',{'mode':'post'})]
        tls={'certificate':str(Path(dart['observations'][0]['evidence']).parents[0]/'tls/leaf.pem'),
             'key':str(Path(dart['observations'][0]['evidence']).parents[0]/'tls/leaf.key')}
        with origin(evidence/'origin',args.bind,18443,tls=tls):
            with owned_reverse(lock,serial,18443,args.bind,18443,evidence,'origin',result['device_mutations'],result['cleanup']):
                for index,(name,label,extras) in enumerate(cases):
                    package=packages[name];artifact=artifacts[name];part=evidence/('case-'+str(index));part.mkdir()
                    if name in owned:_installed_hashes({**owned[name],'members':[owned[name]]},serial,lock,part,'owned-before-update')
                    plan=preflight(artifact,serial,False,lock,part,'fixture',requested_package=package)
                    install(artifact,serial,plan,lock,part,'fixture',result['device_mutations']);owned[name]=artifact
                    _installed_hashes({**artifact,'members':[artifact]},serial,lock,part,'installed')
                    token=uuid.uuid4().hex;observed=None
                    # The owned leaf is valid for localhost; direct fixtures retain the wrong-host control.
                    host='localhost';url='https://'+host+':18443/repack/'+token
                    activity='ExpansionActivity' if name=='expansion' else 'NativeTlsActivity'
                    command=['am','start','-n',package+'/.'+activity,'--es','token',token,'--es','url',url]
                    for key,value in extras.items():command+=['--ez' if isinstance(value,bool) else '--es',key,str(value).lower() if isinstance(value,bool) else value]
                    with capture_startup(lock,serial,part,'fixture') as log:
                        shell(lock,part,'stop',serial,['am','force-stop',package]);shell(lock,part,'launch',serial,command,timeout=20)
                        for _ in range(250):
                            for line in log.read_text(errors='replace').splitlines():
                                tag='REPACK_EXPANSION' if name=='expansion' else 'REPACK_NATIVE'
                                if tag not in line or token not in line or '{' not in line:continue
                                try:row=json.loads(line[line.index('{'):])
                                except ValueError:continue
                                if row.get('token')==token:observed=row
                            if observed:break
                            time.sleep(.1)
                    if not observed:raise RuntimeError('Public fixture result missing: '+label)
                    observed.update(artifact=name,label=label,apk_sha256=artifact['sha256'],evidence=str(part));result['observations'].append(observed)
                    write_json(part/'result.json',observed);print('PUBLIC',json.dumps(observed),flush=True)
                    if name=='expansion' and not observed.get('ok'):raise RuntimeError('Public expansion fixture failed: '+label)
                    if name=='dart' and (observed.get('status')!='response' or observed.get('http_status')!=200 or token not in observed.get('body','')
                            or observed.get('feature_negative_control') is not False):raise RuntimeError('Public Dart fixture failed: '+label)
        result['verification']='passed'
    except BaseException as error:
        result.update(verification='failed',error_class=type(error).__name__,error=str(error));raise
    finally:
        for name,artifact in owned.items():
            try:
                _installed_hashes({**artifact,'members':[artifact]},serial,lock,evidence,'cleanup-'+name)
                shell(lock,evidence,'stop-'+name,serial,['am','force-stop',packages[name]])
                removed=adb(lock,evidence,'remove-'+name,['uninstall',packages[name]],serial=serial)
                if 'Success' not in removed.stdout:raise RuntimeError('Owned fixture removal failed')
                result['cleanup'].append({'action':'remove-owned-fixture','package':packages[name],'verification':'passed'})
            except Exception as error:result['cleanup'].append({'action':'remove-owned-fixture','package':packages[name],'verification':'inconclusive','error':str(error)});result['verification']='failed'
        result['operator_global_proxy_preserved']=shell(lock,evidence,'global-after',serial,['settings','get','global','http_proxy']).stdout==before
        if not result['operator_global_proxy_preserved']:result['verification']='failed'
        write_json(evidence/'report.json',result);write_json(ROOT/'.work/evidence/PINNING-EXPANSION-public.json',{**result,'evidence_refs':[str(evidence/'report.json')]})
        print('EVIDENCE',evidence/'report.json',flush=True)
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--device');parser.add_argument('--bind',default='127.0.0.1')
    parser.add_argument('--expansion-report',type=Path,default=ROOT/'.work/evidence/PINNING-EXPANSION-android.json')
    parser.add_argument('--dart-report',type=Path,default=ROOT/'.work/evidence/DART-PINNING-android.json')
    args=parser.parse_args();sys.exit(0 if main(args)['verification']=='passed' else 1)
