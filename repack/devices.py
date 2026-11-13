"""Read-only connected-device/app discovery, including display names."""
from pathlib import Path
import base64
import hashlib
import json
import threading
import re
import struct
import time
import uuid
import zipfile
from .rebuild import ROOT,PrerequisiteError,environment,execute,tool,sha256,write_json
from .verify import adb,shell

PACKAGE=re.compile(r'[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*')


def devices(lock,evidence):
    text=adb(lock,evidence,'devices',['devices','-l']).stdout
    result=[]
    for line in text.splitlines():
        fields=line.split()
        if len(fields)<2 or fields[0]=='List' or fields[0].startswith('*'):continue
        details=dict(v.split(':',1) for v in fields[2:] if ':' in v)
        result.append({'serial':fields[0],'state':fields[1],'model':details.get('model',fields[0]).replace('_',' ')})
    return result


def require_device(serial,lock,evidence):
    if not isinstance(serial,str) or serial not in {d['serial'] for d in devices(lock,evidence) if d['state']=='device'}:
        raise PrerequisiteError('Select a connected, authorized phone. Enable USB debugging and accept its prompt.')
    return serial


def parse_apps(text,user):
    result=[];done=None
    for line in text.splitlines():
        if line.startswith('REPACK_APP\t'):
            fields=line.split('\t')
            if len(fields) not in (3,6):raise ValueError('Malformed app inventory')
            package,label=[base64.b64decode(v,validate=True).decode('utf-8') for v in fields[1:3]]
            if not PACKAGE.fullmatch(package):raise ValueError('Invalid package in inventory')
            row={'package':package,'name':label[:500],'version':None,'version_code':None,'icon':None}
            if len(fields)==6:
                row['version']=base64.b64decode(fields[3],validate=True).decode('utf-8')[:200]
                if not re.fullmatch(r'[0-9]{1,20}',fields[4]):raise ValueError('Invalid version code')
                row['version_code']=int(fields[4])
                if fields[5]:
                    if len(fields[5])>90000:raise ValueError('Icon too large')
                    png=base64.b64decode(fields[5],validate=True)
                    if len(png)<33 or png[:8]!=b'\x89PNG\r\n\x1a\n' or png[12:16]!=b'IHDR' or struct.unpack('>II',png[16:24])!=(64,64):
                        raise ValueError('Invalid app icon')
                    row['icon']='data:image/png;base64,'+fields[5]
            result.append(row)
        elif line.startswith('REPACK_APPS_DONE\t'):done=line.split('\t')[1:]
    if done!=[str(user),str(len(result))] or len({r['package'] for r in result})!=len(result):
        raise ValueError('Incomplete app inventory')
    return sorted(result,key=lambda r:(r['name'].casefold(),r['package']))


_HELPER_LOCK=threading.Lock()


def app_helper(lock,evidence):
    """Cache the reproducible helper so metadata requests do not compile Java."""
    source=ROOT/'tools/AppList.java'
    key=hashlib.sha256((sha256(source)+lock['android_jar_sha256']+
        lock['tools']['javac']['sha256']+lock['tools']['d8']['sha256']+
        lock['tools']['d8'].get('jar_sha256','')).encode()).hexdigest()
    folder=ROOT/'.work/tools/app-list'/key
    jar=folder/'app-list.jar';record=folder/'helper.json'
    with _HELPER_LOCK:
        try:
            if jar.is_file() and record.is_file() and json.loads(record.read_text()).get('sha256')==sha256(jar):return jar
        except (ValueError,OSError):pass
        work=evidence/'helper-build';work.mkdir()
        classes=work/'classes';dex=work/'dex';classes.mkdir();dex.mkdir()
        execute([tool(lock,'javac'),'--release','8','-cp',lock['android_jar'],'-d',str(classes),str(source)],
                evidence,'apps-javac',env=environment(lock))
        compiled=work/'classes.jar'
        with zipfile.ZipFile(compiled,'w') as z:
            for p in classes.rglob('*.class'):z.write(p,str(p.relative_to(classes)))
        execute([tool(lock,'d8'),'--release','--min-api','28','--lib',lock['android_jar'],'--output',str(dex),str(compiled)],
                evidence,'apps-d8',env=environment(lock))
        folder.mkdir(parents=True,exist_ok=True)
        with zipfile.ZipFile(jar,'w') as z:z.write(dex/'classes.dex','classes.dex')
        write_json(record,{'sha256':sha256(jar),'source_sha256':sha256(source)})
    return jar


def apps(serial,lock,evidence,*,packages=None,expected_user=None):
    started=time.monotonic()
    require_device(serial,lock,evidence)
    user=int(shell(lock,evidence,'apps-user',serial,['am','get-current-user']).stdout.strip())
    if expected_user is not None and user!=expected_user:raise ValueError('Android user changed; reload the app list')
    if packages is not None and (not isinstance(packages,list) or not 1<=len(packages)<=20
            or any(not isinstance(p,str) or not PACKAGE.fullmatch(p) for p in packages) or len(set(packages))!=len(packages)):
        raise ValueError('Choose at most 20 package names for an icon batch')
    dexjar=app_helper(lock,evidence)
    remote='/data/local/tmp/repack-app-list-'+uuid.uuid4().hex+'.jar'
    try:
        adb(lock,evidence,'apps-push',['push',str(dexjar),remote],serial=serial)
        args=[str(user), 'icons' if packages is not None else 'list', *(packages or [])]
        text=shell(lock,evidence,'apps-query',serial,['env','CLASSPATH='+remote,'app_process','/system/bin','dev.repack.tools.AppList',*args],timeout=90).stdout
        return {'apps':parse_apps(text,user),'user':user,'device':serial,'names_available':True,'elapsed_seconds':round(time.monotonic()-started,3)}
    finally:
        shell(lock,evidence,'apps-cleanup',serial,['rm','-f',remote],check=False)


def apk_details(apk,lock,evidence):
    """Presentation metadata from the built input; XML/adaptive icons use a tile."""
    from .rebuild import badging
    import re
    _,text=badging(Path(apk),lock,evidence,'app-details')
    def value(pattern):
        match=re.search(pattern,text,re.M);return match[1] if match else None
    info={'name':value(r"^application-label:'([^']*)'"),
          'version':value(r"versionName='([^']*)'"),'icon':None}
    entries=re.findall(r"^application-icon-[0-9]+:'([^']+)'",text,re.M)
    with zipfile.ZipFile(apk) as z:
        for entry in reversed(entries):
            if entry not in z.namelist() or z.getinfo(entry).file_size>300000:continue
            data=z.read(entry);kind=None
            if data[:8]==b'\x89PNG\r\n\x1a\n' and len(data)>=24:
                w,h=struct.unpack('>II',data[16:24])
                if 0<w<=1024 and 0<h<=1024:kind='png'
            elif data[:4]==b'RIFF' and data[8:12]==b'WEBP':kind='webp'
            if kind:
                info['icon']='data:image/'+kind+';base64,'+base64.b64encode(data).decode();break
    return info
