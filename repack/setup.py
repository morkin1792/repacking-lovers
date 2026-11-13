"""Local first-run setup: SDK discovery/downloads, pinned helpers and one operator key."""
from pathlib import Path, PurePosixPath
import hashlib
import json
import os
import platform
import secrets
import shutil
import stat
import tempfile
import urllib.request
import zipfile
from .rebuild import ROOT, PrerequisiteError, environment, execute, sha256, write_json

OPERATOR_HOME = Path(os.environ.get('XDG_DATA_HOME') or Path.home()/'.local/share') / 'repacking-lovers'
MANAGED_KEY = OPERATOR_HOME / 'keys/repack.p12'
MANAGED_PASSWORD = OPERATOR_HOME / 'keys/keystore.pass'


def discover():
    java = shutil.which('javac')
    jdks = [os.environ.get(name) for name in ('JAVA_HOME', 'JDK_HOME', 'STUDIO_JDK')]
    if java: jdks.append(str(Path(java).resolve().parent.parent))
    jdk = next((Path(p).expanduser() for p in jdks if p and (Path(p).expanduser()/'bin/javac').is_file()), None)
    candidates = []
    def add(path, source, explicit=False):
        if not path: return
        path = Path(os.path.expandvars(str(path))).expanduser().absolute()
        if not any(row['path'] == str(path) for row in candidates):
            candidates.append({'path': str(path), 'source': source, 'explicit': explicit})
    for name in ('ANDROID_HOME', 'ANDROID_SDK_ROOT', 'STUDIO_SDK_PATH'):
        add(os.environ.get(name), name, True)
    # ANDROID_SDK_HOME normally stores preferences. Accept it only if it really
    # contains an SDK, never as a synonym for the SDK root unconditionally.
    preference = os.environ.get('ANDROID_SDK_HOME')
    if preference and any((Path(preference).expanduser()/part).exists() for part in ('platforms','platform-tools','build-tools','cmdline-tools')):
        add(preference, 'ANDROID_SDK_HOME (SDK contents detected)')
    adb = shutil.which('adb')
    if adb:
        binary = Path(adb).resolve()
        if binary.parent.name == 'platform-tools': add(binary.parent.parent, 'adb on PATH')
    for path in (Path.home()/'Android/Sdk', Path.home()/'Android/sdk', Path.home()/'android-sdk',
                 Path.home()/'android-sdk-linux', Path.home()/'.android/sdk', Path.home()/'Library/Android/sdk'):
        add(path, 'Default SDK location')
    if os.environ.get('LOCALAPPDATA'): add(Path(os.environ['LOCALAPPDATA'])/'Android/Sdk', 'LOCALAPPDATA')
    for path in ('/opt/android-sdk','/opt/android-sdk-linux','/usr/lib/android-sdk','/usr/local/lib/android/sdk','/usr/local/share/android-sdk'):
        add(path, 'System SDK location')
    add(ROOT/'.work/tools/android-sdk', 'Managed SDK')
    def is_sdk(row):
        path = Path(row['path'])
        return path.is_dir() and (row['explicit'] or any((path/part).exists() for part in ('platforms','platform-tools','build-tools','cmdline-tools')))
    selected = next((row for row in candidates if is_sdk(row)), None)
    if selected is None:
        selected = next((row for row in candidates if row['explicit']), candidates[-1])
    return {'jdk': str(jdk) if jdk else '', 'sdk': selected['path'], 'sdk_source': selected['source'],
            'sdk_candidates': [row for row in candidates if is_sdk(row)],
            'supported_host': platform.system()=='Linux' and platform.machine() in ('x86_64','amd64'),
            'sdk_license': 'https://developer.android.com/studio/terms'}


def local_tools_available(info=None):
    info=info or discover()
    if not info['supported_host'] or not info['jdk']:return False
    sdk=Path(info['sdk'])
    required=['platforms/android-36/android.jar',*['build-tools/36.0.0/'+name for name in ('aapt2','d8','apksigner','zipalign')]]
    return all((sdk/path).is_file() for path in required) and bool(shutil.which('adb') or (sdk/'platform-tools/adb').is_file())


def fetch(pin, destination, notify=lambda message: None):
    """Check before reuse; never leave partial downloads at their published path."""
    destination=Path(destination)
    if destination.exists():
        if sha256(destination)!=pin['sha256']:raise PrerequisiteError('Cached dependency changed: '+str(destination))
        return destination
    destination.parent.mkdir(parents=True,exist_ok=True)
    notify('Downloading '+destination.name)
    fd,tmp=tempfile.mkstemp(prefix='.download-',dir=destination.parent)
    try:
        h=hashlib.sha256(); size=0
        with os.fdopen(fd,'wb') as output,urllib.request.urlopen(pin.get('source_url') or pin['url'],timeout=60) as response:
            while chunk:=response.read(1024**2):
                size+=len(chunk)
                if size>1024**3:raise ValueError('Dependency exceeds download size limit')
                h.update(chunk);output.write(chunk)
        if h.hexdigest()!=pin['sha256'] or ('size' in pin and size!=pin['size']):raise RuntimeError('Dependency checksum/size mismatch')
        os.replace(tmp,destination)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)
    return destination


def extract_sdk(archive, destination):
    """SDK ZIPs have one top directory; discard it without trusting ZIP paths."""
    destination=Path(destination)
    if destination.exists():raise PrerequisiteError('Incomplete SDK directory exists: '+str(destination))
    destination.parent.mkdir(parents=True,exist_ok=True)
    temporary=Path(tempfile.mkdtemp(prefix='.sdk-',dir=destination.parent))
    try:
        with zipfile.ZipFile(archive) as z:
            seen=set(); roots=set(); total=0
            for item in z.infolist():
                parts=PurePosixPath(item.filename).parts
                if (not parts or item.filename.startswith('/') or '\\' in item.filename or ':' in item.filename
                    or any(p in ('.','..') for p in parts) or item.filename in seen
                    or stat.S_ISLNK(item.external_attr>>16)):
                    raise ValueError('Unsafe SDK archive member')
                seen.add(item.filename);roots.add(parts[0]);total+=item.file_size
                if total>2*1024**3:raise ValueError('Expanded SDK archive is too large')
                if len(parts)==1:continue
                path=temporary.joinpath(*parts[1:])
                if item.is_dir():path.mkdir(parents=True,exist_ok=True);continue
                path.parent.mkdir(parents=True,exist_ok=True)
                with z.open(item) as src,path.open('xb') as dst:shutil.copyfileobj(src,dst)
                path.chmod(0o755 if (item.external_attr>>16)&0o111 else 0o644)
            if len(roots)!=1:raise ValueError('Unexpected SDK archive layout')
        os.replace(temporary,destination)
    finally:
        if temporary.exists():shutil.rmtree(temporary)


def operator_key(lock,evidence):
    MANAGED_KEY.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    # Preserve the identity of an earlier workspace-based guided setup when
    # upgrading. Existing per-user identities always take precedence.
    legacy=ROOT/'.work/keys/operator'
    if not MANAGED_KEY.exists() and (legacy/'repack.p12').is_file():
        if not (legacy/'keystore.pass').is_file():raise PrerequisiteError('Restore the previous operator key password before migrating it')
        if MANAGED_PASSWORD.exists():raise PrerequisiteError('Incomplete per-user key state; restore the existing identity before continuing')
        for source,target in ((legacy/'keystore.pass',MANAGED_PASSWORD),(legacy/'repack.p12',MANAGED_KEY)):
            with source.open('rb') as src,os.fdopen(os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb') as dst:
                shutil.copyfileobj(src,dst)
    if MANAGED_KEY.exists() and not MANAGED_PASSWORD.is_file():raise PrerequisiteError('Restore the existing operator key password; a new key was not generated')
    if not MANAGED_KEY.exists() and MANAGED_PASSWORD.exists():raise PrerequisiteError('An operator password exists without its key. Restore the signing key; a replacement identity was not generated.')
    if not MANAGED_PASSWORD.exists():
        with os.fdopen(os.open(MANAGED_PASSWORD,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as f:f.write(secrets.token_urlsafe(32)+'\n')
    if not MANAGED_KEY.exists():
        execute([lock['tools']['keytool']['path'],'-genkeypair','-keystore',str(MANAGED_KEY),'-storetype','PKCS12',
            '-alias','repack','-keyalg','RSA','-keysize','2048','-validity','3650','-storepass:file',str(MANAGED_PASSWORD),
            '-keypass:file',str(MANAGED_PASSWORD),'-dname','CN=Repacking Lovers operator'],evidence,'operator-key',env=environment(lock))
        MANAGED_KEY.chmod(0o600)
    return str(MANAGED_KEY)


def prepare(evidence, *, sdk=None,jdk=None,accept_sdk_license=False,notify=lambda message:None):
    info=discover()
    if not info['supported_host']:raise PrerequisiteError('The guided release currently supports Linux x86_64')
    jdk=Path(jdk or info['jdk']) if (jdk or info['jdk']) else None
    if jdk is not None:jdk=jdk.expanduser().resolve()
    if jdk is None or not (jdk/'bin/javac').is_file():raise PrerequisiteError('Install a JDK (17 or newer), then select its folder. Java runtime alone is insufficient.')
    sdk=Path(sdk or info['sdk']).expanduser().resolve()
    pins=json.loads((ROOT/'config/setup-dependencies.json').read_text())
    probes={'platform':'platforms/android-36/android.jar','build-tools':'build-tools/36.0.0/aapt2','platform-tools':'platform-tools/adb'}
    for pin in pins['archives']:
        if (sdk/probes[pin['name']]).is_file():continue
        # Existing platform-tools on PATH can be used without downloading a second ADB.
        if pin['name']=='platform-tools' and shutil.which('adb'):continue
        if not accept_sdk_license:raise PrerequisiteError('Accept the linked Android SDK license to download missing SDK components')
        download=ROOT/'.work/tools/setup-downloads'/Path(pin['url']).name
        fetch(pin,download,notify);extract_sdk(download,sdk/pin['destination']);download.unlink()
    names={name:jdk/'bin'/name for name in ('java','javac','keytool')}
    names.update({name:sdk/'build-tools/36.0.0'/name for name in ('aapt2','d8','apksigner','zipalign')})
    names['adb']=Path(shutil.which('adb') or sdk/'platform-tools/adb')
    lock={'schema_version':1,'jdk_path':str(jdk.resolve()),'sdk_path':str(sdk),'android_jar':str(sdk/'platforms/android-36/android.jar'),
          'tools':{},'adb_server_socket':os.environ.get('ADB_SERVER_SOCKET'),
          'build':{'compile_sdk':36,'build_tools':'36.0.0','java_release':8,'min_sdk':28,'target_sdk':35},'cell':None}
    lock['android_jar_sha256']=sha256(Path(lock['android_jar']))
    flags={'java':['-version'],'javac':['--version'],'keytool':['-help'],'adb':['version'],'aapt2':['version'],'d8':['--version'],'apksigner':['version'],'zipalign':[]}
    for name,path in names.items():
        if not path.is_file():raise PrerequisiteError('Missing tool: '+str(path))
        result=execute([str(path),*flags[name]],evidence,'setup-'+name,env=environment(lock),check=False)
        if result.returncode and not(name=='zipalign' and 'Zip alignment utility' in result.stdout+result.stderr):raise PrerequisiteError('Cannot run '+name+'; see setup report')
        lock['tools'][name]={'path':str(path.resolve()),'sha256':sha256(path),'version_output':(result.stdout+result.stderr).strip()}
        if name in ('d8','apksigner'):lock['tools'][name]['jar_sha256']=sha256(path.parent/'lib'/f'{name}.jar')
    import re
    version=re.search(r'(\d+)',lock['tools']['javac']['version_output'])
    if not version or int(version[1])<17:raise PrerequisiteError('Select JDK17 or newer')
    for row in json.loads((ROOT/'config/java-dependencies.json').read_text())['artifacts']:
        if row['suite']=='smali':
            for kind in ('jar','pom'):fetch(row[kind],ROOT/row[kind]['path'],notify)
    from .shim import manifest_editor
    from .trust import resource_engine
    notify('Preparing APK tools');manifest_editor(lock,evidence);lock['resource_engine']=resource_engine(lock,evidence)
    operator_key(lock,evidence)
    write_json(ROOT/'config/implementation-lock.json',lock)
    return lock


def prepare_identity(notify=lambda message:None):
    pins=json.loads((ROOT/'config/hiddenapi-dependency.json').read_text())
    for name,row in pins.items():
        if isinstance(row,dict) and 'source_url' in row:fetch(row,ROOT/row['path'],notify)
    target=ROOT/pins['classes']['path']
    if not target.exists():
        with zipfile.ZipFile(ROOT/pins['aar']['path']) as z:data=z.read('classes.jar')
        if hashlib.sha256(data).hexdigest()!=pins['classes']['sha256']:raise RuntimeError('Hidden API classes hash mismatch')
        target.write_bytes(data)
    if sha256(target)!=pins['classes']['sha256']:raise PrerequisiteError('Hidden API classes changed')
