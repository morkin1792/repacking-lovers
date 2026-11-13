"""Loopback-only, single-operator browser workflow over the existing repacker."""
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
import hashlib
import hmac
import json
import mimetypes
import os
import re
import secrets
import shlex
import shutil
import threading
import traceback
import time
from urllib.parse import unquote,urlsplit
import uuid
import webbrowser
import zipfile

from .rebuild import ROOT,PrerequisiteError,load_lock,sha256,write_json
from .pipeline import patch,validate_toolchain
from .plain import build as plain_build
from .report import load_artifact
from .verify import preflight,install,ReplacementRequired,artifact_members
from . import setup,devices
from .certificates import decode_public, MAX_CERTIFICATE
from .proxy_certificate import fetch_certificate, DEFAULT_URL

ID=re.compile(r'[a-f0-9]{32}')


class Workflow:
    def __init__(self,root=None,*,auto_prepare=True):
        self.root=Path(root or ROOT/'.work/gui');self.root.mkdir(parents=True,exist_ok=True,mode=0o700)
        (self.root/'uploads').mkdir(exist_ok=True);(self.root/'jobs').mkdir(exist_ok=True)
        (self.root/'certificates').mkdir(exist_ok=True)
        self.token=secrets.token_urlsafe(32);self.mutex=threading.RLock();self.worker=ThreadPoolExecutor(max_workers=1)
        self.busy=False;self.uploads={};self.jobs={};self.lock=None;self.app_cache={}
        self.setup_status={'state':'needed','message':'Prepare tools once to begin.'}
        try:
            lock=load_lock();validate_toolchain(lock,device=True)
            if setup.MANAGED_KEY.is_file() and setup.MANAGED_PASSWORD.is_file():self.lock=lock;self.setup_status={'state':'ready','message':'Tools and signing key ready.'}
        except (OSError,ValueError,KeyError,PrerequisiteError):pass
        for p in (self.root/'jobs').glob('*/job.json'):
            if not ID.fullmatch(p.parent.name):continue
            try:
                job=json.loads(p.read_text())
                if job['state'] in ('building','installing'):job.update(state='interrupted',message='The previous session ended. Retained files are available below.')
                self.jobs[p.parent.name]=job
            except (ValueError,KeyError):continue

        if auto_prepare and self.lock is None and setup.local_tools_available():self.prepare({})
        elif auto_prepare and self.lock is not None:self.warm_local()

    def warm_local(self):
        self.reserve();self.setup_status={'state':'preparing','message':'Preparing cached app-list helper…'}
        def run():
            folder=self.operation_folder('helper-warm')
            try:
                devices.app_helper(self.lock,folder)
                self.setup_status={'state':'ready','message':'Installed tools and signing key ready.'}
                self.hydrate_history()
            except Exception as e:self.setup_status={'state':'failed','message':str(e)}
            finally:shutil.rmtree(folder);self.busy=False
        self.worker.submit(run)

    def hydrate_history(self):
        details_cache={}
        for job in list(self.jobs.values()):
            if (job.get('app') or {}).get('name'):continue
            folder=self.root/'jobs'/job['id']
            candidates=[folder/f['path'] for f in job.get('files',[])]+sorted((folder/'originals').glob('*.apk'))
            candidates=[p for p in candidates if p.is_file() and ('base' in p.name or len(candidates)==1)]
            if not candidates:continue
            evidence=self.operation_folder('metadata')
            try:
                key=(job.get('package'),job.get('version_code'))
                if key not in details_cache:details_cache[key]=devices.apk_details(candidates[0],self.ready(),evidence)
                self.change(job,app={**details_cache[key],'package':job.get('package'),'version_code':job.get('version_code')})
            except (ValueError,OSError,RuntimeError,KeyError):pass
            finally:shutil.rmtree(evidence)

    def status(self):
        with self.mutex:
            discovery=setup.discover()
            if self.lock and self.lock.get('sdk_path'):
                if discovery['sdk'] != self.lock['sdk_path']: discovery['sdk_source']='Prepared workspace SDK'
                discovery.update(sdk=self.lock['sdk_path'],jdk=self.lock['jdk_path'])
            return {'setup':dict(self.setup_status),'discovery':discovery,'busy':self.busy,
                    'jobs':[self.public(j) for j in sorted(self.jobs.values(),key=lambda x:x['created'],reverse=True)]}

    def public(self,job):
        result={k:v for k,v in job.items() if k not in ('artifact','lock','options','input_ref')}
        if 'proxy' not in result:
            result['proxy']=None
            if job.get('mode')=='interception':
                from .shim import parse_proxy
                try: result['proxy']=parse_proxy(job.get('options',{}).get('proxy') or '127.0.0.1:8080')
                except ValueError: pass
        return result

    def fetch_ca(self,url=DEFAULT_URL):
        certificate=fetch_certificate(url)
        identity=certificate['sha256'];folder=self.root/'certificates'
        info={k:certificate[k] for k in ('sha256','format','url','provider')}
        with self.mutex:
            (folder/(identity+'.pem')).write_bytes(certificate['pem'])
            write_json(folder/(identity+'.json'),info)
        return {'id':identity,**info}

    def stored_ca(self,identity):
        if not isinstance(identity,str) or not re.fullmatch(r'[a-f0-9]{64}',identity):raise ValueError('Fetch or upload a certificate first')
        path=self.root/'certificates'/(identity+'.pem')
        certificate=decode_public(path.read_bytes())
        if certificate['sha256']!=identity:raise ValueError('Stored certificate changed; fetch it again')
        info=json.loads(path.with_suffix('.json').read_text())
        return str(path),info

    def change(self,job,**values):
        with self.mutex:
            job.update(values);write_json(self.root/'jobs'/job['id']/'job.json',job)

    def reserve(self):
        with self.mutex:
            if self.busy:raise ValueError('Another operation is running. Wait for it to finish.')
            self.busy=True

    def prepare(self,options):
        self.reserve();self.setup_status={'state':'preparing','message':'Checking local tools…'}
        def run():
            folder=self.root/('setup-'+uuid.uuid4().hex);folder.mkdir()
            try:
                self.lock=setup.prepare(folder,sdk=options.get('sdk'),jdk=options.get('jdk'),
                    accept_sdk_license=options.get('accept_sdk_license') is True,
                    notify=lambda text:self.setup_status.update(message=text))
                devices.app_helper(self.lock,folder)
                self.setup_status={'state':'ready','message':'Tools and persistent signing key ready.'}
                self.hydrate_history()
            except Exception as e:self.setup_status={'state':'failed','message':str(e)}
            finally:self.busy=False
        self.worker.submit(run)

    def ready(self):
        if self.lock is None:raise PrerequisiteError('Prepare tools first.')
        return self.lock

    def discovery(self,serial=None):
        lock=self.ready()
        folder=self.operation_folder('discovery')
        try:
            if not serial:return {'devices':devices.devices(lock,folder)}
            result=devices.apps(serial,lock,folder)
            with self.mutex:self.app_cache[(serial,result['user'])]={r['package']:r for r in result['apps']}
            return result
        finally:shutil.rmtree(folder)

    def icons(self,options):
        serial=options.get('device');user=options.get('user');packages=options.get('packages')
        if not isinstance(serial,str) or type(user) is not int:raise ValueError('Choose a phone and reload its apps')
        with self.mutex:known=self.app_cache.get((serial,user),{})
        if not isinstance(packages,list) or any(not isinstance(p,str) or p not in known for p in packages):raise ValueError('Reload the app list before loading icons')
        folder=self.operation_folder('icons')
        try:
            result=devices.apps(serial,self.ready(),folder,packages=packages,expected_user=user)
            with self.mutex:
                for row in result['apps']:
                    if row['package'] in known:known[row['package']].update(icon=row['icon'])
                    if row['icon']:
                        for job in self.jobs.values():
                            app=job.get('app') or {}
                            if job.get('source_device')==serial and job.get('package')==row['package'] and app.get('version_code')==row['version_code']:
                                self.change(job,app={**app,'icon':row['icon']})
            return result
        finally:shutil.rmtree(folder)

    def app_info(self,serial,package):
        with self.mutex:
            return next((dict(rows[package]) for (device,_),rows in self.app_cache.items() if device==serial and package in rows),{})

    def new_upload(self):
        identity=uuid.uuid4().hex;folder=self.root/'uploads'/identity;folder.mkdir(mode=0o700)
        self.uploads[identity]={'folder':folder,'sealed':False,'bytes':0,'files':[],'pending':0}
        return identity

    def upload(self,identity,name,length,stream):
        with self.mutex:
            batch=self.uploads.get(identity)
            if batch is None or batch['sealed']:raise ValueError('Unknown or already-used upload selection.')
            if (not name or len(name)>200 or any(c in name for c in ('/','\\','\0','\r','\n',':'))
                or Path(name).suffix.lower() not in ('.apk','.apks','.xapk','.pem','.der','.crt','.cer')):raise ValueError('Choose APK files, an APK container, or a public PEM/DER certificate.')
            if Path(name).suffix.lower() in ('.pem','.der','.crt','.cer') and length>MAX_CERTIFICATE:raise ValueError('Public certificates must be at most 1 MiB')
            if not 0<length<=2*1024**3 or batch['bytes']+length>4*1024**3 or len(batch['files'])>=64:raise ValueError('Upload limit exceeded (2 GiB per file, 4 GiB per selection, 64 files).')
            path=batch['folder']/name
            # Reserve the name and quota while streaming; failed uploads are removed.
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);batch['bytes']+=length;batch['files'].append(path);batch['pending']+=1
        try:
            with os.fdopen(fd,'wb') as f:
                remaining=length
                while remaining:
                    data=stream.read(min(1024**2,remaining))
                    if not data:raise ValueError('Upload interrupted. Select the files again.')
                    f.write(data);remaining-=len(data)
        except Exception:
            path.unlink(missing_ok=True)
            with self.mutex:batch['bytes']-=length;batch['files'].remove(path)
            raise
        finally:
            with self.mutex:batch['pending']-=1
        return {'name':name,'size':length}

    def source(self,options):
        serial=options.get('device') or None
        if serial:devices.require_device(serial,self.ready(),self.operation_folder('check-device'))
        package=options.get('package')
        if package:
            if not isinstance(package,str) or not devices.PACKAGE.fullmatch(package) or not serial:raise ValueError('Choose an installed package and connected phone.')
            return 'pkg:'+package
        batch=self.uploads.get(options.get('upload'))
        if batch is None or batch['sealed'] or batch['pending']:raise ValueError('Select your original APK files and wait for their upload to finish.')
        files=[p for p in batch['files'] if p.suffix.lower() in ('.apk','.apks','.xapk')]
        if not files:raise ValueError('No APK input was uploaded.')
        if any(p.suffix.lower()!='.apk' for p in files) and len(files)!=1:raise ValueError('Choose one container or a set of APK files.')
        batch['sealed']=True
        return str(files[0] if len(files)==1 else batch['folder'])

    def operation_folder(self,prefix):
        folder=self.root/(prefix+'-'+uuid.uuid4().hex);folder.mkdir();return folder

    def start(self,options):
        if options.get('mode') not in ('plain','interception'):raise ValueError('Choose plain repacking or interception.')
        if options.get('auto_install') and not options.get('device'):raise ValueError('Select a phone for automatic installation.')
        for flag in ('auto_install','antitamper'):
            if flag in options and type(options[flag]) is not bool:raise ValueError(flag+' must be true or false')
        if options.get('package') and options.get('upload'):raise ValueError('Choose a phone app or APK files, not both.')
        self.ready();self.reserve()
        try:
            ca=None;certificate_info=None;proxy=None
            if options['mode']=='interception':
                from .shim import parse_proxy
                proxy=parse_proxy(options.get('proxy') or '127.0.0.1:8080')
                if options.get('ca_upload'):
                    batch=self.uploads.get(options['ca_upload'])
                    choices=[] if batch is None else [p for p in batch['files'] if p.suffix.lower() in ('.pem','.der','.crt','.cer')]
                    if len(choices)!=1 or batch['pending'] or batch['sealed']:raise ValueError('Finish uploading one public PEM/DER certificate')
                    certificate=decode_public(choices[0].read_bytes())
                    ca=str(choices[0]);batch['sealed']=True
                    certificate_info={'sha256':certificate['sha256'],'format':certificate['format'],'source':choices[0].name,'provider':'Uploaded file'}
                else:
                    if options.get('ca_source')=='upload':raise ValueError('Choose a public PEM or DER certificate file')
                    identity=options.get('ca_id') or self.fetch_ca(options.get('certificate_url') or DEFAULT_URL)['id']
                    ca,certificate_info=self.stored_ca(identity)
            source=self.source(options)
            identity=uuid.uuid4().hex;folder=self.root/'jobs'/identity;folder.mkdir(mode=0o700)
            job={'id':identity,'created':time.time(),'state':'building','message':'Reading original APKs…',
                 'mode':options['mode'],'device':options.get('device') or None,'package':options.get('package'),
                 'source_device':options.get('device') if options.get('package') else None,
                 'app':self.app_info(options.get('device'),options.get('package')),
                 'progress':self.progress_steps(options['mode']),
                 'proxy':proxy,'certificate':certificate_info,
                 'files':[],'mutations':[],'input_ref':source,'options':{**options,'ca':ca}}
            self.jobs[identity]=job;self.change(job);self.worker.submit(self.run,job)
            return self.public(job)
        except Exception:self.busy=False;raise

    @staticmethod
    def progress_steps(mode):
        labels=['Inspect original APKs','Rebuild resources']
        if mode=='interception':labels+=['Patch supported pinning','Add startup support']
        return {'labels':labels+['Sign and verify','Save outputs and backups'],'current':0,'done':False}

    def build_progress(self,job,text):
        progress=dict(job.get('progress') or self.progress_steps(job['mode']))
        low=text.casefold();label=None
        if 'resource' in low:label='Rebuild resources'
        elif 'pinning patches' in low:label='Patch supported pinning'
        elif 'startup' in low:label='Add startup support'
        elif 'aligning' in low:label='Sign and verify'
        elif 'backups' in low:label='Save outputs and backups'
        if label in progress['labels']:progress['current']=max(progress['current'],progress['labels'].index(label))
        self.change(job,message=text,progress=progress)

    def run(self,job):
        folder=self.root/'jobs'/job['id'];evidence=folder/'evidence';evidence.mkdir()
        try:
            lock=self.ready();options=job['options']
            build_options={'out':folder/'result','key':setup.MANAGED_KEY,'device':job['device']}
            progress=lambda text:self.build_progress(job,text)
            if job['mode']=='plain':built=plain_build(job['input_ref'],build_options,lock,evidence,progress=progress)
            else:
                from .shim import parse_proxy
                if options.get('antitamper'):
                    if not job['device']:raise ValueError('Signing-check adaptation needs a connected API30 phone.')
                    setup.prepare_identity(lambda text:self.change(job,message=text))
                built=patch(job['input_ref'],{**build_options,'ca':options['ca'],
                    'proxy':parse_proxy(options.get('proxy') or '127.0.0.1:8080'),
                    'antitamper':options.get('antitamper') is True},lock,evidence,output_directory=True,progress=progress)
                _,built_artifact=load_artifact(Path(built['manifest']));built['install_artifact']=built_artifact
            artifact=built.get('install_artifact') or built['artifact']
            self.build_progress(job,'Saving verified outputs and original backups…')
            app=dict(job.get('app') or {})
            app.update(package=artifact['package'],version_code=artifact['version_code'])
            try:
                base=next(m for m in built['inventory']['members'] if not m.get('split'))
                details=devices.apk_details(base['apk'],lock,evidence)
                for name,value in details.items():
                    if value and (name!='icon' or not app.get('icon')):app[name]=value
            except (ValueError,OSError,RuntimeError,KeyError):pass
            if not app.get('icon'):app['icon']=self.app_info(job.get('source_device'),artifact['package']).get('icon')
            originals=folder/'originals';originals.mkdir()
            original_files=[]
            for i,m in enumerate(built['inventory']['members']):
                target=originals/(f'{i:03d}-'+Path(m['apk']).name)
                shutil.copyfile(m['apk'],target)
                if sha256(target)!=m['sha256']:raise RuntimeError('Original backup hash mismatch; no installation attempted')
                original_files.append({'path':str(target.relative_to(folder)),'sha256':m['sha256'],'split':m.get('split')})
            write_json(folder/'originals.json',{'package':artifact['package'],'files':original_files})
            members=artifact_members(artifact)
            files=[{'name':Path(m['apk']).name,'path':str(Path(m['apk']).relative_to(folder)),'sha256':m['sha256']} for m in members]
            self.change(job,package=artifact['package'],artifact=artifact,manifest=str(built['manifest']),files=files,
                        version_code=artifact['version_code'],app=app,
                        progress={**job['progress'],'current':len(job['progress']['labels'])-1,'done':True},
                        state='built',message='Repacked APKs are ready. App behavior has not been tested.')
            for identity in (options.get('upload'),options.get('ca_upload')):
                batch=self.uploads.pop(identity,None)
                if batch:shutil.rmtree(batch['folder'])
            if options.get('auto_install'):self.install_job(job,False)
        except Exception as e:
            (evidence/'error.txt').write_text(traceback.format_exc())
            self.change(job,state='failed',message=str(e),error_log=str(evidence/'error.txt'))
        finally:
            # Preserve originals/results/reports, not another collection of build trees.
            try:self.trim(evidence)
            finally:self.busy=False

    def trim(self,folder):
        for p in list(folder.rglob('decoded')):
            if p.is_dir() and not p.is_symlink():shutil.rmtree(p)
        for p in folder.rglob('*'):
            if p.is_file() and (p.suffix in ('.apk','.dex','.class','.jar','.so') or p.name=='dex-inspect.stdout.log'):p.unlink()

    def install_job(self,job,confirmed,serial=None):
        serial=serial or job.get('source_device') or job.get('device')
        if not serial:raise ValueError('Choose a phone for installation.')
        self.change(job,state='installing',install_device=serial,confirmation_device=None,message='Checking and installing on '+serial+'…')
        lock=self.ready();folder=self.operation_folder('install');start=len(job['mutations'])
        try:
            devices.require_device(serial,lock,folder)
            artifact=job['artifact']
            if job['mode']=='interception' and job.get('manifest'):
                from .verify import validate_runtime
                document,artifact=load_artifact(Path(job['manifest']))
                validate_runtime(document,serial,lock,folder,'gui-runtime')
            job_folder=self.root/'jobs'/job['id']
            candidates=list((job_folder/'originals').glob('*.apk'))+[job_folder/f['path'] for f in job['files']]
            plan=preflight(artifact,serial,confirmed,lock,folder,'gui',requested_package=job['package'],backup_candidates=candidates)
            if plan['replace']:
                backup=self.root/'jobs'/job['id']/'installed-originals'/folder.name;backup.mkdir(parents=True)
                for i,m in enumerate(plan['existing_members']):
                    source=folder/f'gui-previous-{i}.apk';target=backup/f'{i:03d}.apk'
                    shutil.copyfile(source,target)
                    if sha256(target)!=m['sha256']:raise RuntimeError('Installed-original backup failed; replacement stopped')
                write_json(backup/'backup.json',{'package':job['package'],'device':serial,'members':plan['existing_members']})
            install(artifact,serial,plan,lock,folder,'gui',job['mutations'])
            self.change(job,state='installed',message='Installed on '+serial+'. Open the app to check it; runtime behavior is untested.')
        except ReplacementRequired:
            self.change(job,state='awaiting_confirmation',confirmation_device=serial,message='Replacing '+job['package']+' on '+serial+' requires uninstalling its existing copy and deleting its local data.')
        except Exception as e:
            self.change(job,state='install_failed',message='Installation on '+serial+' failed: '+str(e)+'. The build is kept; choose a device and retry.')
        finally:
            attempt={'device':serial,'state':job['state'],'mutations':job['mutations'][start:],'evidence':str(folder),'time':time.time()}
            self.change(job,install_attempts=[*job.get('install_attempts',[]),attempt])
            write_json(folder/'result.json',{'job':job['id'],**attempt})
            self.trim(folder)

    def request_install(self,identity,options):
        with self.mutex:
            job=self.jobs.get(identity)
            if job is None or job['state'] in ('building','installing') or not job.get('files') or job.get('outputs_deleted'):raise ValueError('This job is not ready to install.')
            serial=options.get('device') or job.get('source_device') or job.get('device')
            if not isinstance(serial,str) or not serial:raise ValueError('Choose a connected phone for this installation.')
            confirmed=options.get('confirm_wipe') is True
            pending=job.get('confirmation_device') or job.get('install_device') or job.get('device')
            if (confirmed and (options.get('package')!=job['package'] or job['state']!='awaiting_confirmation' or pending!=serial)) or (job['state']=='awaiting_confirmation' and pending==serial and not confirmed):
                raise ValueError('Confirm data loss for this exact package and device.')
            self.reserve()
        def run():
            try:self.install_job(job,confirmed,serial)
            finally:self.busy=False
        self.worker.submit(run)
        return self.public(job)

    def delete_job(self,identity,scope):
        if scope not in ('apks','build'):raise ValueError('Choose APK deletion or full build deletion')
        self.reserve()
        try:
            with self.mutex:
                job=self.jobs.get(identity)
                if not ID.fullmatch(identity) or job is None:raise ValueError('Unknown build')
                if job['state'] in ('building','installing'):raise ValueError('Wait for this build to finish')
                folder=self.root/'jobs'/identity
                if folder.is_symlink() or folder.resolve().parent!=(self.root/'jobs').resolve():raise ValueError('Build directory changed; deletion refused')
                if scope=='apks':
                    result=folder/'result'
                    if result.is_symlink():result.unlink()
                    elif result.exists():shutil.rmtree(result)
                    self.change(job,files=[],outputs_deleted=True,message='Generated APKs deleted. Original backups and reports kept; the phone app is unchanged.')
                else:
                    for field in ('upload','ca_upload'):
                        batch_id=job.get('options',{}).get(field)
                        if isinstance(batch_id,str) and ID.fullmatch(batch_id):
                            batch=self.uploads.get(batch_id)
                            if batch and batch['pending']:raise ValueError('An upload is still running')
                            uploaded=self.root/'uploads'/batch_id
                            if uploaded.is_symlink():uploaded.unlink()
                            elif uploaded.exists():shutil.rmtree(uploaded)
                            self.uploads.pop(batch_id,None)
                    for record in self.root.glob('install-*/result.json'):
                        if record.parent.is_symlink():continue
                        try: belongs=json.loads(record.read_text()).get('job')==identity
                        except (ValueError,OSError): belongs=False
                        if belongs:shutil.rmtree(record.parent)
                    if folder.exists():shutil.rmtree(folder)
                    del self.jobs[identity]
                return {'deleted':scope,'id':identity}
        finally:self.busy=False


def serve(port=8787,open_browser=True,workflow=None):
    state=workflow or Workflow();assets=Path(__file__).parent/'web'
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def handle(self):
            try:super().handle()
            except (BrokenPipeError,ConnectionResetError,ConnectionAbortedError):pass
        def send(self,status,body,kind='application/json',cookie=False):
            if not isinstance(body,bytes):body=json.dumps(body).encode()
            self.send_response(status);self.send_header('Content-Type',kind);self.send_header('Content-Length',str(len(body)))
            self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff')
            self.send_header('Referrer-Policy','no-referrer');self.send_header('X-Frame-Options','DENY')
            self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
            if cookie:self.send_header('Set-Cookie','repack_session='+state.token+'; HttpOnly; SameSite=Strict; Path=/')
            self.end_headers();self.wfile.write(body)
        def guard(self,api=False,download=False):
            allowed={'127.0.0.1:'+str(self.server.server_port),'localhost:'+str(self.server.server_port)}
            host=self.headers.get('Host','');origin=self.headers.get('Origin')
            if host not in allowed or (origin is not None and origin not in {'http://'+h for h in allowed}):raise PermissionError('Use the local Repacking Lovers address.')
            token=self.headers.get('X-Repack-Token','')
            if download:
                cookies=dict(v.strip().split('=',1) for v in self.headers.get('Cookie','').split(';') if '=' in v)
                token=cookies.get('repack_session','')
            if api and not hmac.compare_digest(token,state.token):raise PermissionError('Refresh the local interface to start a session.')
        def do_GET(self):
            try:
                path=urlsplit(self.path).path;download=re.fullmatch(r'/api/jobs/([a-f0-9]{32})/download/(\d+)',path)
                bundle=re.fullmatch(r'/api/jobs/([a-f0-9]{32})/bundle',path)
                self.guard(api=path.startswith('/api/'),download=bool(download or bundle))
                if path=='/':
                    body=(assets/'index.html').read_text().replace('REPACK_SESSION_TOKEN',state.token).encode();return self.send(200,body,'text/html; charset=utf-8',True)
                if path in ('/app.js','/style.css'):return self.send(200,(assets/path[1:]).read_bytes(),'text/javascript' if path.endswith('.js') else 'text/css')
                if path=='/api/status':return self.send(200,state.status())
                if bundle:
                    job=state.jobs.get(bundle[1])
                    if not job or not job['files']:raise ValueError('This build has no output APKs')
                    folder=state.root/'jobs'/job['id'];files=[]
                    for entry in job['files']:
                        file=(folder/entry['path']).resolve()
                        if not file.is_relative_to(folder.resolve()) or sha256(file)!=entry['sha256']:raise ValueError('Output changed or is unavailable')
                        files.append((file,entry))
                    self.send_response(200);self.send_header('Content-Type','application/zip')
                    self.send_header('Content-Disposition','attachment; filename="'+job['package']+'-repacked.zip"');self.end_headers()
                    with zipfile.ZipFile(self.wfile,'w',compression=zipfile.ZIP_STORED) as archive:
                        for file,entry in files:archive.write(file,file.name)
                        names=[file.name for file,_ in files]
                        verb='install-multiple' if len(names)>1 else 'install'
                        command='adb -s SERIAL '+verb+' -r '+' '.join(shlex.quote(name) for name in names)
                        archive.writestr('INSTALL.txt','Extract this ZIP to a folder. Open a terminal in that folder.\nEnable USB debugging, authorize the phone, and run adb devices -l.\nReplace SERIAL with the intended authorized device serial:\n\n'+command+'\n\nIf the signing key differs, Android refuses the update. Use the tool to review and confirm replacement/data loss.\nThis APK set was selected for the build device; another device must have compatible Android/ABI/splits.\n')
                        archive.writestr('outputs.json',json.dumps({'package':job['package'],
                            'files':[{'name':f.name,'sha256':e['sha256']} for f,e in files],'runtime_verification':'not-run'},indent=2))
                    return
                if download:
                    job=state.jobs.get(download[1]);index=int(download[2])
                    if job is None or index>=len(job['files']):raise ValueError('Unknown output file')
                    folder=state.root/'jobs'/job['id'];entry=job['files'][index];file=(folder/entry['path']).resolve()
                    if not file.is_relative_to(folder.resolve()) or sha256(file)!=entry['sha256']:raise ValueError('Output changed or is unavailable.')
                    self.send_response(200);self.send_header('Content-Type','application/vnd.android.package-archive')
                    self.send_header('Content-Disposition','attachment; filename="'+file.name+'"');self.send_header('Content-Length',str(file.stat().st_size));self.end_headers()
                    with file.open('rb') as stream:shutil.copyfileobj(stream,self.wfile)
                    return
                self.send(404,{'error':'Not found'})
            except (BrokenPipeError,ConnectionResetError,ConnectionAbortedError):return
            except PermissionError as e:self.send(403,{'error':str(e)})
            except (ValueError,OSError,KeyError,RuntimeError) as e:self.send(400,{'error':str(e)})
        def do_POST(self):
            try:
                self.guard(api=True)
                if self.headers.get('Transfer-Encoding'):raise ValueError('Chunked requests are unsupported')
                length=int(self.headers.get('Content-Length','0'));path=urlsplit(self.path).path
                match=re.fullmatch(r'/api/uploads/([a-f0-9]{32})/(.+)',path)
                if match:return self.send(200,state.upload(match[1],unquote(match[2]),length,self.rfile))
                if not 0<=length<=1024**2:raise ValueError('Request is too large')
                body=json.loads(self.rfile.read(length) or b'{}')
                if not isinstance(body,dict):raise ValueError('Expected a JSON object')
                if path=='/api/setup':state.prepare(body);return self.send(202,{'started':True})
                if path=='/api/devices':return self.send(200,state.discovery())
                if path=='/api/apps':return self.send(200,state.discovery(body.get('device')))
                if path=='/api/app-icons':return self.send(200,state.icons(body))
                if path=='/api/certificate':return self.send(200,state.fetch_ca(body.get('url') or DEFAULT_URL))
                if path=='/api/uploads':return self.send(201,{'id':state.new_upload()})
                if path=='/api/jobs':return self.send(202,state.start(body))
                match=re.fullmatch(r'/api/jobs/([a-f0-9]{32})/install',path)
                if match:return self.send(202,state.request_install(match[1],body))
                match=re.fullmatch(r'/api/jobs/([a-f0-9]{32})/delete',path)
                if match:return self.send(200,state.delete_job(match[1],body.get('scope')))
                self.send(404,{'error':'Not found'})
            except (BrokenPipeError,ConnectionResetError,ConnectionAbortedError):return
            except PermissionError as e:self.send(403,{'error':str(e)})
            except (ValueError,OSError,KeyError,RuntimeError,PrerequisiteError) as e:self.send(400,{'error':str(e)})
    server=ThreadingHTTPServer(('127.0.0.1',port),Handler);server.daemon_threads=True
    url='http://127.0.0.1:'+str(server.server_port)
    if open_browser:threading.Timer(.2,lambda:webbrowser.open(url)).start()
    print('Repacking Lovers: '+url+' — press Ctrl+C to stop.',flush=True)
    return server,state
