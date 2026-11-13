"""Browser API boundaries and build/install consent, without a device."""
import base64
import http.client
import io
import json
import struct
import socket
from pathlib import Path
import tempfile
import threading
import time
import unittest
import zipfile
from unittest.mock import patch,Mock

from repack.gui import Workflow,serve
from repack.rebuild import PrerequisiteError,sha256
from repack.verify import ReplacementRequired
from repack.devices import parse_apps


class WorkflowControls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        with patch('repack.gui.load_lock',side_effect=PrerequisiteError('fresh host')):
            self.state=Workflow(Path(self.temp.name)/'gui',auto_prepare=False)
        self.state.lock={};self.addCleanup(self.state.worker.shutdown,wait=True)

    def wait(self):
        end=time.monotonic()+5
        while self.state.busy and time.monotonic()<end:time.sleep(.01)
        self.assertFalse(self.state.busy)

    def upload(self):
        identity=self.state.new_upload();self.state.upload(identity,'base.apk',8,io.BytesIO(b'original'))
        return identity

    def build(self,input_ref,options,lock,evidence,**kwargs):
        out=Path(options['out']);out.mkdir();apk=out/'base.apk';apk.write_bytes(b'new-apk')
        original=Path(input_ref)
        return {'manifest':str(out/'artifact.json'),
                'artifact':{'package':'dev.repack.fixture.other','version_code':1,'signer_sha256':['a'*64],
                            'members':[{'apk':str(apk),'sha256':sha256(apk),'split':None}]},
                'inventory':{'members':[{'apk':str(original),'sha256':sha256(original),'split':None}]}}

    def test_upload_rejects_traversal_duplicates_and_interruption(self):
        identity=self.state.new_upload()
        for name in ('../base.apk','sub/base.apk','sub\\base.apk','bad:base.apk'):
            with self.assertRaises(ValueError):self.state.upload(identity,name,1,io.BytesIO(b'x'))
        self.state.upload(identity,'base.apk',1,io.BytesIO(b'x'))
        with self.assertRaises(FileExistsError):self.state.upload(identity,'base.apk',1,io.BytesIO(b'x'))
        with self.assertRaises(ValueError):self.state.upload(identity,'partial.apk',10,io.BytesIO(b'bad'))
        self.assertFalse((self.state.uploads[identity]['folder']/'partial.apk').exists())
        self.assertEqual(self.state.uploads[identity]['pending'],0)

    def test_build_only_does_not_install_and_keeps_original(self):
        with patch('repack.gui.plain_build',side_effect=self.build),patch('repack.gui.install') as install:
            self.state.start({'mode':'plain','upload':self.upload(),'auto_install':False});self.wait()
        job=next(iter(self.state.jobs.values()));self.assertEqual(job['state'],'built');install.assert_not_called()
        self.assertEqual((self.state.root/'jobs'/job['id']/'originals/000-base.apk').read_bytes(),b'original')
        self.assertFalse(self.state.uploads)

    def test_failed_build_never_installs(self):
        with patch('repack.gui.plain_build',side_effect=RuntimeError('cannot rebuild')),patch('repack.gui.install') as install:
            self.state.start({'mode':'plain','upload':self.upload(),'auto_install':False});self.wait()
        self.assertEqual(next(iter(self.state.jobs.values()))['state'],'failed');install.assert_not_called()

    def test_auto_install_waits_for_exact_package_consent_and_rechecks(self):
        with patch('repack.gui.devices.require_device',return_value='serial'),patch('repack.gui.plain_build',side_effect=self.build),\
             patch('repack.gui.preflight',side_effect=ReplacementRequired('dev.repack.fixture.other','serial')) as preflight,\
             patch('repack.gui.install') as install:
            self.state.start({'mode':'plain','upload':self.upload(),'device':'serial','auto_install':True});self.wait()
        job=next(iter(self.state.jobs.values()));self.assertEqual(job['state'],'awaiting_confirmation')
        self.assertFalse(preflight.call_args.args[2]);install.assert_not_called()
        with self.assertRaises(ValueError):self.state.request_install(job['id'],{'confirm_wipe':True,'package':'wrong.package'})
        with self.assertRaises(ValueError):self.state.request_install(job['id'],{'confirm_wipe':False,'package':job['package']})
        with patch('repack.gui.devices.require_device',return_value='serial'),patch('repack.gui.preflight',return_value={'replace':False}) as fresh,\
             patch('repack.gui.install') as installed:
            self.state.request_install(job['id'],{'confirm_wipe':True,'package':job['package']});self.wait()
        self.assertTrue(fresh.call_args.args[2]);installed.assert_called_once();self.assertEqual(job['state'],'installed')

    def test_app_names_are_decoded_and_partial_inventory_is_rejected(self):
        enc=lambda s:base64.b64encode(s.encode()).decode()
        line='REPACK_APP\t'+enc('dev.example')+'\t'+enc('My App é')+'\n'
        self.assertEqual(parse_apps(line+'REPACK_APPS_DONE\t0\t1\n',0)[0]['name'],'My App é')
        for text in (line,line+'REPACK_APPS_DONE\t10\t1',line+'REPACK_APPS_DONE\t0\t2'):
            with self.assertRaises(ValueError):parse_apps(text,0)

    def test_versions_and_small_icons_are_parsed_with_fallback(self):
        enc=lambda s:base64.b64encode(s.encode()).decode()
        # Envelope validation; the device emits an actual PNG drawn by Bitmap.
        png=b'\x89PNG\r\n\x1a\n'+b'\0'*4+b'IHDR'+struct.pack('>II',64,64)+b'\0'*9
        line='REPACK_APP\t'+enc('dev.example')+'\t'+enc('Example App')+'\t'+enc('2.3.1')+'\t42\t'
        row=parse_apps(line+base64.b64encode(png).decode()+'\nREPACK_APPS_DONE\t0\t1',0)[0]
        self.assertEqual((row['version'],row['version_code']),('2.3.1',42));self.assertTrue(row['icon'].startswith('data:image/png;base64,'))
        self.assertIsNone(parse_apps(line+'\nREPACK_APPS_DONE\t0\t1',0)[0]['icon'])
        with self.assertRaises(ValueError):parse_apps(line+base64.b64encode(b'bad').decode()+'\nREPACK_APPS_DONE\t0\t1',0)

    def test_delete_apks_keeps_originals_key_and_reports_then_full_delete(self):
        with patch('repack.gui.plain_build',side_effect=self.build):
            self.state.start({'mode':'plain','upload':self.upload(),'auto_install':False});self.wait()
        job=next(iter(self.state.jobs.values()));folder=self.state.root/'jobs'/job['id']
        key=self.state.root/'operator.p12';key.write_bytes(b'persistent identity')
        with patch('repack.gui.install') as install:
            self.state.delete_job(job['id'],'apks')
            self.assertFalse((folder/'result').exists());self.assertTrue((folder/'originals/000-base.apk').is_file())
            self.assertTrue((folder/'evidence').is_dir());self.assertEqual(job['files'],[])
            with self.assertRaises(ValueError):self.state.request_install(job['id'],{})
            self.state.delete_job(job['id'],'build');install.assert_not_called()
        self.assertFalse(folder.exists());self.assertNotIn(job['id'],self.state.jobs);self.assertEqual(key.read_bytes(),b'persistent identity')

    def test_deletion_refuses_busy_active_and_symlinked_builds(self):
        identity='c'*32;folder=self.state.root/'jobs'/identity
        self.state.jobs[identity]={'id':identity,'state':'building'}
        with self.assertRaises(ValueError):self.state.delete_job(identity,'build')
        self.assertFalse(self.state.busy)
        self.state.jobs[identity]['state']='built'
        outside=self.state.root/'outside';outside.mkdir();(outside/'keep').write_text('keep')
        folder.symlink_to(outside,target_is_directory=True)
        with self.assertRaises(ValueError):self.state.delete_job(identity,'build')
        self.assertTrue((outside/'keep').exists())
        self.state.busy=True
        with self.assertRaises(ValueError):self.state.delete_job(identity,'apks')
        self.state.busy=False

    def test_old_build_proxy_metadata_remains_visible(self):
        row=self.state.public({'mode':'interception','options':{'proxy':'192.0.2.5:8888'}})
        self.assertEqual(row['proxy'],{'host':'192.0.2.5','port':8888});self.assertNotIn('options',row)
        self.assertIsNone(self.state.public({'mode':'plain'})['proxy'])

    def test_downloaded_certificates_are_cached_as_pem_and_checked_before_use(self):
        from test_certificates import DER,PEM
        from repack.certificates import decode_public
        certificate={**decode_public(DER),'url':'http://127.0.0.1:8080/cert','provider':'Burp Suite'}
        with patch('repack.gui.fetch_certificate',return_value=certificate):result=self.state.fetch_ca()
        path,info=self.state.stored_ca(result['id'])
        self.assertEqual(Path(path).read_bytes(),PEM.encode());self.assertEqual(info['format'],'DER')
        Path(path).write_bytes(b'changed')
        with self.assertRaises(ValueError):self.state.stored_ca(result['id'])

    def test_der_upload_is_accepted_and_interception_records_proxy(self):
        from test_certificates import DER
        ca=self.state.new_upload();self.state.upload(ca,'proxy.der',len(DER),io.BytesIO(DER))
        built={}
        def fake_patch(*args,**kwargs):
            built.update(self.build(*args,**kwargs));return built
        with patch('repack.gui.patch',side_effect=fake_patch),patch('repack.gui.load_artifact',side_effect=lambda path:({},built['artifact'])):
            self.state.start({'mode':'interception','upload':self.upload(),'ca_upload':ca,'proxy':'192.0.2.5:8888','auto_install':False});self.wait()
        job=next(iter(self.state.jobs.values()));self.assertEqual(job['state'],'built')
        self.assertEqual(job['proxy'],{'host':'192.0.2.5','port':8888});self.assertEqual(job['certificate']['format'],'DER')

    def test_auto_install_uses_source_serial_even_with_another_device_present(self):
        with patch('repack.gui.devices.require_device',return_value='source'),patch('repack.gui.plain_build',side_effect=self.build),patch('repack.gui.preflight',return_value={'replace':False}) as preflight,patch('repack.gui.install') as installed:
            self.state.start({'mode':'plain','upload':self.upload(),'device':'source','auto_install':True});self.wait()
        self.assertEqual(preflight.call_args.args[1],'source');self.assertEqual(installed.call_args.args[1],'source')
        job=next(iter(self.state.jobs.values()));self.assertEqual(job['device'],'source')

    def test_install_failure_keeps_build_for_explicit_other_device_retry(self):
        with patch('repack.gui.devices.require_device',return_value='source'),patch('repack.gui.plain_build',side_effect=self.build),patch('repack.gui.preflight',side_effect=RuntimeError('transfer stopped')),patch('repack.gui.install') as installed:
            self.state.start({'mode':'plain','upload':self.upload(),'device':'source','auto_install':True});self.wait()
        job=next(iter(self.state.jobs.values()));self.assertEqual(job['state'],'install_failed');self.assertTrue(job['files']);installed.assert_not_called()
        with patch('repack.gui.devices.require_device',return_value='other'),patch('repack.gui.preflight',return_value={'replace':False}) as preflight,patch('repack.gui.install') as installed:
            self.state.request_install(job['id'],{'device':'other'});self.wait()
        self.assertEqual(preflight.call_args.args[1],'other');self.assertEqual(installed.call_args.args[1],'other')
        self.assertEqual(job['device'],'source');self.assertEqual(job['install_device'],'other')
        self.assertEqual([a['device'] for a in job['install_attempts']],['source','other'])

    def test_wipe_consent_cannot_move_to_another_device(self):
        with patch('repack.gui.devices.require_device',return_value='source'),patch('repack.gui.plain_build',side_effect=self.build),patch('repack.gui.preflight',side_effect=ReplacementRequired('dev.repack.fixture.other','source')):
            self.state.start({'mode':'plain','upload':self.upload(),'device':'source','auto_install':True});self.wait()
        job=next(iter(self.state.jobs.values()))
        with self.assertRaises(ValueError):self.state.request_install(job['id'],{'device':'other','confirm_wipe':True,'package':job['package']})
        self.assertFalse(self.state.busy)

    def test_icons_can_load_while_build_is_busy_without_occupying_worker(self):
        self.state.app_cache[('source',0)]={'dev.example':{'package':'dev.example','name':'Example'}}
        self.state.busy=True
        with patch('repack.gui.devices.apps',return_value={'apps':[{'package':'dev.example','icon':None}],'user':0}) as query:
            self.state.icons({'device':'source','user':0,'packages':['dev.example']})
        self.assertTrue(self.state.busy);self.assertEqual(query.call_args.kwargs['packages'],['dev.example'])
        self.state.busy=False

    def test_progress_advances_through_named_steps(self):
        with patch('repack.gui.plain_build',side_effect=self.build):
            self.state.start({'mode':'plain','upload':self.upload(),'auto_install':False});self.wait()
        job=next(iter(self.state.jobs.values()));self.assertTrue(job['progress']['done']);self.assertEqual(len(job['progress']['labels']),4)

    def test_installed_local_tools_start_preparation_without_user_click(self):
        with patch('repack.gui.load_lock',side_effect=PrerequisiteError('fresh')),patch('repack.gui.setup.local_tools_available',return_value=True),patch.object(Workflow,'prepare') as prepare:
            state=Workflow(Path(self.temp.name)/'auto');self.addCleanup(state.worker.shutdown,wait=True)
        prepare.assert_called_once_with({})

    def test_missing_local_tools_leave_license_setup_available(self):
        with patch('repack.gui.load_lock',side_effect=PrerequisiteError('fresh')),patch('repack.gui.setup.local_tools_available',return_value=False),patch.object(Workflow,'prepare') as prepare:
            state=Workflow(Path(self.temp.name)/'missing');self.addCleanup(state.worker.shutdown,wait=True)
        prepare.assert_not_called();self.assertEqual(state.setup_status['state'],'needed')


class BrowserBoundaryControls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        with patch('repack.gui.load_lock',side_effect=PrerequisiteError('fresh host')):
            self.state=Workflow(Path(self.temp.name)/'gui',auto_prepare=False)
        self.server,_=serve(0,False,self.state)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.addCleanup(self.close)
    def close(self):
        self.server.shutdown();self.server.server_close();self.thread.join();self.state.worker.shutdown(wait=True)
    def request(self,path,body=None,headers=None):
        c=http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=5)
        c.request('POST' if body is not None else 'GET',path,body=body,headers=headers or {})
        r=c.getresponse();data=r.read();status=r.status;c.close();return status,data
    def test_index_has_session_but_api_requires_it(self):
        status,body=self.request('/');self.assertEqual(status,200);self.assertIn(self.state.token.encode(),body)
        self.assertEqual(self.request('/api/status')[0],403)
        self.assertEqual(self.request('/api/status',headers={'X-Repack-Token':self.state.token})[0],200)
    def test_foreign_origin_and_host_cannot_operate(self):
        self.assertEqual(self.request('/api/uploads',b'{}',{'X-Repack-Token':self.state.token,'Origin':'https://evil.invalid'})[0],403)
        self.assertEqual(self.request('/',headers={'Host':'evil.invalid'})[0],403)
        self.assertFalse(self.state.uploads)
    def test_encoded_upload_path_cannot_escape(self):
        headers={'X-Repack-Token':self.state.token};identity=json.loads(self.request('/api/uploads',b'{}',headers)[1])['id']
        self.assertEqual(self.request('/api/uploads/'+identity+'/..%2Fescape.apk',b'x',headers)[0],400)
        self.assertFalse((self.state.root/'uploads/escape.apk').exists())
    def test_download_needs_session_and_checks_hash(self):
        jobid='a'*32;folder=self.state.root/'jobs'/jobid;folder.mkdir();apk=folder/'app.apk';apk.write_bytes(b'APK')
        self.state.jobs[jobid]={'id':jobid,'files':[{'path':'app.apk','sha256':sha256(apk)}]}
        url='/api/jobs/'+jobid+'/download/0'
        self.assertEqual(self.request(url)[0],403)
        headers={'Cookie':'repack_session='+self.state.token}
        self.assertEqual(self.request(url,headers=headers),(200,b'APK'))
        apk.write_bytes(b'changed');self.assertEqual(self.request(url,headers=headers)[0],400)
    def test_disconnected_browser_does_not_trigger_a_second_response_or_traceback(self):
        started=threading.Event();release=threading.Event();done=threading.Event()
        def discovery(*args):
            started.set();release.wait(3);return {'apps':[],'padding':'x'*1000000}
        def error(*args):done.set()
        with patch.object(self.state,'discovery',side_effect=discovery),patch.object(self.server,'handle_error',side_effect=error) as server_error:
            client=socket.create_connection(('127.0.0.1',self.server.server_port))
            body=b'{}';headers=('POST /api/apps HTTP/1.1\r\nHost: 127.0.0.1:'+str(self.server.server_port)+'\r\nX-Repack-Token: '+self.state.token+'\r\nContent-Length: 2\r\n\r\n').encode()
            client.sendall(headers+body);self.assertTrue(started.wait(3))
            client.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack('ii',1,0));client.close();release.set()
            done.wait(.2)
            self.assertEqual(self.request('/api/status',headers={'X-Repack-Token':self.state.token})[0],200)
            server_error.assert_not_called()

    def test_split_bundle_contains_only_outputs_and_public_metadata(self):
        identity='b'*32;folder=self.state.root/'jobs'/identity;folder.mkdir();apk=folder/'base.apk';apk.write_bytes(b'APK')
        self.state.jobs[identity]={'id':identity,'package':'dev.example','files':[{'path':'base.apk','sha256':sha256(apk)}]}
        status,data=self.request('/api/jobs/'+identity+'/bundle',headers={'Cookie':'repack_session='+self.state.token})
        self.assertEqual(status,200)
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            self.assertEqual(set(archive.namelist()),{'base.apk','outputs.json','INSTALL.txt'})
            self.assertEqual(archive.read('base.apk'),b'APK')
            self.assertIn(b'adb -s SERIAL install -r base.apk',archive.read('INSTALL.txt'))

if __name__=='__main__':unittest.main()
