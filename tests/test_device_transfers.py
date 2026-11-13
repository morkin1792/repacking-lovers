"""Read-only backup retries must stay pinned to one device and verify cache bytes."""
from pathlib import Path
import subprocess
import hashlib
import json
import tempfile
import unittest
from unittest.mock import patch
from repack.verify import pull_apk,backup_apk,adb
from repack.rebuild import sha256,PrerequisiteError

class TransferControls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name);self.target=self.root/'backup.apk'
    def snapshot(self,data):
        def query(lock,evidence,label,serial,args,**kwargs):
            text=str(len(data)) if args[0]=='stat' else hashlib.sha256(data).hexdigest()+'  /data/base.apk'
            return subprocess.CompletedProcess([],0,text,'')
        return query
    def test_short_zero_exit_chunk_is_retried_at_same_offset(self):
        data=b'0123456789';offsets=[]
        def read(lock,folder,label,serial,remote,offset,size,target):
            self.assertEqual(serial,'source');self.assertFalse(self.target.exists());offsets.append(offset)
            content=data[offset:offset+size]
            if len(offsets)==2:content=content[:1]
            Path(target).write_bytes(content);return len(content)==size
        with patch('repack.transfers.CHUNK_BYTES',4),patch('repack.transfers.wait_for_device',return_value=True),patch('repack.verify.shell',side_effect=self.snapshot(data)),patch('repack.transfers.read_chunk',side_effect=read):
            result=pull_apk({},self.root,'pull','source','/data/base.apk',self.target)
        self.assertEqual(offsets,[0,4,4,8]);self.assertEqual(self.target.read_bytes(),data);self.assertTrue(result['verified'])
    def test_retry_shrinks_chunks_without_skipping_or_duplicating_bytes(self):
        data=b'0123456789';reads=[]
        def read(lock,folder,label,serial,remote,offset,size,target):
            reads.append((offset,size));content=data[offset:offset+size]
            if len(reads)==2:content=content[:1]
            Path(target).write_bytes(content);return len(content)==size
        with patch('repack.transfers.CHUNK_BYTES',4),patch('repack.transfers.BLOCK_BYTES',1),patch('repack.transfers.time.sleep'),patch('repack.transfers.wait_for_device',return_value=True),patch('repack.verify.shell',side_effect=self.snapshot(data)),patch('repack.transfers.read_chunk',side_effect=read):
            pull_apk({},self.root,'pull','source','/data/base.apk',self.target)
        self.assertEqual(reads,[(0,4),(4,4),(4,2),(6,2),(8,2)]);self.assertEqual(self.target.read_bytes(),data)
    def test_failed_chunk_never_publishes_partial_apk(self):
        def read(*args):Path(args[-1]).write_bytes(b'partial');return False
        with patch('repack.transfers.wait_for_device',return_value=True),patch('repack.verify.shell',side_effect=self.snapshot(b'original')),patch('repack.transfers.read_chunk',side_effect=read) as operation:
            with self.assertRaisesRegex(PrerequisiteError,'source.*chunk retries'):pull_apk({},self.root,'pull','source','/data/base.apk',self.target)
        self.assertEqual(operation.call_count,5);self.assertFalse(self.target.exists());self.assertFalse(list(self.root.glob('.apk-transfer-*')))
    def test_full_length_wrong_checksum_is_rejected(self):
        def read(*args):Path(args[-1]).write_bytes(b'corrupt!');return True
        with patch('repack.transfers.wait_for_device',return_value=True),patch('repack.verify.shell',side_effect=self.snapshot(b'original')),patch('repack.transfers.read_chunk',side_effect=read):
            with self.assertRaisesRegex(PrerequisiteError,'checksum mismatch'):pull_apk({},self.root,'pull','source','/data/base.apk',self.target)
        self.assertFalse(self.target.exists())
    def test_offline_transport_wait_is_scoped_to_selected_serial(self):
        from repack.transfers import wait_for_device
        responses=[subprocess.CompletedProcess([],1,'','device offline'),subprocess.CompletedProcess([],0,'device','')]
        with patch('repack.verify.adb',side_effect=responses) as operation,patch('repack.transfers.time.sleep'):
            self.assertTrue(wait_for_device({},self.root,'ready','source'))
        self.assertEqual([call.kwargs['serial'] for call in operation.call_args_list],['source','source'])
        self.assertTrue(all(call.args[3]==['get-state'] for call in operation.call_args_list))
    def test_chunk_stream_is_binary_and_zero_exit_short_read_is_failure(self):
        from repack.transfers import read_chunk
        def run(command,**kwargs):kwargs['stdout'].write(b'\xff\x00');return subprocess.CompletedProcess(command,0)
        with patch('repack.transfers.subprocess.run',side_effect=run) as run:
            self.assertFalse(read_chunk({'tools':{'adb':{'path':'/adb'}},'jdk_path':'/jdk'},self.root,'chunk','source','/data/app/base.apk',0,10,self.target))
        self.assertEqual(run.call_args.args[0][:3],['/adb','-s','source']);self.assertEqual(run.call_args.args[0][3:5],['shell','-T']);self.assertEqual(self.target.read_bytes(),b'\xff\x00')
        report=json.loads((self.root/'chunk.command.json').read_text());self.assertEqual(report['received_bytes'],2)
    def test_explicit_serial_is_passed_even_if_other_devices_exist(self):
        lock={'tools':{'adb':{'path':'/adb'}},'jdk_path':'/jdk'}
        with patch('repack.verify.execute',return_value=subprocess.CompletedProcess([],0,'','')) as execute:
            adb(lock,self.root,'pull',['pull','/data/base.apk',str(self.target)],serial='source')
        self.assertEqual(execute.call_args.args[0][:3],['/adb','-s','source'])
    def test_cache_is_reused_only_with_current_remote_hash_match(self):
        cache=self.root/'original.apk';cache.write_bytes(b'original')
        response=subprocess.CompletedProcess([],0,sha256(cache)+'  /data/base.apk\n','')
        with patch('repack.verify.shell',return_value=response) as shell,patch('repack.verify.pull_apk') as pull:
            backup_apk({},self.root,'pull','source','/data/base.apk',self.target,[cache])
        pull.assert_not_called();self.assertEqual(shell.call_args.args[3],'source');self.assertEqual(self.target.read_bytes(),b'original')
        response.stdout='f'*64+'  /data/base.apk\n'
        with patch('repack.verify.shell',return_value=response),patch('repack.verify.pull_apk') as pull:
            backup_apk({},self.root,'pull2','source','/data/base.apk',self.target,[cache])
        pull.assert_called_once()

if __name__=='__main__':unittest.main()
