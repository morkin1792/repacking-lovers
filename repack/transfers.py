"""Bounded APK reads over ADB, with chunk retries and end-to-end verification."""
import hashlib
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import time
from .rebuild import PrerequisiteError,environment,tool,write_json

BLOCK_BYTES=64*1024
CHUNK_BYTES=1024*1024
MAX_ATTEMPTS=5


def wait_for_device(lock,evidence,label,serial,seconds=15):
    from .verify import adb
    deadline=time.monotonic()+seconds
    while True:
        result=adb(lock,evidence,label,['get-state'],serial=serial,check=False,timeout=3)
        if result.returncode==0 and result.stdout.strip()=='device':return True
        if 'unauthorized' in result.stderr.lower() or time.monotonic()>=deadline:return False
        time.sleep(.5)


def read_chunk(lock,evidence,label,serial,remote,offset,size,destination):
    # No PTY: shell-v2 keeps binary stdout, stderr and the remote exit status separate.
    # Legacy exec-out can return success with a truncated stream; always check length.
    args=['dd','if='+remote,'bs='+str(BLOCK_BYTES),'skip='+str(offset//BLOCK_BYTES),
          'count='+str((size+BLOCK_BYTES-1)//BLOCK_BYTES)]
    command=[tool(lock,'adb'),'-s',serial,'shell','-T',shlex.join(args)]
    timed_out=False
    with Path(destination).open('wb') as output,(evidence/(label+'.stderr.log')).open('wb') as error:
        try:
            result=subprocess.run(command,stdin=subprocess.DEVNULL,stdout=output,stderr=error,
                                  env=environment(lock),timeout=60)
            status=result.returncode
        except subprocess.TimeoutExpired:status=124;timed_out=True
    actual=Path(destination).stat().st_size
    record={'argv':command,'exit_status':status,'timed_out':timed_out,'timeout_seconds':60,
            'offset':offset,'expected_bytes':size,'received_bytes':actual}
    write_json(evidence/(label+'.command.json'),record)
    return status==0 and actual==size


def pull_apk(lock,evidence,label,serial,remote,destination):
    from .verify import shell
    if not isinstance(serial,str) or not serial:raise ValueError('APK transfer requires an explicit device')
    evidence=Path(evidence);destination=Path(destination);destination.unlink(missing_ok=True)
    if not wait_for_device(lock,evidence,label+'-ready',serial):
        raise PrerequisiteError('Selected device '+serial+' is offline or unauthorized on the configured ADB server. Reconnect that device and retry; no replacement was attempted')
    # Bind every chunk to the same read-only source snapshot.
    size_result=shell(lock,evidence,label+'-size',serial,['stat','-c','%s',remote],check=False)
    hash_result=shell(lock,evidence,label+'-sha256',serial,['sha256sum',remote],check=False)
    digest=re.match(r'^([0-9a-fA-F]{64})\s',hash_result.stdout)
    if size_result.returncode or not size_result.stdout.strip().isdigit() or hash_result.returncode or not digest:
        raise PrerequisiteError('Cannot read APK size/checksum from '+serial+'; reconnect this device and retry. No replacement was attempted')
    size=int(size_result.stdout.strip());expected=digest[1].lower()
    if size<=0:raise PrerequisiteError('Selected APK is empty; no replacement was attempted')
    attempts=[];received=0;capacity=CHUNK_BYTES;number=0;checksum=hashlib.sha256()
    try:
        with tempfile.TemporaryDirectory(prefix='.apk-transfer-',dir=destination.parent) as temporary:
            stage=Path(temporary)/'complete';piece=Path(temporary)/'chunk'
            with stage.open('wb') as output:
                while received<size:
                    count=min(capacity,size-received)
                    success=False
                    for attempt in range(MAX_ATTEMPTS):
                        name=label+'-chunk-'+str(number)+'-try-'+str(attempt+1)
                        piece.unlink(missing_ok=True)
                        success=read_chunk(lock,evidence,name,serial,remote,received,count,piece)
                        attempts.append({'offset':received,'bytes':count,'attempt':attempt+1,'verified_length':success})
                        if success:break
                        if attempt+1<MAX_ATTEMPTS:
                            if not wait_for_device(lock,evidence,name+'-ready',serial):break
                            if count>BLOCK_BYTES:
                                capacity=max(BLOCK_BYTES,(count//2//BLOCK_BYTES)*BLOCK_BYTES)
                                count=min(capacity,size-received)
                            time.sleep(.25)
                    if not success:
                        raise PrerequisiteError('APK transfer from '+serial+' stopped at '+str(received)+'/'+str(size)+' bytes after chunk retries; see '+str(evidence/(name+'.stderr.log'))+'. No replacement was attempted')
                    with piece.open('rb') as source:
                        while block:=source.read(1024*1024):output.write(block);checksum.update(block)
                    received+=count;number+=1
            if checksum.hexdigest()!=expected:
                raise PrerequisiteError('APK checksum mismatch from '+serial+'; the source changed or the transfer was corrupted. Reload the app and retry; no replacement was attempted')
            os.replace(stage,destination)
        report={'device':serial,'remote':remote,'method':'chunked-shell-v2','bytes':received,
                'expected_bytes':size,'sha256':checksum.hexdigest(),'remote_sha256':expected,'verified':True,'chunks':attempts}
        write_json(evidence/(label+'-transfer.json'),report)
        return report
    except Exception:
        destination.unlink(missing_ok=True)
        write_json(evidence/(label+'-transfer.json'),{'device':serial,'remote':remote,'method':'chunked-shell-v2',
            'expected_bytes':size,'received_bytes':received,'remote_sha256':expected,'verified':False,'chunks':attempts})
        raise
