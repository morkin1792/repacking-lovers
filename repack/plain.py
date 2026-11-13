"""Plain resource round trip and signing, without trust/routing/runtime injection."""
from pathlib import Path
import re
from .pipeline import resolve_key,validate_toolchain
from .rebuild import align_sign,sha256,write_json,source_hash
from .recon import inspect_input
from .trust import decode_resources,rebuild_resources


def build(input_ref,options,lock,evidence,*,progress=None):
    notify=progress or (lambda text:None);revision=source_hash()
    validate_toolchain(lock,device=bool(options.get('device')))
    source=inspect_input(input_ref,options.get('device'),lock,evidence/'input')
    key=resolve_key(Path(options['key']),lock,evidence)
    out=Path(options['out']);out.mkdir(parents=True,exist_ok=False)
    base=next(m for m in source['members'] if not m.get('split'))
    work=evidence/'rebuild';work.mkdir()
    notify('Rebuilding resources; preserving DEX and native code…')
    decode_resources(Path(base['apk']),work/'decoded',lock,work)
    rebuilt=rebuild_resources(Path(base['apk']),work/'decoded',work/'rebuilt.apk',lock,work)
    members=[]
    notify('Aligning, signing and verifying the APKs…')
    for index,m in enumerate(source['members']):
        split=m.get('split')
        if split and not re.fullmatch(r'[A-Za-z0-9_.-]+',split):raise ValueError('Unsafe split identifier')
        part=evidence/f'sign-{index}';part.mkdir()
        apk=out/('base.apk' if not split else 'split_'+split+'.apk')
        if sha256(Path(m['apk']))!=m['sha256']:raise RuntimeError('Original input changed during repacking')
        align_sign(Path(rebuilt['unsigned_apk']) if not split else Path(m['apk']),apk,key,lock,part)
        members.append({'apk':str(apk.resolve()),'sha256':sha256(apk),'split':split})
    artifact={'package':source['package'],'version_code':source['version_code'],'signer_sha256':[key['sha256']],'members':members}
    if source_hash()!=revision or any(sha256(Path(m['apk']))!=m['sha256'] for m in source['members']):
        raise RuntimeError('Implementation or input changed during the build; no installation attempted')
    manifest=out/'plain-artifact.json'
    write_json(manifest,{'schema_version':1,'kind':'plain-repack','artifact':artifact,'input':source,
                        'routing_changes':False,'pinning_changes':False,'runtime_verification':'not-run'})
    return {'manifest':str(manifest.resolve()),'artifact':artifact,'inventory':source}
