"""Prepare a matching, hash-bound optional Dart analyzer; downloads require --fetch.

Blutter is MIT licensed; the metadata exporter patch and upstream license are
retained in tools/blutter-export.patch and docs/licenses/Blutter-MIT.txt.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.request
import zipfile

from repack.rebuild import ROOT, PrerequisiteError, execute, report, sha256, write_json
from repack.dart_pinning import identity


def setup(args):
    result,evidence=report('DART-analyzer-setup');config=ROOT/'config/dart-analysis-dependency.json'
    registry=json.loads(config.read_text());source=ROOT/'.work/tools/blutter';venv=ROOT/'.work/tools/blutter-env'
    env=os.environ.copy();env['PATH']=str(venv/'bin')+os.pathsep+env.get('PATH','')
    result.update(verification='not-run',downloads_authorized=args.fetch)
    try:
        pins=json.loads((ROOT/'config/dart-analysis-python.json').read_text())
        wheels=[]
        for row in pins['artifacts']:
            path=ROOT/row['path']
            if not path.is_file():
                if not args.fetch:raise PrerequisiteError('Missing analyzer wheel; repeat setup with --fetch: '+row['name'])
                data=urllib.request.urlopen(row['url'],timeout=180).read()
                if hashlib.sha256(data).hexdigest()!=row['sha256']:raise RuntimeError('Analyzer wheel download hash changed')
                path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
            if sha256(path)!=row['sha256']:raise PrerequisiteError('Analyzer wheel cache hash changed')
            wheels.append(str(path))
        if not (venv/'bin/python').is_file():execute([sys.executable,'-m','venv',str(venv)],evidence,'venv',timeout=90)
        execute([str(venv/'bin/python'),'-m','pip','install','--no-index','--no-deps','--force-reinstall',*wheels],evidence,'python-dependencies',timeout=120)
        if not (source/'.git').is_dir():
            if not args.fetch:raise PrerequisiteError('Pinned Blutter source missing; repeat with --fetch')
            source.mkdir(parents=True,exist_ok=True)
            execute(['git','init',str(source)],evidence,'git-init')
            execute(['git','-C',str(source),'remote','add','origin',registry['upstream']],evidence,'git-remote')
            execute(['git','-C',str(source),'fetch','--depth','1','origin',registry['commit']],evidence,'git-fetch',timeout=180)
            execute(['git','-C',str(source),'checkout','--detach','FETCH_HEAD'],evidence,'git-checkout')
        commit=execute(['git','-C',str(source),'rev-parse','HEAD'],evidence,'git-head').stdout.strip()
        if commit!=registry['commit']:raise PrerequisiteError('Cached Blutter commit differs; no checkout was reset')
        patch=ROOT/registry['export_patch']['path']
        if sha256(patch)!=registry['export_patch']['sha256']:raise PrerequisiteError('Metadata exporter patch hash changed')
        target=source/'blutter/src/DartDumper.cpp';target_pin=registry['source_files']['blutter/src/DartDumper.cpp']
        if sha256(target)==target_pin['original_sha256']:
            execute(['git','-C',str(source),'apply','--check',str(patch)],evidence,'export-patch-check')
            execute(['git','-C',str(source),'apply',str(patch)],evidence,'export-patch')
        for name,row in registry['source_files'].items():
            if sha256(source/name)!=row['prepared_sha256']:raise PrerequisiteError('Analyzer source changed: '+name)
        source_paths=evidence/'input';source_paths.mkdir()
        if args.apk:
            with zipfile.ZipFile(args.apk) as archive:
                for name in ('libapp.so','libflutter.so'):
                    (source_paths/name).write_bytes(archive.read('lib/arm64-v8a/'+name))
            app=source_paths/'libapp.so';engine=source_paths/'libflutter.so'
        else:
            app=args.libapp.resolve();engine=args.libflutter.resolve() if args.libflutter else None
        ident=identity(app.read_bytes());version=args.dart_version
        if not version:
            if engine is None:raise ValueError('Provide --dart-version or --libflutter for version discovery')
            probe_env={**env,'PYTHONPATH':str(source)}
            value=execute([str(venv/'bin/python'),'-c',
                'import json,sys;from extract_dart_info import extract_dart_info;print(json.dumps(extract_dart_info(sys.argv[1],sys.argv[2])))',str(app),str(engine)],
                evidence,'dart-version',env=probe_env)
            version=json.loads(value.stdout.splitlines()[-1])[0]
        if not re.fullmatch(r'\d+\.\d+\.\d+',version):raise PrerequisiteError('Only stable Dart version identifiers are prepared by this setup')
        if 'compressed-pointers' not in ident['flags'].split():raise PrerequisiteError('This analyzer setup currently supports compressed-pointer Android ARM64 snapshots')
        binary=source/('bin/blutter_dartvm'+version+'_android_arm64')
        if not binary.is_file():
            if not args.fetch:raise PrerequisiteError('Matching Dart runtime has not been built; repeat with --fetch')
            # Blutter performs its pinned-source runtime build explicitly here;
            # the production APK patch command never downloads/builds tools.
            execute([str(venv/'bin/python'),str(source/'blutter.py'),'--dart-version',version+'_android_arm64',str(app),str(evidence/'build-proof')],
                evidence,'build-analyzer',env=env,timeout=1800)
        else:
            execute([str(binary),'-i',str(app),'-o',str(evidence/'build-proof')],evidence,'analyzer-proof',env=env,timeout=180)
        from repack.dart_pinning import read_metadata
        abi,functions=read_metadata(evidence/'build-proof/repack-functions.tsv')
        runtime={**ident,'dart_version':version,'analyzer':{'path':str(binary.relative_to(ROOT)),'sha256':sha256(binary)}}
        registry['runtimes']=[row for row in registry['runtimes'] if (row['snapshot_hash'],row['flags'])!=(ident['snapshot_hash'],ident['flags'])]+[runtime]
        write_json(config,registry)
        result.update(verification='passed',runtime=runtime,dart_abi=abi,exported_functions=len(functions),input_sha256=sha256(app),
            scope='Optional analyzer setup only; no APK transformation, installation or device/root mutation')
        print('PREPARED',version,ident['snapshot_hash'],binary,flush=True)
    except BaseException as error:
        result.update(verification='failed',error_class=type(error).__name__,error=str(error));raise
    finally:
        write_json(evidence/'report.json',result);print('EVIDENCE',evidence/'report.json',flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser();inputs=parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument('--apk',type=Path);inputs.add_argument('--libapp',type=Path)
    parser.add_argument('--libflutter',type=Path);parser.add_argument('--dart-version');parser.add_argument('--fetch',action='store_true')
    setup(parser.parse_args())
