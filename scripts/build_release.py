"""Build a deterministic source bundle without tools, APKs, credentials or history."""
import argparse,hashlib,json,stat,tomllib,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]


def build(destination):
    version=tomllib.loads((ROOT/'pyproject.toml').read_text())['project']['version']
    files=[ROOT/p for p in ('README.md','PLAN.md','pyproject.toml','repack.sh','.gitignore','.gitattributes')]
    extensions={'.py','.java','.xml','.json','.md','.txt','.c','.h','.cpp','.S','.dart','.yaml','.lock','.js','.html','.css','.patch'}
    for name in ('repack','tools','shim','native','config','docs','scripts','tests'):
        files.extend(p for p in (ROOT/name).rglob('*') if p.is_file() and not p.is_symlink()
            and '__pycache__' not in p.parts and p.suffix in extensions and p.name!='implementation-lock.json')
    destination=Path(destination);destination.parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(destination,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for p in sorted(set(files)):
            info=zipfile.ZipInfo('repacking-lovers-'+version+'/'+str(p.relative_to(ROOT)),(2020,1,1,0,0,0))
            info.compress_type=zipfile.ZIP_DEFLATED;info.create_system=3
            info.external_attr=(stat.S_IFREG|(0o755 if p.name=='repack.sh' else 0o644))<<16
            z.writestr(info,p.read_bytes())
    sha=hashlib.sha256(destination.read_bytes()).hexdigest()
    destination.with_suffix(destination.suffix+'.sha256').write_text(sha+'  '+destination.name+'\n')
    print(destination,sha)
    return destination

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--out',type=Path,required=True)
    build(parser.parse_args().out)
