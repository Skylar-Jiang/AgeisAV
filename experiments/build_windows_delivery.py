"""Build an offline portable directory from reviewed public source and pinned runtime."""
import argparse
import base64
import hashlib
import html
import importlib.metadata as metadata
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile
import zipfile

from packaging.requirements import Requirement

ROOT=Path(__file__).resolve().parents[1]
VERSION='0.2.0'
DIRECT=('fastapi','uvicorn','pefile','ppdeep','tlsh-python','yara-x','PyYAML')


def safe_member(name):
    if not name or '\\' in name or ':' in name or name.startswith('/') or any(p in ('.','..','') for p in name.rstrip('/').split('/')):
        raise ValueError('Unsafe archive path')
    return PurePosixPath(name)


def app_sources(root):
    root=Path(root)
    yield from sorted((root/'backend/aegisav').glob('*.py'))
    if (root/'rules/hashes.json').is_file(): yield root/'rules/hashes.json'
    for folder in ('yara','sigma'):
        yield from sorted(p for p in (root/'rules'/folder).rglob('*') if p.is_file() and p.suffix in {'.json','.yar','.yml','.txt','.md'})


def deterministic_zip(root,output):
    with zipfile.ZipFile(output,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as archive:
        for path in sorted(root.rglob('*')):
            if path.is_file():
                entry=zipfile.ZipInfo(path.relative_to(root).as_posix(),date_time=(2026,10,19,0,0,0))
                entry.compress_type=zipfile.ZIP_DEFLATED;entry.external_attr=0o100644<<16
                archive.writestr(entry,path.read_bytes(),compresslevel=9)


def write(path,data):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_bytes(data)


def dependencies():
    pending=list(DIRECT);found={}
    while pending:
        name=pending.pop();dist=metadata.distribution(name)
        identity=dist.metadata['Name'].lower().replace('_','-')
        if identity in found: continue
        found[identity]=dist
        for text in dist.requires or []:
            req=Requirement(text)
            if (req.marker is None or req.marker.evaluate({'extra':''})):
                installed=metadata.version(req.name)
                if installed not in req.specifier: raise ValueError('Installed dependency constraint mismatch: '+req.name)
                pending.append(req.name)
    return found


def copy_dependencies(root):
    rows=[]
    for name,dist in sorted(dependencies().items()):
        base=Path(dist.locate_file('')).resolve();count=0
        for item in dist.files or []:
            path=Path(dist.locate_file(item)).resolve()
            if not path.is_relative_to(base): continue # console scripts are not needed
            relative=path.relative_to(base)
            if '__pycache__' in relative.parts or relative.suffix=='.pyc' or relative.name in {'direct_url.json','INSTALLER','REQUESTED'}: continue
            data=path.read_bytes()
            if item.hash:
                digest=hashlib.new(item.hash.mode,data).digest()
                if base64.urlsafe_b64encode(digest).rstrip(b'=').decode()!=item.hash.value:
                    raise ValueError('Installed dependency RECORD mismatch: '+name+'/'+str(relative))
            # Reviewed setuptools distutils shim is irrelevant to an isolated
            # runtime with no import-site; never distribute its executable hook.
            if name=='setuptools' and relative.as_posix()=='distutils-precedence.pth': continue
            if relative.suffix=='.pth': raise ValueError('Unreviewed dependency startup hook')
            write(root/'runtime/Lib/site-packages'/relative,data);count+=1
        license_id=dist.metadata.get('License-Expression') or dist.metadata.get('License')
        if license_id and len(license_id)>100: license_id='Full license retained in distribution METADATA'
        rows.append(dict(name=dist.metadata['Name'],version=dist.version,files=count,license=license_id,
                         source='Pinned installed distribution; each hashed RECORD entry verified; not a PyPI origin attestation'))
    return rows


def render_guide(text):
    """Trusted project manuals only; escaped offline HTML, no remote scripts/fonts."""
    output=[];code=False
    for line in text.splitlines():
        if line.startswith('```'):
            output.append('</code></pre>' if code else '<pre><code>');code=not code
        elif code: output.append(html.escape(line)+'\n')
        elif line.startswith('#'):
            level=min(4,len(line)-len(line.lstrip('#')))
            output.append(f'<h{level}>'+html.escape(line[level:].strip())+f'</h{level}>')
        elif line.strip(): output.append('<p>'+html.escape(line)+'</p>')
    return ('<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        '<title>AegisAV 使用文档</title><style>body{background:#f3f2ed;color:#30352c;font:16px/1.9 system-ui,sans-serif;max-width:880px;margin:40px auto;padding:0 24px}h1,h2,h3{line-height:1.4;margin-top:36px}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#e8e9e1;padding:20px;border-radius:8px}a{color:#43593a}p{overflow-wrap:anywhere}</style>'
        '<nav><a href="USER_GUIDE.html">用户手册</a> · <a href="DELIVERY_RUNBOOK.html">部署与故障排除</a> · <a href="DEMO_GUIDE.html">课程演示</a> · <a href="SYSTEM_DESIGN.html">架构</a> · <a href="KNOWN_LIMITATIONS.html">限制</a></nav>'+''.join(output)+'</html>').encode()


def copy_npm_licenses(package,frontend):
    project=frontend.parent
    lock=json.loads((project/'package-lock.json').read_bytes());rows=[]
    for relative,entry in sorted(lock['packages'].items()):
        if not relative: continue
        base=project/relative
        if not base.is_dir(): continue
        name=relative.replace('node_modules/','').replace('/','_')
        copied=[]
        for path in sorted(base.iterdir()):
            if path.is_file() and path.name.lower().startswith(('license','copying','notice','ofl')):
                target=package/'licenses/npm'/name/path.name
                write(target,path.read_bytes());copied.append(path.name)
        rows.append(dict(package=relative,version=entry.get('version'),license=entry.get('license'),license_files=copied))
    write(package/'licenses/npm/components.json',(json.dumps(rows,indent=2)+'\n').encode())
    return len(rows)


def native_component(bundle, source):
    bundle, source = Path(bundle), Path(source)
    manifest=json.loads((bundle/'manifest.json').read_bytes())
    if manifest['schema']!=1 or manifest['abi']!=1 or manifest['file']!='aegisav_ssdeep.dll':
        raise ValueError('Unsupported native component')
    if hashlib.sha256((bundle/manifest['file']).read_bytes()).hexdigest()!=manifest['sha256']:
        raise ValueError('Native DLL digest mismatch')
    digest=hashlib.sha256((source/'experiments/native_ssdeep.c').read_bytes()).hexdigest()
    if digest!=manifest['source_sha256'] or hashlib.sha256((bundle/'native_ssdeep.c').read_bytes()).hexdigest()!=digest:
        raise ValueError('Native component source differs from reviewed source')
    return {name:manifest[name] for name in ('schema','abi','file','sha256','source_sha256')}


def build(source,frontend,runtime_archive,runtime_lock,output,native_bundle=None):
    source,frontend,output=source.resolve(),frontend.resolve(),output.resolve()
    if output.exists() or not output.is_relative_to(ROOT/'artifacts'): raise ValueError('Fresh output under artifacts required')
    reviewed=json.loads((source/'PUBLIC_SOURCE_MANIFEST.json').read_bytes())
    if reviewed.get('private_history_included') is not False or not reviewed.get('generic_secret_patterns_absent'):
        raise ValueError('Reviewed public source gate required')
    known={r['path']:r['sha256'] for r in reviewed['files']}
    inputs=list(app_sources(source))
    for path in inputs:
        if hashlib.sha256(path.read_bytes()).hexdigest()!=known[path.relative_to(source).as_posix()]:
            raise ValueError('Reviewed source integrity mismatch')
    if not (frontend/'linen/behavior/index.html').is_file(): raise ValueError('Build full Linen frontend first')
    lock=json.loads(runtime_lock.read_bytes())
    if hashlib.sha256(runtime_archive.read_bytes()).hexdigest()!=lock['sha256'] or lock['version']!='3.12.15':
        raise ValueError('Pinned runtime digest/version mismatch')
    native=native_component(native_bundle,source) if native_bundle is not None else None
    version='0.2.1rc1' if native else VERSION
    output.mkdir();package=output/('AegisAV-'+version+'-Windows-x64');package.mkdir()
    with tarfile.open(runtime_archive,'r:gz') as archive:
        total=0
        for member in archive:
            path=safe_member(member.name)
            if path.parts[0]!='python' or not member.isfile():
                if member.isdir(): continue
                raise ValueError('Unexpected runtime member/link')
            relative=Path(*path.parts[1:])
            if relative.parts[:2]==('Lib','site-packages') or relative.parts[:2]==('Lib','ensurepip') or relative.parts[0]=='Scripts': continue
            total+=member.size
            if total>150*1024**2: raise ValueError('Expanded runtime limit')
            write(package/'runtime'/relative,archive.extractfile(member).read())
    for path in inputs: write(package/'app'/path.relative_to(source),path.read_bytes())
    if native:
        for name in ('aegisav_ssdeep.dll','native_ssdeep.c','NATIVE_SSDEEP_LICENSE.txt','NATIVE_SSDEEP_NOTICE.md'):
            write(package/'app/native'/name,(native_bundle/name).read_bytes())
        write(package/'app/native/manifest.json',(json.dumps(native,indent=2)+'\n').encode())
    # Explicit portable module paths: registry, PYTHONPATH and user-site are ignored.
    write(package/'runtime/python312._pth',b'Lib\nDLLs\n.\nLib/site-packages\n../app/backend\n')
    python_deps=copy_dependencies(package)
    for path in sorted(frontend.rglob('*')):
        if path.is_file():
            relative=path.relative_to(frontend)
            if path.suffix in {'.map','.zip','.exe','.dll','.sqlite3'}: raise ValueError('Unexpected frontend output')
            write(package/'app/frontend/out'/relative,path.read_bytes())
    for name in ('USER_GUIDE.md','SYSTEM_DESIGN.md','DELIVERY_RUNBOOK.md','DEMO_GUIDE.md','KNOWN_LIMITATIONS.md','BEHAVIOR_ANALYSIS.md','STAGE_E_CLOSEOUT.md','research/ROUND_REPORT_20261019_STAGE_G_PUBLIC.md'):
        path=source/'docs'/name
        if not path.is_file(): raise ValueError('Missing delivery document: '+name)
        write(package/'docs'/path.name,path.read_bytes())
        write(package/'docs'/Path(path.name).with_suffix('.html'),render_guide(path.read_text(encoding='utf-8')))
    for path in sorted((source/'distribution').rglob('*')):
        if path.is_file() and path.suffix in {'.cmd','.md','.txt','.json','.mmd','.html'}:
            data=path.read_bytes()
            if path.suffix=='.cmd': data=data.replace(b'\r\n',b'\n').replace(b'\n',b'\r\n')
            write(package/path.relative_to(source/'distribution'),data)
    if native:
        for name in ('NATIVE_SSDEEP_RC_20261022.md','COURSE_EVALUATION_20261022.md','WINDOWS_CLAMAV_SIDECAR_20261022.md'):
            path=source/'docs/research'/name
            write(package/'docs'/name,path.read_bytes())
            write(package/'docs'/Path(name).with_suffix('.html'),render_guide(path.read_text(encoding='utf-8')))
        for name,action in (('Start-AegisAV.cmd','start'),('Stop-AegisAV.cmd','stop'),('Access-Key.cmd','key')):
            command=('@echo off\r\n"%~dp0runtime\\python.exe" -I -B -m aegisav.desktop '+action+
                ' --data-dir "%LOCALAPPDATA%\\AegisAVDesktop-Candidate" --port 3420 %*\r\nif errorlevel 1 pause\r\n')
            write(package/name,command.encode())
        write(package/'Read-Me-First.txt',('AegisAV '+version+' native SSDeep release candidate\r\n'
            'Independent candidate; stable 0.2.0 is unchanged. Default port3420, private profile AegisAVDesktop-Candidate.\r\n'
            'Rollback: stop this candidate and start the original stable package. Models, rules and thresholds are unchanged.\r\n'
            'Native DLL is integrity checked and loaded only in the unelevated disposable Job. Optional ML/ClamAV assets are external.\r\n'
            'See docs and app/native notices. Do not run this application elevated.\r\n').encode())
    npm_count=copy_npm_licenses(package,frontend)
    write(package/'examples/sysmon_harmless.json',(source/'backend/tests/fixtures/sysmon_harmless.json').read_bytes())
    write(package/'SBOM.json',(json.dumps(dict(schema=1,application_version=version,runtime=lock,native_ssdeep=native,
        python_dependencies=python_deps,optional_excluded=['private ML model assets and ML environment','ClamAV and its signature databases'],
        node_runtime_required=False,npm_license_records=npm_count,source_revision=reviewed['source_revision']),indent=2)+'\n').encode())
    # Explicit source/control files are copied, never the entire working tree.
    files={p.relative_to(package).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(package.rglob('*')) if p.is_file()}
    lowered=[p.casefold() for p in files]
    if len(set(lowered))!=len(lowered): raise ValueError('Case-insensitive package path collision')
    for name in files:
        if name.startswith(('models/','data/','artifacts/','.git/','app/models/','app/data/')): raise ValueError('Private package path gate')
        if name.endswith(('.sqlite3','.key','.vmx','.vmdk','.vmem','.jsonl')): raise ValueError('Private package asset gate')
    manifest=dict(schema=1,version=version,platform='Windows 11 x64',files=files,
                  ssdeep_backend='native' if native else 'python',
                  source_revision=reviewed['source_revision'],static_policy='evidence-or-v1',research='open')
    write(package/'PACKAGE_MANIFEST.json',(json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode())
    bundle=output/(package.name+'.zip');deterministic_zip(package,bundle)
    digest=hashlib.sha256(bundle.read_bytes()).hexdigest()
    write(output/(bundle.name+'.sha256'),(digest+'  '+bundle.name+'\n').encode())
    summary=dict(version=version,bundle=str(bundle),sha256=digest,bytes=bundle.stat().st_size,
        expanded_bytes=sum(p.stat().st_size for p in package.rglob('*') if p.is_file()),files=len(files)+1,
        runtime=lock['version'],python_dependencies=len(python_deps),private_assets_included=False)
    write(output/'build-summary.json',(json.dumps(summary,indent=2)+'\n').encode())
    return summary


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--frontend',type=Path,default=ROOT/'frontend/out')
    parser.add_argument('--runtime',type=Path,required=True)
    parser.add_argument('--runtime-lock',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--native-bundle',type=Path,help='Explicit ABI1 candidate; leaves default stable packaging unchanged')
    args=parser.parse_args()
    print(json.dumps(build(args.source,args.frontend,args.runtime,args.runtime_lock,args.output,args.native_bundle)))


if __name__=='__main__': main()
