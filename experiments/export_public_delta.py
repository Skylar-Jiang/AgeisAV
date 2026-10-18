"""Export reviewed source without reading credentials; inherit unchanged public blobs.

Generic credential checks cannot prove absence of every possible secret. Review the
changed paths before publishing. The manifest states this limitation explicitly.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess

from experiments.export_public_source import ROOT, PREFIXES, ROOT_FILES, DOCS, OVERRIDES, FORBIDDEN

ADDITIONAL_DOCS={'docs/research/ROUND_REPORT_20261017_STAGE_E_R3_PUBLIC.md',
                 'docs/benchmarks/stage_e3_summary_20261017.json',
                 'docs/research/ROUND_REPORT_20261017_STAGE_E_R4_PUBLIC.md',
                 'docs/benchmarks/stage_e4_summary_20261017.json',
                 'docs/research/ROUND_REPORT_20261017_STAGE_E_R4_VM_PUBLIC.md',
                 'docs/benchmarks/stage_e4_vm_summary_20261017.json',
                 'docs/research/ROUND_REPORT_20261018_STAGE_E_R5_PUBLIC.md',
                 'docs/benchmarks/stage_e5_summary_20261018.json',
                 'docs/DATASET_ADMISSION_R6.md',
                 'docs/research/ROUND_REPORT_20261018_STAGE_E_R6_PUBLIC.md',
                 'docs/benchmarks/stage_e6_summary_20261018.json'}


def check_blob(name,data,private_hashes):
    path=Path(name)
    if path.suffix.lower() in FORBIDDEN or path.is_absolute() or '..' in path.parts or '\\' in name:
        raise ValueError('public_path_gate:'+name)
    credential=re.compile(rb'''(?i)(?:api[_-]?key|auth[_-]?key|access[_-]?token|password)["']?\s*[=:]\s*["']([a-z0-9_+/=-]{32,})["']''')
    if (len(data)>2*1024**2 or data.startswith(b'MZ') or b'\0' in data or
        re.search(rb'-----BEGIN [A-Z ]*PRIVATE KEY-----',data) or credential.search(data) or
        re.search(rb'(?i)(?<![a-f0-9])[a-f0-9]{45,63}(?![a-f0-9])',data) or
        any(sha.encode() in data.lower() for sha in private_hashes)):
        raise ValueError('public_content_gate:'+name)


def git(*args,input=None):
    return subprocess.check_output(['git',*args],cwd=ROOT,input=input)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('output',type=Path)
    parser.add_argument('--public-parent',required=True)
    args=parser.parse_args()
    parent=git('rev-parse',args.public_parent+'^{commit}').decode().strip()
    branch='refs/heads/codex/public-platform-20261014'
    if (git('rev-parse',branch).decode().strip()!=parent or
        git('ls-remote','origin',branch).decode().split()[0]!=parent):
        raise ValueError('public_parent_moved')
    prior=json.loads(git('show',parent+':PUBLIC_SOURCE_MANIFEST.json'))
    if not prior.get('private_candidate_hashes_absent') or prior.get('private_history_included') is not False:
        raise ValueError('public_parent_gate_missing')
    inherited={row['path']:row['sha256'] for row in prior['files']}
    output=args.output.resolve()
    if not output.is_relative_to(ROOT/'artifacts') or output.exists():
        raise ValueError('export_requires_new_directory_inside_artifacts')
    revision=git('rev-parse','HEAD').decode().strip()
    tracked=git('ls-tree','-r','--name-only','-z',revision).decode().split('\0')
    names=[n for n in filter(None,tracked) if n.startswith(PREFIXES) or n in ROOT_FILES|DOCS|ADDITIONAL_DOCS or n in OVERRIDES]
    private_hashes=set()
    for source in (ROOT/'docs/benchmarks').glob('*candidates*.jsonl'):
        for line in source.read_text(encoding='utf-8').splitlines():
            sha=json.loads(line).get('sha256')
            if isinstance(sha,str) and re.fullmatch('[a-fA-F0-9]{64}',sha): private_hashes.add(sha.lower())
    if not private_hashes: raise ValueError('private_candidate_catalog_required')
    objects=io.BytesIO(git('cat-file','--batch',input=''.join(revision+':'+n+'\n' for n in names).encode()))
    selected=[];changed=[]
    for name in names:
        header=objects.readline().split()
        if len(header)!=3 or header[1]!=b'blob': raise ValueError('committed_blob_required:'+name)
        data=objects.read(int(header[2]));assert objects.read(1)==b'\n'
        destination=OVERRIDES.get(name,name)
        check_blob(destination,data,private_hashes)
        digest=hashlib.sha256(data).hexdigest()
        if inherited.get(destination)!=digest: changed.append(destination)
        selected.append((destination,data,digest))
    output.mkdir(parents=True)
    for name,data,_ in selected:
        target=output/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
    manifest=dict(schema=2,source_revision=revision,files=[dict(path=n,sha256=h,bytes=len(d)) for n,d,h in selected],
        inherited_public_gate_revision=parent,changed_paths=changed,
        secret_values_read=False,secrets_checked=0,exact_secret_comparison_run=False,
        generic_secret_patterns_absent=True,private_candidate_hashes_absent=True,private_history_included=False,
        limitation='Generic checks plus review; no assertion of exact secret-value exclusion for changed blobs.')
    (output/'PUBLIC_SOURCE_MANIFEST.json').write_bytes((json.dumps(manifest,indent=2)+'\n').encode())
    print(json.dumps(dict(files=len(selected),changed_paths=changed,secret_values_read=False)))


if __name__=='__main__': main()
