"""Export a reviewed source snapshot without private research history or datasets.

Read the current API key from stdin for an exact-secret exclusion check. Never log it.
This creates files only; Git branch creation and push are separate reviewed operations.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
PREFIXES=('backend/','ml/','experiments/','vm/','rules/','frontend/','distribution/','.agents/skills/')
ROOT_FILES={'.gitignore','.gitattributes','pyproject.toml','requirements-win-py312.txt',
            'requirements-ml.txt','requirements-ml-lock.txt','requirements.txt','.env.example'}
DOCS={'docs/BEHAVIOR_ANALYSIS.md',
      'docs/COURSE_GUIDE.md',
      'docs/COURSE_HASH_QUERY.md',
      'docs/DELIVERY_RUNBOOK.md',
      'docs/EVALUATION.md',
      'docs/KNOWN_LIMITATIONS.md',
      'docs/ML_INTEGRATION.md',
      'docs/PERFORMANCE.md',
      'docs/README.md',
      'docs/RELEASE_STATUS.md',
      'docs/SYSTEM_DESIGN.md',
      'docs/TASK_RELIABILITY.md',
      'docs/USER_GUIDE.md',
      'docs/benchmarks/collection_expansion_summary_20261014.json',
      'docs/benchmarks/collection_summary_20261013.json',
      'docs/benchmarks/course_evaluation_20261022.json',
      'docs/benchmarks/model_binning_20261022.json',
      'docs/benchmarks/native_rc_20261023.json',
      'docs/benchmarks/optimization_20261022.json',
      'docs/benchmarks/product_pages_check_20261016.json',
      'docs/benchmarks/stage_e6_summary_20261018.json',
      'docs/benchmarks/stage_e7_summary_20261019.json',
      'docs/benchmarks/stage_f_summary_20261019.json',
      'docs/benchmarks/stage_g_summary_20261019.json',
      'docs/benchmarks/task_reliability_check_20261016.json',
      'docs/benchmarks/upstream_windows_rule_audit_20261003.json',
      'docs/benchmarks/windows_controls_20261022.json',
      'docs/benchmarks/yara_bundle_20261101.json',
      'docs/examples/course-query/README.md',
      'docs/examples/course-query/sha256.txt'}
OVERRIDES={'docs/PUBLIC_SOURCE_README.md':'README.md'}
FORBIDDEN={'.exe','.dll','.sys','.zip','.7z','.rar','.vmdk','.vmem','.vmsn','.vmx',
           '.ova','.deb','.whl','.pkl','.joblib','.bin','.parquet','.npy','.npz','.jsonl'}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('output',type=Path)
    args=parser.parse_args()
    output=args.output.resolve()
    if not output.is_relative_to(ROOT/'artifacts') or output.exists():
        raise ValueError('export_requires_new_directory_inside_artifacts')
    secret=sys.stdin.buffer.read().strip()
    if len(secret)<16:
        raise ValueError('exact_secret_check_required_via_stdin')
    secrets = [secret]
    key_root = Path(os.environ.get('LOCALAPPDATA', str(Path.home()/'.local/share'))) / 'AegisAV'
    local_key = Path(os.environ.get('AEGISAV_ACCESS_TOKEN_FILE', str(key_root/'local-access.key')))
    if local_key.exists():
        value = local_key.read_bytes().strip()
        if not 32 <= len(value) <= 4096:
            raise ValueError('invalid_local_access_key_for_export_audit')
        secrets.append(value)
    revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    tracked=subprocess.check_output(['git','ls-files','-z'],cwd=ROOT).decode().split('\0')
    private_hashes=set()
    for source in (ROOT/'docs/benchmarks').glob('*candidates*.jsonl'):
        for line in source.read_text(encoding='utf-8').splitlines():
            sha=json.loads(line).get('sha256')
            if isinstance(sha,str) and len(sha)==64:
                private_hashes.add(sha.encode())
    names=[name for name in filter(None,tracked)
           if name.startswith(PREFIXES) or name in ROOT_FILES|DOCS or name in OVERRIDES]
    queries=''.join(revision+':'+name+'\n' for name in names).encode()
    objects=io.BytesIO(subprocess.check_output(['git','cat-file','--batch'],cwd=ROOT,input=queries))
    selected=[]
    for name in names:
        destination=OVERRIDES.get(name,name)
        path=Path(destination)
        if path.suffix.lower() in FORBIDDEN or path.is_absolute() or '..' in path.parts:
            raise ValueError('forbidden_export_path:'+destination)
        header=objects.readline().split()
        if len(header)!=3 or header[1]!=b'blob':
            raise ValueError('committed_blob_required:'+name)
        data=objects.read(int(header[2]))
        assert objects.read(1)==b'\n'
        if len(data)>2*1024**2 or any(value in data for value in secrets) or any(sha in data for sha in private_hashes):
            raise ValueError('export_content_gate:'+destination)
        selected.append((destination,data))
    output.mkdir(parents=True)
    manifest=[]
    for name,data in selected:
        target=output/name
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(data)
        manifest.append(dict(path=name,sha256=hashlib.sha256(data).hexdigest(),bytes=len(data)))
    evidence=dict(schema=1,source_revision=revision,files=manifest,
                  exact_secret_absent=True,private_candidate_hashes_absent=True,
                  secrets_checked=len(secrets),
                  private_history_included=False)
    (output/'PUBLIC_SOURCE_MANIFEST.json').write_bytes((json.dumps(evidence,indent=2)+'\n').encode('utf-8'))
    print(json.dumps(dict(files=len(manifest),bytes=sum(row['bytes'] for row in manifest),
                         secret_and_private_candidates_gate='pass')))


if __name__=='__main__':
    main()
