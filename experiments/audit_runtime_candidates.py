"""Audit only the new official runtime cohort; never loads model vectors or scores."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from collections import Counter

ROOT=Path(__file__).resolve().parents[1]
MANIFEST=ROOT/'artifacts/official-runtime-pe-20261017/manifest.jsonl'


def main():
    rows=[json.loads(line) for line in MANIFEST.read_text(encoding='utf-8').splitlines()]
    if len(sys.argv)>1 and sys.argv[1]=='--membership':
        import numpy as np
        matches={};sources={};candidates={r['sha256'] for r in rows}
        for split in ('fit','validation','test'):
            path=ROOT/'artifacts/ember2024/vectors'/('meta_'+split+'.npz')
            with np.load(path,allow_pickle=False) as archive:
                identifiers={x.decode() if isinstance(x,bytes) else str(x) for x in archive['sha']}
            matches[split]=sorted(candidates&identifiers)
            sources[split]=dict(rows=len(identifiers),sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        print(json.dumps(dict(matches=matches,sources=sources)));return
    import tlsh,ppdeep
    from aegisav.hashes import compute_fuzzy
    current={}
    for row in rows:
        data=Path(row['source_path']).read_bytes()
        assert hashlib.sha256(data).hexdigest()==row['sha256']
        current[row['sha256']]=compute_fuzzy(data)
    prior={};base=ROOT/'docs/benchmarks'
    for name in ('benign_windows_static_20261010.json','benign_vendor_static_20261011.json',
                 'benign_expansion_static_20261010.json','user_archive_static_20261010.json',
                 'collection_analysis_20261013.json','collection_expansionscan_20261013.json'):
        for row in json.loads((base/name).read_bytes())['files']:
            scan=row.get('report') or row
            hashes=scan.get('engines',{}).get('fuzzy',{}).get('hashes')
            if hashes: prior[row['sha256']]=hashes
    prior.update(json.loads((base/'official_benign_candidate_similarity_20261012.json').read_bytes())['fingerprints'])
    parents={sha:sha for sha in {*current,*prior}}
    def find(sha):
        while parents[sha]!=sha:
            parents[sha]=parents[parents[sha]];sha=parents[sha]
        return sha
    edges=[];errors=[];values=list(current.items())
    for index,(left,a) in enumerate(values):
        for right,b in [*values[:index],*prior.items()]:
            if left==right: continue
            for method,compare,limit in (('tlsh',tlsh.diff,40),('ssdeep',ppdeep.compare,80)):
                if not a.get(method) or not b.get(method): continue
                try:
                    value=compare(a[method],b[method])
                    if (method=='tlsh' and value<=limit) or (method=='ssdeep' and value>=limit):
                        edges.append(dict(a=left,b=right,method=method,value=value))
                        x,y=find(left),find(right);parents[max(x,y)]=min(x,y)
                except (ValueError,TypeError,AssertionError) as error:
                    errors.append(dict(a=left,b=right,reason=type(error).__name__))
    linked={find(x) for x in current.keys()&prior.keys()}|{find(e['b']) for e in edges if e['b'] in prior}
    membership=json.loads(subprocess.check_output([str(ROOT/'.venv-ml/Scripts/python.exe'),__file__,'--membership'],text=True))
    result=dict(schema=1,candidates=len(rows),unique_sha=len(current),prior_exact_overlap=len(current.keys()&prior.keys()),
        scope_counts=dict(Counter(r['pe_scope'] for r in rows)),fingerprints=current,edges=edges,fingerprint_errors=errors,
        screening_components=len({find(x) for x in current}),prior_linked_files=sum(find(x) in linked for x in current),
        training=membership,full_author_training_verified=False,strict_final_test=False,
        limitations='Only local Win64 SHA membership; fuzzy screening is not proof of independence.',
        manifest_sha256=hashlib.sha256(MANIFEST.read_bytes()).hexdigest())
    (MANIFEST.parent/'similarity-training-audit.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:result[k] for k in ('candidates','unique_sha','prior_exact_overlap','scope_counts','screening_components','prior_linked_files')}))
    print(json.dumps(dict(local_win64_membership={k:len(v) for k,v in membership['matches'].items()})))


if __name__=='__main__': main()
