"""Audit exported fingerprints only; never loads a PE or selects a detector threshold."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import ppdeep
import tlsh


def audit(state,manifest,downloads,prior,label_rows):
    candidates={row['sha256']:row for row in manifest}
    rows={row['sha256']:row for row in state['files']}
    if state.get('detector_evaluation_performed') is not False or not rows.keys()<=candidates.keys():
        raise ValueError('blind_cohort_identity')
    if any(row.get('report') is not None or row.get('detector_results_observed') is True for row in rows.values()):
        raise ValueError('detector_results_already_observed')
    acquired={sha:row for sha,row in rows.items() if row.get('status')=='acquired'}
    fetched={row['sha256']:row for row in downloads['files']}
    mismatches=[]
    for sha,row in acquired.items():
        if not row.get('raw_sha_verified'):
            raise ValueError('raw_sha_unverified')
        for method in ('tlsh','ssdeep'):
            actual=(row.get('fingerprints') or {}).get(method)
            expected=candidates[sha].get('source_'+method)
            if actual and expected and actual!=expected:
                mismatches.append(dict(sha256=sha,method=method,actual=actual,source_reported=expected))
    current={sha:row['fingerprints'] for sha,row in acquired.items() if row.get('fingerprints')}
    edges=[]
    errors=[]
    values=list(current.items())
    for index,(left,a) in enumerate(values):
        for right,b in [*values[:index],*prior.items()]:
            if left==right:
                continue
            for method,compare,limit in (('tlsh',tlsh.diff,40),('ssdeep',ppdeep.compare,80)):
                if not a.get(method) or not b.get(method):
                    continue
                try:
                    value=compare(a[method],b[method])
                    if (method=='tlsh' and value<=limit) or (method=='ssdeep' and value>=limit):
                        edges.append(dict(a=left,b=right,method=method,value=value))
                except (ValueError,TypeError,AssertionError) as error:
                    errors.append(dict(a=left,b=right,method=method,reason=type(error).__name__))
    parents={sha:sha for sha in {*current,*prior}}
    def root(sha):
        while parents[sha]!=sha:
            parents[sha]=parents[parents[sha]]
            sha=parents[sha]
        return sha
    for edge in edges:
        a,b=root(edge['a']),root(edge['b'])
        parents[max(a,b)]=min(a,b)
    clusters={}
    for sha in parents:
        clusters.setdefault(root(sha),[]).append(sha)
    components=[dict(component_id=key,candidates=sorted(set(members)&current.keys()),
                     previously_observed_peers=sorted(set(members)&prior.keys()))
                for key,members in sorted(clusters.items()) if set(members)&current.keys()]
    return dict(schema=1,identity=state['identity'],manifest_candidates=len(candidates),journal_rows=len(state['files']),
        unique_journal_files=len(rows),status_counts=dict(Counter(r.get('status') for r in rows.values())),
        failure_reasons=dict(Counter(r.get('reason') for r in rows.values() if r.get('status')=='error')),
        download_unattempted=len(candidates.keys()-fetched.keys()),download_status_counts=dict(Counter(r['status'] for r in fetched.values())),
        raw_sha_verified=len(acquired),raw_bytes=sum(r['size_bytes'] for r in acquired.values()),
        strict_valid_pe=sum(r['pe']['strict_pe_valid'] for r in acquired.values()),
        scope_counts=dict(Counter(r['pe'].get('scope') for r in acquired.values())),
        fingerprint_missing=sum(not r.get('fingerprints') for r in acquired.values()),source_fingerprint_mismatches=mismatches,
        near_edges=edges,fingerprint_errors=errors,components=components,tlsh_max_distance=40,ssdeep_min_similarity=80,
        model_scores_observed=0,accuracy_metrics=None,independent_final_eligible=0,labels_changed=False,
        temporal_exclusions=[r['sha256'] for r in label_rows if r.get('temporal_status')=='exclude_current_temporal_holdout'],
        unresolved_gates=['Independent labels','Global first-seen evidence','Full author training and near overlap','Independent benign paired final cohort'],
        caveat='Single-link near screening can overgroup. Fixed screening thresholds, no tuning. Fingerprints missing or unacquired files are unresolved, never declared independent.')


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('acquisition',type=Path)
    parser.add_argument('download',type=Path)
    parser.add_argument('manifest',type=Path)
    parser.add_argument('output',type=Path)
    args=parser.parse_args()
    base=Path('docs/benchmarks')
    prior={}
    for name in ('collection_analysis_20261013.json','benign_windows_static_20261010.json','benign_vendor_static_20261011.json','benign_expansion_static_20261010.json','user_archive_static_20261010.json'):
        for row in json.loads((base/name).read_bytes())['files']:
            scan=row.get('report') or row
            fingerprints=scan.get('engines',{}).get('fuzzy',{}).get('hashes')
            if fingerprints:
                prior[row['sha256']]=fingerprints
    labels=json.loads((base/'collection_label_audit_20261013.json').read_bytes())['files']
    paths=dict(acquisition=args.acquisition,download=args.download,manifest=args.manifest)
    data={name:path.read_bytes() for name,path in paths.items()}
    result=audit(*(json.loads(data[name]) for name in ('acquisition','manifest','download')),prior,labels)
    result['input_sha256']={name:hashlib.sha256(content).hexdigest() for name,content in data.items()}
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({key:result[key] for key in ('raw_sha_verified','strict_valid_pe','status_counts','independent_final_eligible')}))


if __name__=='__main__':
    main()
