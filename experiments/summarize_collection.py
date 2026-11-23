"""Paired diagnostic replay; unknown source labels never become accuracy metrics."""
import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import statistics

from experiments.fusion_replay import policies

ENGINES=('sha256','fuzzy','yara_x','clamav','lightgbm')


def distribution(values):
    values=sorted(values)
    return dict(n=len(values),p50=statistics.median(values) if values else None,
                p95=values[math.ceil(.95*len(values))-1] if values else None)


def summarize(state):
    rows=list({r['sha256']:r for r in state['files']}.values())
    results=dict(schema=1,identity=state['identity'],dataset_role=state.get('dataset_role','development_pilot'),strict_final_test=False,
                 attempts=len(state['files']),files=len(rows),
                 previous_failed_attempts=sum(r['status']=='error' for r in state['files'])-sum(r['status']=='error' for r in rows),
                 status_counts=dict(Counter(r['status'] for r in rows)),
                 accuracy_metrics=None,fixed_low_fpr_recall=None,
                 accuracy_unavailable_reason='Source-reported unknown labels, no independently reviewed paired validation/final cohort',
                 thresholds_changed=False,policy_selection_performed=False,
                 engines={},policies={},costs={})
    decisions=[]
    for row in rows:
        scan=row.get('report') or {}
        vector=[]
        for name in ENGINES:
            engine=scan.get('engines',{}).get(name,{})
            vector.append(bool(engine.get('risk_signal')) if engine.get('status') in ('matched','no_match') else None)
        decisions.append(vector)
    for index,name in enumerate(ENGINES):
        outcomes=[v[index] for v in decisions]
        results['engines'][name]=dict(positive=sum(v is True for v in outcomes),negative=sum(v is False for v in outcomes),
            abstained=sum(v is None for v in outcomes),status_counts=dict(Counter((r.get('report') or {}).get('engines',{}).get(name,{}).get('status','file_not_scanned') for r in rows)))
        results['costs'][name+'_elapsed_ms']=distribution([(r['report']['engines'][name]['elapsed_ms']) for r in rows if r.get('report')])
    replay=[policies(v[:4],v[4]) for v in decisions]
    for name in ('signature_or','ml_only','evidence_or','corroborated'):
        results['policies'][name]=dict(positive=sum(r[name] is True for r in replay),negative=sum(r[name] is False for r in replay),abstained=sum(r[name] is None for r in replay))
    results['costs']['attempt_elapsed_ms']=distribution([r['elapsed_ms'] for r in state['files']])
    results['costs']['scanned_file_elapsed_ms']=distribution([r['elapsed_ms'] for r in rows if r['status']=='scanned'])
    results['costs']['worker_peak_rss_kib']=distribution([r['report']['worker_peak_rss_kib'] for r in rows if r.get('report')])
    results['costs']['worker_cpu_seconds']=distribution([r['report']['worker_cpu_seconds'] for r in rows if r.get('report')])
    results['timing_limitations']='Cache disabled; sequential new workers; includes unpack and startup; RSS excludes descendants/clamd. Use cgroup evidence for aggregate memory. Engine timing intervals overlap.'
    if results['dataset_role']=='development_expansion':
        results['timing_limitations']=results['timing_limitations'].replace('includes unpack and startup','includes startup, excludes unpack')
    results['complementarity']=dict(ml_only_positive=sum(v[4] is True and all(x is False for x in v[:4]) for v in decisions),
        signatures_only_positive=sum(any(x is True for x in v[:4]) and v[4] is False for v in decisions))
    return results


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('input',type=Path)
    parser.add_argument('output',type=Path)
    args=parser.parse_args()
    raw=args.input.read_bytes()
    result=summarize(json.loads(raw))
    result['input_sha256']=hashlib.sha256(raw).hexdigest()
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:result[k] for k in ('files','status_counts','engines','policies')}))


if __name__=='__main__':
    main()
