"""Offline shadow study only; frozen win64_low_fpr profile versus saved general reports."""
import contextlib,hashlib,json,os,sys,threading,time
from pathlib import Path

ASSETS=Path('/opt/aegisav-product/current/models/ember2024')
CASE=Path('/srv/aegisav-corpus/cohorts/analyst-case-20261017-v2')
PROFILE='win64_low_fpr'


def worker():
    from aegisav.scan_process import contain_worker
    contain_worker()
    from aegisav.ml_engine import MLEngine
    from aegisav.ml_worker import infer
    data=sys.stdin.buffer.read(16*1024**2+1)
    assert len(data)<=16*1024**2
    registry=MLEngine(ASSETS,profile=PROFILE)
    with open(os.devnull,'w') as sink,contextlib.redirect_stdout(sink),contextlib.redirect_stderr(sink):
        result=infer(ASSETS,PROFILE,registry.artifact_version,data)
    print(json.dumps(dict(report=result),allow_nan=False))


def main():
    assert os.getuid()==1001
    if len(sys.argv)>1 and sys.argv[1]=='worker': worker();return
    import subprocess
    from aegisav.scan_process import ProcessScanner
    from stage_e_checkpoint import persist
    subprocess.run(['/usr/local/bin/aegisav-isolation-check'],check=True)
    output=CASE/'results/frozen-profile-shadow-v1.json'
    assert not output.exists()
    source=Path('/opt/aegisav-benign/official-runtime-20261017')
    benign_path=Path('/var/lib/aegisav-stagee2/official-runtime-v1/scan.json')
    benign=json.loads(benign_path.read_bytes())
    manifest={r['sha256']:r for r in map(json.loads,(source/'manifest.jsonl').read_text().splitlines())}
    cases=json.loads((CASE/'results/scan.json').read_bytes())
    inputs=[]
    for row in cases['files']:
        if row['status']=='completed':
            assert row['admission']['grade']=='high-confidence'
            inputs.append(('malicious_primary_case',row,CASE/'raw'/(row['sha256']+'.bin')))
    for row in benign['files']:
        assert row['status']=='completed'
        inputs.append(('presumed_benign',row,source/manifest[row['sha256']]['path']))
    assert len(inputs)==66
    result=dict(schema=1,profile=PROFILE,production_activated=False,strict_final_test=False,
        registry_sha256=hashlib.sha256((ASSETS/'registry.json').read_bytes()).hexdigest(),
        case_baseline_sha256=hashlib.sha256((CASE/'results/scan.json').read_bytes()).hexdigest(),
        benign_baseline_sha256=hashlib.sha256(benign_path.read_bytes()).hexdigest(),files=[],completed=False)
    start=time.monotonic();aborted=False
    for label,baseline,path in inputs:
        row=dict(sha256=baseline['sha256'],label=label,status='error',reason=None)
        data=path.read_bytes();assert hashlib.sha256(data).hexdigest()==row['sha256']
        runner=ProcessScanner([sys.executable,__file__,'worker'],memory_bytes=1536*1024**2)
        before=time.monotonic()
        try:
            actual=runner.scan(data,threading.Event(),time.monotonic()+60)
            old=baseline['report']['engines']['lightgbm']
            assert actual['status'] in {'matched','no_match'}
            assert actual['feature_sha256']==old['feature_sha256']
            assert actual['feature_schema']==old['feature_schema']
            assert actual['feature_implementation']==old['feature_implementation']
            if actual['model_id']=='general': assert actual['score']==old['score'] and actual['threshold']==old['threshold']
            row.update(status=actual['status'],report=actual,baseline_score=old['score'],baseline_threshold=old['threshold'],baseline_status=old['status'])
        except Exception as error: row['reason']=type(error).__name__
        row['elapsed_ms']=(time.monotonic()-before)*1000
        result['files'].append(row);persist(output,result)
        if not runner.healthy: aborted=True;break
    result['completed']=not aborted and len(result['files'])==len(inputs)
    result['wall_ms']=(time.monotonic()-start)*1000
    relative=next(x.split(':',2)[2] for x in Path('/proc/self/cgroup').read_text().splitlines() if x.startswith('0::'))
    cg=Path('/sys/fs/cgroup')/relative.lstrip('/')
    result['memory_peak_bytes']=int((cg/'memory.peak').read_text())
    result['cpu_stat']=(cg/'cpu.stat').read_text()
    persist(output,result)
    print(json.dumps(dict(files=len(result['files']),completed=result['completed'],matched=sum(r['status']=='matched' for r in result['files']),errors=sum(r['status']=='error' for r in result['files']))))


if __name__=='__main__': main()
