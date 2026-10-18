"""Offline exploratory pairing; frozen root allowlist, production scanner, shadow ML."""
import contextlib,hashlib,json,os,sys,threading,time
from pathlib import Path

WORK=Path('/var/lib/aegisav-r7-evaluation-v3')
ASSETS=Path('/opt/aegisav-product/current/models/ember2024')


def freeze():
    p=WORK/'freeze.json'
    for node in [p,*p.parents]:
        if node.is_symlink() or node.stat().st_uid!=0 or node.stat().st_mode&0o022:
            raise RuntimeError('evaluation_freeze_not_root_controlled')
    raw=p.read_bytes();state=json.loads(raw)
    assert state['script_sha256']==hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    assert state['registry_sha256']==hashlib.sha256((ASSETS/'registry.json').read_bytes()).hexdigest()
    assert all(r['dataset_role']=='development' for r in state['files'])
    assert not {r['sha256'] for r in state['files']}&set(state['protected_sha256'])
    assert len({r['sha256'] for r in state['files']})==len(state['files'])
    return state,hashlib.sha256(raw).hexdigest()


def shadow():
    from aegisav.scan_process import contain_worker
    contain_worker();bound,_=freeze()
    data=sys.stdin.buffer.read(16*1024**2+1);assert len(data)<=16*1024**2
    if hashlib.sha256(data).hexdigest() not in {r['sha256'] for r in bound['files']}:
        raise ValueError('input_not_in_frozen_development_cohort')
    from aegisav.ml_engine import MLEngine
    from aegisav.ml_worker import infer
    model=MLEngine(ASSETS,profile='win64_low_fpr');assert model.ready
    with open(os.devnull,'w') as sink,contextlib.redirect_stdout(sink),contextlib.redirect_stderr(sink):
        result=infer(ASSETS,'win64_low_fpr',model.artifact_version,data)
    print(json.dumps(dict(report=result),allow_nan=False))


def main():
    assert os.getuid()==1001
    if len(sys.argv)>1 and sys.argv[1]=='shadow':shadow();return
    from aegisav.scan_process import ProcessScanner
    from aegisav.clamav_engine import ClamAVEngine
    from stage_e_checkpoint import persist
    import subprocess
    isolation=subprocess.check_output(['/usr/local/bin/aegisav-isolation-check'],text=True).strip()
    bound,digest=freeze();clam=ClamAVEngine()
    for _ in range(120):
        if clam.probe() and (clam.engine_version,clam.artifact_version)==('ClamAV 1.5.4','28148'):break
        time.sleep(.5)
    else:raise RuntimeError('frozen_clamd_readiness_failed')
    output=WORK/'results/paired.json'
    state=json.loads(output.read_bytes()) if output.exists() else dict(freeze_sha256=digest,isolation=isolation,
        strict_final_test=False,labels_are_operational=True,files=[],completed=False)
    assert state['freeze_sha256']==digest
    started=time.monotonic()
    for source in bound['files']:
        if any(r['sha256']==source['sha256'] for r in state['files']):continue
        row=dict(source,status='error',reason=None,report=None,shadow=None);before=time.monotonic()
        first=ProcessScanner();second=ProcessScanner([sys.executable,__file__,'shadow'],memory_bytes=1536*1024**2)
        try:
            p=Path(source['path']);resolved=p.resolve()
            assert not p.is_symlink() and any(resolved.is_relative_to(Path(root)) for root in ['/opt/aegisav-benign','/srv/aegisav-corpus/cohorts'])
            assert 0<p.stat().st_size<=16*1024**2
            data=p.read_bytes();assert hashlib.sha256(data).hexdigest()==source['sha256']
            report=first.scan(data,threading.Event(),time.monotonic()+120)
            row['report']=report
            engines=report['engines'];assert set(engines)=={'sha256','fuzzy','yara_x','clamav','lightgbm'}
            expected={'sha256':'279d0104511d2850','fuzzy':'279d0104511d2850','yara_x':'55ccec8463af1166','clamav':'28148',
                'lightgbm':bound['registry_sha256']+':general'}
            assert all(engines[k]['artifact_version']==v for k,v in expected.items())
            routed=second.scan(data,threading.Event(),time.monotonic()+60);row['shadow']=routed
            general=engines['lightgbm']
            if general['status'] in {'matched','no_match'} and routed['status'] in {'matched','no_match'}:
                assert general['feature_sha256']==routed['feature_sha256']
                if routed['model_id']=='general':assert general['score']==routed['score'] and general['threshold']==routed['threshold']
                row['feature_vector_equal']=True
            row['status']='completed'
        except Exception as error:row['reason']=type(error).__name__
        row['elapsed_ms']=(time.monotonic()-before)*1000
        state['files'].append(row);state['wall_ms_this_run']=(time.monotonic()-started)*1000;persist(output,state)
        print(json.dumps(dict(processed=len(state['files']),total=len(bound['files']),status=row['status'])),flush=True)
        if not first.healthy or not second.healthy:raise RuntimeError('cleanup_unconfirmed_stop_batch')
    relative=next(x.split(':',2)[2] for x in Path('/proc/self/cgroup').read_text().splitlines() if x.startswith('0::'))
    cg=Path('/sys/fs/cgroup')/relative.lstrip('/')
    state['resources']=dict(memory_peak_bytes=int((cg/'memory.peak').read_text()),memory_events=(cg/'memory.events').read_text(),cpu_stat=(cg/'cpu.stat').read_text())
    state['completed']=len(state['files'])==len(bound['files']);persist(output,state)


if __name__=='__main__':main()
