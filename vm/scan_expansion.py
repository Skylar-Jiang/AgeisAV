"""Offline development diagnostics; immutable plan, bounded per-file workers and checkpoints."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import time

CODE=Path(__file__).resolve().parent
sys.path.insert(0,'/opt/aegisav-collection-v2')
from collect_malwarebazaar import save,network,identity,RELEASE

BASE=Path('/srv/aegisav-corpus/cohorts/76816a606721f48e00f696a5f265409aa72b9d5182672f24f46952075dc4b221')
RESULTS=BASE/'results/development-scan-v1'


def worker(sha):
    resource.setrlimit(resource.RLIMIT_AS,(2560*1024**2,)*2)
    resource.setrlimit(resource.RLIMIT_CPU,(110,)*2)
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    resource.setrlimit(resource.RLIMIT_FSIZE,(2*1024**2,)*2)
    source=BASE/'raw'/(sha+'.bin')
    if source.stat().st_size>64*1024**2:
        return dict(sha256=sha,status='abstained',reason='scanner_64MiB_input_limit',report=None)
    data=source.read_bytes()
    if hashlib.sha256(data).hexdigest()!=sha:
        raise ValueError('raw_sha_changed')
    sys.path.insert(0,str(RELEASE/'backend'))
    from aegisav.scanner import StaticScanner
    from aegisav.hashes import HashDatabase
    from aegisav.yara_engine import load_yara_engine
    from aegisav.clamav_engine import ClamAVEngine
    from aegisav.ml_engine import MLEngine,pe_scope
    scanner=StaticScanner(HashDatabase.from_file(RELEASE/'rules/hashes.json'),
        load_yara_engine(RELEASE/'rules/yara',RELEASE/'rules/yara/metadata.json'),ClamAVEngine(),
        cache_capacity=0,ml_engine=MLEngine(RELEASE/'models/ember2024'))
    report=scanner.scan(data)
    report['pe_scope']=pe_scope(data)
    usage=resource.getrusage(resource.RUSAGE_SELF)
    report.update(worker_peak_rss_kib=usage.ru_maxrss,worker_cpu_seconds=usage.ru_utime+usage.ru_stime)
    return dict(sha256=sha,status='scanned',reason=None,size_bytes=len(data),report=report)


def main():
    assert sys.platform=='linux' and os.getuid()==1001
    isolation=network('offline')
    # The system manager checks key absence before ProtectHome hides the home tree.
    parser=argparse.ArgumentParser()
    parser.add_argument('--worker')
    args=parser.parse_args()
    plan_raw=(CODE/'plan.json').read_bytes()
    plan=json.loads(plan_raw)
    assert plan['dataset_role']=='development_expansion' and plan['strict_final_test'] is False
    candidates={row['sha256']:row for row in plan['files']}
    _,release_identity=identity()
    assert release_identity==plan['acquisition_identity']
    if args.worker:
        assert args.worker in candidates and candidates[args.worker]['acquired']
        try:
            result=worker(args.worker)
        except Exception as error:
            result=dict(sha256=args.worker,status='error',report=None,reason=str(error)[:200] if isinstance(error,ValueError) else type(error).__name__)
        print(json.dumps(result,allow_nan=False))
        return
    bound=dict(plan_sha256=hashlib.sha256(plan_raw).hexdigest(),source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),**release_identity)
    lock=(RESULTS/'scan.lock').open('a')
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    path=RESULTS/'analysis.json'
    state=json.loads(path.read_bytes()) if path.exists() else dict(schema=1,identity=bound,isolation=isolation,
        dataset_role='development_expansion',strict_final_test=False,files=[],completed=False)
    assert state['identity']==bound
    done={row['sha256'] for row in state['files']}
    for sha,item in candidates.items():
        if sha in done:
            continue
        started=time.monotonic()
        row=dict(sha256=sha,label='unknown',label_grade='source_reported_only',status='error',reason=item['reason'],report=None)
        if item['acquired']:
            temporary=RESULTS/(sha+'.worker.tmp')
            with temporary.open('wb') as target:
                process=subprocess.Popen([sys.executable,'-I',__file__,'--worker',sha],stdout=target,stderr=subprocess.DEVNULL,
                    start_new_session=True,env={**os.environ,'OMP_NUM_THREADS':'1','OPENBLAS_NUM_THREADS':'1'})
                try:
                    code=process.wait(timeout=120)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid,signal.SIGKILL)
                    process.wait(timeout=5)
                    code=-signal.SIGKILL
            row['worker_returncode']=code
            if code or temporary.stat().st_size>2*1024**2:
                row['reason']='static_worker_timeout' if code==-signal.SIGKILL else 'static_worker_failed'
            else:
                try:
                    result=json.loads(temporary.read_bytes())
                    report=result.get('report')
                    assert result['sha256']==sha and result['status'] in ('scanned','abstained','error')
                    assert report is None or (report['sha256']==sha and set(report['engines'])=={'sha256','fuzzy','yara_x','clamav','lightgbm'})
                    row.update(result)
                    os.replace(temporary,RESULTS/(sha+'.worker.json'))
                except (ValueError,KeyError,TypeError,AssertionError,OSError) as error:
                    row['reason']='worker_output_invalid:'+type(error).__name__
        row['elapsed_ms']=(time.monotonic()-started)*1000
        state['files'].append(row)
        save(path,state)
    state['completed']=len(state['files'])==len(candidates)
    save(path,state)


if __name__=='__main__':
    main()
