"""Benign-only bounded batch reuse experiment. Never changes the production worker."""
import hashlib
import contextlib
import json
import os
from pathlib import Path
import resource
import sys
import threading
import time

ASSETS=Path('/opt/aegisav-product/current/models/ember2024')


def worker(mode):
    from aegisav.scan_process import contain_worker
    contain_worker()
    resource.setrlimit(resource.RLIMIT_AS,(1536*1024**2,)*2)
    from aegisav.ml_engine import MLEngine
    from aegisav.ml_worker import infer
    registry=MLEngine(ASSETS)
    paths=json.loads(sys.stdin.buffer.read())
    assert 1<=len(paths)<=8
    reports=[]
    for value in paths:
        path=Path(value).resolve()
        assert path.is_relative_to('/opt/aegisav-benign') and path.stat().st_size<=16*1024**2
        data=path.read_bytes();assert hashlib.sha256(data).hexdigest()==path.stem
        if mode=='hang':
            import subprocess
            child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'])
            Path(sys.argv[2]).write_text(json.dumps(dict(worker=os.getpid(),child=child.pid)))
            time.sleep(60)
        started=time.perf_counter()
        with open(os.devnull,'w') as sink,contextlib.redirect_stdout(sink),contextlib.redirect_stderr(sink):
            result=infer(ASSETS,'general',registry.artifact_version,data)
        reports.append(dict(sha256=path.stem,infer_ms=(time.perf_counter()-started)*1000,result=result))
    print(json.dumps(dict(report=dict(files=reports,peak_self_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss))))


def check_stop(selected):
    from aegisav.scan_process import ProcessScanner
    from aegisav.tasks import ScanStopped
    from validate_stage_e_guard import live_group
    checks=[]
    for kind in ('timeout','cancel'):
        ready=Path('/var/lib/aegisav-stagee2/ml-reuse-v3')/(kind+'-ready.json')
        assert not ready.exists()
        runner=ProcessScanner([sys.executable,__file__,'hang',str(ready)])
        event=threading.Event();errors=[]
        def run():
            try: runner.scan(json.dumps(selected).encode(),event,time.monotonic()+(3 if kind=='timeout' else 5))
            except Exception as error: errors.append(error)
        thread=threading.Thread(target=run);thread.start()
        try:
            for _ in range(150):
                if ready.exists():
                    try: marker=json.loads(ready.read_text());break
                    except ValueError: pass
                time.sleep(.01)
            else: raise AssertionError('Batch never reached descendant-ready state')
            group=runner.active_pid
            assert group and marker['worker'] in live_group(group) and marker['child'] in live_group(group)
            if kind=='cancel': event.set()
            thread.join(timeout=5)
            assert not thread.is_alive() and len(errors)==1 and isinstance(errors[0],ScanStopped)
            assert errors[0].status==('timed_out' if kind=='timeout' else 'cancelled')
            assert runner.active_pid is None and runner.healthy and not live_group(group)
        finally:
            event.set();thread.join(timeout=6)
        checks.append(kind+'_after_descendant_ready_group_empty')
    return checks


def main():
    assert os.getuid()==1001
    guard_only=len(sys.argv)>1 and sys.argv[1]=='guard-checks'
    if len(sys.argv)>1 and not guard_only:
        worker(sys.argv[1]);return
    import subprocess
    from aegisav.scan_process import ProcessScanner
    subprocess.run(['/usr/local/bin/aegisav-isolation-check'],check=True,stdout=subprocess.DEVNULL)
    paths=sorted(Path('/opt/aegisav-benign/windows/samples').glob('*'))
    selected=[]
    for scope in ('win32','win64'):
        from aegisav.ml_engine import pe_scope
        for path in paths:
            if path.stat().st_size<1024**2 and pe_scope(path.read_bytes())==scope:
                selected.append(str(path));break
    assert len(selected)==2
    selected=selected*2
    if guard_only:
        result=dict(passed=True,benign_only=True,checks=check_stop(selected))
        output=Path('/var/lib/aegisav-stagee2/ml-reuse-v3/guard.json')
        assert not output.exists();output.write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps(result));return
    batches=[];expected={}
    relative=next(line.split(':',2)[2] for line in Path('/proc/self/cgroup').read_text().splitlines() if line.startswith('0::'))
    cgroup=Path('/sys/fs/cgroup')/relative.lstrip('/')
    for mode in ('fresh','batch','batch','fresh'):
        started=time.perf_counter();reports=[]
        samples=[];stop=threading.Event()
        def sample():
            while not stop.is_set():
                samples.append(int((cgroup/'memory.current').read_text()))
                stop.wait(.01)
        monitor=threading.Thread(target=sample,daemon=True);monitor.start()
        groups=[[path] for path in selected] if mode=='fresh' else [selected]
        worker_peaks=[]
        try:
            for group in groups:
                runner=ProcessScanner([sys.executable,__file__,'compute'])
                before=time.perf_counter()
                actual=runner.scan(json.dumps(group).encode(),threading.Event(),time.monotonic()+40)
                reports.extend(actual['files']);worker_peaks.append(actual['peak_self_rss_kib'])
                if mode=='fresh': actual['files'][0]['boundary_wall_ms']=(time.perf_counter()-before)*1000
        finally:
            stop.set();monitor.join(timeout=1)
        assert samples and not monitor.is_alive()
        for row in reports:
            result=row['result']
            assert result['status'] in ('matched','no_match')
            semantic={key:result[key] for key in ('status','score','threshold','model_id','model_version','feature_sha256','feature_schema','feature_implementation')}
            if row['sha256'] in expected: assert expected[row['sha256']]==semantic
            expected[row['sha256']]=semantic
        batches.append(dict(mode=mode,wall_ms=(time.perf_counter()-started)*1000,files=reports,
                            worker_peak_rss_kib=max(worker_peaks),cgroup_sampled_peak_bytes=max(samples),memory_samples=len(samples)))
    checks=check_stop(selected)
    result=dict(schema=1,benign_only=True,production_activated=False,unique_files=len(expected),
        order='ABBA',cache_mode='result cache disabled; OS cache not flushed',batches=batches,
        checks=checks,feature_and_score_parity=True,
        scope='ML infer path only. Batch retains Python imports, but re-verifies assets and reloads extractor/model per file. Not a live per-file-deadline queue or full-five-engine throughput claim.')
    result['cgroup_kernel_peak_bytes']=int((cgroup/'memory.peak').read_text())
    result['memory_scope']='Whole benchmark cgroup including parent/supervisors/workers and charged page cache; 10ms sampled per batch, kernel peak overall. Separate clamd excluded.'
    output=Path('/var/lib/aegisav-stagee2/ml-reuse-v3/result.json')
    assert not output.exists()
    output.write_text(json.dumps(result,indent=2,allow_nan=False)+'\n')
    print(json.dumps(dict(unique_files=len(expected),wall_ms=[b['wall_ms'] for b in batches],checks=checks)))


if __name__=='__main__': main()
