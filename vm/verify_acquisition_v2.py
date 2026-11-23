"""Harmless Linux fixtures for acquisition-v2; never imports or executes a PE."""
import hashlib,io,json,os,subprocess,sys,threading,time
from pathlib import Path


def worker(mode,work):
    if mode=='old_writer':
        from aegisav.scan_process import contain_worker
        contain_worker()
    else:
        from acquisition_limits import contain_acquisition_worker
        contain_acquisition_worker()
    work=Path(work)
    if mode=='timeout':
        child=subprocess.Popen(['/usr/bin/sleep','30']);(work/'child.pid').write_text(str(child.pid));time.sleep(30)
    if mode=='crash':
        (work/'recover.partial').write_bytes(b'inert-partial');os._exit(7)
    if mode=='memory':
        try:bytearray(1024**3)
        except MemoryError:return dict(status='memory_rejected')
        raise AssertionError('memory_limit_failed')
    if mode in {'old_writer','write_exhaust'}:
        path=work/(mode+'.partial')
        try:
            with path.open('wb') as f:
                for _ in range(17 if mode=='write_exhaust' else 3):f.write(b'x'*1024**2);f.flush()
        except OSError as error:return dict(status='write_rejected',errno=error.errno,bytes=path.stat().st_size)
        raise AssertionError('writer_cap_failed')
    sys.path.insert(0,'/opt/aegisav-collection/deps')
    sys.path.insert(0,'/opt/aegisav-collection-v2')
    import pyzipper
    from collection_boundary import unpack_verified
    size=16*1024**2 if mode=='at_limit' else 16*1024**2+1 if mode=='oversize' else 3*1024**2 if mode=='large' else 1024
    data=(b'inert-fixture-'*((size+13)//14))[:size]
    archive=io.BytesIO()
    with pyzipper.AESZipFile(archive,'w',compression=pyzipper.ZIP_DEFLATED,encryption=pyzipper.WZ_AES) as z:
        z.setpassword(b'wrong' if mode=='password' else b'infected')
        z.writestr('../escape' if mode=='path' else 'inert.bin',data)
        if mode=='extra':z.writestr('second',b'harmless')
    content=archive.getvalue()
    if mode=='truncated':content=content[:-9]
    digest='0'*64 if mode=='sha' else hashlib.sha256(data).hexdigest()
    destination=work/('recover.bin' if mode=='recover' else mode+'.bin')
    try:
        count=unpack_verified(content,digest,destination,16*1024**2)
        if mode=='resume':assert unpack_verified(content,digest,destination,16*1024**2)==count
        assert hashlib.sha256(destination.read_bytes()).hexdigest()==digest
        return dict(status='acquired',bytes=count,partial=destination.with_suffix('.partial').exists())
    except Exception as error:
        return dict(status='rejected',exception=type(error).__name__,committed=destination.exists(),partial=destination.with_suffix('.partial').exists())


def main():
    if sys.argv[1]=='worker':
        print(json.dumps(dict(report=worker(sys.argv[2],sys.argv[3]))));return
    assert os.getuid()==1001
    from aegisav.scan_process import ProcessScanner
    from stage_e_checkpoint import persist
    subprocess.run(['/usr/local/bin/aegisav-isolation-check'],check=True)
    work=Path(sys.argv[1]);output=work/'fixtures.json';assert not output.exists()
    results=[]
    modes=['old_writer','large','at_limit','oversize','truncated','sha','password','path','extra','resume','memory','write_exhaust','crash','recover','timeout']
    for mode in modes:
        runner=ProcessScanner([sys.executable,__file__,'worker',mode,str(work)],memory_bytes=512*1024**2)
        try:actual=runner.scan(b'inert-control',threading.Event(),time.monotonic()+(.7 if mode=='timeout' else 25))
        except Exception as error:actual=dict(status='process_stopped',exception=type(error).__name__)
        if mode in {'large','at_limit','resume','recover'}:passed=actual['status']=='acquired' and not actual['partial']
        elif mode=='memory':passed=actual['status']=='memory_rejected'
        elif mode in {'old_writer','write_exhaust'}:passed=actual['status']=='write_rejected' and actual['bytes']<=(2 if mode=='old_writer' else 16)*1024**2
        elif mode=='crash':
            marker=work/'recover.partial';passed=actual['status']=='process_stopped' and runner.healthy and marker.exists() and marker.read_bytes()==b'inert-partial'
        elif mode=='timeout':passed=actual['status']=='process_stopped' and actual.get('exception')=='ScanStopped' and runner.healthy and (work/'child.pid').exists()
        else:passed=actual['status']=='rejected' and not actual['committed'] and not actual['partial']
        if mode=='timeout' and (work/'child.pid').exists():
            time.sleep(.2);present=Path('/proc/'+(work/'child.pid').read_text()).exists();actual['child_survived']=present;passed=passed and not present
        results.append(dict(mode=mode,passed=passed,result=actual,cleanup_confirmed=runner.healthy));persist(output,dict(files=results,completed=False))
        if not passed or not runner.healthy:raise RuntimeError('Acquisition fixture failed: '+mode)
    persist(output,dict(files=results,completed=True));print(json.dumps(dict(fixtures=len(results),passed=sum(x['passed'] for x in results))))


if __name__=='__main__':
    sys.excepthook=sys.__excepthook__
    main()
