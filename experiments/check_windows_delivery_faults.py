"""Actual packaged runtime/API failure injection; inert bytes, never real malware.

Separate from normal detector acceptance: the fixture deliberately stalls/exits
inside the unchanged ProcessScanner containment. No fixture is included in ZIP.
"""
import argparse
import base64
import ctypes
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

WORKER="""from aegisav.scan_process import contain_worker
contain_worker()
import sys,time,os,subprocess
data=sys.stdin.buffer.read()
if data==b'inert-crash': os._exit(7)
child=subprocess.Popen([sys.executable,'-I','-B','-c','import time;time.sleep(90)'])
time.sleep(90)
"""

SERVER="""import sys,os
from pathlib import Path
from aegisav.api import create_app
from aegisav.desktop import private_root
from aegisav.local_access import load_access_token
from aegisav.runtime import build_scanner
from aegisav.scan_process import ProcessScanner
import uvicorn
profile=private_root(Path(sys.argv[1]),Path(sys.argv[2]))
runner=ProcessScanner([sys.executable,'-I','-B','-c',sys.argv[5]])
app=create_app(build_scanner(),access_token=load_access_token(profile/'access.key'),db_path=profile/'tasks.sqlite3',runner=runner,file_timeout=float(sys.argv[3]))
@app.get('/v1/test/resources')
def resources():
 return dict(pid=os.getpid(),worker=runner.active_pid,pending=app.state.tasks.pending,reserved=app.state.tasks.reserved_bytes,healthy=runner.healthy)
uvicorn.run(app,host='127.0.0.1',port=int(sys.argv[4]),access_log=False,log_level='error',proxy_headers=False)
"""


def alive(pid):
    from ctypes import wintypes as w
    api=ctypes.WinDLL('kernel32',use_last_error=True)
    api.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD];api.OpenProcess.restype=w.HANDLE
    api.WaitForSingleObject.argtypes=[w.HANDLE,w.DWORD];api.WaitForSingleObject.restype=w.DWORD
    api.CloseHandle.argtypes=[w.HANDLE]
    handle=api.OpenProcess(0x100000,False,pid)
    if not handle: return False
    try: return api.WaitForSingleObject(handle,0)==258
    finally: api.CloseHandle(handle)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();package=args.package.resolve();python=package/'runtime/python.exe'
    result=dict(schema=1,actual_packaged_runtime=True,inert_fault_injection_only=True,normal_detection_claim=False,checks=[])
    args.output.mkdir(parents=True,exist_ok=False)
    with tempfile.TemporaryDirectory(prefix='aegisav-delivery-fault-') as temp:
        profile=Path(temp)/'profile';service=None;key=None;port=3427;base=f'http://127.0.0.1:{port}'
        with socket.socket() as probe: probe.bind(('127.0.0.1',port))
        def request(route,method='GET',body=None):
            data=json.dumps(body).encode() if body is not None else None
            call=urllib.request.Request(base+route,data=data,method=method,headers={'Authorization':'Bearer '+key,'Content-Type':'application/json'})
            with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(call,timeout=5) as response: return json.load(response)
        def wait(predicate,timeout=15):
            start=time.monotonic()
            while time.monotonic()-start<timeout:
                value=predicate()
                if value: return value
                time.sleep(.05)
            raise AssertionError('Fixture condition not reached')
        def start(timeout=30):
            nonlocal service,key
            clean={k:v for k,v in os.environ.items() if not k.startswith('AEGISAV_')}
            service=subprocess.Popen([str(python),'-I','-B','-c',SERVER,str(package),str(profile),str(timeout),str(port),WORKER],
                cwd=temp,env=clean,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW)
            def ready():
                nonlocal key
                if service.poll() is not None: raise AssertionError('Owned fixture service exited')
                try:
                    key=(profile/'access.key').read_text().strip()
                    return request('/v1/test/resources')
                except (OSError,ValueError): return False
            started=time.monotonic();wait(ready,45)
            result.setdefault('fixture_startup_ms',[]).append(round((time.monotonic()-started)*1000,3))
        def stop():
            if service and service.poll() is None: service.terminate();service.wait(timeout=10)
        def submit(content=b'inert-hang',identity='fault'):
            return request('/v1/tasks','POST',{'files':[{'name':identity+'.exe','content_base64':base64.b64encode(content).decode()}]})
        def terminal(identity):
            def done():
                job=request('/v1/tasks/'+identity)
                return job if job['status'] not in ('queued','running','cancelling') else False
            return wait(done)
        def empty():
            row=request('/v1/test/resources')
            return row if row['pending']==0 and row['reserved']==0 and row['worker'] is None else False
        try:
            start()
            task=submit();worker=wait(lambda:request('/v1/test/resources')['worker'])
            request('/v1/tasks/'+task['id']+'/cancel','POST')
            cancelled=terminal(task['id']);assert cancelled['status']=='cancelled' and cancelled['files'][0]['report'] is None
            wait(empty);wait(lambda:not alive(worker));result['checks'].append('actual cancellation, owned child exit and reserved resource release')
            crashed=terminal(submit(b'inert-crash')['id']);assert crashed['files'][0]['status']=='error' and crashed['files'][0]['report'] is None
            wait(empty);result['checks'].append('parser exit without report remains error, not negative')
            active=submit();worker=wait(lambda:request('/v1/test/resources')['worker'])
            stop();wait(lambda:not alive(worker));start()
            recovered=request('/v1/tasks/'+active['id']);assert recovered['status']=='interrupted' and recovered['files'][0]['report'] is None
            assert request('/v1/tasks/'+task['id'])==cancelled
            result['checks'].append('actual forced service death, Job cleanup, SQLite interrupted recovery and cancelled report persistence')
            queued=[submit(identity='capacity-'+str(i)) for i in range(4)]
            try: submit(identity='excess')
            except urllib.error.HTTPError as error: assert error.code==429
            else: raise AssertionError('Backpressure missing')
            for item in queued: request('/v1/tasks/'+item['id']+'/cancel','POST')
            for item in queued: assert terminal(item['id'])['status']=='cancelled'
            result['resources_after_cancel']=wait(empty)
            result['checks'].append('actual bounded queue 429 and full reservation release')
            stop();start(.1)
            timed=terminal(submit()['id']);assert timed['files'][0]['status']=='timed_out' and timed['files'][0]['report'] is None
            result['resources_after_timeout']=wait(empty)
            result['checks'].append('actual 100ms injected file deadline, tree termination and no negative report')
        except Exception as error:
            result.update(failed=1,error=str(error))
            (args.output/'failed-check.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
            raise
        finally: stop();key=None
    result['passed']=len(result['checks']);result['failed']=0
    (args.output/'check.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result))


if __name__=='__main__': main()
