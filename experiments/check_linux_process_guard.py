"""Inert Linux process-tree acceptance. Never downloads or parses malware."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time

from aegisav.scan_process import ProcessScanner
from aegisav.tasks import ScanStopped, ScanTasks

root = Path(__file__).resolve().parents[1]
fixture = str(root/'backend/tests/fixtures_scan_worker.py')
checks = []
for mode in ('no_read','hang'):
    runner = ProcessScanner([sys.executable,fixture,mode],memory_bytes=512*1024**2)
    started = time.monotonic()
    try:
        runner.scan(b'x'*1024**2,threading.Event(),started+.7)
        raise AssertionError('deadline was ignored')
    except ScanStopped as error:
        assert error.status == 'timed_out'
    assert time.monotonic()-started < 2
    checks.append(mode+' deadline')
assert ProcessScanner([sys.executable,fixture,'allocate'],memory_bytes=512*1024**2).scan(b'inert',threading.Event(),time.monotonic()+5)['limited']
checks.append('OS address-space limit')

# The stand-in owner starts a supervisor/parser tree. Stop the parser (no Python
# signal handler can run), then kill only the owner and verify the group is dead.
code = '''import os,subprocess,sys,time
env=dict(os.environ,AEGISAV_SCAN_PARENT=str(os.getpid()),AEGISAV_SCAN_MEMORY=str(512*1024**2))
p=subprocess.Popen([sys.executable,'-m','aegisav.scan_supervisor',sys.executable,sys.argv[1],'hang'],stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,env=env,start_new_session=True)
p.stdin.write(b'inert');p.stdin.close()
print(p.pid,flush=True)
time.sleep(60)
'''
owner = subprocess.Popen([sys.executable,'-c',code,fixture],stdout=subprocess.PIPE,text=True)
supervisor = int(owner.stdout.readline())
def group_live():
    rows=[]
    for path in Path('/proc').glob('[0-9]*/stat'):
        try:
            raw=path.read_text().rsplit(')',1)[1].split()
            if int(raw[2])==supervisor and raw[0]!='Z':
                rows.append(int(path.parent.name))
        except (OSError,ValueError,IndexError):
            pass
    return rows
try:
    time.sleep(.5)
    children = [pid for pid in group_live() if pid != supervisor]
    assert len(children)>=2
    for pid in children:
        os.kill(pid,signal.SIGSTOP)
    owner.kill()
    owner.wait(timeout=3)
    for _ in range(40):
        if not group_live():
            break
        time.sleep(.05)
    assert not group_live(), 'stopped parser survived owner death'
    checks.append('service death kills stopped parser and descendant independently')
finally:
    if owner.poll() is None:
        owner.kill();owner.wait()
    try:
        os.killpg(supervisor,signal.SIGKILL)
    except ProcessLookupError:
        pass
    owner.stdout.close()

manager=ScanTasks(None,runner=ProcessScanner([sys.executable,fixture,'hang']),file_timeout=5,task_timeout=.7)
try:
    jobs=[manager.submit([('inert',b'inert')]) for _ in range(2)]
    for _ in range(100):
        actual=[manager.get(job['id']) for job in jobs]
        if all(job['status']=='timed_out' for job in actual):
            break
        time.sleep(.03)
    assert all(job['status']=='timed_out' and job['files'][0]['report'] is None for job in actual)
    assert manager.pending==manager.reserved_bytes==0
    checks.append('whole-task deadline includes queue delay')
finally:
    manager.close()
print(json.dumps({'platform':sys.platform,'non_root':os.geteuid()!=0,'inert_only':True,'checks':checks,'passed':True}))
