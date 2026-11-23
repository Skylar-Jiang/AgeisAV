"""Bounded replay of failed pilot workers, never changes their recorded outcomes."""
import json
import os
import re
import signal
import sys
sys.path.insert(0,'/opt/aegisav-collection')
from collect_malwarebazaar import ROOT,network,worker

assert os.getuid()==1001
network('offline')
sha=sys.argv[1]
assert re.fullmatch('[0-9a-f]{64}',sha)
state=json.loads((ROOT/'results'/'analysis.json').read_bytes())
assert any(r['sha256']==sha and r['reason']=='static_worker_failed' for r in state['files'])
def expired(*unused):
    raise TimeoutError('diagnostic_deadline')
signal.signal(signal.SIGALRM,expired)
signal.setitimer(signal.ITIMER_REAL,120)
try:
    result=worker(sha)
    print(json.dumps(dict(sha256=sha,replay_status=result['status'],original_result_unchanged=True)))
except Exception as error:
    print(json.dumps(dict(sha256=sha,error_type=type(error).__name__,reason=str(error)[:200],original_result_unchanged=True)))
