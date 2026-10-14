"""Offline real HTTP proof on the first three pre-existing pilot candidates."""
import hashlib
import http.client
import json
import os
import resource
import signal
import sys
import time
sys.path.insert(0,'/opt/aegisav-collection')
from collect_malwarebazaar import ROOT,RELEASE,network,identity,save

assert os.getuid()==1001
isolation=network('offline')
resource.setrlimit(resource.RLIMIT_AS,(512*1024**2,)*2)
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
def expired(*unused):
    raise TimeoutError('api_proof_deadline')
signal.signal(signal.SIGALRM,expired)
signal.setitimer(signal.ITIMER_REAL,180)
rows,bound=identity()
baseline={r['sha256']:r for r in json.loads((ROOT/'results/analysis.json').read_bytes())['files']}
results=[]
connection=http.client.HTTPConnection('127.0.0.1',8000,timeout=120)
connection.request('GET','/v1/engines')
response=connection.getresponse()
assert response.status==200
inventory=json.loads(response.read(16385))
assert inventory['service_release']==hashlib.sha256((RELEASE/'release.json').read_bytes()).hexdigest()[:16]
assert inventory['ml']['assets_valid'] is True
for item in rows[:3]:
    sha=item['sha256']
    original=baseline[sha]['report']
    data=(ROOT/'raw'/(sha+'.bin')).read_bytes()
    assert len(data)<=16*1024**2 and hashlib.sha256(data).hexdigest()==sha
    for pass_id in ('cold','hot'):
        started=time.monotonic()
        connection.request('POST','/v1/scan',body=data,headers={'Content-Type':'application/octet-stream'})
        response=connection.getresponse()
        assert response.status==200
        report=json.loads(response.read(2*1024**2+1))
        assert report['sha256']==sha and report['cached'] is (pass_id=='hot')
        assert set(report['engines'])==set(original['engines'])
        for name,engine in original['engines'].items():
            actual=report['engines'][name]
            for key in ('status','risk_signal','artifact_version','engine_version'):
                assert actual[key]==engine[key],(name,key)
        for key in ('score','threshold','feature_sha256','model_id','model_version'):
            assert report['engines']['lightgbm'][key]==original['engines']['lightgbm'][key],key
        results.append(dict(sha256=sha,pass_id=pass_id,elapsed_ms=(time.monotonic()-started)*1000,report=report))
connection.close()
save(ROOT/'results/api-proof.json',dict(schema=1,isolation=isolation,identity=bound,inventory=inventory,
    strict_final_test=False,source='first_three_pilot_candidates',results=results,all_assertions_passed=True))
print('REAL_HTTP_PILOT_API PASS 3 cold + 3 hot; exact feature/score/version/status parity')
