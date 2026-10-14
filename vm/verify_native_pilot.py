"""Offline fingerprint equivalence against previously observed pilot results only."""
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
sys.path.insert(0,'/opt/aegisav-collection-v2')
from native_fuzzy import NativeFuzzy

assert os.getuid()==1001
resource.setrlimit(resource.RLIMIT_AS,(512*1024**2,)*2)
resource.setrlimit(resource.RLIMIT_CPU,(60,)*2)
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
isolation=subprocess.check_output(['/usr/local/bin/aegisav-isolation-check'],text=True).strip()
base=Path('/srv/aegisav-corpus')
state=json.loads((base/'results/analysis.json').read_bytes())
native=NativeFuzzy()
rows=[]
for row in {r['sha256']:r for r in state['files']}.values():
    if row['status']!='scanned':
        continue
    data=(base/'raw'/(row['sha256']+'.bin')).read_bytes()
    assert hashlib.sha256(data).hexdigest()==row['sha256']
    actual=native.compute(data)
    expected=row['report']['engines']['fuzzy']['hashes']
    rows.append(dict(sha256=row['sha256'],size_bytes=len(data),full_hashes_identical=actual==expected))
result=dict(schema=1,development_pilot_only=True,strict_final_test=False,isolation=isolation,files=rows,
            product_activated=False,failures=sum(not r['full_hashes_identical'] for r in rows),
            source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
(Path.home()/'native-pilot-parity.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(dict(files=len(rows),failures=result['failures'])))
assert rows and result['failures']==0
