"""Read-only frozen release audit plus harmless EICAR detection in the offline guest."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

from aegisav.clamav_engine import ClamAVEngine
from aegisav.ml_engine import MLEngine

assert os.getuid()==1001
isolation=subprocess.check_output(['/usr/local/bin/aegisav-isolation-check'],text=True).strip()
release=Path('/opt/aegisav-product/current').resolve()
raw=(release/'release.json').read_bytes();manifest=json.loads(raw)
assert release.name==hashlib.sha256(raw).hexdigest()[:16]
assert all(hashlib.sha256((release/name).read_bytes()).hexdigest()==digest for name,digest in manifest['files'].items())
assert all(p.stat().st_uid==0 and not p.stat().st_mode&0o222 and not os.access(p,os.W_OK)
           for p in [release,*release.rglob('*')])
assert MLEngine(release/'models/ember2024').probe()
clam=ClamAVEngine();assert clam.probe()
data=b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$'+b'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
assert len(data)==68
report=clam.scan(data);assert report['status']=='matched'
result=dict(schema=1,passed=True,isolation=isolation,release_id=release.name,all_release_digests_valid=True,
            root_owned_nonwritable=True,model_probe=True,eicar_clamav=report,real_malware_used=False)
print(json.dumps(result))
