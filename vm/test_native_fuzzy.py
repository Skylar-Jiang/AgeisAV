"""Harmless synthetic equivalence assertions, independent of any malware corpus."""
import hashlib
import json
import os
import resource
import sys
sys.path.insert(0,'/opt/aegisav-collection-v2')
sys.path.insert(0,'/opt/aegisav-product/releases/c699902f19640593/backend')
from native_fuzzy import NativeFuzzy
from aegisav.hashes import compute_fuzzy

assert os.getuid()==1001
resource.setrlimit(resource.RLIMIT_AS,(1024*1024**2,)*2)
resource.setrlimit(resource.RLIMIT_CPU,(60,)*2)
native=NativeFuzzy()
cases=0
for size in (0,1,49,50,51,256,257,4096,65536,1048575,1048576,1048577):
    for data in (b'\0'*size,hashlib.shake_256(str(size).encode()).digest(size)):
        expected=compute_fuzzy(data)
        actual=native.compute(data)
        assert actual==expected,(size,expected,actual)
        cases+=1
print(json.dumps(dict(synthetic_cases=cases,all_hashes_identical=True,raw_malware_used=False)))
