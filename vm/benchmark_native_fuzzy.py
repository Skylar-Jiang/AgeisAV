"""Paired hash microbenchmark on six frozen benign fixtures; no detector changes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import time

CODE=Path('/opt/aegisav-collection-v2')
RELEASE=Path('/opt/aegisav-product/releases/c699902f19640593')
sys.path.insert(0,str(CODE))
sys.path.insert(0,str(RELEASE/'backend'))


def worker(path,method):
    resource.setrlimit(resource.RLIMIT_AS,(1536*1024**2,)*2)
    resource.setrlimit(resource.RLIMIT_CPU,(120,)*2)
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    assert path.is_relative_to('/opt/aegisav-benign') and path.stat().st_size<=128*1024**2
    from aegisav.hashes import compute_fuzzy
    from native_fuzzy import NativeFuzzy
    compute=compute_fuzzy if method=='reference' else NativeFuzzy().compute
    data=path.read_bytes()
    assert hashlib.sha256(data).hexdigest()==path.stem
    cpu=time.process_time()
    wall=time.perf_counter()
    hashes=compute(data)
    return dict(sha256=path.stem,method=method,size_bytes=len(data),hashes=hashes,
                wall_ms=(time.perf_counter()-wall)*1000,cpu_ms=(time.process_time()-cpu)*1000,
                peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)


def main():
    assert os.getuid()==1001
    parser=argparse.ArgumentParser()
    parser.add_argument('--worker',type=Path)
    parser.add_argument('--method',choices=('reference','native'))
    args=parser.parse_args()
    if args.worker:
        print(json.dumps(worker(args.worker,args.method)))
        return
    isolation=subprocess.check_output(['/usr/local/bin/aegisav-isolation-check'],text=True).strip()
    fixture=CODE/'benign-benchmark-baseline.json'
    baseline=json.loads(fixture.read_bytes())
    assert baseline['release_id']==RELEASE.name and baseline['raw_malware_used'] is False
    rows=[]
    failures=[]
    for original in baseline['batches'][0]['files']:
        sha=original['sha256']
        paths=list(Path('/opt/aegisav-benign').glob('*/samples/'+sha+original['type']))
        assert paths
        expected=original['report']['engines']['fuzzy']['hashes']
        for pass_id,method in enumerate(('reference','native','native','reference')):
            try:
                result=subprocess.run([sys.executable,__file__,'--worker',str(paths[0]),'--method',method],
                                      capture_output=True,text=True,timeout=150,check=True)
                row=json.loads(result.stdout)
                row.update(pass_id=pass_id,size_bin=original['size_bin'],type=original['type'])
                assert row['hashes']==expected,'hash_parity'
                rows.append(row)
            except Exception as error:
                failures.append(dict(sha256=sha,pass_id=pass_id,method=method,reason=type(error).__name__))
    result=dict(schema=1,raw_malware_used=False,strict_final_test=False,release_id=RELEASE.name,isolation=isolation,
                fixture_evidence_sha256=hashlib.sha256(fixture.read_bytes()).hexdigest(),
                source_sha256={name:hashlib.sha256((CODE/name).read_bytes()).hexdigest()
                               for name in ('native_fuzzy.py','benchmark_native_fuzzy.py')},
                order='ABBA per fixture; isolated fresh process per measurement',
                timing='hash computation only; file read and module startup excluded; OS cache not flushed',
                product_activated=False,files=rows,failures=failures)
    (Path.home()/'native-fuzzy-benchmark.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(measurements=len(rows),failures=len(failures))))
    assert not failures


if __name__=='__main__':
    main()
