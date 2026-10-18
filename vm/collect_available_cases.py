"""Availability-first R6 research intake. Never evaluates a detection engine."""
import fcntl,hashlib,json,os,sys,threading,time,urllib.error,urllib.parse,urllib.request
from pathlib import Path

CODE=Path(__file__).resolve().parent
SCOPE=Path('/srv/aegisav-corpus/cohorts/available-20261018-r6')
sys.path.insert(0,str(CODE))
from availability_sampling import select_available,POLICY_ID
from collect_primary_cases_v2 import collection_dependency,retry_deadline
import collect_malwarebazaar as collection


def identity():
    return dict(policy_id=POLICY_ID,dependency=collection_dependency(),
        sources={name:hashlib.sha256((CODE/name).read_bytes()).hexdigest() for name in
                 ['collect_available_cases.py','availability_sampling.py','acquisition_limits.py',
                  'collect_primary_cases_v2.py','label_admission.py','exclude.json']})


def request_metadata(query):
    with (collection.BASE/'budget/budget.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        path=collection.BASE/'budget/request-budget.json';budget=json.loads(path.read_bytes())
        day=time.strftime('%Y-%m-%d',time.gmtime())
        if budget['day']!=day:budget.update(day=day,count=0)
        if budget['count']>=400:raise RuntimeError('local_request_budget_exhausted')
        delay=budget.get('not_before',0)-time.time()
        if delay>60:raise RuntimeError('request_backoff_active')
        if delay>0:time.sleep(delay)
        budget.update(count=budget['count']+1,not_before=time.time()+5);collection.save(path,budget)
        secret=(Path(os.environ['CREDENTIALS_DIRECTORY'])/'auth.key').read_text().strip()
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),collection.NoRedirect())
        request=urllib.request.Request('https://mb-api.abuse.ch/api/v1/',
            data=urllib.parse.urlencode(query).encode(),headers={'Auth-Key':secret})
        try:
            with opener.open(request,timeout=30) as response:raw=response.read(8*1024**2+1)
        except urllib.error.HTTPError as error:
            if error.code==429:
                budget['not_before']=retry_deadline(error.headers.get('Retry-After'),time.time());collection.save(path,budget)
            raise RuntimeError('metadata_http_'+str(error.code)) from None
        finally:secret=None
        if len(raw)>8*1024**2:raise ValueError('metadata_response_boundary')
        value=json.loads(raw)
        return dict(query=query,query_status=value.get('query_status'),response_sha256=hashlib.sha256(raw).hexdigest(),
                    rows=value.get('data',[]) if value.get('query_status')=='ok' else [])


def discover():
    assert os.getuid()==1002 and os.geteuid()==1002
    collection.network('online');bound=identity();path=SCOPE/'incoming/discovery.json'
    state=json.loads(path.read_bytes()) if path.exists() else dict(identity=bound,queries=[])
    assert state['identity']==bound
    queries=[dict(query='get_file_type',file_type='exe',limit=1000),dict(query='get_file_type',file_type='dll',limit=500)]
    for query in queries:
        if not any(r['query']==query for r in state['queries']):
            state['queries'].append(request_metadata(query));collection.save(path,state)
    rows=[r for q in state['queries'] for r in q['rows']]
    selection=select_available(rows,set(json.loads((CODE/'exclude.json').read_bytes())))
    if not selection['selected']:raise RuntimeError('no_eligible_candidates')
    selected=dict(identity=bound,discovery_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),**selection)
    selection_path=SCOPE/'incoming/selection.json'
    if selection_path.exists():assert json.loads(selection_path.read_bytes())==selected
    else:collection.save(selection_path,selected)
    print(json.dumps(dict(queries=len(state['queries']),metadata_rows=len(rows),selected=len(selected['selected']),
        family_proxies=selection['selected_family_proxies'],detector_results_observed=False)))


def download():
    assert os.getuid()==1002 and os.geteuid()==1002
    state=json.loads((SCOPE/'incoming/selection.json').read_bytes());assert state['identity']==identity()
    from collection_boundary import validate_manifest
    validate_manifest(state['selected']);collection.ROOT=SCOPE
    collection.download(state['selected'],dict(**identity(),selection_sha256=hashlib.sha256((SCOPE/'incoming/selection.json').read_bytes()).hexdigest()))


def frozen():
    path=SCOPE/'freeze/intake.json'
    for controlled in [path,*path.parents]:
        if controlled.is_symlink() or controlled.stat().st_uid!=0 or controlled.stat().st_mode&0o022:
            raise RuntimeError('intake_freeze_not_root_controlled')
    raw=path.read_bytes();state=json.loads(raw);assert state['identity']==identity()
    return state,hashlib.sha256(raw).hexdigest()


def worker(sha):
    from acquisition_limits import contain_acquisition_worker,MAX_ACQUIRED_PE
    contain_acquisition_worker();collection.network('offline')
    state,digest=frozen();item=next(r for r in state['selected'] if r['sha256']==sha)
    downloads=json.loads((SCOPE/'incoming/download.json').read_bytes())
    assert downloads['identity']==dict(**identity(),selection_sha256=digest)
    previous=next(r for r in reversed(downloads['files']) if r['sha256']==sha and r['status']=='downloaded')
    content=(SCOPE/'incoming'/(sha+'.zip')).read_bytes()
    assert hashlib.sha256(content).hexdigest()==previous['archive_sha256']
    sys.path.insert(0,'/opt/aegisav-collection/deps')
    from collection_boundary import unpack_verified
    raw=SCOPE/'raw'/(sha+'.bin');size=unpack_verified(content,sha,raw,MAX_ACQUIRED_PE)
    if size!=item['file_size']:raise ValueError('metadata_raw_size_mismatch')
    from aegisav.pe import validate_pe
    from aegisav.ml_engine import pe_scope
    from aegisav.hashes import compute_fuzzy
    import pefile
    data=raw.read_bytes();validate_pe(data)
    with pefile.PE(data=data,fast_load=True) as pe:
        info=dict(machine=pe.FILE_HEADER.Machine,sections=pe.FILE_HEADER.NumberOfSections,
                  coff_timestamp_untrusted=pe.FILE_HEADER.TimeDateStamp,is_dll=bool(pe.FILE_HEADER.Characteristics&0x2000))
    print(json.dumps(dict(report=dict(sha256=sha,integrity_verified=True,strict_pe_valid=True,size_bytes=size,
        pe_scope=pe_scope(data),fingerprints=compute_fuzzy(data),pe=info,detector_results_observed=False))))


def acquire():
    assert os.getuid()==1001 and os.geteuid()==1001
    isolation=collection.network('offline');state,digest=frozen();path=SCOPE/'results/acquire.json'
    result=json.loads(path.read_bytes()) if path.exists() else dict(identity=identity(),freeze_sha256=digest,
        isolation=isolation,files=[],completed=False,detector_results_observed=False,label='proxy_malicious_unreviewed')
    assert result['identity']==identity() and result['freeze_sha256']==digest
    from aegisav.scan_process import ProcessScanner
    downloads=json.loads((SCOPE/'incoming/download.json').read_bytes())
    assert downloads['identity']==dict(**identity(),selection_sha256=digest)
    for item in state['selected']:
        sha=item['sha256']
        if any(r['sha256']==sha for r in result['files']):continue
        row=dict(item,status='error',reason=None);start=time.monotonic();runner=None
        try:
            if not any(r['sha256']==sha and r['status']=='downloaded' for r in downloads['files']):raise ValueError('download_unavailable')
            runner=ProcessScanner([sys.executable,__file__,'worker',sha],memory_bytes=512*1024**2)
            row.update(raw=runner.scan(b'inert-control',threading.Event(),time.monotonic()+40),status='acquired')
        except Exception as error:
            row['reason']=str(error)[:100] if isinstance(error,ValueError) else type(error).__name__
        row['elapsed_ms']=(time.monotonic()-start)*1000
        result['files'].append(row);collection.save(path,result)
        if runner and not runner.healthy:raise RuntimeError('cleanup_unconfirmed_stop_batch')
    result['completed']=True;collection.save(path,result)
    print(json.dumps(dict(files=len(result['files']),acquired=sum(r['status']=='acquired' for r in result['files']),
        observed=False,formal_eligible=0)))


if __name__=='__main__':
    assert sys.platform=='linux'
    action=sys.argv[1]
    if action=='worker':worker(sys.argv[2])
    elif action=='discover':discover()
    elif action=='download':download()
    elif action=='acquire':acquire()
    else:raise ValueError('Unknown mode')
