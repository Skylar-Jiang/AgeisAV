"""Small primary-evidence PE intake. Encrypted online; bounded acquisition/scanning offline."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from email.utils import parsedate_to_datetime

CODE=Path(__file__).resolve().parent
SCOPE=Path('/srv/aegisav-corpus/cohorts/analyst-case-20261017-v1')
sys.path.insert(0,'/opt/aegisav-collection')
import collect_malwarebazaar as collection
from collection_boundary import unpack_verified,validate_manifest
sys.path.insert(0,str(CODE))
from label_admission import assess,POLICY_ID
from stage_e_checkpoint import wait_terminal


def retry_deadline(value,now):
    try:
        requested=now+int(value) if str(value).isdigit() else parsedate_to_datetime(value).timestamp()
    except (ValueError,TypeError,OverflowError):
        requested=now+3600
    return max(now+3600,requested)


def seed():
    raw=(CODE/'seed.json').read_bytes()
    rows=json.loads(raw)
    assert len(rows)==2 and len({r['sha256'] for r in rows})==2
    assert all(assess(r)['grade']=='probable' for r in rows)
    return rows,dict(seed_sha256=hashlib.sha256(raw).hexdigest(),policy_id=POLICY_ID,
                     policy_sha256=hashlib.sha256((CODE/'label_admission.py').read_bytes()).hexdigest())


def online(rows,bound):
    assert os.getuid()==1002
    collection.network('online')
    path=SCOPE/'incoming/metadata.json'
    if path.exists():
        state=json.loads(path.read_bytes());assert state['identity']==bound
    else: state=dict(identity=bound,files=[])
    secret=(Path(os.environ['CREDENTIALS_DIRECTORY'])/'auth.key').read_text().strip()
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),collection.NoRedirect())
    for row in rows:
        sha=row['sha256']
        if any(item['sha256']==sha for item in state['files']): continue
        with (collection.BASE/'budget/budget.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            budget_path=collection.BASE/'budget/request-budget.json'
            budget=json.loads(budget_path.read_bytes())
            day=time.strftime('%Y-%m-%d',time.gmtime())
            if budget['day']!=day: budget.update(day=day,count=0)
            if budget['count']>=400: raise RuntimeError('local_request_budget_exhausted')
            remaining=budget.get('not_before',0)-time.time()
            if remaining>60: raise RuntimeError('request_backoff_active')
            if remaining>0: time.sleep(remaining)
            budget.update(count=budget['count']+1,not_before=time.time()+5)
            collection.save(budget_path,budget)
            result=dict(sha256=sha,status='error',reason=None)
            try:
                request=urllib.request.Request('https://mb-api.abuse.ch/api/v1/',
                    data=urllib.parse.urlencode(dict(query='get_info',hash=sha)).encode(),headers={'Auth-Key':secret})
                with opener.open(request,timeout=30) as response: raw=response.read(2*1024**2+1)
                if len(raw)>2*1024**2: raise ValueError('metadata_size_limit')
                metadata=json.loads(raw)
                result['query_status']=metadata.get('query_status')
                if metadata.get('query_status')=='ok':
                    values=metadata['data'];assert len(values)==1 and values[0]['sha256_hash']==sha
                    result.update(status='available',metadata=values[0],response_sha256=hashlib.sha256(raw).hexdigest())
                else: result['reason']='metadata_not_available'
            except urllib.error.HTTPError as error:
                result.update(reason='http_error',http_status=error.code)
                if error.code==429:
                    budget['not_before']=max(retry_deadline(error.headers.get('Retry-After'),time.time()),budget['not_before'])
                    collection.save(budget_path,budget)
            except Exception as error: result['reason']=type(error).__name__
            state['files'].append(result);collection.save(path,state)
            if result.get('http_status')==429: return
    secret=None
    downloads=[]
    for item in state['files']:
        metadata=item.get('metadata',{})
        if item['status']=='available' and metadata.get('file_type') in {'exe','dll'} and 0<metadata.get('file_size',0)<=16*1024**2:
            downloads.append(dict(sha256=item['sha256'],file_size=metadata['file_size'],
                                  source_url='https://bazaar.abuse.ch/sample/'+item['sha256']+'/'))
    if downloads:
        validate_manifest(downloads)
        collection.ROOT=SCOPE
        collection.download(downloads,bound)
    print(json.dumps(dict(metadata_candidates=len(state['files']),available=sum(r['status']=='available' for r in state['files']),download_candidates=len(downloads))))


def acquire_worker(sha):
    from aegisav.scan_process import contain_worker
    contain_worker()
    collection.network('offline')
    rows,bound=seed();assert sha in {r['sha256'] for r in rows}
    sys.path.insert(0,'/opt/aegisav-collection/deps')
    downloads=json.loads((SCOPE/'incoming/download.json').read_bytes());assert downloads['identity']==bound
    record=next(r for r in reversed(downloads['files']) if r['sha256']==sha and r['status']=='downloaded')
    archive=(SCOPE/'incoming'/(sha+'.zip')).read_bytes()
    assert hashlib.sha256(archive).hexdigest()==record['archive_sha256']
    raw=SCOPE/'raw'/(sha+'.bin')
    # Existing scanner's hard RLIMIT_FSIZE is 2 MiB. Larger cases explicitly
    # abstain here; do not silently truncate or weaken the worker boundary.
    size=unpack_verified(archive,sha,raw,2*1024**2)
    from aegisav.pe import validate_pe
    from aegisav.ml_engine import pe_scope
    from aegisav.hashes import compute_fuzzy
    data=raw.read_bytes();validate_pe(data)
    print(json.dumps(dict(report=dict(sha256=sha,integrity_verified=True,strict_pe_valid=True,
        size_bytes=size,pe_scope=pe_scope(data),fingerprints=compute_fuzzy(data)))))


def offline(rows,bound,action):
    assert os.getuid()==1001
    isolation=collection.network('offline')
    from aegisav.scan_process import ProcessScanner
    from aegisav.tasks import ScanTasks
    path=SCOPE/'results'/(action+'.json')
    assert not path.exists(), 'Preserve prior evidence; use a new version for retry'
    metadata=json.loads((SCOPE/'incoming/metadata.json').read_bytes())
    assert metadata['identity']==bound
    downloads=json.loads((SCOPE/'incoming/download.json').read_bytes()) if (SCOPE/'incoming/download.json').exists() else dict(files=[])
    if (SCOPE/'incoming/download.json').exists(): assert downloads['identity']==bound
    result=dict(identity=bound,isolation=isolation,dataset_role='exploratory_primary_case',strict_final_test=False,files=[])
    acquired=json.loads((SCOPE/'results/acquire.json').read_bytes()) if action=='scan' else None
    if acquired: assert acquired['identity']==bound
    manager=ScanTasks(None,db_path=SCOPE/'results/tasks.sqlite3',runner=ProcessScanner()) if action=='scan' else None
    abort=False;acquirer=None
    try:
        for item in rows:
            row=dict(item,status='error',reason=None,report=None)
            sha=item['sha256'];started=time.monotonic()
            try:
                if not any(r['sha256']==sha and r['status']=='downloaded' for r in downloads['files']):
                    raise ValueError('download_not_available')
                if action=='acquire':
                    acquirer=ProcessScanner([sys.executable,__file__,'acquire-worker',sha],memory_bytes=512*1024**2)
                    row['raw']=acquirer.scan(b'inert-control',threading.Event(),time.monotonic()+40)
                    row.update(status='acquired',admission=assess(row))
                else:
                    previous=next(r for r in acquired['files'] if r['sha256']==sha)
                    row['raw']=previous.get('raw');row['admission']=assess(row)
                    if not row['admission']['exploratory_eligible']: raise ValueError('label_not_admitted')
                    data=(SCOPE/'raw'/(sha+'.bin')).read_bytes();assert hashlib.sha256(data).hexdigest()==sha
                    job=manager.submit([('case-'+sha[:8]+'.pe',data)],idempotency_key='primary-case-v1:'+sha)
                    job=wait_terminal(manager,job['id'])
                    row.update(status=job['files'][0]['status'],reason=job['files'][0]['error'],report=job['files'][0]['report'])
                    row['scan_elapsed_ms']=job['files'][0].get('elapsed_ms')
            except TimeoutError:
                row['reason']='terminal_state_unconfirmed';abort=True
            except Exception as error: row['reason']=str(error)[:120] if isinstance(error,ValueError) else type(error).__name__
            row['elapsed_ms']=(time.monotonic()-started)*1000
            result['files'].append(row);collection.save(path,result)
            if abort or (acquirer and not acquirer.healthy) or (manager and not manager.runner.healthy):
                abort=True
                for remaining in rows[len(result['files']):]:
                    result['files'].append(dict(remaining,status='not_attempted',reason='terminal_or_cleanup_unconfirmed',report=None))
                break
    finally:
        if manager: manager.close()
    result['completed']=not abort;collection.save(path,result)
    print(json.dumps(dict(action=action,files=len(result['files']),statuses=[r['status'] for r in result['files']])))


if __name__=='__main__':
    assert sys.platform=='linux'
    action=sys.argv[1]
    if action=='acquire-worker': acquire_worker(sys.argv[2])
    elif action=='online': online(*seed())
    elif action in {'acquire','scan'}: offline(*seed(),action)
    else: raise ValueError('Unknown intake mode')
