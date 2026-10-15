import copy
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import time
from threading import Lock
from uuid import uuid4


class ScanTasks:
    """Single-worker bounded queue. Reports survive in memory, uploaded bytes do not."""
    def __init__(self,scanner,max_pending=4,max_bytes=64*1024**2):
        self.scanner=scanner
        self.max_pending=max_pending
        self.max_bytes=max_bytes
        self.reserved_bytes=0
        self.pending=0
        self.jobs=OrderedDict()
        self.lock=Lock()
        self.executor=ThreadPoolExecutor(max_workers=1,thread_name_prefix='aegisav-task')
        self.closed=False

    def submit(self,files):
        size=sum(len(data) for _,data in files)
        with self.lock:
            if self.closed or self.pending>=self.max_pending or self.reserved_bytes+size>self.max_bytes:
                raise OverflowError('Scan queue is full; retry after current tasks finish')
            identity=uuid4().hex
            job=dict(id=identity,status='queued',created_at=datetime.now(timezone.utc).isoformat(),
                     total=len(files),finished=0,persistent=False,cancel_requested=False,
                     files=[dict(name=name,size_bytes=len(data),status='queued',report=None,error=None) for name,data in files])
            self.jobs[identity]=job
            self.pending+=1
            self.reserved_bytes+=size
            for old in list(self.jobs):
                if len(self.jobs)<=100:
                    break
                if self.jobs[old]['status'] in ('completed','completed_with_errors','cancelled'):
                    del self.jobs[old]
            self.executor.submit(self._run,identity,files,size)
            return copy.deepcopy(job)

    def _run(self,identity,files,size):
        seen={}
        try:
            with self.lock:
                self.jobs[identity]['status']='running'
            for index,(name,data) in enumerate(files):
                with self.lock:
                    if self.jobs[identity]['cancel_requested']:
                        for row in self.jobs[identity]['files'][index:]:
                            row.update(status='cancelled', error='cancelled_before_scan')
                        break
                    self.jobs[identity]['files'][index]['status']='running'
                started = time.perf_counter()
                result=dict(status='completed',report=None,error=None)
                try:
                    digest=hashlib.sha256(data).hexdigest()
                    if digest in seen:
                        previous=seen[digest]
                        with self.lock:
                            result.update(report=copy.deepcopy(self.jobs[identity]['files'][previous]['report']),duplicate_of=previous)
                    else:
                        result['report']=self.scanner.scan(data)
                        seen[digest]=index
                except Exception as error:
                    result.update(status='error',error=str(error)[:200] if isinstance(error,ValueError) else type(error).__name__)
                with self.lock:
                    result['elapsed_ms'] = round((time.perf_counter()-started)*1000, 3)
                    self.jobs[identity]['files'][index].update(result)
                    self.jobs[identity]['finished']+=1
        finally:
            # Update completion and release the reservation under the same lock.
            with self.lock:
                job=self.jobs[identity]
                job['status']=('cancelled' if job['cancel_requested'] else
                               'completed_with_errors' if any(r['status']=='error' for r in job['files']) else 'completed')
                self.pending-=1
                self.reserved_bytes-=size

    def get(self,identity):
        with self.lock:
            return copy.deepcopy(self.jobs.get(identity))

    def cancel(self, identity):
        with self.lock:
            job = self.jobs.get(identity)
            if job is not None and job['status'] in ('queued', 'running', 'cancelling'):
                job['cancel_requested'] = True
                job['status'] = 'cancelling'
            return copy.deepcopy(job)

    def list(self):
        with self.lock:
            return [dict(**{key:job[key] for key in ('id','status','created_at','total','finished','persistent')},
                         files=[dict(name=row['name'],status=row['status'],size_bytes=row['size_bytes'],
                                     verdict=(row['report'] or {}).get('verdict')) for row in job['files']])
                    for job in reversed(self.jobs.values())]

    def close(self):
        with self.lock:
            self.closed=True
        self.executor.shutdown(wait=True)
