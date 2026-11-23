import copy
from collections import OrderedDict
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
import json
import time
from threading import Event, Lock
from uuid import uuid4

from .task_store import TaskStore

ACTIVE = ('queued', 'running', 'cancelling')


class IdempotencyConflict(Exception):
    pass


class ScanStopped(Exception):
    def __init__(self, status):
        self.status = status
        super().__init__(status)


def now():
    return datetime.now(timezone.utc).isoformat()


class ScanTasks:
    """One dispatcher. Durable reports never imply recoverable uploaded bytes."""
    def __init__(self, scanner, max_pending=4, max_bytes=64*1024**2, db_path=None,
                 runner=None, file_timeout=120, task_timeout=600, service_release=None):
        self.scanner, self.runner = scanner, runner
        self.max_pending, self.max_bytes = max_pending, max_bytes
        self.file_timeout, self.task_timeout = file_timeout, task_timeout
        self.service_release = service_release
        self.reserved_bytes = self.pending = 0
        self.jobs, self.signals = OrderedDict(), {}
        self.lock = Lock()
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix='aegisav-task')
        self.closed = False
        self.store = TaskStore(db_path) if db_path is not None else None
        if self.store:
            for identity in self.store.ids(active=True):
                job = self.store.get(identity)
                job.update(status='interrupted', error='service_restarted_uploads_not_retained', updated_at=now())
                for row in job['files']:
                    if row['status'] in ACTIVE:
                        row.update(status='interrupted', error='resubmit_required', report=None)
                self.store.save(job)

    @property
    def persistent(self):
        return self.store is not None

    def _save(self, job):
        job['updated_at'] = now()
        if self.store:
            self.store.save(job)

    def _get(self, identity):
        return self.jobs.get(identity) or (self.store.get(identity) if self.store else None)

    def submit(self, files, idempotency_key=None):
        size = sum(len(data) for _, data in files)
        fingerprint = hashlib.sha256(json.dumps({'files':[(name,len(data),hashlib.sha256(data).hexdigest())
                                                          for name,data in files],
                                                 'operation':'static-task-v1'},ensure_ascii=False,separators=(',',':')).encode()).hexdigest()
        if idempotency_key is not None and (not 1 <= len(idempotency_key) <= 128 or
                                            not all(c.isascii() and (c.isalnum() or c in '-_.:') for c in idempotency_key)):
            raise ValueError('Invalid Idempotency-Key')
        with self.lock:
            if self.closed:
                raise OverflowError('Service is shutting down')
            previous = self.store.key(idempotency_key) if self.store and idempotency_key else next(
                (job for job in self.jobs.values() if idempotency_key and job['idempotency_key']==idempotency_key), None)
            if previous:
                if previous['request_fingerprint'] != fingerprint:
                    raise IdempotencyConflict('Idempotency key was already used for different ordered files or names')
                return copy.deepcopy(previous)
            if self.pending >= self.max_pending or self.reserved_bytes+size > self.max_bytes:
                raise OverflowError('Scan queue is full; retry after current tasks finish')
            if self.store:
                self.store.ensure_capacity()
            identity = uuid4().hex
            job = dict(id=identity, status='queued', created_at=now(), updated_at=now(),
                       deadline_at=(datetime.now(timezone.utc)+timedelta(seconds=self.task_timeout)).isoformat(),
                       total=len(files), finished=0, persistent=self.persistent, cancel_requested=False,
                       request_fingerprint=fingerprint,idempotency_key=idempotency_key,
                       service_release=self.service_release,error=None,
                       files=[dict(name=name,size_bytes=len(data),status='queued',report=None,error=None) for name,data in files])
            self._save(job)  # Commit before admission and before a 202 response.
            self.jobs[identity] = job
            self.signals[identity] = Event()
            self.pending += 1
            self.reserved_bytes += size
            self.executor.submit(self._run, identity, files, size, time.monotonic()+self.task_timeout)
            return copy.deepcopy(job)

    def _run(self, identity, files, size, deadline):
        seen = {}
        ending = None
        try:
            with self.lock:
                job = self.jobs[identity]
                if not job['cancel_requested']:
                    job['status'] = 'running'
                    self._save(job)
            for index, (_, data) in enumerate(files):
                with self.lock:
                    if job['cancel_requested'] or self.closed or time.monotonic() >= deadline:
                        stop = 'cancelled' if job['cancel_requested'] else 'interrupted' if self.closed else 'timed_out'
                        for row in job['files'][index:]:
                            row.update(status=stop, error=stop+'_before_scan')
                        ending = stop
                        self._save(job)
                        break
                    job['files'][index]['status'] = 'running'
                    self._save(job)
                started = time.perf_counter()
                result = dict(status='completed', report=None, error=None)
                try:
                    digest = hashlib.sha256(data).hexdigest()
                    if digest in seen:
                        previous = seen[digest]
                        result.update(report=copy.deepcopy(job['files'][previous]['report']),duplicate_of=previous)
                    else:
                        if self.runner:
                            result['report'] = self.runner.scan(data, self.signals[identity],
                                                               min(deadline,time.monotonic()+self.file_timeout))
                        else:
                            result['report'] = self.scanner.scan(data)
                        seen[digest] = index
                except ScanStopped as error:
                    result.update(status=error.status,error='scan_process_'+error.status)
                except Exception as error:
                    result.update(status='error',error=str(error)[:200] if isinstance(error,ValueError) else type(error).__name__)
                    if self.runner and not getattr(self.runner,'healthy',True):
                        self.closed = True
                        ending = 'failed'
                with self.lock:
                    result['elapsed_ms'] = round((time.perf_counter()-started)*1000,3)
                    job['files'][index].update(result)
                    job['finished'] += 1
                    if ending == 'failed':
                        job['error'] = 'process_cleanup_not_confirmed'
                        for row in job['files'][index+1:]:
                            row.update(status='interrupted',error='process_cleanup_not_confirmed',report=None)
                    elif not job['cancel_requested'] and time.monotonic() >= deadline:
                        ending = 'timed_out'
                        for row in job['files'][index+1:]:
                            row.update(status='timed_out',error='timed_out_before_scan',report=None)
                    self._save(job)
                if ending:
                    break
        except Exception:
            # Persistence failures are not successful scans. No new work is admitted.
            with self.lock:
                self.closed = True
                job.update(status='failed',error='task_journal_failure')
                for row in job['files']:
                    if row['status'] in ACTIVE:
                        row.update(status='interrupted',error='journal_failure',report=None)
        finally:
            with self.lock:
                if job['status'] in ACTIVE:
                    job['status'] = ('cancelled' if job['cancel_requested'] else ending if ending else
                                     'completed_with_errors' if any(r['status'] != 'completed' for r in job['files']) else 'completed')
                try:
                    self._save(job)
                except Exception:
                    self.closed = True
                    job.update(status='failed',error='task_journal_failure')
                self.pending -= 1
                self.reserved_bytes -= size
                self.signals.pop(identity, None)
                # Durable history lives on disk; only terminal summaries are bounded in memory.
                for old in list(self.jobs):
                    if self.store and self.jobs[old]['status'] not in ACTIVE and old != identity:
                        del self.jobs[old]
                    elif not self.store and len(self.jobs)>100 and self.jobs[old]['status'] not in ACTIVE:
                        del self.jobs[old]

    def get(self, identity):
        with self.lock:
            return copy.deepcopy(self._get(identity))

    def cancel(self, identity):
        with self.lock:
            job = self._get(identity)
            if job is not None and job['status'] in ACTIVE:
                job.update(cancel_requested=True,status='cancelling')
                self._save(job)  # Acknowledgement follows durable intent.
                self.signals[identity].set()
            return copy.deepcopy(job)

    def list(self, limit=100, offset=0, state='all'):
        with self.lock:
            if self.store:
                return self.store.summaries(limit,offset,state)
            jobs = [job for job in reversed(self.jobs.values()) if state=='all' or
                    (job['status'] in ACTIVE if state=='active' else job['status'] not in ACTIVE)][offset:offset+limit]
            return [dict(**{key:job[key] for key in ('id','status','created_at','total','finished','persistent')},
                         files=[dict(name=row['name'],status=row['status'],size_bytes=row['size_bytes'],
                                     verdict=(row['report'] or {}).get('verdict')) for row in job['files']]) for job in jobs]

    def statistics(self):
        names = ('sha256','fuzzy','yara_x','clamav','lightgbm')
        with self.lock:
            if self.store:
                stats = self.store.statistics()
            else:
                files = [row for job in self.jobs.values() for row in job['files']]
                rows = []
                for row in files[-500:]:
                    report = row['report'] or {}
                    item = dict(status=row['status'],elapsed_ms=row.get('elapsed_ms'),has_report=bool(report),
                                sha256=report.get('sha256'),cached=report.get('cached'))
                    for name in names:
                        engine = report.get('engines',{}).get(name,{})
                        item[name+'_status'], item[name+'_ms'] = engine.get('status'),engine.get('elapsed_ms')
                    rows.append(item)
                stats = dict(task_count=len(self.jobs),file_count=len(files),
                             task_statuses=dict(Counter(job['status'] for job in self.jobs.values())),
                             file_statuses=dict(Counter(row['status'] for row in files)),rows=rows)
            pending, reserved = self.pending,self.reserved_bytes
        rows = stats.pop('rows')
        reports = [row for row in rows if row['has_report']]
        def costs(values):
            values = sorted(value for value in values if isinstance(value,(float,int)) and value>=0)
            return {'n':len(values),'p50_ms':values[(len(values)-1)//2] if values else None,
                    'p95_ms':values[max(0,(95*len(values)+99)//100-1)] if values else None}
        stats.update(persistent=self.persistent,generated_at=now(),pending=pending,reserved_bytes=reserved,
                     accuracy={'available':False,'reason':'No independently labelled frozen evaluation set in task storage'},
                     recent={'limit':500,'files':len(rows),'reports':len(reports),
                             'distinct_report_sha256':len({row['sha256'] for row in reports if row['sha256']}),
                             'cached_reports':sum(bool(row['cached']) for row in reports),
                             'file_wall':costs(row['elapsed_ms'] for row in rows),
                             'engines':{}})
        for name in names:
            statuses = Counter(row[name+'_status'] or 'missing' for row in reports)
            stats['recent']['engines'][name] = {'statuses':dict(statuses),
                'abstentions':sum(count for status,count in statuses.items() if status not in ('matched','no_match')),
                'cost':costs(row[name+'_ms'] for row in reports)}
        return stats

    def close(self):
        with self.lock:
            self.closed = True
            for identity, signal in self.signals.items():
                self.jobs[identity]['cancel_requested'] = True
                signal.set()
                try:
                    self._save(self.jobs[identity])
                except Exception:
                    pass  # Recovery will mark the last durable active state interrupted.
        try:
            self.executor.shutdown(wait=True)
        finally:
            if self.store:
                self.store.close()
