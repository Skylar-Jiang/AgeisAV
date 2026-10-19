"""Authenticated offline import; same-origin access guard is owned by create_app."""
import asyncio
from datetime import datetime, timezone
from pathlib import Path
import re
import sys
from threading import BoundedSemaphore, Event
import time
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Query, Request
from starlette.concurrency import run_in_threadpool

from .behavior import MAX_BYTES
from .behavior_store import BehaviorStore
from .scan_process import ProcessScanner
from .tasks import ScanStopped


class BehaviorAPI:
    def __init__(self, tasks, runner=None):
        self.tasks=tasks
        self.store=BehaviorStore()
        self.runner=runner or ProcessScanner([sys.executable,'-m','aegisav.behavior_worker'],memory_bytes=256*1024**2)
        self.gate=BoundedSemaphore(1)
        self.router=APIRouter(prefix='/v1/behavior',tags=['offline behavior'])
        self.router.add_api_route('',self.submit,methods=['POST'],status_code=201)
        self.router.add_api_route('',self.list,methods=['GET'])
        self.router.add_api_route('/{identity}',self.get,methods=['GET'])

    def open(self, task_db):
        self.store.close()
        self.store=BehaviorStore(Path(task_db).with_suffix('.behavior.sqlite3'))

    def list(self, limit:int=Query(50,ge=1,le=100), offset:int=Query(0,ge=0,le=1000000),
             sha256:str|None=Query(None,pattern='^[a-f0-9]{64}$')):
        return dict(reports=self.store.list(limit,offset,sha256),persistent=self.store.path is not None,
                    limit=limit,offset=offset)

    def get(self, identity:str):
        report=self.store.get(identity)
        if report is None: raise HTTPException(404,'Behavior report not found')
        return report

    async def submit(self, request:Request, task:str|None=None, file:int=Query(0,ge=0,le=19)):
        if not self.gate.acquire(blocking=False):
            raise HTTPException(429,'Behavior parser busy; retry shortly',headers={'Retry-After':'5'})
        try:
            target=None
            if task:
                job=self.tasks().get(task)
                if not job or file>=len(job['files']): raise HTTPException(404,'Static file report not found')
                target=job['files'][file]['report']
                if target is None: raise HTTPException(409,'Static report unavailable; no file evidence to link')
            raw=bytearray()
            try:
                async with asyncio.timeout(10):
                    async for chunk in request.stream():
                        if len(raw)+len(chunk)>MAX_BYTES: raise HTTPException(413,'Behavior log exceeds 4 MiB')
                        raw.extend(chunk)
            except TimeoutError as error:
                raise HTTPException(408,'Behavior upload deadline exceeded; no result') from error
            cancel=Event(); started=time.monotonic()
            try:
                report=await run_in_threadpool(self.runner.scan,bytes(raw),cancel,started+20)
            except ScanStopped as error:
                raise HTTPException(504,'Behavior parser deadline exceeded; no result') from error
            except ValueError as error:
                raise HTTPException(422,str(error)) from error
            except RuntimeError as error:
                raise HTTPException(503,'Behavior parser failed; no result') from error
            finally:
                cancel.set()
            link=dict(status='not_linked',reason='No static report selected',authenticity_verified=False)
            if target:
                found=[p['id'] for p in report['processes'] if target['sha256'].lower() in
                       [s.lower() for s in re.findall(r'(?:^|[,;])\s*SHA256=([a-fA-F0-9]{64})(?=$|[,;])',p['hashes'],re.I)]]
                link=(dict(status='log_claimed_sha256',task_id=task,file_index=file,sha256=target['sha256'],
                           process_ids=found,authenticity_verified=False,
                           reason='Exact hash asserted in imported process-create telemetry; log authenticity not verified') if found else
                      dict(status='not_linked',reason='No matching process-create SHA256 in log; image names are not identity',authenticity_verified=False))
            report.update(id=uuid4().hex,created_at=datetime.now(timezone.utc).isoformat(),
                          persistent=self.store.path is not None,static_link=link,elapsed_ms=(time.monotonic()-started)*1000)
            try:
                await run_in_threadpool(self.store.save,report)
            except OverflowError as error:
                raise HTTPException(507,str(error)) from error
            return report
        finally:
            self.gate.release()
