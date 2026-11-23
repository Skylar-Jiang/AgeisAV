import base64
import binascii
import asyncio
import sqlite3
from typing import Literal
from contextlib import asynccontextmanager
from threading import BoundedSemaphore

from fastapi import FastAPI, HTTPException, Request, Response, Query
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, ConfigDict
from starlette.concurrency import run_in_threadpool

from .scanner import StaticScanner
from .tasks import ScanTasks, IdempotencyConflict, ACTIVE
from .local_access import LocalAccess, COOKIE, SESSION_SECONDS
from .behavior_api import BehaviorAPI


class BatchRequest(BaseModel):
    files: list[str]


class TaskFile(BaseModel):
    name: str = Field(min_length=1,max_length=256)
    content_base64: str


class TaskRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    files: list[TaskFile] = Field(min_length=1,max_length=20)


def create_app(scanner: StaticScanner, max_file_bytes: int = 16 * 1024 * 1024, release_id=None,
               access_token=None, frontend_dir=None, db_path=None, runner=None,
               file_timeout=120, task_timeout=600, behavior_runner=None) -> FastAPI:
    def manager(path=None):
        return ScanTasks(scanner, db_path=path, runner=runner, file_timeout=file_timeout,
                         task_timeout=task_timeout, service_release=release_id)
    tasks=manager()
    behavior=BehaviorAPI(lambda:tasks,runner=behavior_runner)
    uploads=BoundedSemaphore(2)
    @asynccontextmanager
    async def lifespan(app):
        nonlocal tasks
        if db_path is not None:
            tasks.close()
            tasks=manager(db_path)
            try:
                behavior.open(db_path)
            except BaseException:
                tasks.close()
                raise
        app.state.tasks=tasks
        try:
            yield
        finally:
            await run_in_threadpool(tasks.close)
            await run_in_threadpool(behavior.store.close)
    app = FastAPI(title="AegisAV Static Scan API",lifespan=lifespan)
    app.state.tasks=tasks
    app.include_router(behavior.router)

    @app.exception_handler(sqlite3.Error)
    async def database_failure(request, error):
        return JSONResponse(status_code=503,content={'detail':'Task storage unavailable; preserve the database and retry after repair'})

    @app.exception_handler(IdempotencyConflict)
    async def idempotency_conflict(request, error):
        return JSONResponse(status_code=409,content={'detail':str(error)})
    if access_token is not None:
        access = LocalAccess(access_token)
        app.middleware('http')(access.guard)

        @app.post('/v1/session')
        def session_start(request: Request, response: Response):
            if not access.bearer(request):
                raise HTTPException(401, 'Access key required to start a session')
            response.set_cookie(COOKIE, access.session(), httponly=True, samesite='strict',
                                secure=request.url.scheme == 'https', max_age=SESSION_SECONDS)
            return {'authenticated': True, 'expires_in_seconds': SESSION_SECONDS}

        @app.delete('/v1/session')
        def session_end(response: Response):
            response.delete_cookie(COOKIE)
            return {'authenticated': False}

    @app.post('/v1/tasks/{identity}/cancel')
    def task_cancel(identity: str):
        job = tasks.cancel(identity)
        if job is None:
            raise HTTPException(404, 'Task not found')
        return job

    @app.get('/v1/tasks')
    def task_list(limit: int=Query(100,ge=1,le=100), offset: int=Query(0,ge=0,le=1000000), state: Literal['all','active','terminal']='all'):
        return {'tasks':tasks.list(limit,offset,state),'persistent':tasks.persistent,'limit':limit,'offset':offset}

    @app.get('/v1/statistics')
    def task_statistics():
        return tasks.statistics()

    @app.get('/v1/tasks/{identity}')
    def task_detail(identity: str):
        job=tasks.get(identity)
        if job is None:
            raise HTTPException(404,'Task not found')
        return job

    @app.post('/v1/tasks',status_code=202)
    async def submit_task(request: Request):
        if not uploads.acquire(blocking=False):
            raise HTTPException(429,'Upload capacity reached; retry shortly',headers={'Retry-After':'5'})
        try:
            raw=bytearray()
            async for chunk in request.stream():
                if len(raw)+len(chunk)>45*1024**2:
                    raise HTTPException(413,'Task request too large')
                raw.extend(chunk)
            try:
                body=TaskRequest.model_validate_json(raw)
                files=[]
                total=0
                for item in body.files:
                    if len(item.content_base64)>4*((max_file_bytes+2)//3):
                        raise HTTPException(413,'File too large')
                    data=base64.b64decode(item.content_base64,validate=True)
                    total+=len(data)
                    if len(data)>max_file_bytes or total>32*1024**2:
                        raise HTTPException(413,'File or task byte budget exceeded')
                    files.append((item.name,data))
                return tasks.submit(files,idempotency_key=request.headers.get('Idempotency-Key'))
            except (ValueError,binascii.Error) as error:
                raise HTTPException(422,'Invalid task files or base64') from error
            except OverflowError as error:
                raise HTTPException(429,str(error),headers={'Retry-After':'5'}) from error
        finally:
            uploads.release()

    @app.get('/v1/engines')
    def engine_inventory():
        model = getattr(scanner, 'ml_engine', None)
        engines=[]
        for name,engine in [('sha256',getattr(scanner,'database',None)),('fuzzy',getattr(scanner,'database',None)),
                            ('yara_x',getattr(scanner,'yara_engine',None)),('clamav',getattr(scanner,'clamav_engine',None)),('lightgbm',model)]:
            ready=engine is not None
            if ready and hasattr(engine,'probe'):
                try:
                    ready=engine.probe()
                except Exception:
                    ready=False
            engines.append({'id':name,'status':'ready' if ready else 'unavailable',
                            'artifact_version':getattr(scanner,'database_version',None) if name in ('sha256','fuzzy') else getattr(engine,'artifact_version',None),
                            'engine_version':getattr(engine,'engine_version',None)})
        manifest=getattr(model,'manifest',None) or {}
        profile=manifest.get('models',{}).get('general' if getattr(model,'profile',None)=='general' else 'win64',{})
        metadata=getattr(getattr(scanner,'yara_engine',None),'metadata',{})
        return {'service_release': release_id, 'fusion_policy': 'evidence-or-v1','engines':engines,
                'rules':{'count':len(metadata),'entries':[{key:row.get(key) for key in ('rule_id','version','source','scope','confidence')} for row in metadata.values()]},
                'hash_reference_count':len(getattr(getattr(scanner,'database',None),'records',[])),
                'task_limits':{'max_file_bytes':max_file_bytes,'max_files':20,'max_task_bytes':32*1024**2,
                               'max_pending':tasks.max_pending,'max_reserved_bytes':tasks.max_bytes,'workers':1,'persistent':tasks.persistent,
                               'file_timeout_seconds':file_timeout,'task_deadline_seconds':task_timeout,
                               'cancellation':'process_tree' if runner else 'cooperative',
                               'memory_bytes':getattr(runner,'memory_bytes',None),'automatic_resume':False},
                'ml': None if model is None else {
            'artifact_version': model.artifact_version, 'profile': getattr(model, 'profile', 'unknown'),
            'model_version':profile.get('version'),'scope':profile.get('scope'), 'threshold':profile.get('threshold'),
            'models':{name:{key:entry.get(key) for key in ('version','scope','threshold','threshold_source')}
                      for name,entry in manifest.get('models',{}).items()},
            'routing':{'win32':'general','dot_net':'general',
                       'win64':'win64' if getattr(model,'profile',None)=='win64_low_fpr' else 'general',
                       'unsupported':'abstain'},
            'feature_dim':manifest.get('feature_dim'),'feature_implementation':manifest.get('feature_implementation'),
            'assets_valid': model.probe() if hasattr(model, 'probe') else None,
            'runtime_check': 'performed_in_bounded_inference_worker', 'deployment_fpr_guaranteed': False}}

    async def queued_reports(files):
        try:
            job=tasks.submit(files)
        except OverflowError as error:
            raise HTTPException(429,str(error),headers={'Retry-After':'5'}) from error
        while job['status'] in ACTIVE:
            await asyncio.sleep(.05)
            job=tasks.get(job['id'])
        if any(row['status']=='timed_out' for row in job['files']):
            raise HTTPException(504,'Scan process deadline exceeded; no negative result')
        if job['status'] in ('failed','interrupted'):
            raise HTTPException(503,'Scan interrupted; no negative result')
        if any(row['status']!='completed' for row in job['files']):
            raise HTTPException(422,'One or more files could not be scanned; inspect task history')
        return [dict(row['report'],**({'duplicate_of':row['duplicate_of']} if 'duplicate_of' in row else {})) for row in job['files']]

    @app.post("/v1/scan")
    async def scan(request: Request):
        if not uploads.acquire(blocking=False):
            raise HTTPException(429,'Upload capacity reached',headers={'Retry-After':'5'})
        data = bytearray()
        try:
            async for chunk in request.stream():
                if len(data)+len(chunk)>max_file_bytes:
                    raise HTTPException(413,'File too large')
                data.extend(chunk)
        finally:
            uploads.release()
        try:
            if runner:
                return (await queued_reports([('upload.pe',bytes(data))]))[0]
            return await run_in_threadpool(scanner.scan, bytes(data))
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    @app.post("/v1/scan/batch")
    async def scan_batch(request: Request):
        if not uploads.acquire(blocking=False):
            raise HTTPException(429,'Upload capacity reached',headers={'Retry-After':'5'})
        try:
            raw=bytearray()
            async for chunk in request.stream():
                if len(raw)+len(chunk)>45*1024**2:
                    raise HTTPException(413,'Task request too large')
                raw.extend(chunk)
            try:
                body=BatchRequest.model_validate_json(raw)
            except ValueError as error:
                raise HTTPException(422,'Invalid batch request') from error
        finally:
            uploads.release()
        if not 1 <= len(body.files) <= 20:
            raise HTTPException(422, "Batch must contain 1-20 files")
        try:
            if any(len(item)>4*((max_file_bytes+2)//3) for item in body.files):
                raise HTTPException(413, "File too large")
            files = [base64.b64decode(item, validate=True) for item in body.files]
            if any(len(item)>max_file_bytes for item in files) or sum(map(len,files))>32*1024**2:
                raise HTTPException(413,'File or task byte budget exceeded')
            return {"results":await queued_reports([(str(i)+'.pe',data) for i,data in enumerate(files)]) if runner else
                    await run_in_threadpool(scanner.scan_many,files)}
        except binascii.Error as exc:
            raise HTTPException(422, "Invalid base64") from exc
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    if frontend_dir is not None:
        app.mount('/', StaticFiles(directory=frontend_dir, html=True), name='linen')
    return app
