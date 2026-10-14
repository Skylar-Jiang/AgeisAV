import base64
import binascii
from contextlib import asynccontextmanager
from threading import BoundedSemaphore

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from .scanner import StaticScanner
from .tasks import ScanTasks


class BatchRequest(BaseModel):
    files: list[str]


class TaskFile(BaseModel):
    name: str = Field(min_length=1,max_length=256)
    content_base64: str


class TaskRequest(BaseModel):
    files: list[TaskFile] = Field(min_length=1,max_length=20)


def create_app(scanner: StaticScanner, max_file_bytes: int = 16 * 1024 * 1024, release_id=None) -> FastAPI:
    tasks=ScanTasks(scanner)
    uploads=BoundedSemaphore(2)
    @asynccontextmanager
    async def lifespan(app):
        yield
        await run_in_threadpool(tasks.close)
    app = FastAPI(title="AegisAV Static Scan API",lifespan=lifespan)

    @app.get('/v1/tasks')
    def task_list():
        return {'tasks':tasks.list(),'persistent':False}

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
                return tasks.submit(files)
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
        return {'service_release': release_id, 'fusion_policy': 'evidence-or-v1','engines':engines,
                'task_limits':{'max_file_bytes':max_file_bytes,'max_files':20,'max_task_bytes':32*1024**2,
                               'max_pending':tasks.max_pending,'max_reserved_bytes':tasks.max_bytes,'workers':1,'persistent':False},
                'ml': None if model is None else {
            'artifact_version': model.artifact_version, 'profile': getattr(model, 'profile', 'unknown'),
            'assets_valid': model.probe() if hasattr(model, 'probe') else None,
            'runtime_check': 'performed_in_bounded_inference_worker', 'deployment_fpr_guaranteed': False}}

    @app.post("/v1/scan")
    async def scan(request: Request):
        data = bytearray()
        async for chunk in request.stream():
            data.extend(chunk)
            if len(data) > max_file_bytes:
                raise HTTPException(413, "File too large")
        try:
            return await run_in_threadpool(scanner.scan, bytes(data))
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    @app.post("/v1/scan/batch")
    def scan_batch(body: BatchRequest):
        if not 1 <= len(body.files) <= 20:
            raise HTTPException(422, "Batch must contain 1-20 files")
        try:
            files = [base64.b64decode(item, validate=True) for item in body.files]
            if any(len(item) > max_file_bytes for item in files):
                raise HTTPException(413, "File too large")
            return {"results": scanner.scan_many(files)}
        except binascii.Error as exc:
            raise HTTPException(422, "Invalid base64") from exc
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    return app
