import base64
import threading
import time
from fastapi.testclient import TestClient
from aegisav.api import create_app
from aegisav.tasks import ScanTasks


def wait(client,identity):
    for _ in range(100):
        job=client.get('/v1/tasks/'+identity).json()
        if job['status'] in ('completed','completed_with_errors'):
            return job
        time.sleep(.01)
    raise AssertionError('task did not finish')


def test_task_keeps_file_failures_duplicates_and_engine_abstentions(pe_bytes):
    calls=[]
    class Scanner:
        def scan(self,data):
            calls.append(data)
            if data==b'not PE':
                raise ValueError('Invalid PE')
            return dict(sha256='a'*64,verdict='undetermined',engines={'lightgbm':{'status':'unavailable'}})
    with TestClient(create_app(Scanner())) as client:
        files=[dict(name=name,content_base64=base64.b64encode(data).decode()) for name,data in
               [('valid.exe',pe_bytes),('invalid.exe',b'not PE'),('duplicate.exe',pe_bytes)]]
        response=client.post('/v1/tasks',json={'files':files})
        assert response.status_code==202
        job=wait(client,response.json()['id'])
        assert job['status']=='completed_with_errors' and job['finished']==3
        assert job['files'][1]['status']=='error' and job['files'][1]['report'] is None
        assert job['files'][2]['duplicate_of']==0 and len(calls)==2
        assert job['files'][0]['report']['engines']['lightgbm']['status']=='unavailable'
        assert client.get('/v1/tasks').json()['tasks'][0]['id']==job['id']
        assert client.get('/v1/tasks/'+'0'*32).status_code==404


def test_bounded_task_queue_rejects_overflow_and_releases_byte_reservations():
    started=threading.Event()
    release=threading.Event()
    class Scanner:
        def scan(self,data):
            started.set()
            assert release.wait(2)
            return {'verdict':'undetermined'}
    manager=ScanTasks(Scanner(),max_pending=1,max_bytes=10)
    try:
        identity=manager.submit([('a',b'123')])['id']
        assert started.wait(1)
        try:
            manager.submit([('b',b'123')])
        except OverflowError:
            pass
        else:
            raise AssertionError('queue overflow accepted')
        release.set()
        for _ in range(100):
            if manager.get(identity)['status']=='completed':
                break
            time.sleep(.01)
        assert manager.reserved_bytes==0
        try:
            manager.submit([('c',b'x'*11)])
        except OverflowError:
            pass
        else:
            raise AssertionError('byte overflow accepted')
    finally:
        release.set()
        manager.close()


def test_task_validation_occurs_before_enqueue_and_rejects_bad_base64(pe_bytes):
    class Forbidden:
        def scan(self,data):
            raise AssertionError('invalid request reached scanner')
    with TestClient(create_app(Forbidden(),max_file_bytes=100)) as client:
        assert client.post('/v1/tasks',json={'files':[]}).status_code==422
        assert client.post('/v1/tasks',json={'files':[{'name':'x','content_base64':'?'}]}).status_code==422
        assert client.post('/v1/tasks',json={'files':[{'name':'x','content_base64':'é'}]}).status_code==422
        encoded=base64.b64encode(pe_bytes).decode()
        assert client.post('/v1/tasks',json={'files':[{'name':'x','content_base64':encoded}]}).status_code==413


def test_concurrent_upload_budget_rejects_third_body_before_reading_it():
    import asyncio
    import httpx
    class Scanner:
        def scan(self,data):
            return {'verdict':'undetermined'}
    async def run():
        app=create_app(Scanner())
        async with app.router.lifespan_context(app):
            transport=httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport,base_url='http://test') as client:
                ready=asyncio.Event()
                release=asyncio.Event()
                started=0
                async def body():
                    nonlocal started
                    yield b'{'
                    started+=1
                    if started==2:
                        ready.set()
                    await release.wait()
                    yield b'"files":[{"name":"a","content_base64":"YQ=="}]}'
                requests=[asyncio.create_task(client.post('/v1/tasks',content=body())) for _ in range(2)]
                try:
                    await asyncio.wait_for(ready.wait(),1)
                    third=await client.post('/v1/tasks',content=b'never read')
                    assert third.status_code==429
                finally:
                    release.set()
                    responses=await asyncio.gather(*requests)
                assert all(r.status_code==202 for r in responses)
    asyncio.run(run())


def test_cancel_preserves_running_result_and_skips_remaining_files():
    started, release = threading.Event(), threading.Event()
    calls = []
    class Scanner:
        def scan(self, data):
            calls.append(data)
            started.set()
            assert release.wait(3)
            return {'verdict': 'undetermined', 'engines': {'clamav': {'status': 'unavailable'}}}
    with TestClient(create_app(Scanner())) as client:
        job = client.post('/v1/tasks', json={'files': [
            {'name': str(i)+'.exe', 'content_base64': base64.b64encode(bytes([i])).decode()}
            for i in range(3)]}).json()
        try:
            assert started.wait(1)
            response = client.post('/v1/tasks/'+job['id']+'/cancel')
            assert response.status_code == 200
            assert response.json()['status'] == 'cancelling'
            assert client.post('/v1/tasks/'+job['id']+'/cancel').status_code == 200
        finally:
            release.set()
        for _ in range(100):
            result = client.get('/v1/tasks/'+job['id']).json()
            if result['status'] == 'cancelled':
                break
            time.sleep(.01)
        assert result['status'] == 'cancelled' and result['finished'] == 1
        assert result['files'][0]['report']['engines']['clamav']['status'] == 'unavailable'
        assert result['files'][0]['elapsed_ms'] >= 0
        assert all(row['status'] == 'cancelled' and row['report'] is None for row in result['files'][1:])
        assert len(calls) == 1
        assert client.post('/v1/tasks/not-found/cancel').status_code == 404
