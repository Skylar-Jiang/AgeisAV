import base64
import time

from fastapi.testclient import TestClient
from aegisav.api import create_app


class Scanner:
    def scan(self, data):
        return {'verdict':'undetermined','engines':{}}


def test_authenticated_durable_api_replay_conflict_restart_and_limits(tmp_path):
    db = tmp_path/'tasks.sqlite3'
    headers = {'Authorization':'Bearer '+'a'*40, 'Idempotency-Key':'stable-key'}
    body = {'files':[{'name':'a.exe','content_base64':base64.b64encode(b'inert').decode()}]}
    def application():
        return create_app(Scanner(),db_path=db,access_token='a'*40,release_id='frozen')
    with TestClient(application(),base_url='http://127.0.0.1',client=('127.0.0.1',1)) as client:
        assert client.get('/v1/tasks').status_code == 401
        response = client.post('/v1/tasks',json=body,headers=headers)
        assert response.status_code == 202
        identity = response.json()['id']
        for _ in range(100):
            expected = client.get('/v1/tasks/'+identity,headers=headers).json()
            if expected['status']=='completed':
                break
            time.sleep(.01)
        assert expected['status']=='completed' and expected['persistent']
        assert client.post('/v1/tasks',json=body,headers=headers).json()['id']==identity
        changed = {'files':[dict(body['files'][0],name='new-name.exe')]}
        assert client.post('/v1/tasks',json=changed,headers=headers).status_code==409
        assert client.get('/v1/tasks?limit=101',headers=headers).status_code==422
        assert client.post('/v1/tasks',json=dict(body,profile='other'),headers=headers).status_code==422
    with TestClient(application(),base_url='http://127.0.0.1',client=('127.0.0.1',1)) as client:
        assert client.get('/v1/tasks/'+identity,headers=headers).json()==expected
        assert client.post('/v1/tasks',json=body,headers=headers).json()['id']==identity
        assert client.get('/v1/tasks',headers=headers).json()['persistent'] is True
        assert client.get('/v1/engines',headers=headers).json()['task_limits']['automatic_resume'] is False


def test_sqlite_transaction_rolls_back_whole_admission(tmp_path):
    from aegisav.tasks import ScanTasks
    import sqlite3
    import pytest
    manager = ScanTasks(Scanner(),db_path=tmp_path/'tasks.sqlite3')
    connection = manager.store.connection
    connection.execute("CREATE TRIGGER inject BEFORE INSERT ON task_files BEGIN SELECT RAISE(ABORT,'injected'); END")
    with pytest.raises(sqlite3.IntegrityError):
        manager.submit([('a',b'inert')],idempotency_key='transaction')
    assert connection.execute('SELECT count(*) FROM tasks').fetchone()[0]==0
    assert connection.execute('SELECT count(*) FROM task_events').fetchone()[0]==0
    assert manager.pending==manager.reserved_bytes==0
    connection.execute('DROP TRIGGER inject')
    assert manager.submit([('a',b'inert')],idempotency_key='transaction')['status']=='queued'
    manager.close()
