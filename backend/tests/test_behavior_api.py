import json
from pathlib import Path
import threading
import time

from fastapi.testclient import TestClient

from aegisav.api import create_app
from aegisav.behavior import analyze
from aegisav.hashes import HashDatabase
from aegisav.scanner import StaticScanner
from aegisav.scan_process import ProcessScanner
from aegisav.tasks import ScanStopped


class InlineFixture:
    def scan(self, data, cancel, deadline):
        return analyze(data)


def app(path=None, runner=None, token=None):
    return create_app(StaticScanner(HashDatabase.from_records([])), db_path=path,
                      access_token=token, behavior_runner=runner or InlineFixture())


def test_auth_import_and_real_restart_with_reports(tmp_path):
    db=tmp_path/'private'/'tasks.db'
    token='harmless-local-test-token-'+'x'*32
    with TestClient(app(db, token=token),base_url='http://127.0.0.1',client=('127.0.0.1',50000)) as client:
        assert client.post('/v1/behavior',content=b'{"events":[]}').status_code==401
        headers={'Authorization':'Bearer '+token}
        response=client.post('/v1/behavior',content=b'{"events":[]}',headers=headers)
        assert response.status_code==201
        result=response.json()
        assert result['status']=='not_observed'
        assert result['persistent'] is True
        assert result['static_link']['status']=='not_linked'
    with TestClient(app(db)) as client:
        assert client.get('/v1/behavior/'+result['id']).json()==result
        assert client.get('/v1/behavior').json()['reports'][0]['id']==result['id']
        assert client.post('/v1/behavior',content=b'not json').status_code==422
        assert client.post('/v1/behavior',content=b' '*(4*1024**2+1)).status_code==413
        assert client.get('/v1/behavior/not-there').status_code==404
    assert b'{"events":[]}' not in db.with_suffix('.behavior.sqlite3').read_bytes()


def test_exact_static_link_is_claimed_hash_only(pe_bytes):
    import base64
    with TestClient(app()) as client:
        task=client.post('/v1/tasks',json={'files':[{'name':'fixture.exe','content_base64':base64.b64encode(pe_bytes).decode()}]}).json()
        for _ in range(100):
            task=client.get('/v1/tasks/'+task['id']).json()
            if task['files'][0]['report']: break
            time.sleep(.02)
        sha=task['files'][0]['report']['sha256']
        url='/v1/behavior?task='+task['id']+'&file=0'
        assert client.post(url,content=b'{"events":[]}').json()['static_link']['status']=='not_linked'
        row=dict(event_id=1,provider='Microsoft-Windows-Sysmon',computer='fixture',timestamp='2026-10-19T00:00:00Z',
                 fields={'ProcessGuid':'{fixture}','Image':'fixture.exe','ProcessId':'3','CommandLine':'harmless','Hashes':'SHA256='+sha})
        report=client.post(url,content=json.dumps({'events':[row]})).json()
        assert report['static_link']['status']=='log_claimed_sha256'
        assert report['static_link']['sha256']==sha
        assert report['static_link']['authenticity_verified'] is False
        assert len(client.get('/v1/behavior?sha256='+sha).json()['reports'])==1
        assert client.post('/v1/behavior?task=absent',content=b'{"events":[]}').status_code==404


def test_backpressure_timeout_no_negative_result():
    started=threading.Event(); release=threading.Event()
    class Slow:
        def scan(self,*args):
            started.set(); release.wait(3)
            raise ScanStopped('timed_out')
    with TestClient(app(runner=Slow())) as client:
        result=[]
        worker=threading.Thread(target=lambda:result.append(client.post('/v1/behavior',content=b'{"events":[]}')))
        worker.start(); assert started.wait(2)
        try:
            assert client.post('/v1/behavior',content=b'{"events":[]}').status_code==429
        finally:
            release.set(); worker.join(3)
        assert result[0].status_code==504
        assert client.get('/v1/behavior').json()['reports']==[]


def test_real_contained_behavior_child_and_timeout():
    import sys
    runner=ProcessScanner([sys.executable,'-m','aegisav.behavior_worker'],memory_bytes=256*1024**2)
    report=runner.scan(b'{"events":[]}',threading.Event(),time.monotonic()+10)
    assert report['status']=='not_observed'
    assert runner.active_pid is None and runner.healthy
    # Run only an inert owned sleep process; OS containment cleanup is shared with static workers.
    sleeper=ProcessScanner([sys.executable,'-c','from aegisav.scan_process import contain_worker;contain_worker();import time;time.sleep(20)'],memory_bytes=256*1024**2)
    try:
        sleeper.scan(b'',threading.Event(),time.monotonic()+.2)
        assert False,'deadline must terminate child'
    except ScanStopped as error:
        assert error.status=='timed_out'
    assert sleeper.active_pid is None and sleeper.healthy


def test_behavior_store_corruption_schema_and_permissions(tmp_path):
    import os
    import sqlite3
    import pytest
    from aegisav.behavior_store import BehaviorStore
    corrupt=tmp_path/'bad.sqlite3'; corrupt.write_bytes(b'inert corrupt database')
    with pytest.raises(sqlite3.DatabaseError): BehaviorStore(corrupt)
    assert corrupt.read_bytes()==b'inert corrupt database'
    future=tmp_path/'future.sqlite3'
    with sqlite3.connect(future) as db: db.execute('PRAGMA user_version=99')
    with pytest.raises(sqlite3.DatabaseError,match='schema'): BehaviorStore(future)
    path=tmp_path/'private'/'behavior.sqlite3'; store=BehaviorStore(path)
    try:
        assert store.db.execute('PRAGMA user_version').fetchone()[0]==1
        assert store.db.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
        assert store.db.execute('PRAGMA journal_mode').fetchone()[0]=='wal'
        if os.name!='nt': assert path.stat().st_mode&0o777==0o600
    finally: store.close()
