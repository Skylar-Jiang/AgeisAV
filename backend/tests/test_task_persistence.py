import sqlite3
import threading
import time

import pytest

from aegisav.tasks import ScanTasks, IdempotencyConflict


class Scanner:
    def scan(self, data):
        if data == b'bad':
            raise ValueError('invalid fixture')
        return {'verdict': 'undetermined', 'engines': {'sha256': {'artifact_version': 'frozen'}}}


def completed(manager, identity):
    for _ in range(300):
        job = manager.get(identity)
        if job['status'] not in ('queued', 'running', 'cancelling'):
            return job
        time.sleep(.01)
    raise AssertionError('task did not terminate')


def test_reports_errors_idempotency_and_semantics_survive_restart(tmp_path):
    path = tmp_path/'tasks.sqlite3'
    first = ScanTasks(Scanner(), db_path=path)
    job = first.submit([('a.exe', b'a'), ('bad.exe', b'bad')], idempotency_key='retry-1')
    expected = completed(first, job['id'])
    first.close()
    second = ScanTasks(Scanner(), db_path=path)
    try:
        assert second.get(job['id']) == expected
        assert second.submit([('a.exe', b'a'), ('bad.exe', b'bad')], idempotency_key='retry-1')['id'] == job['id']
        with pytest.raises(IdempotencyConflict):
            second.submit([('renamed.exe', b'a')], idempotency_key='retry-1')
        assert second.submit([('a.exe', b'a')], idempotency_key='new-intent')['id'] != job['id']
    finally:
        second.close()
    connection = sqlite3.connect(path)
    assert connection.execute('pragma integrity_check').fetchone()[0] == 'ok'
    assert connection.execute('pragma user_version').fetchone()[0] == 1
    assert connection.execute('select count(*) from task_files').fetchone()[0] == 3
    assert b'content_base64' not in path.read_bytes()
    connection.close()


def test_recover_only_unfinished_files_and_do_not_resume_bytes(tmp_path):
    from aegisav.task_store import TaskStore
    path = tmp_path/'tasks.sqlite3'
    store = TaskStore(path)
    job = dict(id='a'*32, status='running', created_at='2026-10-16T00:00:00+00:00',
               updated_at='2026-10-16T00:00:01+00:00', total=2, finished=1, persistent=True,
               cancel_requested=False, request_fingerprint='f', idempotency_key='k',
               deadline_at='2026-10-16T00:10:00+00:00', service_release='frozen', error=None,
               files=[dict(name='done', size_bytes=1, status='completed', report={'verdict':'undetermined'}, error=None),
                      dict(name='lost', size_bytes=1, status='running', report=None, error=None)])
    store.save(job)
    store.close()
    manager = ScanTasks(Scanner(), db_path=path)
    try:
        recovered = manager.get(job['id'])
        assert recovered['status'] == 'interrupted'
        assert recovered['files'][0]['report'] == job['files'][0]['report']
        assert recovered['files'][1]['status'] == 'interrupted'
        assert recovered['files'][1]['report'] is None
        assert manager.pending == manager.reserved_bytes == 0
    finally:
        manager.close()


def test_concurrent_idempotency_is_atomic_and_has_one_reservation(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    manager = ScanTasks(Scanner(), db_path=tmp_path/'tasks.sqlite3')
    try:
        with ThreadPoolExecutor(max_workers=8) as pool:
            jobs = list(pool.map(lambda _: manager.submit([('a', b'a')], idempotency_key='same'), range(16)))
        assert len({job['id'] for job in jobs}) == 1
        assert len(manager.list()) == 1
    finally:
        manager.close()


def test_single_owner_corruption_and_future_schema_fail_closed(tmp_path):
    from aegisav.task_store import TaskStore
    path = tmp_path/'tasks.sqlite3'
    first = TaskStore(path)
    with pytest.raises(RuntimeError, match='already in use'):
        TaskStore(path)
    first.close()
    connection = sqlite3.connect(path)
    connection.execute('pragma user_version=99')
    connection.close()
    with pytest.raises(RuntimeError, match='schema'):
        TaskStore(path)
    path.write_bytes(b'not a database')
    with pytest.raises(sqlite3.DatabaseError):
        TaskStore(path)
    assert path.read_bytes() == b'not a database'


def test_persist_failure_does_not_admit_or_leak_reservations(tmp_path, monkeypatch):
    manager = ScanTasks(Scanner(), db_path=tmp_path/'tasks.sqlite3')
    original = manager.store.save
    monkeypatch.setattr(manager.store, 'save', lambda _: (_ for _ in ()).throw(sqlite3.OperationalError('disk full')))
    with pytest.raises(sqlite3.OperationalError):
        manager.submit([('a', b'a')])
    assert manager.pending == manager.reserved_bytes == 0
    assert manager.list() == []
    monkeypatch.setattr(manager.store, 'save', original)
    manager.close()
