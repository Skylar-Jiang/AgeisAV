import sys
from pathlib import Path
import threading
import time

import pytest

from aegisav.scan_process import ProcessScanner
from aegisav.tasks import ScanStopped


def runner(code):
    return ProcessScanner(command=[sys.executable, str(Path(__file__).with_name('fixtures_scan_worker.py')), code], memory_bytes=512*1024**2)


def test_process_deadline_kills_owned_tree_and_releases_slot():
    scanner = runner('hang')
    started = time.monotonic()
    with pytest.raises(ScanStopped) as caught:
        scanner.scan(b'inert', threading.Event(), started+.8)
    assert caught.value.status == 'timed_out'
    assert time.monotonic()-started < 4
    assert scanner.active_pid is None
    assert runner('echo').scan(b'inert', threading.Event(), time.monotonic()+5)['verdict'] == 'undetermined'


def test_process_cancel_crash_and_report_size_limit():
    event = threading.Event()
    scanner = runner('hang')
    timer = threading.Timer(.5,event.set)
    timer.start()
    try:
        with pytest.raises(ScanStopped) as caught:
            scanner.scan(b'inert', event, time.monotonic()+5)
        assert caught.value.status == 'cancelled'
        assert scanner.active_pid is None
    finally:
        timer.join()
    with pytest.raises(RuntimeError, match='worker'):
        runner('crash').scan(b'inert',threading.Event(),time.monotonic()+5)
    with pytest.raises(RuntimeError, match='worker'):
        runner('oversized').scan(b'inert',threading.Event(),time.monotonic()+5)


def test_deadline_also_bounds_blocked_stdin_delivery():
    scanner = runner('no_read')
    started = time.monotonic()
    with pytest.raises(ScanStopped) as caught:
        scanner.scan(b'x'*1024**2,threading.Event(),started+.5)
    assert caught.value.status == 'timed_out'
    assert time.monotonic()-started < 1.5
    assert scanner.active_pid is None


def test_os_memory_quota_is_enforced():
    report = runner('allocate').scan(b'inert',threading.Event(),time.monotonic()+5)
    assert report['limited'] is True


def test_task_deadline_never_publishes_terminal_with_queued_files():
    from aegisav.tasks import ScanTasks
    manager = ScanTasks(None,runner=runner('hang'),file_timeout=5,task_timeout=.4)
    snapshots = []
    original = manager._save
    def capture(job):
        snapshots.append((job['status'],[row['status'] for row in job['files']]))
        original(job)
    manager._save = capture
    try:
        identity = manager.submit([('one',b'inert'),('two',b'inert-two')])['id']
        for _ in range(100):
            job = manager.get(identity)
            if job['status']=='timed_out':
                break
            time.sleep(.02)
        assert job['status']=='timed_out'
        assert all(row['status']=='timed_out' for row in job['files'])
        assert not any(status=='timed_out' and any(row in ('queued','running') for row in rows) for status,rows in snapshots)
        assert manager.pending==manager.reserved_bytes==0
    finally:
        manager.close()


def test_report_tempfile_failure_still_closes_windows_job(monkeypatch):
    import os
    if os.name != 'nt':
        pytest.skip('Windows Job handle allocation')
    from unittest.mock import Mock
    from aegisav import scan_process
    api = Mock()
    api.CloseHandle.return_value = True
    monkeypatch.setattr(scan_process,'create_job',lambda _: (api,123,'inert-job'))
    monkeypatch.setattr(scan_process.tempfile,'TemporaryFile',lambda: (_ for _ in ()).throw(OSError('injected')))
    with pytest.raises(OSError,match='injected'):
        runner('echo').scan(b'inert',threading.Event(),time.monotonic()+5)
    api.CloseHandle.assert_called_once_with(123)
