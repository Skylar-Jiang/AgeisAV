import subprocess
import os
import sys

import pytest


def test_feature_implementation_is_bound_to_verified_registry(tmp_path):
    import hashlib
    import json
    from pathlib import Path
    files = {}
    for name in ('features.py', 'pefile_warnings.txt', 'EMBER2024_PE.model', 'ember2024_win64_temporal_local.model'):
        (tmp_path / name).write_bytes(b'trusted-test-fixture')
        files[name] = hashlib.sha256(b'trusted-test-fixture').hexdigest()
    registry = dict(schema=1, feature_dim=2568, files=files, feature_implementation='chunked-histogram-v1',
                    feature_adapter_sha256='0' * 64, models={
        'general': dict(scope=['win32', 'win64', 'dot_net'], file='EMBER2024_PE.model', threshold=.5,
                        version='frozen', threshold_source='fixture'),
        'win64': dict(scope=['win64'], file='ember2024_win64_temporal_local.model', threshold=.9,
                      version='frozen', threshold_source='fixture')})
    target = tmp_path / 'registry.json'
    target.write_text(json.dumps(registry))
    assert MLEngine(tmp_path).ready is False
    adapter = Path(__file__).resolve().parents[1] / 'aegisav/ember_features.py'
    registry['feature_adapter_sha256'] = hashlib.sha256(adapter.read_bytes()).hexdigest()
    target.write_text(json.dumps(registry))
    assert MLEngine(tmp_path).ready is True
    registry['feature_implementation'] = 'unknown-extractor'
    target.write_text(json.dumps(registry))
    assert MLEngine(tmp_path).ready is False
from fastapi.testclient import TestClient

from aegisav.api import create_app
from aegisav.hashes import HashDatabase
from aegisav.scanner import StaticScanner
from aegisav.ml_engine import MLEngine, pe_scope, run_worker, WorkerCleanupError


class ModelEngine:
    artifact_version = 'model-v1:threshold=.5'
    calls = 0

    def scan(self, data):
        self.calls += 1
        return {'engine_id': 'lightgbm', 'engine_version': 'test', 'artifact_version': self.artifact_version,
                'status': 'matched', 'elapsed_ms': 1., 'evidence': ['model-v1 score=.8 threshold=.5'],
                'risk_signal': 'suspicious', 'score': .8, 'threshold': .5}


def test_api_ml_evidence_and_cache_version(pe_bytes):
    model = ModelEngine()
    class Complete:
        artifact_version = 'fixture-only'
        def __init__(self, name):
            self.name = name
        def scan(self, data):
            return dict(engine_id=self.name, engine_version='test', artifact_version=self.artifact_version,
                        status='no_match', elapsed_ms=0., evidence=[], risk_signal=None)
    scanner = StaticScanner(HashDatabase.from_records([]), ml_engine=model,
                            yara_engine=Complete('yara_x'), clamav_engine=Complete('clamav'))
    client = TestClient(create_app(scanner))
    first = client.post('/v1/scan', content=pe_bytes).json()
    assert first['engines']['lightgbm']['score'] == .8
    assert first['verdict'] == 'suspicious'
    assert first['fusion']['policy_id'] == 'evidence-or-v1'
    assert 'lightgbm' in first['fusion']['positive_engines']
    assert client.post('/v1/scan', content=pe_bytes).json()['cached'] is True
    assert model.calls == 1
    model.artifact_version = 'model-v2:threshold=.9'
    second = client.post('/v1/scan', content=pe_bytes).json()
    assert second['cached'] is False
    assert second['engines']['lightgbm']['artifact_version'] == model.artifact_version


def test_scope_uses_machine_optional_header_and_managed_directory(pe_bytes):
    assert pe_scope(pe_bytes) == 'win32'
    data = bytearray(pe_bytes)
    import struct
    offset = struct.unpack_from('<I', data, 0x3c)[0]
    struct.pack_into('<H', data, offset + 4, 0x8664)
    struct.pack_into('<H', data, offset + 24, 0x20b)
    struct.pack_into('<H', data, offset + 20, 240)
    struct.pack_into('<I', data, offset + 24 + 108, 16)
    section = bytes(data[offset + 24 + 224:offset + 24 + 224 + 40])
    data[offset + 24 + 112:offset + 24 + 240] = bytes(128)
    data[offset + 24 + 240:offset + 24 + 240 + 40] = section
    assert pe_scope(bytes(data)) == 'win64'
    struct.pack_into('<II', data, offset + 24 + 112 + 14 * 8, 0x2000, 72)
    assert pe_scope(bytes(data)) == 'dot_net'
    struct.pack_into('<H', data, offset + 4, 0xaa64)
    assert pe_scope(bytes(data)) == 'unsupported'


def test_missing_model_is_explicit_abstention(tmp_path, pe_bytes):
    model = MLEngine(tmp_path)
    result = model.scan(pe_bytes)
    assert result['status'] == 'unavailable'
    assert result['score'] is None
    assert result['risk_signal'] is None


def test_timeout_kills_child_and_never_becomes_negative(tmp_path, monkeypatch, pe_bytes):
    model = MLEngine(tmp_path)
    model.ready = True
    monkeypatch.setattr(model, 'verify_assets', lambda: None)
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired('trusted-worker', 1)
    monkeypatch.setattr('aegisav.ml_engine.run_worker', timeout)
    assert model.scan(pe_bytes)['status'] == 'timeout'


def test_failed_ml_is_not_cached_or_treated_as_benign(pe_bytes):
    class Failed(ModelEngine):
        calls = 0
        def scan(self, data):
            return dict(super().scan(data), status='error', risk_signal=None, score=None)
    model = Failed()
    scanner = StaticScanner(HashDatabase.from_records([]), ml_engine=model)
    for _ in range(2):
        report = scanner.scan(pe_bytes)
        assert report['verdict'] == 'undetermined'
        assert report['cached'] is False
        assert 'lightgbm' in report['fusion']['abstained_engines']
    assert model.calls == 2


@pytest.mark.skipif(os.name != 'nt', reason='Windows venv redirector process-tree regression')
def test_real_timeout_reaps_windows_python_worker_tree(tmp_path):
    marker = tmp_path / 'worker.pid'
    program = tmp_path / 'harmless_worker.py'
    program.write_text('import os,time\nfrom pathlib import Path\n'
                       f'Path({str(marker)!r}).write_text(str(os.getpid()))\ntime.sleep(30)\n')
    clean_env = {key: os.environ[key] for key in ('SystemRoot', 'PATH', 'TEMP', 'TMP') if key in os.environ}
    with pytest.raises((subprocess.TimeoutExpired, WorkerCleanupError)):
        run_worker([sys.executable, str(program)], b'', 1.5, clean_env)
    assert marker.exists()
    import ctypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.restype = ctypes.c_void_p
    handle = kernel.OpenProcess(0x1000, False, int(marker.read_text()))
    if handle:
        code = ctypes.c_ulong()
        kernel.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        try:
            assert kernel.GetExitCodeProcess(handle, ctypes.byref(code))
            assert code.value != 259  # STILL_ACTIVE
        finally:
            kernel.CloseHandle(handle)


@pytest.mark.skipif(os.name != 'nt', reason='Windows tree termination failure regression')
def test_tree_termination_failure_still_kills_and_reaps_direct_child(monkeypatch):
    import io
    class Worker:
        pid = 12345
        stdin = io.BytesIO()
        killed = False
        waited = False
        def communicate(self, *args, **kwargs):
            raise subprocess.TimeoutExpired('fixture', .01)
        def poll(self):
            return None
        def kill(self):
            self.killed = True
        def wait(self, timeout):
            assert timeout == 2
            self.waited = True
    worker = Worker()
    monkeypatch.setattr(subprocess, 'Popen', lambda *args, **kwargs: worker)
    def failed_tree_kill(*args, **kwargs):
        raise OSError('simulated taskkill failure')
    monkeypatch.setattr(subprocess, 'run', failed_tree_kill)
    with pytest.raises(WorkerCleanupError) as error:
        run_worker(['fixture'], b'', .01, {})
    assert isinstance(error.value.__cause__, subprocess.TimeoutExpired)
    assert worker.killed and worker.waited
    assert worker.stdin.closed


def test_queued_request_does_not_launch_after_cleanup_disables_ml(tmp_path, monkeypatch, pe_bytes):
    model = MLEngine(tmp_path)
    model.ready = True
    class Queue:
        released = False
        def acquire(self, timeout):
            model.ready = False
            return True
        def release(self):
            self.released = True
    queue = Queue()
    model.slots = queue
    def unexpected():
        pytest.fail('Disabled queued request must not verify or launch a worker')
    monkeypatch.setattr(model, 'verify_assets', unexpected)
    result = model.scan(pe_bytes)
    assert result['status'] == 'unavailable'
    assert result['evidence'] == ['worker_disabled_restart_required']
    assert queue.released
