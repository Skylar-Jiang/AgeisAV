"""Versioned static PE model registry with a bounded, disposable inference process."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import tempfile

import pefile


class WorkerCleanupError(RuntimeError):
    pass


def run_worker(command, data, timeout, env):
    # A regular output file avoids Windows pipe-reader threads waiting on orphaned
    # inherited handles during timeout cleanup. PE input still travels through stdin.
    output = tempfile.TemporaryFile()
    process = None
    try:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=output,
                                   stderr=subprocess.DEVNULL, env=env)
        try:
            process.communicate(data, timeout=timeout)
        except subprocess.TimeoutExpired as original:
            cleanup_ok = True
            try:
                if os.name == 'nt':
                    # Windows venv redirectors can launch a second Python process.
                    killed = subprocess.run(['taskkill.exe', '/PID', str(process.pid), '/T', '/F'],
                                            capture_output=True, timeout=2)
                    cleanup_ok = killed.returncode == 0
            except (OSError, subprocess.TimeoutExpired):
                cleanup_ok = False
            finally:
                try:
                    if process.poll() is None:
                        process.kill()
                    process.wait(timeout=2)
                except (OSError, subprocess.TimeoutExpired):
                    cleanup_ok = False
            if not cleanup_ok:
                raise WorkerCleanupError('Worker tree cleanup not confirmed') from original
            raise
        output.seek(0)
        return subprocess.CompletedProcess(command, process.returncode, output.read(16385), b'')
    finally:
        if process is not None:
            process.stdin.close()
        output.close()


def pe_scope(data):
    with pefile.PE(data=data, fast_load=True) as pe:
        machine, magic = pe.FILE_HEADER.Machine, pe.OPTIONAL_HEADER.Magic
        if (machine, magic) not in {(0x14c, 0x10b), (0x8664, 0x20b)}:
            return 'unsupported'
        directories = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        if len(directories) > 14 and (directories[14].VirtualAddress or directories[14].Size):
            return 'dot_net'
        return 'win64' if machine == 0x8664 else 'win32'


class MLEngine:
    def __init__(self, root, profile='general', python_executable=None, timeout_seconds=60):
        if profile not in {'general', 'win64_low_fpr'} or not 0 < timeout_seconds <= 120:
            raise ValueError('Unsupported ML operating policy')
        self.root = Path(root).resolve()
        self.profile = profile
        self.python_executable = python_executable or sys.executable
        self.timeout_seconds = timeout_seconds
        self.slots = threading.BoundedSemaphore(2)
        self.manifest = None
        self.ready = False
        self.artifact_version = 'unconfigured:' + profile
        try:
            raw = (self.root / 'registry.json').read_bytes()
            if len(raw) > 16384:
                raise ValueError('Registry size limit')
            self.manifest = json.loads(raw)
            self.verify_assets()
            self.artifact_version = hashlib.sha256(raw).hexdigest() + ':' + profile
            self.ready = True
        except (OSError, ValueError, KeyError, TypeError):
            pass

    def verify_assets(self):
        manifest = self.manifest
        if manifest['schema'] != 1 or manifest['feature_dim'] != 2568:
            raise ValueError('Unsupported feature schema')
        implementation = manifest.get('feature_implementation', 'upstream-v3')
        if implementation not in {'upstream-v3', 'chunked-histogram-v1'}:
            raise ValueError('Unsupported feature implementation')
        if implementation == 'chunked-histogram-v1':
            adapter = Path(__file__).with_name('ember_features.py')
            if hashlib.sha256(adapter.read_bytes()).hexdigest() != manifest['feature_adapter_sha256']:
                raise ValueError('Feature adapter digest mismatch')
        allowed = {'features.py', 'pefile_warnings.txt', 'EMBER2024_PE.model', 'ember2024_win64_temporal_local.model'}
        if set(manifest['files']) != allowed or set(manifest['models']) != {'general', 'win64'}:
            raise ValueError('Model registry asset boundary')
        for name, digest in manifest['files'].items():
            path = self.root / name
            if not path.resolve().is_relative_to(self.root) or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise ValueError('Model asset digest mismatch')
        for name, scope, filename in [('general', ['win32', 'win64', 'dot_net'], 'EMBER2024_PE.model'),
                                      ('win64', ['win64'], 'ember2024_win64_temporal_local.model')]:
            entry = manifest['models'][name]
            if entry['scope'] != scope or entry['file'] != filename or not 0 < entry['threshold'] < 1:
                raise ValueError('Unsupported model applicability or threshold')
            if not entry['version'] or not entry['threshold_source']:
                raise ValueError('Missing model provenance')

    def probe(self):
        if not self.ready:
            return False
        try:
            self.verify_assets()
            digest = hashlib.sha256((self.root / 'registry.json').read_bytes()).hexdigest()
            return self.artifact_version == digest + ':' + self.profile
        except Exception:
            return False

    def _result(self, status, started, reason, **fields):
        return {'engine_id': 'lightgbm', 'engine_version': 'LightGBM/4.6.0 EMBER2024/v3',
                'artifact_version': self.artifact_version, 'status': status,
                'elapsed_ms': round((time.perf_counter() - started) * 1000, 3),
                'evidence': [reason], 'risk_signal': 'suspicious' if status == 'matched' else None,
                'score': None, 'threshold': None, 'profile': self.profile, **fields}

    def scan(self, data):
        started = time.perf_counter()
        if not self.ready:
            return self._result('unavailable', started, 'model_registry_unavailable')
        if len(data) > 64 * 1024**2:
            return self._result('error', started, 'input_size_limit')
        try:
            scope = pe_scope(data)
        except Exception:
            return self._result('error', started, 'pe_scope_parse_failed')
        if scope == 'unsupported':
            return self._result('not_applicable', started, 'unsupported_pe_architecture')
        if not self.slots.acquire(timeout=self.timeout_seconds):
            return self._result('timeout', started, 'inference_queue_timeout')
        try:
            if not self.ready:
                return self._result('unavailable', started, 'worker_disabled_restart_required')
            self.verify_assets()
            remaining = self.timeout_seconds - (time.perf_counter() - started)
            if remaining <= 0:
                return self._result('timeout', started, 'inference_queue_timeout')
            env = dict(os.environ, OMP_NUM_THREADS='1', OPENBLAS_NUM_THREADS='1')
            env['PYTHONPATH'] = str(Path(__file__).resolve().parents[1])
            completed = run_worker([self.python_executable, str(Path(__file__).with_name('ml_worker.py')),
                                        str(self.root), self.profile, self.artifact_version],
                                       data=data, timeout=remaining, env=env)
            if completed.returncode or len(completed.stdout) > 16384:
                return self._result('error', started, 'inference_worker_failed')
            result = json.loads(completed.stdout)
            if result['status'] not in {'matched', 'no_match', 'error', 'unavailable'}:
                raise ValueError('Unexpected worker status')
            return self._result(result.pop('status'), started, result.pop('reason'), **result)
        except subprocess.TimeoutExpired:
            return self._result('timeout', started, 'inference_deadline_exceeded')
        except WorkerCleanupError:
            self.ready = False
            return self._result('error', started, 'worker_cleanup_unconfirmed_restart_required')
        except Exception:
            return self._result('error', started, 'model_integrity_or_inference_failed')
        finally:
            self.slots.release()
