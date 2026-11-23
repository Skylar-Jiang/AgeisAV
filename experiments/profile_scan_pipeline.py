"""Profile an authenticated loopback task with owned temporary SQLite and safe installed PE.

The worker is unchanged on disk. Timers wrap calls only in this experiment;
cProfile in the ML child is diagnostic and its overhead precludes speed claims.
"""
import argparse
import json
import os
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))


def timed(timings, name, function):
    def call(*args, **kwargs):
        started = time.perf_counter()
        try:
            return function(*args, **kwargs)
        finally:
            timings[name] = timings.get(name, 0.) + (time.perf_counter() - started) * 1000
    return call


def profile_ml(path, arguments):
    import cProfile
    import runpy
    sys.argv = arguments
    profiler = cProfile.Profile()
    try:
        profiler.runcall(runpy.run_path, arguments[0], run_name='__main__')
    finally:
        profiler.dump_stats(path)


def worker():
    from aegisav.scan_process import contain_worker, MAX_REPORT
    contain_worker()
    timings = {}
    started = time.perf_counter()
    from aegisav import runtime, scanner as scanner_module, hashes, ml_engine
    timings['scanner_import_ms'] = (time.perf_counter() - started) * 1000
    runtime.load_yara_engine = timed(timings, 'yara_load_compile_ms', runtime.load_yara_engine)
    ml_engine.MLEngine.verify_assets = timed(timings, 'ml_asset_verify_ms', ml_engine.MLEngine.verify_assets)
    scanner_module.validate_pe = timed(timings, 'pe_validation_ms', scanner_module.validate_pe)
    hashes.compute_fuzzy = timed(timings, 'fuzzy_ms', hashes.compute_fuzzy)
    original_worker = ml_engine.run_worker

    def child(command, data, timeout, env):
        from uuid import uuid4
        target = Path(os.environ['AEGISAV_PROFILE_DIR']) / (uuid4().hex + '.pstats')
        code = (f'import sys; sys.path.insert(0, {str(ROOT)!r}); '
                f'from experiments.profile_scan_pipeline import profile_ml; profile_ml({str(target)!r}, sys.argv[1:])')
        return timed(timings, 'ml_child_launch_through_exit_ms', original_worker)(
            [command[0], '-c', code, *command[1:]], data, timeout, env)

    ml_engine.run_worker = child
    data = sys.stdin.buffer.read(16 * 1024**2 + 1)
    if len(data) > 16 * 1024**2:
        raise ValueError('File too large')
    scan = timed(timings, 'scanner_build_ms', runtime.build_scanner)()
    scan.clamav_engine.probe = timed(timings, 'clamav_probe_ms', scan.clamav_engine.probe)
    report = timed(timings, 'scan_ms', scan.scan)(data)
    report['_profile'] = timings
    started = time.perf_counter()
    raw = json.dumps({'report': report}, ensure_ascii=False).encode('utf-8')
    timings['worker_json_ms'] = (time.perf_counter() - started) * 1000
    raw = json.dumps({'report': report}, ensure_ascii=False).encode('utf-8')
    if len(raw) > MAX_REPORT:
        raise RuntimeError('Report too large')
    sys.stdout.buffer.write(raw)


def main():
    import base64
    import hashlib
    import pstats
    import secrets
    import socket
    import tempfile
    import threading
    import httpx
    import uvicorn
    from aegisav.api import create_app
    from aegisav.runtime import build_scanner
    from aegisav.scan_process import ProcessScanner
    from aegisav.task_store import TaskStore
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    os.environ['AEGISAV_PROFILE_DIR'] = str(args.output.resolve())
    os.environ['AEGISAV_MODEL_DIR'] = str(ROOT / 'models/ember2024')
    os.environ['AEGISAV_ML_PYTHON'] = str(ROOT / '.venv-ml/Scripts/python.exe')
    os.environ['AEGISAV_ML_PROFILE'] = 'general'
    timings = {}
    TaskStore.save = timed(timings, 'sqlite_save_including_report_json_ms', TaskStore.save)
    code = 'from experiments.profile_scan_pipeline import worker; worker()'
    runner = ProcessScanner([str(ROOT / '.venv/Scripts/python.exe'), '-B', '-c', code])
    key = secrets.token_urlsafe(32)
    rows = []
    with tempfile.TemporaryDirectory(prefix='aegisav-profile-') as directory:
        app = create_app(build_scanner(), access_token=key, db_path=Path(directory) / 'tasks.sqlite3', runner=runner)
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
        server = uvicorn.Server(uvicorn.Config(app, log_level='critical', access_log=False, timeout_graceful_shutdown=10))
        thread = threading.Thread(target=server.run, kwargs={'sockets': [listener]}, daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 30
            while not server.started:
                if not thread.is_alive() or time.monotonic() >= deadline:
                    raise RuntimeError('Owned profiling service did not start')
                time.sleep(.01)
            with httpx.Client(base_url=f'http://127.0.0.1:{port}', headers={'Authorization': 'Bearer ' + key},
                              timeout=120, trust_env=False) as client:
                for path in (Path('C:/Windows/System32/notepad.exe'), Path(sys.base_prefix) / 'python312.dll'):
                    data = path.read_bytes()
                    started = time.perf_counter()
                    payload = json.dumps({'files': [{'name': path.name, 'content_base64': base64.b64encode(data).decode()}]}).encode()
                    serialize_ms = (time.perf_counter() - started) * 1000
                    before_saves = timings.get('sqlite_save_including_report_json_ms', 0.)
                    started = time.perf_counter()
                    response = client.post('/v1/tasks', content=payload, headers={'Content-Type': 'application/json'})
                    response.raise_for_status()
                    admitted_ms = (time.perf_counter() - started) * 1000
                    job = response.json()
                    deadline = time.monotonic() + 120
                    while job['status'] in {'queued', 'running', 'cancelling'}:
                        if time.monotonic() >= deadline:
                            raise TimeoutError('Profile task deadline')
                        time.sleep(.01)
                        response = client.get('/v1/tasks/' + job['id'])
                        response.raise_for_status()
                        job = response.json()
                    rows.append({'file': path.name, 'size_bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                                 'request_json_base64_ms': serialize_ms, 'post_to_202_ms': admitted_ms,
                                 'post_to_terminal_ms': (time.perf_counter() - started) * 1000,
                                 'sqlite_save_ms': timings['sqlite_save_including_report_json_ms'] - before_saves,
                                 'job': job})
                    print(path.name, round(rows[-1]['post_to_terminal_ms'], 2), flush=True)
        finally:
            server.should_exit = True
            thread.join(timeout=15)
            listener.close()
            if thread.is_alive() or not runner.healthy or runner.active_pid is not None:
                raise RuntimeError('Owned service/worker cleanup not confirmed')
    stats = {}
    for path in args.output.glob('*.pstats'):
        profile = pstats.Stats(str(path))
        stats[path.name] = [{'file': file, 'line': line, 'function': function, 'calls': values[1],
                            'self_seconds': values[2], 'cumulative_seconds': values[3]}
                           for (file, line, function), values in sorted(profile.stats.items(), key=lambda item: item[1][3], reverse=True)[:60]]
    result = {'method': 'Authenticated real loopback HTTP and temporary SQLite; diagnostic ML cProfile overhead',
              'observations': rows, 'ml_profiles': stats, 'owned_service_and_worker_cleanup_confirmed': True}
    (args.output / 'profile.json').write_text(json.dumps(result, indent=2), encoding='utf-8')


if __name__ == '__main__':
    main()
