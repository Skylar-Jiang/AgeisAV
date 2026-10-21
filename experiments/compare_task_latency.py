"""Paired authenticated loopback upload/task/SQLite study on installed benign files only."""
import argparse
import base64
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import sys
import tempfile
import threading
import time

import httpx
import uvicorn

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))

from aegisav.api import create_app
from aegisav.runtime import build_scanner
from aegisav.scan_process import ProcessScanner
from aegisav.task_store import TaskStore
from experiments.compare_scan_latency import normalized, quantiles

def report_identity(job):
    return [{'name': row['name'], 'status': row['status'], 'duplicate_of': row.get('duplicate_of'),
             'report': normalized(row['report'])} for row in job['files']]


def terminal(client, identity, timeout=120):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        response = client.get('/v1/tasks/' + identity)
        response.raise_for_status()
        job = response.json()
        if job['status'] not in {'queued', 'running', 'cancelling'}:
            return job
        time.sleep(.02)
    raise TimeoutError('Owned task did not terminate')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rounds', type=int, default=3)
    parser.add_argument('--scenario', action='append', choices=('small', 'large', 'batch'))
    args = parser.parse_args()
    if args.output.exists() or not 1 <= args.rounds <= 5:
        raise ValueError('Requires new output and 1–5 rounds')
    os.environ['AEGISAV_MODEL_DIR'] = str(ROOT / 'models/ember2024')
    os.environ['AEGISAV_ML_PYTHON'] = str(ROOT / '.venv-ml/Scripts/python.exe')
    os.environ['AEGISAV_ML_PROFILE'] = 'general'
    system = Path('C:/Windows/System32')
    small, large = system / 'notepad.exe', Path(sys.base_prefix) / 'python312.dll'
    command, identity = system / 'cmd.exe', system / 'whoami.exe'
    managed = Path('C:/Windows/Microsoft.NET/Framework/v4.0.30319/csc.exe')
    scenarios = {'small': [small], 'large': [large], 'batch': [identity, command, managed, identity]}
    if args.scenario:
        scenarios = {name: paths for name, paths in scenarios.items() if name in args.scenario}
    data = {p: p.read_bytes() for p in {small, large, command, identity, managed}}
    result = {'schema': 1, 'method': 'Client base64/JSON preparation through terminal real HTTP response; '
              'authenticated loopback, actual disposable workers and SQLite FULL/WAL, polling20ms',
              'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'scanner_sha256': {name: hashlib.sha256((root / 'backend/aegisav/scanner.py').read_bytes()).hexdigest()
                                 for name, root in {'baseline': args.baseline_root.resolve(), 'candidate': ROOT}.items()},
              'inputs': [{'name': str(p), 'size_bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
                         for p, raw in data.items()], 'observations': [], 'summary': {}, 'fault_checks': {}}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    servers, clients, runners, databases, recorded = {}, {}, {}, {}, {}
    with ExitStack() as stack:
        temporary = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='aegisav-task-study-')))
        try:
            for name, root in {'baseline': args.baseline_root.resolve(), 'candidate': ROOT}.items():
                key = secrets.token_urlsafe(32)
                code = (f'import sys; sys.path.insert(0, {str(root / "backend")!r}); '
                        'from aegisav.scan_worker import main; main()')
                runner = ProcessScanner([str(ROOT / '.venv/Scripts/python.exe'), '-B', '-c', code])
                path = temporary / name / 'tasks.sqlite3'
                app = create_app(build_scanner(), access_token=key, db_path=path, runner=runner)
                listener = socket.socket()
                listener.bind(('127.0.0.1', 0))
                server = uvicorn.Server(uvicorn.Config(app, log_level='critical', access_log=False,
                                                      timeout_graceful_shutdown=10))
                thread = threading.Thread(target=server.run, kwargs={'sockets': [listener]}, daemon=True)
                servers[name] = (server, thread, listener)
                runners[name], databases[name], recorded[name] = runner, path, {}
                thread.start()
                deadline = time.monotonic() + 30
                while not server.started:
                    if not thread.is_alive() or time.monotonic() >= deadline:
                        raise RuntimeError('Owned study API failed to start')
                    time.sleep(.01)
                clients[name] = stack.enter_context(httpx.Client(
                    base_url=f'http://127.0.0.1:{listener.getsockname()[1]}',
                    headers={'Authorization': 'Bearer ' + key}, timeout=120, trust_env=False))
            for repeat in range(args.rounds):
                for index, (scenario, paths) in enumerate(scenarios.items()):
                    order = ('baseline', 'candidate') if (repeat + index) % 2 == 0 else ('candidate', 'baseline')
                    pair = {}
                    for name in order:
                        started = time.perf_counter()
                        payload = json.dumps({'files': [{'name': p.name, 'content_base64': base64.b64encode(data[p]).decode()}
                                                       for p in paths]}).encode()
                        encoded_ms = (time.perf_counter() - started) * 1000
                        response = clients[name].post('/v1/tasks', content=payload,
                                                      headers={'Content-Type': 'application/json'})
                        response.raise_for_status()
                        admitted_ms = (time.perf_counter() - started) * 1000
                        job = terminal(clients[name], response.json()['id'])
                        row = {'version': name, 'round': repeat, 'scenario': scenario,
                               'elapsed_ms': (time.perf_counter() - started) * 1000,
                               'client_encoding_ms': encoded_ms, 'through_admission_ms': admitted_ms, 'job': job}
                        result['observations'].append(row)
                        recorded[name][job['id']] = report_identity(job)
                        pair[name] = report_identity(job)
                        args.output.write_text(json.dumps(result, indent=2), encoding='utf-8')
                        if job['status'] != 'completed':
                            raise RuntimeError('Task scan did not complete; partial record retained')
                        print(name, repeat, scenario, round(row['elapsed_ms'], 2), flush=True)
                    if pair['baseline'] != pair['candidate']:
                        raise AssertionError('Non-timing report mismatch; partial records retained')
            # An actual API cancellation of the large file must kill the owned tree;
            # a new request then confirms that no poisoned result/worker survives.
            for name, client in clients.items():
                response = client.post('/v1/tasks', json={'files': [
                    {'name': large.name, 'content_base64': base64.b64encode(data[large]).decode()}]})
                response.raise_for_status()
                identity = response.json()['id']
                deadline = time.monotonic() + 10
                while runners[name].active_pid is None and time.monotonic() < deadline:
                    time.sleep(.01)
                owned_pid = runners[name].active_pid
                if owned_pid is None:
                    raise AssertionError('No running worker observed before cancellation')
                cancelled = client.post('/v1/tasks/' + identity + '/cancel')
                cancelled.raise_for_status()
                stopped = terminal(client, identity, timeout=10)
                if stopped['status'] != 'cancelled' or not runners[name].healthy or runners[name].active_pid is not None:
                    raise AssertionError('Cancellation cleanup not confirmed')
                response = client.post('/v1/tasks', json={'files': [
                    {'name': small.name, 'content_base64': base64.b64encode(data[small]).decode()}]})
                response.raise_for_status()
                recovered = terminal(client, response.json()['id'])
                if recovered['status'] != 'completed':
                    raise AssertionError('Post-cancel task did not recover')
                result['fault_checks'][name] = {'worker_pid_observed_before_cancel': owned_pid,
                    'real_api_cancel_tree_cleanup': True, 'following_task_completed': True}
        finally:
            for server, thread, listener in servers.values():
                server.should_exit = True
            for server, thread, listener in servers.values():
                thread.join(timeout=15)
                listener.close()
                if thread.is_alive():
                    raise RuntimeError('Owned study service did not stop')
        for name, path in databases.items():
            store = TaskStore(path)
            try:
                for identity, expected in recorded[name].items():
                    if report_identity(store.get(identity)) != expected:
                        raise AssertionError('SQLite reload mismatch after service close')
            finally:
                store.close()
    for scenario, paths in scenarios.items():
        result['summary'][scenario] = {}
        for name in clients:
            rows = [r for r in result['observations'] if r['version'] == name and r['scenario'] == scenario]
            values = [r['elapsed_ms'] for r in rows]
            result['summary'][scenario][name] = {**quantiles(values),
                'throughput_inputs_per_second': len(paths) * len(rows) * 1000 / sum(values)}
    result.update(completed=True, all_report_pairs_equal=True, sqlite_reload_equal=True,
                  services_and_workers_closed=all(r.healthy and r.active_pid is None for r in runners.values()))
    args.output.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result['summary']), flush=True)


if __name__ == '__main__':
    main()
