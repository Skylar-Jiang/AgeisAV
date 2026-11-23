"""Paired bounded-worker reports/resources and harmless snapshot fault checks.

Only installed PE controls and already observed benign development files are read.
No independent accuracy estimate, VM access, sample execution or network downloads.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))


def main():
    from aegisav.clamav_engine import ClamAVEngine
    from aegisav.scan_process import ProcessScanner
    from aegisav.tasks import ScanStopped
    from experiments.compare_scan_latency import measure, normalized, quantiles
    from experiments.yara_bundle import worker_command
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', required=True, type=Path)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--native-root', required=True, type=Path)
    parser.add_argument('--clam-state', required=True, choices=('healthy', 'unavailable'))
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    if ClamAVEngine().probe() != (args.clam_state == 'healthy'):
        raise ValueError('ClamAV state disagrees with declared stratum')
    if hashlib.sha256(args.bundle.read_bytes()).hexdigest() != args.sha256:
        raise ValueError('Bundle does not match trusted deployment digest')
    os.environ.update(AEGISAV_MODEL_DIR=str(ROOT / 'models/ember2024'),
                      AEGISAV_ML_PYTHON=str(ROOT / '.venv-ml/Scripts/python.exe'),
                      AEGISAV_ML_PROFILE='general', PYTHONDONTWRITEBYTECODE='1')
    def command(mode):
        bundle, digest = (str(args.bundle.resolve()), args.sha256) if mode == 'bundle' else (None, None)
        return worker_command(ROOT, ROOT / '.venv/Scripts/python.exe', bundle, digest, args.native_root)
    runners = {mode: ProcessScanner(command(mode)) for mode in ('compile', 'bundle')}
    paths = [Path('C:/Windows/System32') / name for name in
             ('notepad.exe', 'whoami.exe', 'kernel32.dll', 'shell32.dll', 'ntoskrnl.exe')]
    paths += [Path('C:/Windows/SysWOW64') / name for name in ('notepad.exe', 'kernel32.dll')]
    paths += [Path(sys.base_prefix) / 'python312.dll', Path('C:/Windows/Microsoft.NET/Framework/v4.0.30319/csc.exe')]
    controls = json.loads((ROOT / 'artifacts/optimization-20261022-r2-stream/observed-false-positives.json').read_text())['files']
    for source in ('SQLite', 'Igor Pavlov'):
        control = next(row for row in controls if row['source'] == source)
        path = ROOT / control['path']
        if hashlib.sha256(path.read_bytes()).hexdigest() != control['sha256']:
            raise ValueError('Observed development control identity changed')
        paths.append(path)
    result = {'completed': False, 'scope': 'Observed benign regression controls; not independent accuracy',
              'clam_state': args.clam_state, 'bundle_sha256': args.sha256, 'rows': [],
              'pairs_equal': 0, 'fault_checks': {}, 'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    output = args.output / 'result.json'
    def save():
        output.write_text(json.dumps(result, indent=2), encoding='utf-8')
    save()
    try:
        for index, path in enumerate(paths):
            data = path.read_bytes()
            if len(data) > 16 * 1024**2:
                raise ValueError('Control exceeds unchanged product limit')
            pair = {}
            order = ('compile', 'bundle') if index % 2 == 0 else ('bundle', 'compile')
            for mode in order:
                row = dict(mode=mode, name=path.name, size_bytes=len(data),
                           sha256=hashlib.sha256(data).hexdigest(), **measure(runners[mode], data))
                result['rows'].append(row); save()
                pair[mode] = normalized(row['report'])
                expected = {'matched', 'no_match'} if args.clam_state == 'healthy' else {'unavailable'}
                if row['report']['engines']['clamav']['status'] not in expected:
                    raise AssertionError('ClamAV stratum changed')
                if any(engine['status'] not in {'matched', 'no_match'} for name, engine in row['report']['engines'].items() if name != 'clamav'):
                    raise AssertionError('Unexpected engine abstention/failure')
                print(mode, index, path.name, round(row['elapsed_ms'], 2), flush=True)
            if pair['compile'] != pair['bundle']:
                raise AssertionError('Non-timing report differs')
            result['pairs_equal'] += 1
        # These fixtures load the actual verified bundle inside a Job, acknowledge
        # that boundary, then deliberately hang/crash/allocate; they execute no PE.
        prefix = (f'import sys,json,time;sys.path.insert(0,{str(ROOT / "backend")!r});'
                  'from aegisav.scan_process import contain_worker;contain_worker();'
                  'sys.stdin.buffer.read();from aegisav.yara_engine import load_yara_engine;'
                  f'from pathlib import Path;load_yara_engine(Path({str(ROOT / "rules/yara")!r}),'
                  f'Path({str(ROOT / "rules/yara/metadata.json")!r}),compiled_file=Path({str(args.bundle.resolve())!r}),'
                  f'compiled_sha256={args.sha256!r});')
        for fault in ('cancel', 'timeout', 'crash', 'memory'):
            marker = args.output / (fault + '-loaded.txt')
            code = prefix + f'Path({str(marker.resolve())!r}).write_text("loaded");'
            if fault == 'crash':
                code += 'import os;os._exit(7)'
            elif fault == 'memory':
                code += '\ntry: allocation=bytearray(512*1024**2); limited=False\nexcept MemoryError: limited=True\nprint(json.dumps({"report":{"limited":limited}}))'
            else:
                code += 'time.sleep(30)'
            runner = ProcessScanner([str(ROOT / '.venv/Scripts/python.exe'), '-B', '-c', code],
                                    memory_bytes=256*1024**2 if fault == 'memory' else 2*1024**3)
            cancel = threading.Event()
            def trigger():
                for _ in range(500):
                    if marker.exists():
                        cancel.set(); return
                    time.sleep(.01)
            thread = threading.Thread(target=trigger) if fault == 'cancel' else None
            if thread:
                thread.start()
            try:
                try:
                    report = runner.scan(b'inert fixture', cancel, time.monotonic() + (5 if fault == 'timeout' else 10))
                    if fault != 'memory' or report != {'limited': True}:
                        raise AssertionError('Fault was not contained')
                except ScanStopped as error:
                    if error.status != {'cancel': 'cancelled', 'timeout': 'timed_out'}.get(fault):
                        raise
                except RuntimeError:
                    if fault != 'crash':
                        raise
                if not marker.exists() or not runner.healthy or runner.active_pid is not None:
                    raise AssertionError('Loaded-bundle boundary/cleanup not confirmed')
                result['fault_checks'][fault] = {'loaded_verified_bundle': True, 'cleanup_confirmed': True}
            finally:
                if thread:
                    thread.join(timeout=6)
            save()
        recovery = measure(runners['bundle'], paths[0].read_bytes())
        if normalized(recovery['report']) != normalized(result['rows'][0]['report']):
            raise AssertionError('Following scan did not recover consistently')
        result['following_scan_recovered'] = recovery['cleanup_confirmed']
        result['summary'] = {mode: {
            **quantiles([r['elapsed_ms'] for r in result['rows'] if r['mode'] == mode]),
            'max_sampled_tree_rss_bytes': max(r['resources']['rss_bytes'] for r in result['rows'] if r['mode'] == mode),
            'sampled_cpu_seconds': sum(r['resources']['cpu_seconds'] for r in result['rows'] if r['mode'] == mode)} for mode in runners}
        result['completed'] = True
    finally:
        save()
    print(json.dumps(result['summary']), flush=True)


if __name__ == '__main__':
    main()
