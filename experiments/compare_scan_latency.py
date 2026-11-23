"""Compare source snapshots using installed benign files and disposable scan workers.

Run with .venv-ml (psutil); workers use the normal .venv. Outputs are private.
No input PE is executed. No API, user database or credentials are opened.
"""
import argparse
import hashlib
import json
import math
import os
import platform
from pathlib import Path
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))
from aegisav.scan_process import ProcessScanner
from aegisav.pe import validate_pe


def quantiles(values):
    ordered = sorted(values)
    return {f'p{p}_ms': ordered[math.ceil(p / 100 * len(ordered)) - 1] for p in (50, 95)}


def normalized(value):
    if isinstance(value, dict):
        return {k: normalized(v) for k, v in value.items()
                if k not in {'elapsed_ms', 'feature_elapsed_ms', 'inference_elapsed_ms'}}
    if isinstance(value, list):
        return [normalized(v) for v in value]
    return value


def measure(scanner, data):
    import psutil
    stop = threading.Event()
    peaks = {'rss_bytes': 0, 'private_bytes': 0, 'sample_count': 0}
    counters = {}

    def monitor():
        while not stop.wait(.02):
            try:
                parent = psutil.Process(scanner.active_pid) if scanner.active_pid else None
                tree = [parent, *parent.children(recursive=True)] if parent else []
            except psutil.Error:
                continue
            rss = private = 0
            for process in tree:
                try:
                    identity = (process.pid, process.create_time())
                    memory, cpu, io = process.memory_info(), process.cpu_times(), process.io_counters()
                    rss += memory.rss
                    private += getattr(memory, 'private', 0)
                    counters[identity] = {'cpu_seconds': cpu.user + cpu.system,
                                          'read_bytes': io.read_bytes, 'write_bytes': io.write_bytes}
                except psutil.Error:
                    continue
            peaks['rss_bytes'] = max(peaks['rss_bytes'], rss)
            peaks['private_bytes'] = max(peaks['private_bytes'], private)
            peaks['sample_count'] += bool(tree)

    thread = threading.Thread(target=monitor, daemon=True)
    thread.start()
    started = time.perf_counter()
    try:
        report = scanner.scan(data, threading.Event(), time.monotonic() + 120)
        return {'elapsed_ms': (time.perf_counter() - started) * 1000, 'report': report,
                'resources': peaks, 'cleanup_confirmed': scanner.healthy and scanner.active_pid is None}
    finally:
        stop.set()
        thread.join()
        peaks.update({key: sum(row[key] for row in counters.values())
                      for key in ('cpu_seconds', 'read_bytes', 'write_bytes')})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline-root', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--rounds', type=int, default=3)
    parser.add_argument('--extended', action='store_true', help='Also read three installed 6–13 MiB DLL/kernel files')
    args = parser.parse_args()
    if os.name != 'nt' or not 1 <= args.rounds <= 10 or args.output.exists():
        raise ValueError('Requires Windows, 1–10 rounds and a new output path')
    paths = [Path('C:/Windows/System32') / name for name in
             ('notepad.exe', 'cmd.exe', 'whoami.exe', 'kernel32.dll')]
    paths += [Path('C:/Windows/SysWOW64/notepad.exe'),
              Path('C:/Windows/Microsoft.NET/Framework/v4.0.30319/csc.exe')]
    if args.extended:
        paths += [Path(sys.base_prefix) / 'python312.dll', Path('C:/Windows/System32/shell32.dll'),
                  Path('C:/Windows/System32/ntoskrnl.exe')]
    samples = []
    for path in paths:
        data = path.read_bytes()
        validate_pe(data)
        if len(data) > 16 * 1024**2:
            raise ValueError('Input exceeds product limit')
        samples.append((path, data))
    os.environ['AEGISAV_MODEL_DIR'] = str(ROOT / 'models/ember2024')
    os.environ['AEGISAV_ML_PYTHON'] = str(ROOT / '.venv-ml/Scripts/python.exe')
    os.environ['AEGISAV_ML_PROFILE'] = 'general'
    roots = {'baseline': args.baseline_root.resolve(), 'candidate': ROOT}
    scanners = {}
    for name, root in roots.items():
        code = (f'import sys; sys.path.insert(0, {str(root / "backend")!r}); '
                'from aegisav.scan_worker import main; main()')
        scanners[name] = ProcessScanner([str(ROOT / '.venv/Scripts/python.exe'), '-B', '-c', code])
    result = {'schema': 1, 'scope': 'Preloaded benign files; disposable worker through cleanup; no HTTP',
              'environment': {'platform': platform.platform(), 'python': sys.version, 'processor': platform.processor()},
              'source_sha256': {name: {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                                      for p in (root / 'backend/aegisav').glob('*.py')}
                                for name, root in roots.items()},
              'registry_sha256': hashlib.sha256((ROOT / 'models/ember2024/registry.json').read_bytes()).hexdigest(),
              'sampling_caveat': '20 ms observed owned-tree sums; short-lived processes and peaks can be missed; '
                                 'RSS sums can double-count shared pages; excludes the benchmark controller.',
              'files': [{'path': str(path), 'size_bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
                        for path, data in samples], 'observations': [], 'summary': {}}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    for repeat in range(args.rounds):
        for index, (path, data) in enumerate(samples):
            order = ('baseline', 'candidate') if (repeat + index) % 2 == 0 else ('candidate', 'baseline')
            pair = {}
            for name in order:
                row = {'version': name, 'round': repeat, 'file_index': index}
                try:
                    row.update(measure(scanners[name], data))
                except Exception as error:
                    row.update(error=type(error).__name__ + ': ' + str(error))
                    result['observations'].append(row)
                    args.output.write_text(json.dumps(result, indent=2), encoding='utf-8')
                    raise
                result['observations'].append(row)
                pair[name] = row
                print(name, repeat, path.name, round(row['elapsed_ms'], 2), flush=True)
            if normalized(pair['baseline']['report']) != normalized(pair['candidate']['report']):
                result.setdefault('report_mismatches', []).append({'round': repeat, 'file_index': index})
            args.output.write_text(json.dumps(result, indent=2), encoding='utf-8')
    for name in roots:
        rows = [r for r in result['observations'] if r['version'] == name]
        values = [r['elapsed_ms'] for r in rows]
        result['summary'][name] = {**quantiles(values), 'scans': len(rows),
                                  'throughput_files_per_second': len(rows) * 1000 / sum(values),
                                  'max_sampled_tree_rss_bytes': max(r['resources']['rss_bytes'] for r in rows),
                                  'max_sampled_tree_private_bytes': max(r['resources']['private_bytes'] for r in rows),
                                  'sampled_cpu_seconds': sum(r['resources']['cpu_seconds'] for r in rows),
                                  'sampled_read_bytes': sum(r['resources']['read_bytes'] for r in rows),
                                  'sampled_write_bytes': sum(r['resources']['write_bytes'] for r in rows)}
    result['report_pairs_equal'] = not result.get('report_mismatches')
    result['completed'] = True
    args.output.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result['summary']), flush=True)


if __name__ == '__main__':
    main()
