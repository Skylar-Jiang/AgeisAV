"""Paired real five-engine reports on installed/previously-observed benign PE only."""
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
    import psutil
    from aegisav.clamav_engine import ClamAVEngine
    from aegisav.ml_engine import pe_scope
    from aegisav.scan_process import ProcessScanner
    from experiments.compare_scan_latency import measure, normalized, quantiles
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--clam-state', choices=('healthy', 'unavailable'), required=True)
    parser.add_argument('--rounds', type=int, default=2)
    parser.add_argument('--clam-pid', type=int)
    args = parser.parse_args()
    if args.output.exists() or not 1 <= args.rounds <= 3:
        raise ValueError('Requires fresh output and one to three complete rounds')
    clam = ClamAVEngine()
    if clam.probe() != (args.clam_state == 'healthy'):
        raise ValueError('ClamAV state disagrees with the declared stratum')
    source = args.source_root.resolve()
    paths = [Path('C:/Windows/System32') / name for name in
             ('notepad.exe', 'whoami.exe', 'kernel32.dll', 'shell32.dll', 'ntoskrnl.exe')]
    paths += [Path('C:/Windows/SysWOW64') / name for name in ('notepad.exe', 'kernel32.dll')]
    paths += [Path(sys.base_prefix) / 'python312.dll',
              Path('C:/Windows/Microsoft.NET/Framework/v4.0.30319/csc.exe')]
    controls = json.loads((ROOT / 'artifacts/optimization-20261022-r2-stream/observed-false-positives.json').read_text())['files']
    for origin, scope in (('SQLite', 'win64'), ('Igor Pavlov', 'win32')):
        selected = [r for r in controls if r['source'] == origin and pe_scope((ROOT / r['path']).read_bytes()) == scope]
        if not selected:
            raise ValueError('Expected observed benign development control missing')
        path = ROOT / selected[0]['path']
        if hashlib.sha256(path.read_bytes()).hexdigest() != selected[0]['sha256']:
            raise ValueError('Previously observed benign identity mismatch')
        paths.append(path)
    samples = [(path, path.read_bytes()) for path in paths]
    if any(len(data) > 16 * 1024**2 for _, data in samples):
        raise ValueError('Sample exceeds product limit')
    os.environ['AEGISAV_MODEL_DIR'] = str(ROOT / 'models/ember2024')
    os.environ['AEGISAV_ML_PYTHON'] = str(ROOT / '.venv-ml/Scripts/python.exe')
    os.environ['AEGISAV_ML_PROFILE'] = 'general'
    scanners = {}
    for mode in ('python', 'native'):
        code = (f'import sys,os;sys.path.insert(0,{str(source / "backend")!r});'
                f'os.environ["AEGISAV_SSDEEP_BACKEND"]={mode!r};'
                'from aegisav.scan_worker import main;main()')
        scanners[mode] = ProcessScanner([str(ROOT / '.venv/Scripts/python.exe'), '-B', '-c', code])
    manifest = json.loads((source / 'native/manifest.json').read_text())
    expected_suffix = ' native-ssdeep/abi1+' + manifest['sha256'][:16]
    result = {'completed': False, 'clam_state': args.clam_state, 'clam_version': clam.engine_version,
              'clam_signature': clam.artifact_version, 'rows': [], 'pairs_equal': 0,
              'samples': [{'name': p.name, 'sha256': hashlib.sha256(d).hexdigest(),
                           'size_bytes': len(d), 'scope': pe_scope(d)} for p, d in samples],
              'independent_accuracy_evaluation': False,
              'scope': 'ProcessScanner including cleanup; no upload/HTTP; external ClamAV RAM reported separately',
              'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'scanner_sha256': hashlib.sha256((source / 'backend/aegisav/scanner.py').read_bytes()).hexdigest(),
              'native_sha256': manifest['sha256'], 'daemon_samples': []}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    def save():
        args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    save()
    try:
        for repeat in range(args.rounds):
            for index, (path, data) in enumerate(samples):
                pair = {}
                order = ('python', 'native') if (repeat + index) % 2 == 0 else ('native', 'python')
                for mode in order:
                    row = dict(mode=mode, repeat=repeat, file=path.name, **measure(scanners[mode], data))
                    result['rows'].append(row)
                    if args.clam_pid:
                        memory = psutil.Process(args.clam_pid).memory_info()
                        result['daemon_samples'].append({'rss': memory.rss, 'peak_wset': getattr(memory, 'peak_wset', None)})
                    save()
                    report = row['report']
                    expected_clam = {'matched', 'no_match'} if args.clam_state == 'healthy' else {'unavailable'}
                    assert report['engines']['clamav']['status'] in expected_clam
                    assert all(e['status'] in {'matched', 'no_match'} for name, e in report['engines'].items() if name != 'clamav')
                    pair[mode] = normalized(report)
                    print(args.clam_state, repeat, index, mode, path.name, round(row['elapsed_ms'], 2), flush=True)
                version = pair['python']['engines']['fuzzy']['engine_version']
                assert pair['native']['engines']['fuzzy']['engine_version'] == version + expected_suffix
                pair['native']['engines']['fuzzy']['engine_version'] = version
                assert pair['python'] == pair['native'], 'Unexpected non-timing report difference'
                result['pairs_equal'] += 1
        result['summary'] = {}
        for mode in scanners:
            rows = [row for row in result['rows'] if row['mode'] == mode]
            result['summary'][mode] = {**quantiles([row['elapsed_ms'] for row in rows]),
                'throughput_files_per_second': len(rows) * 1000 / sum(row['elapsed_ms'] for row in rows),
                'max_sampled_tree_rss_bytes': max(row['resources']['rss_bytes'] for row in rows),
                'sampled_cpu_seconds': sum(row['resources']['cpu_seconds'] for row in rows)}
        result.update(completed=True, all_cleanup_confirmed=all(row['cleanup_confirmed'] for row in result['rows']))
    except Exception as error:
        result.update(exception_type=type(error).__name__, message=str(error))
        raise
    finally:
        save()
    print(json.dumps(result['summary']), flush=True)


if __name__ == '__main__':
    main()
