"""Explicit research-only SSDeep parity and disposable-worker comparison.

Build native_ssdeep.c yourself; supply its reviewed DLL and digest. No production
loader or model registry is changed. Inputs are generated or installed benign PE.
"""
import argparse
import ctypes
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import random
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))


class NativeSSDeep:
    def __init__(self, path, digest):
        path = Path(path).resolve()
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('Research native library digest mismatch')
        self.library = ctypes.CDLL(str(path))
        self.function = self.library.aegisav_ssdeep
        self.function.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t]
        self.function.restype = ctypes.c_int

    def hash(self, data):
        output = ctypes.create_string_buffer(128)
        length = self.function(data, len(data), output, len(output))
        if not 0 <= length < len(output) or len(output.value) != length:
            raise ValueError('Research native hash input/output budget failed')
        return output.value.decode('ascii')


def worker(path, digest):
    # The DLL is loaded only after the ordinary worker enters its existing Job.
    from aegisav import scan_process
    original = scan_process.contain_worker

    def contained():
        original()
        import ppdeep
        from aegisav.scanner import StaticScanner
        provider = NativeSSDeep(path, digest)
        ppdeep.hash = provider.hash
        original_scan = StaticScanner.scan

        def scan(self, data):
            report = original_scan(self, data)
            report['engines']['fuzzy']['engine_version'] += ' native-ssdeep/research+' + digest[:16]
            return report

        StaticScanner.scan = scan

    scan_process.contain_worker = contained
    from aegisav.scan_worker import main
    main()


def safe_paths():
    return [Path('C:/Windows/System32/notepad.exe'), Path(sys.base_prefix) / 'python312.dll',
            Path('C:/Windows/System32/shell32.dll'), Path('C:/Windows/System32/ntoskrnl.exe')]


def checkpoint(output, result):
    output.write_text(json.dumps(result, indent=2), encoding='utf-8')


def parity(provider, output):
    import ppdeep
    cases = []
    rng = random.Random(0)
    for length in (0, 1, 6, 7, 8, 31, 192, 193, 4095, 4096, 4097, 65535, 65536, 65537, 1024**2):
        cases += [('zero-' + str(length), bytes(length)), ('ff-' + str(length), b'\xff' * length),
                  ('cycle-' + str(length), (bytes(range(256)) * (length // 256 + 1))[:length]),
                  ('random-' + str(length), rng.randbytes(length))]
    cases.append(('random-max16MiB', rng.randbytes(16 * 1024**2)))
    cases += [(path.name, path.read_bytes()) for path in safe_paths()]
    rows = []
    for name, data in cases:
        expected, observed = ppdeep.hash(data), provider.hash(data)
        rows.append(dict(case=name, size_bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                         expected=expected, observed=observed, equal=expected == observed))
        checkpoint(output, {'completed': False, 'cases': rows})
        if expected != observed:
            return {'completed': False, 'cases': rows}
        print('PARITY', name, len(data), flush=True)
    with ThreadPoolExecutor(max_workers=4) as pool:
        concurrent = list(pool.map(provider.hash, [cases[-2][1]] * 4))
    assert concurrent == [rows[-2]['expected']] * 4
    assert provider.function(b'', 16 * 1024**2 + 1, ctypes.create_string_buffer(128), 128) == -1
    assert provider.function(b'', 0, ctypes.create_string_buffer(127), 127) == -1
    return {'completed': True, 'cases': rows, 'thread_parity': True, 'input_output_budget_rejections': True,
            'interpretation': 'Engineering byte parity on these cases; no malware accuracy or speed claim'}


def benchmark(path, digest, output):
    from aegisav.scan_process import ProcessScanner
    from experiments.compare_scan_latency import measure, normalized, quantiles
    os.environ['AEGISAV_MODEL_DIR'] = str(ROOT / 'models/ember2024')
    os.environ['AEGISAV_ML_PYTHON'] = str(ROOT / '.venv-ml/Scripts/python.exe')
    os.environ['AEGISAV_ML_PROFILE'] = 'general'
    code = (f'from experiments.benchmark_native_ssdeep import worker; worker({str(path)!r}, {digest!r})')
    scanners = {'reference': ProcessScanner([str(ROOT / '.venv/Scripts/python.exe'), '-B', '-m', 'aegisav.scan_worker']),
                'native': ProcessScanner([str(ROOT / '.venv/Scripts/python.exe'), '-B', '-c', code])}
    samples = [(p, p.read_bytes()) for p in safe_paths()]
    rows = []
    for repeat in range(3):
        for index, (p, data) in enumerate(samples):
            pair = {}
            order = ('reference', 'native') if (repeat + index) % 2 == 0 else ('native', 'reference')
            for name in order:
                row = {'version': name, 'round': repeat, 'file': p.name, 'size_bytes': len(data),
                       **measure(scanners[name], data)}
                rows.append(row)
                checkpoint(output, {'completed': False, 'observations': rows})
                pair[name] = normalized(row['report'])
                print(name, repeat, p.name, round(row['elapsed_ms'], 2), flush=True)
            expected_version = pair['reference']['engines']['fuzzy']['engine_version']
            assert pair['native']['engines']['fuzzy']['engine_version'] == expected_version + ' native-ssdeep/research+' + digest[:16]
            pair['native']['engines']['fuzzy']['engine_version'] = expected_version
            if pair['native'] != pair['reference']:
                return {'completed': False, 'reason': 'unexpected_report_difference', 'observations': rows}
    return {'completed': True, 'observations': rows,
            'summary': {name: {**quantiles([r['elapsed_ms'] for r in rows if r['version'] == name]),
                               'throughput_files_per_second': 12000 / sum(r['elapsed_ms'] for r in rows if r['version'] == name),
                               'max_sampled_tree_rss_bytes': max(r['resources']['rss_bytes'] for r in rows if r['version'] == name)}
                        for name in scanners},
            'scope': 'Explicit C SSDeep override in existing disposable worker, no HTTP; same overlap-enabled source',
            'all_other_non_timing_report_fields_equal': True,
            'all_worker_cleanup_confirmed': all(r['cleanup_confirmed'] for r in rows)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library', required=True, type=Path)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--benchmark', action='store_true')
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError('Existing results must be retained')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    provenance = {'library_sha256': args.sha256,
                  'source_sha256': hashlib.sha256(Path(__file__).with_name('native_ssdeep.c').read_bytes()).hexdigest(),
                  'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  'scanner_sha256': hashlib.sha256((ROOT / 'backend/aegisav/scanner.py').read_bytes()).hexdigest(),
                  'registry_sha256': hashlib.sha256((ROOT / 'models/ember2024/registry.json').read_bytes()).hexdigest()}
    checkpoint(args.output, {**provenance, 'completed': False, 'phase': 'initialization'})
    try:
        result = (benchmark(args.library.resolve(), args.sha256, args.output) if args.benchmark
                  else parity(NativeSSDeep(args.library, args.sha256), args.output))
    except Exception as error:
        result = json.loads(args.output.read_text())
        result.update(provenance, completed=False, exception_type=type(error).__name__, message=str(error))
        checkpoint(args.output, result)
        raise
    result.update(provenance)
    checkpoint(args.output, result)
    if not result['completed']:
        raise RuntimeError('Research native comparison failed; retained result')


if __name__ == '__main__':
    main()
