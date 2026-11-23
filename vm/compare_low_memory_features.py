"""Paired full-vector equivalence on immutable benign fixtures, each attempt in a fresh process."""

import argparse
import base64
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import time


def child(path, implementation):
    limit = (2048 if implementation == 'upstream-v3' else 1536) * 1024**2
    resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
    resource.setrlimit(resource.RLIMIT_CPU, (150, 150))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (65536, 65536))
    result = dict(implementation=implementation, memory_limit_bytes=limit, status='error')
    started = time.perf_counter()
    with open(os.devnull, 'w') as sink, contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
        try:
            import lightgbm
            import numpy as np
            from ember_features import build_extractor
            root = Path('/opt/aegisav-static/ember')
            manifest = json.loads((root / 'manifest.json').read_text())
            for name, digest in manifest['files'].items():
                assert hashlib.sha256((root / name).read_bytes()).hexdigest() == digest
            spec = importlib.util.spec_from_file_location('pinned_features', root / 'features.py')
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            extractor = build_extractor(module, implementation)
            model = lightgbm.Booster(model_file=str(root / 'EMBER2024_PE.model'))
            data = path.read_bytes()
            feature_start = time.perf_counter()
            vector = extractor.feature_vector(data)
            feature_ms = (time.perf_counter() - feature_start) * 1000
            assert vector.shape == (2568,) and np.isfinite(vector).all()
            score = float(model.predict(vector.reshape(1, -1), num_threads=1)[0])
            result.update(status='complete', sha256=hashlib.sha256(data).hexdigest(), size_bytes=len(data),
                          feature_ms=feature_ms, feature_sha256=hashlib.sha256(vector.astype('<f4').tobytes()).hexdigest(),
                          vector_b64=base64.b64encode(vector.astype('<f4').tobytes()).decode(), score=score,
                          model_sha256=manifest['files']['EMBER2024_PE.model'])
        except Exception as error:
            result['exception_class'] = type(error).__name__
    result.update(elapsed_ms=(time.perf_counter() - started) * 1000,
                  peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    print(json.dumps(result))


def main():
    assert sys.platform == 'linux' and os.getuid() == 1001
    parser = argparse.ArgumentParser()
    parser.add_argument('--child', choices=('upstream-v3', 'chunked-histogram-v1'))
    parser.add_argument('--path', type=Path)
    args = parser.parse_args()
    fixture = Path('/opt/aegisav-benign')
    if args.child:
        assert args.path.resolve().is_relative_to(fixture) and args.path.stat().st_size <= 64 * 1024**2
        child(args.path, args.child)
        return
    isolation = subprocess.check_output(['/usr/local/bin/aegisav-isolation-check'], text=True).strip()
    large = fixture / 'vendor/samples/4fbd024b8071aa5fa7315626c57ce5b820fc52bcddb64e8ab297f2206c83ebed.dll'
    small = fixture / 'windows/samples/c77aa0bc43913e8da4d98f22c326d716617021bd2f6afbf1030749f296738cc5.dll'
    medium = max((path for path in (fixture / 'vendor/samples').iterdir()
                  if 1024**2 <= path.stat().st_size <= 8 * 1024**2), key=lambda path: path.stat().st_size)
    rows = []
    for path in (small, medium, large):
        attempts = []
        for implementation in ('upstream-v3', 'chunked-histogram-v1'):
            process = subprocess.run([sys.executable, __file__, '--child', implementation, '--path', str(path)],
                                     env=dict(os.environ, OPENBLAS_NUM_THREADS='1', OMP_NUM_THREADS='1'),
                                     capture_output=True, timeout=180)
            assert not process.returncode and len(process.stdout) <= 65536
            attempts.append(json.loads(process.stdout))
        original, chunked = attempts
        equal = all(item['status'] == 'complete' for item in attempts)
        equal = equal and original['vector_b64'] == chunked['vector_b64'] and original['score'] == chunked['score']
        for item in attempts:
            item.pop('vector_b64', None)
        rows.append(dict(full_vector_bitwise_equal=equal, score_exact_equal=equal, attempts=attempts))
        assert equal, 'Feature equivalence failed; keep results and do not release'
    report = dict(schema=1, raw_malware_used=False, strict_final_test=False, isolation=isolation,
                  source_sha256={name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                                 for name in ('compare_low_memory_features.py', 'ember_features.py')}, rows=rows)
    (Path.home() / 'low-memory-feature-comparison.json').write_text(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
