"""Supplemental static retry of one frozen vendor fixture; never replaces batch results."""

import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import time
import traceback


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--memory-mib', type=int, choices=(1536, 2048), default=1536)
    parser.add_argument('--context', choices=('full', 'ml'), default='full')
    args = parser.parse_args()
    assert sys.platform == 'linux' and os.getuid() == 1001
    isolation = subprocess.check_output(['/usr/local/bin/aegisav-isolation-check'], text=True).strip()
    os.environ['OPENBLAS_NUM_THREADS'] = os.environ['OMP_NUM_THREADS'] = '1'
    limit = args.memory_mib * 1024**2
    resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
    resource.setrlimit(resource.RLIMIT_CPU, (180, 180))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (65536, 65536))
    root = Path('/opt/aegisav-static')
    sys.path[:0] = [str(root), str(root / 'backend')]
    digest = '4fbd024b8071aa5fa7315626c57ce5b820fc52bcddb64e8ab297f2206c83ebed'
    data = (Path('/opt/aegisav-benign/vendor/samples') / (digest + '.dll')).read_bytes()
    assert hashlib.sha256(data).hexdigest() == digest
    report = dict(schema=1, supplemental_retry=True, strict_final_test=False,
                  raw_malware_used=False, sha256=digest, size_bytes=len(data),
                  isolation=isolation, memory_limit_bytes=limit, context=args.context,
                  original_batch_replaced=False, threshold=0.5)
    phase = 'initialize'
    started = time.perf_counter()
    with open(os.devnull, 'w') as sink, contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
        try:
            if args.context == 'full':
                from aegisav.scanner import StaticScanner
                from aegisav.hashes import HashDatabase
                from aegisav.yara_engine import load_yara_engine
                from aegisav.clamav_engine import ClamAVEngine
                scanner = StaticScanner(HashDatabase.from_file(root / 'rules/hashes.json'),
                    load_yara_engine(root / 'rules/yara', root / 'rules/yara/metadata.json'),
                    ClamAVEngine(), cache_capacity=0)
            from static_ember import EmberEngine
            model = EmberEngine(root / 'ember')
            report['artifact_version'] = model.artifact_version
            if args.context == 'full':
                phase = 'base_scan'
                base = scanner.scan(data)
                report['base_statuses'] = {name: item['status'] for name, item in base['engines'].items()}
            phase = 'feature_vector'
            feature_start = time.perf_counter()
            vector = model.extractor.feature_vector(data)
            report['feature_ms'] = (time.perf_counter() - feature_start) * 1000
            assert vector.shape == (2568,) and model.np.isfinite(vector).all()
            report['feature_sha256'] = hashlib.sha256(vector.astype('<f4').tobytes()).hexdigest()
            phase = 'prediction'
            score = float(model.model.predict(vector.reshape(1, -1), num_threads=1)[0])
            assert 0 <= score <= 1
            report.update(status='matched' if score >= .5 else 'no_match', score=score)
        except Exception as error:
            report.update(status='error', score=None, phase=phase, exception_class=type(error).__name__,
                          frames=[dict(file=Path(frame.filename).name, function=frame.name, line=frame.lineno)
                                  for frame in traceback.extract_tb(error.__traceback__)][-8:])
    report['elapsed_ms'] = (time.perf_counter() - started) * 1000
    report['peak_rss_kib'] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    output = Path.home() / ('benign-ml-retry-' + args.context + '-' + str(args.memory_mib) + '.json')
    output.write_text(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
