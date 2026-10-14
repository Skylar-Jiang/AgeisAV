"""Balanced paired cache/concurrency study on previously observed benign fixtures, never final accuracy."""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import time


def main():
    assert sys.platform == 'linux' and os.getuid() == 1001
    isolation = subprocess.check_output(['/usr/local/bin/aegisav-isolation-check'], text=True).strip()
    root = Path('/opt/aegisav-product/current').resolve()
    sys.path.insert(0, str(root / 'backend'))
    from aegisav.scanner import StaticScanner
    from aegisav.hashes import HashDatabase
    from aegisav.yara_engine import load_yara_engine
    from aegisav.clamav_engine import ClamAVEngine
    from aegisav.ml_engine import MLEngine
    paths = sorted(Path('/opt/aegisav-benign').glob('*/samples/*'))
    selected = []
    for name, lower, upper in [('small', 0, 1024**2), ('medium', 1024**2, 8 * 1024**2),
                               ('large', 8 * 1024**2, 64 * 1024**2)]:
        for suffix in ('.exe', '.dll'):
            choices = sorted((path for path in paths if path.suffix == suffix and lower < path.stat().st_size <= upper),
                             key=lambda path: (-path.stat().st_size, str(path)))
            for path in choices[:1]:
                data = path.read_bytes()
                assert hashlib.sha256(data).hexdigest() == path.stem
                selected.append(dict(path=str(path), data=data, sha256=path.stem, size_bytes=len(data), size_bin=name, type=suffix))
    assert len({item['sha256'] for item in selected}) == len(selected)
    batches = []
    def make_scanner(capacity):
        clam = ClamAVEngine()
        assert clam.probe()
        return StaticScanner(HashDatabase.from_file(root / 'rules/hashes.json'),
            load_yara_engine(root / 'rules/yara', root / 'rules/yara/metadata.json'), clam,
            cache_capacity=capacity, ml_engine=MLEngine(root / 'models/ember2024'))
    def run(scanner, workers, pass_id, mode):
        started = time.perf_counter()
        def scan(item, submitted):
            actual = time.perf_counter()
            report = scanner.scan(item['data'])
            finished = time.perf_counter()
            return dict(sha256=item['sha256'], size_bytes=item['size_bytes'], size_bin=item['size_bin'], type=item['type'],
                        queue_ms=(actual - submitted) * 1000, processing_wall_ms=(finished - actual) * 1000,
                        submission_to_finish_ms=(finished - submitted) * 1000, report=report)
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(scan, item, time.perf_counter()) for item in selected]
            rows = [future.result() for future in futures]
        elapsed = time.perf_counter() - started
        batches.append(dict(workers=workers, pass_id=pass_id, cache_mode=mode, files=rows,
                            batch_wall_seconds=elapsed, throughput_files_per_second=len(rows) / elapsed))
    # ABBA reduces ordering bias; OS/daemon caches remain warm and are explicitly separate from result caching.
    for workers, pass_id in ((1, 0), (2, 0), (2, 1), (1, 1)):
        run(make_scanner(0), workers, pass_id, 'disabled')
    cached = make_scanner(32)
    run(cached, 2, 0, 'enabled_cold')
    run(cached, 2, 1, 'enabled_warm')
    result = dict(schema=1, raw_malware_used=False, strict_final_test=False, release_id=root.name,
                  isolation=isolation, ml_concurrency_limit=2, vm=dict(vcpu=4, memory_mib=8192),
                  http_service_benchmark=False, worker_reuse_enabled=False,
                  limits='Static scanner entry point; API retains 16 MiB per-file limit. Six observed benign engineering fixtures; not population P95 or accuracy.',
                  fixture_sha256=hashlib.sha256(json.dumps([{key: value for key, value in item.items() if key != 'data'}
                                                         for item in selected], sort_keys=True).encode()).hexdigest(),
                  parent_peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss, batches=batches)
    (Path.home() / 'product-pipeline-benchmark.json').write_text(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
