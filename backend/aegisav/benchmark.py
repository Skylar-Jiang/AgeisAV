"""Measure scan-only latency on explicitly supplied, safe PE files."""

import argparse
import hashlib
import json
import math
import time
from collections import Counter, defaultdict
from pathlib import Path

from .main import build_scanner
from .scanner import StaticScanner


def benchmark(paths: list[Path], iterations: int, scanner: StaticScanner | None = None) -> dict:
    if not paths or iterations < 1:
        raise ValueError("At least one file and iteration are required")
    samples = [path.read_bytes() for path in paths]
    scanner = scanner or build_scanner()
    durations = []
    counts = defaultdict(Counter)
    cache_hits = 0
    for index in range(iterations):
        started = time.perf_counter()
        report = scanner.scan(samples[index % len(samples)])
        durations.append((time.perf_counter() - started) * 1000)
        cache_hits += int(report["cached"])
        for name, result in report["engines"].items():
            counts[name][result["status"]] += 1
    ordered = sorted(durations)
    total_ms = sum(durations)
    return {
        "method": "preloaded bytes; scan-only wall-clock; repeated samples",
        "files": [{"path": str(path), "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)}
                  for path, data in zip(paths, samples)],
        "scan_count": iterations, "cache_hits": cache_hits,
        "p50_ms": ordered[math.ceil(0.50 * iterations) - 1],
        "p95_ms": ordered[math.ceil(0.95 * iterations) - 1],
        "throughput_files_per_sec": iterations / (total_ms / 1000),
        "engine_status_counts": {name: dict(statuses) for name, statuses in counts.items()},
        "raw_latency_ms": durations,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", type=Path, action="append", required=True)
    parser.add_argument("--iterations", type=int, default=30)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = benchmark(args.file, args.iterations)
    output = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        args.output.write_text(output + "\n", encoding="utf-8")
    else:
        print(output)


if __name__ == "__main__":
    main()
