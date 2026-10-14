"""Evaluate static engines on a pre-labelled, SHA-256-checked PE manifest."""

import argparse
import hashlib
import json
import math
import time
from pathlib import Path

from aegisav.pe import validate_pe


def aggregate_engine_metrics(labels: list[str], statuses: list[str]) -> dict:
    if len(labels) != len(statuses):
        raise ValueError("Labels and statuses must have equal length")
    counts = {key: 0 for key in ("tp", "fp", "tn", "fn", "abstain")}
    for label, status in zip(labels, statuses):
        if label not in {"benign", "malicious"}:
            raise ValueError(f"Unknown label: {label}")
        if status == "matched":
            counts["tp" if label == "malicious" else "fp"] += 1
        elif status == "no_match":
            counts["fn" if label == "malicious" else "tn"] += 1
        elif status in {"error", "timeout", "unavailable"}:
            counts["abstain"] += 1
        else:
            raise ValueError(f"Unknown engine status: {status}")
    malicious = labels.count("malicious")
    benign = labels.count("benign")
    predictions = counts["tp"] + counts["fp"]
    result = {**counts, "malicious_count": malicious, "benign_count": benign}
    result["precision"] = counts["tp"] / predictions if predictions else None
    result["detection_yield"] = counts["tp"] / malicious if malicious else None
    evaluated_benign = counts["fp"] + counts["tn"]
    result["fpr"] = counts["fp"] / evaluated_benign if evaluated_benign else None
    result["false_positive_yield"] = counts["fp"] / benign if benign else None
    result["coverage"] = (len(labels) - counts["abstain"]) / len(labels) if labels else None
    return result


def load_samples(manifest: Path, split: str, isolated: bool = False) -> list[tuple[dict, bytes]]:
    samples = []
    seen = {}
    for line_number, line in enumerate(manifest.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        row = json.loads(line)
        digest = row["sha256"]
        if row["label"] not in {"benign", "malicious"} or not row.get("source"):
            raise ValueError(f"Invalid label or source at line {line_number}")
        if digest in seen:
            if seen[digest] != (row["label"], row["split"]):
                raise ValueError(f"Conflicting duplicate SHA-256 at line {line_number}")
            continue
        seen[digest] = (row["label"], row["split"])
        if row["split"] != split:
            continue
        if row["label"] == "malicious" and not isolated:
            raise ValueError("Malicious samples require explicit isolated mode")
        sample_path = Path(row["path"])
        if not sample_path.is_absolute():
            sample_path = manifest.parent / sample_path
        data = sample_path.read_bytes()
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError(f"SHA-256 mismatch at line {line_number}")
        validate_pe(data)
        samples.append((row, data))
    return samples


def benchmark_configs(files: list[bytes], scanner_factory, workers: list[int], passes: int = 2) -> dict:
    if not files or passes < 1:
        raise ValueError("Benchmark needs files and at least one pass")
    output = {}
    for worker_count in workers:
        for cache_enabled in (False, True):
            scanner = scanner_factory()
            scanner.max_workers = worker_count
            scanner.cache_capacity = max(512, len(files)) if cache_enabled else 0
            durations = []
            cache_hits = 0
            for _ in range(passes):
                started = time.perf_counter()
                reports = scanner.scan_many(files)
                durations.append((time.perf_counter() - started) * 1000)
                cache_hits += sum(bool(report["cached"]) for report in reports)
            ordered = sorted(durations)
            output[f"cache_{'on' if cache_enabled else 'off'}_workers_{worker_count}"] = {
                "passes": passes, "files_per_pass": len(files), "cache_hits": cache_hits,
                "cold_batch_ms": durations[0], "warm_batch_ms": durations[1:],
                "p50_batch_ms": ordered[math.ceil(0.50 * passes) - 1],
                "p95_batch_ms": ordered[math.ceil(0.95 * passes) - 1],
                "throughput_files_per_sec": len(files) * passes / (sum(durations) / 1000),
                "raw_batch_ms": durations,
            }
            print(f"Benchmark workers={worker_count} cache={cache_enabled}: {durations}", flush=True)
    return output


def benchmark_subset(samples: list[tuple[dict, bytes]], limit: int) -> list[bytes]:
    if limit < 1:
        raise ValueError("Benchmark limit must be positive")
    return [data for _, data in samples[:limit]]


def main() -> None:
    from aegisav.main import build_scanner

    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--split", choices=("validation", "test"), required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--workers", nargs="+", type=int, default=[1, 2, 4])
    parser.add_argument("--passes", type=int, default=2)
    parser.add_argument("--benchmark-limit", type=int, default=100)
    parser.add_argument("--isolated-environment", action="store_true",
                        help="Acknowledge that malicious files are already inside a verified isolated guest")
    args = parser.parse_args()
    samples = load_samples(args.manifest, args.split, isolated=args.isolated_environment)
    if not samples:
        raise ValueError("No samples in requested split")
    benchmark_files = benchmark_subset(samples, args.benchmark_limit)
    scanner = build_scanner()
    print(f"Engine readiness: yara_x={scanner.yara_engine is not None}, "
          f"clamav={scanner.clamav_engine is not None}", flush=True)
    reports = []
    for index, (_, data) in enumerate(samples, 1):
        started = time.perf_counter()
        report = scanner.scan(data)
        report["scan_elapsed_ms"] = round((time.perf_counter() - started) * 1000, 3)
        reports.append(report)
        if index % 50 == 0 or index == len(samples):
            print(f"Scanned {index}/{len(samples)} files", flush=True)
    observed = sorted(report["scan_elapsed_ms"] for report in reports)
    labels = [row["label"] for row, _ in samples]
    engines = {name: aggregate_engine_metrics(labels, [report["engines"][name]["status"] for report in reports])
               for name in reports[0]["engines"]}
    result = {
        "manifest": str(args.manifest), "split": args.split, "sample_count": len(samples),
        "benchmark_sample_count": len(benchmark_files),
        "manifest_sha256": hashlib.sha256(args.manifest.read_bytes()).hexdigest(),
        "scan_latency_ms": {
            "p50": observed[math.ceil(0.50 * len(observed)) - 1],
            "p95": observed[math.ceil(0.95 * len(observed)) - 1],
        },
        "engines": engines,
        "benchmark": benchmark_configs(benchmark_files, build_scanner, args.workers, args.passes),
        "reports": reports,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
