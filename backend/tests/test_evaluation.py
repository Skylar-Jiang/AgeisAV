import hashlib
import json

import pytest

from aegisav.hashes import HashDatabase
from aegisav.scanner import StaticScanner
from experiments import evaluate_stage1
from experiments.evaluate_stage1 import aggregate_engine_metrics, load_samples, benchmark_configs


def test_engine_metrics_keep_abstentions_out_of_true_negatives():
    labels = ["malicious", "malicious", "benign", "benign"]
    statuses = ["matched", "unavailable", "matched", "no_match"]
    result = aggregate_engine_metrics(labels, statuses)
    assert result["tp"] == 1
    assert result["fp"] == 1
    assert result["tn"] == 1
    assert result["fn"] == 0
    assert result["abstain"] == 1
    assert result["detection_yield"] == 0.5
    assert result["fpr"] == 0.5
    assert result["coverage"] == 0.75


def test_false_positive_rate_excludes_unscanned_benign_files():
    result = aggregate_engine_metrics(["benign", "benign"], ["matched", "unavailable"])
    assert result["fpr"] == 1.0
    assert result["false_positive_yield"] == 0.5


def test_manifest_rejects_changed_pe_bytes(tmp_path, pe_bytes):
    path = tmp_path / "sample.exe"
    path.write_bytes(pe_bytes)
    manifest = tmp_path / "manifest.jsonl"
    manifest.write_text(json.dumps({"path": str(path), "sha256": "a" * 64, "label": "benign",
                                    "source": "synthetic", "split": "test"}) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="SHA-256"):
        load_samples(manifest, split="test")


def test_manifest_deduplicates_by_sha256(tmp_path, pe_bytes):
    path = tmp_path / "sample.exe"
    path.write_bytes(pe_bytes)
    row = {"path": str(path), "sha256": hashlib.sha256(pe_bytes).hexdigest(), "label": "benign",
           "source": "synthetic", "split": "test"}
    manifest = tmp_path / "manifest.jsonl"
    manifest.write_text(json.dumps(row) + "\n" + json.dumps(row) + "\n", encoding="utf-8")
    assert len(load_samples(manifest, split="test")) == 1


def test_manifest_resolves_sample_path_relative_to_itself(tmp_path, pe_bytes):
    sample_dir = tmp_path / "samples"
    sample_dir.mkdir()
    (sample_dir / "clean.exe").write_bytes(pe_bytes)
    manifest = tmp_path / "manifest.jsonl"
    manifest.write_text(json.dumps({"path": "samples/clean.exe", "sha256": hashlib.sha256(pe_bytes).hexdigest(),
                                    "label": "benign", "source": "synthetic", "split": "test"}) + "\n",
                        encoding="utf-8")
    assert len(load_samples(manifest, split="test")) == 1


def test_malicious_manifest_requires_explicit_isolated_mode(tmp_path, pe_bytes):
    path = tmp_path / "sample.exe"
    path.write_bytes(pe_bytes)
    manifest = tmp_path / "manifest.jsonl"
    manifest.write_text(json.dumps({"path": str(path), "sha256": hashlib.sha256(pe_bytes).hexdigest(),
                                    "label": "malicious", "source": "synthetic fixture", "split": "test"}) + "\n",
                        encoding="utf-8")
    with pytest.raises(ValueError, match="isolated"):
        load_samples(manifest, split="test")
    assert len(load_samples(manifest, split="test", isolated=True)) == 1


def test_cache_benchmark_separates_cold_and_warm_runs(pe_bytes):
    class CleanEngine:
        artifact_version = "fixture-v1"

        def scan(self, data):
            return {"engine_id": "fixture", "engine_version": "1", "artifact_version": self.artifact_version,
                    "status": "no_match", "elapsed_ms": 0.1, "evidence": [], "risk_signal": None}

    def scanner_factory():
        return StaticScanner(HashDatabase.from_records([]), CleanEngine(), CleanEngine())

    result = benchmark_configs([pe_bytes], scanner_factory, workers=[1], passes=2)
    assert result["cache_on_workers_1"]["cache_hits"] == 1
    assert result["cache_off_workers_1"]["cache_hits"] == 0
    assert result["cache_on_workers_1"]["cold_batch_ms"] >= 0
    assert len(result["cache_on_workers_1"]["warm_batch_ms"]) == 1


def test_cache_benchmark_can_hold_entire_measured_set():
    class LruProbeScanner:
        cache_capacity = 512

        def __init__(self):
            self.cache = {}

        def scan_many(self, files):
            reports = []
            for data in files:
                cached = data in self.cache
                if cached:
                    self.cache.pop(data)
                if self.cache_capacity:
                    self.cache[data] = None
                    if len(self.cache) > self.cache_capacity:
                        self.cache.pop(next(iter(self.cache)))
                reports.append({"cached": cached})
            return reports

    files = [index.to_bytes(2, "little") for index in range(513)]
    result = benchmark_configs(files, LruProbeScanner, workers=[1], passes=2)
    assert result["cache_on_workers_1"]["cache_hits"] == 513


def test_benchmark_subset_is_fixed_before_results():
    assert hasattr(evaluate_stage1, "benchmark_subset")
    samples = [({"label": "benign"}, b"a"), ({"label": "benign"}, b"b"), ({"label": "benign"}, b"c")]
    assert evaluate_stage1.benchmark_subset(samples, 2) == [b"a", b"b"]
    with pytest.raises(ValueError, match="limit"):
        evaluate_stage1.benchmark_subset(samples, 0)
