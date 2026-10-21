import copy
import hashlib
import json
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from importlib.metadata import version
from threading import Lock

from .hashes import HashDatabase, hash_scan
from .pe import validate_pe


class StaticScanner:
    def __init__(self, database: HashDatabase, yara_engine=None, clamav_engine=None,
                 max_workers: int = 4, cache_capacity: int = 512, ml_engine=None):
        self.database = database
        self.yara_engine = yara_engine
        self.clamav_engine = clamav_engine
        self.ml_engine = ml_engine
        self.max_workers = max_workers
        self.cache = OrderedDict()
        self.cache_capacity = cache_capacity
        self.cache_lock = Lock()
        self.database_version = hashlib.sha256(json.dumps(database.records, sort_keys=True).encode()).hexdigest()[:16]

    def scan(self, data: bytes) -> dict:
        validate_pe(data)
        clamav_ready = True
        clamav_started = time.perf_counter()
        if self.clamav_engine is not None and hasattr(self.clamav_engine, "probe"):
            try:
                clamav_ready = self.clamav_engine.probe()
            except Exception:
                clamav_ready = False
        clamav_probe_ms = (time.perf_counter() - clamav_started) * 1000
        hash_started = time.perf_counter()
        digest = hashlib.sha256(data).hexdigest()
        hash_ms = (time.perf_counter() - hash_started) * 1000
        artifacts = (self.database_version, getattr(self.yara_engine, "artifact_version", None),
                     getattr(self.clamav_engine, "artifact_version", None),
                     getattr(self.ml_engine, "artifact_version", None))
        key = (digest, artifacts)
        cached = None
        ml_ready = self.ml_engine is None or not hasattr(self.ml_engine, 'probe') or self.ml_engine.probe()
        if clamav_ready and ml_ready:
            with self.cache_lock:
                cached = self.cache.get(key)
                if cached is not None:
                    self.cache.move_to_end(key)
        if cached is not None:
            report = copy.deepcopy(cached)
            report["cached"] = True
            return report
        overlap_hashes = len(data) >= 1024**2
        hashes = None if overlap_hashes else hash_scan(data, self.database, digest)
        with ThreadPoolExecutor(max_workers=4 if overlap_hashes else 3) as pool:
            hash_future = pool.submit(hash_scan, data, self.database, digest) if overlap_hashes else None
            futures = {}
            configured = [("yara_x", self.yara_engine), ("clamav", self.clamav_engine)]
            if self.ml_engine is not None:
                configured.append(("lightgbm", self.ml_engine))
            for name, engine in configured:
                if engine is not None and (name != "clamav" or clamav_ready):
                    futures[name] = pool.submit(self._run_engine, name, engine, data)
            if hash_future is not None:
                hashes = hash_future.result()
            engines = {
                "sha256": {"engine_id": "sha256", "engine_version": "sha256", "artifact_version": self.database_version,
                           "status": hashes["exact"]["status"], "elapsed_ms": round(hash_ms + hashes["exact"]["elapsed_ms"], 6),
                           "evidence": hashes["exact"]["evidence"], "risk_signal": "malicious" if any(r.get("verdict") == "malicious" for r in hashes["exact"]["evidence"]) else None},
                "fuzzy": {"engine_id": "fuzzy", "engine_version": f"tlsh-python/{version('tlsh-python')} ppdeep/{version('ppdeep')}",
                          "artifact_version": self.database_version, "status": hashes["fuzzy"]["status"],
                          "elapsed_ms": round(hashes["fuzzy"]["elapsed_ms"], 6), "evidence": hashes["fuzzy"]["evidence"],
                          "hashes": hashes["fuzzy"]["hashes"], "risk_signal": "suspicious" if hashes["fuzzy"]["evidence"] else None},
            }
            for name, engine in configured:
                if engine is None:
                    engines[name] = {"engine_id": name, "engine_version": "unavailable", "artifact_version": None,
                                     "status": "unavailable", "elapsed_ms": 0.0, "evidence": [], "risk_signal": None}
                elif name == "clamav" and not clamav_ready:
                    engines[name] = {"engine_id": name, "engine_version": getattr(engine, "engine_version", "unknown"),
                                     "artifact_version": getattr(engine, "artifact_version", None),
                                     "status": "unavailable", "elapsed_ms": round(clamav_probe_ms, 3),
                                     "evidence": [], "risk_signal": None}
            for name, future in futures.items():
                engines[name] = future.result()
        statuses = {item["status"] for item in engines.values()}
        if engines["sha256"]["risk_signal"] == "malicious":
            verdict = "malicious"
        elif any(item["risk_signal"] == "suspicious" for item in engines.values()):
            verdict = "suspicious"
        elif any(record.get("verdict") == "benign" for record in hashes["exact"]["evidence"]):
            verdict = "benign"
        else:
            verdict = "undetermined"
        report = {"sha256": digest, "size_bytes": len(data), "verdict": verdict,
                  "engines": engines, "cached": False}
        report['fusion'] = {'policy_id': 'evidence-or-v1',
                            'positive_engines': [name for name, item in engines.items() if item.get('risk_signal')],
                            'abstained_engines': [name for name, item in engines.items()
                                                 if item['status'] not in {'matched', 'no_match', 'not_applicable'}],
                            'ml_score_calibrated_probability': False,
                            'deployment_fpr_guaranteed': False}
        if clamav_ready and statuses <= {"matched", "no_match"}:
            with self.cache_lock:
                self.cache[key] = copy.deepcopy(report)
                if len(self.cache) > self.cache_capacity:
                    self.cache.popitem(last=False)
        return report

    @staticmethod
    def _run_engine(name, engine, data):
        started = time.perf_counter()
        try:
            return engine.scan(data)
        except Exception:
            return {"engine_id": name, "engine_version": "unknown", "artifact_version": getattr(engine, "artifact_version", None),
                    "status": "error", "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
                    "evidence": [], "risk_signal": None}

    def scan_many(self, files: list[bytes]) -> list[dict]:
        first_index = {}
        digests = [hashlib.sha256(data).hexdigest() for data in files]
        for index, digest in enumerate(digests):
            first_index.setdefault(digest, index)
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {index: pool.submit(self.scan, files[index]) for index in first_index.values()}
            unique = {index: future.result() for index, future in futures.items()}
        results = []
        for digest in digests:
            index = first_index[digest]
            report = copy.deepcopy(unique[index])
            if len(results) != index:
                report["duplicate_of"] = index
            results.append(report)
        return results
