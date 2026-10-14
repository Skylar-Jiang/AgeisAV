import hashlib

from aegisav.hashes import HashDatabase, compute_fuzzy
from aegisav.scanner import StaticScanner


def test_trusted_exact_hash_can_be_malicious_without_rules(pe_bytes):
    db = HashDatabase.from_records([{
        "sha256": hashlib.sha256(pe_bytes).hexdigest(),
        "source": "synthetic fixture", "verdict": "malicious",
    }])
    result = StaticScanner(db).scan(pe_bytes)
    assert result["verdict"] == "malicious"
    assert result["engines"]["sha256"]["status"] == "matched"
    assert result["engines"]["clamav"]["status"] == "unavailable"


def test_trusted_exact_benign_hash_can_be_benign_without_other_evidence(pe_bytes):
    db = HashDatabase.from_records([{"sha256": hashlib.sha256(pe_bytes).hexdigest(),
                                     "source": "synthetic fixture", "verdict": "benign"}])
    assert StaticScanner(db).scan(pe_bytes)["verdict"] == "benign"


def test_fuzzy_candidate_cannot_make_malicious_verdict(pe_bytes):
    db = HashDatabase.from_records([{
        "sha256": "a" * 64, "source": "synthetic fixture", "verdict": "malicious",
        **compute_fuzzy(pe_bytes),
    }])
    result = StaticScanner(db).scan(pe_bytes)
    assert result["engines"]["fuzzy"]["status"] == "matched"
    assert result["verdict"] == "suspicious"


def test_no_engine_evidence_and_unavailable_services_is_undetermined(pe_bytes):
    result = StaticScanner(HashDatabase.from_records([])).scan(pe_bytes)
    assert result["verdict"] == "undetermined"
    assert result["engines"]["sha256"]["elapsed_ms"] > 0
    assert result["engines"]["fuzzy"]["elapsed_ms"] > 0


def test_all_negative_engines_do_not_prove_file_benign(pe_bytes):
    class NegativeEngine:
        artifact_version = "fixture-v1"

        def scan(self, data):
            return {"engine_id": "fixture", "engine_version": "1", "artifact_version": self.artifact_version,
                    "status": "no_match", "elapsed_ms": 0.1, "evidence": [], "risk_signal": None}

    result = StaticScanner(HashDatabase.from_records([]), NegativeEngine(), NegativeEngine()).scan(pe_bytes)
    assert result["verdict"] == "undetermined"


def test_batch_deduplicates_identical_files_and_preserves_order(pe_bytes):
    scanner = StaticScanner(HashDatabase.from_records([]))
    different = pe_bytes + b"safe-difference"
    results = scanner.scan_many([pe_bytes, different, pe_bytes])
    assert [r["sha256"] for r in results] == [hashlib.sha256(x).hexdigest() for x in [pe_bytes, different, pe_bytes]]
    assert results[2]["duplicate_of"] == 0


def test_completed_scan_can_be_cached_but_unavailable_engine_is_not(pe_bytes):
    class CleanEngine:
        artifact_version = "fixture-v1"

        def __init__(self, engine_id):
            self.engine_id = engine_id
            self.calls = 0

        def scan(self, data):
            self.calls += 1
            return {"engine_id": self.engine_id, "engine_version": "fixture", "artifact_version": self.artifact_version,
                    "status": "no_match", "elapsed_ms": 0.1, "evidence": [], "risk_signal": None}

    yara = CleanEngine("yara_x")
    clam = CleanEngine("clamav")
    scanner = StaticScanner(HashDatabase.from_records([]), yara_engine=yara, clamav_engine=clam)
    assert scanner.scan(pe_bytes)["cached"] is False
    assert scanner.scan(pe_bytes)["cached"] is True
    assert yara.calls == clam.calls == 1
    assert scanner.scan(pe_bytes + b"other")["cached"] is False
    incomplete = StaticScanner(HashDatabase.from_records([]))
    assert incomplete.scan(pe_bytes)["cached"] is False
    assert incomplete.scan(pe_bytes)["cached"] is False


def test_result_cache_has_bounded_capacity(pe_bytes):
    class CleanEngine:
        artifact_version = "fixture-v1"

        def __init__(self, name):
            self.name = name
            self.calls = 0

        def scan(self, data):
            self.calls += 1
            return {"engine_id": self.name, "engine_version": "fixture", "artifact_version": self.artifact_version,
                    "status": "no_match", "elapsed_ms": 0.1, "evidence": [], "risk_signal": None}

    yara = CleanEngine("yara_x")
    clam = CleanEngine("clamav")
    scanner = StaticScanner(HashDatabase.from_records([]), yara, clam, cache_capacity=1)
    scanner.scan(pe_bytes)
    scanner.scan(pe_bytes + b"second")
    assert scanner.scan(pe_bytes)["cached"] is False
    assert yara.calls == clam.calls == 3


def test_clamav_signature_update_invalidates_cached_result(pe_bytes):
    class CleanYara:
        artifact_version = "rule-v1"

        def scan(self, data):
            return {"engine_id": "yara_x", "engine_version": "1", "artifact_version": self.artifact_version,
                    "status": "no_match", "elapsed_ms": 0.1, "evidence": [], "risk_signal": None}

    class UpdatingClam:
        artifact_version = "sig-v1"

        def __init__(self):
            self.current_version = "sig-v1"
            self.calls = 0

        def probe(self):
            self.artifact_version = self.current_version
            return True

        def scan(self, data):
            self.calls += 1
            matched = self.current_version == "sig-v2"
            return {"engine_id": "clamav", "engine_version": "1", "artifact_version": self.artifact_version,
                    "status": "matched" if matched else "no_match", "elapsed_ms": 0.1,
                    "evidence": [{"signature": "fixture"}] if matched else [],
                    "risk_signal": "suspicious" if matched else None}

    clam = UpdatingClam()
    scanner = StaticScanner(HashDatabase.from_records([]), CleanYara(), clam)
    assert scanner.scan(pe_bytes)["cached"] is False
    clam.current_version = "sig-v2"
    result = scanner.scan(pe_bytes)
    assert result["cached"] is False
    assert result["verdict"] == "suspicious"
    assert clam.calls == 2
