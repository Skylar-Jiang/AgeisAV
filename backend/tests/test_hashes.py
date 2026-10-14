import hashlib
import json

import pytest

from aegisav.hashes import HashDatabase, compute_fuzzy, hash_scan
from aegisav.pe import validate_pe


def test_valid_pe_and_exact_sha256_match(pe_bytes):
    validate_pe(pe_bytes)
    digest = hashlib.sha256(pe_bytes).hexdigest()
    db = HashDatabase.from_records([{"sha256": digest, "label": "test-only", "source": "fixture"}])
    result = hash_scan(pe_bytes, db)
    assert result["sha256"] == digest
    assert result["exact"]["status"] == "matched"
    assert result["exact"]["evidence"][0]["source"] == "fixture"


def test_rejects_non_pe():
    with pytest.raises(ValueError, match="PE"):
        validate_pe(b"hello world")


def test_rejects_pe_with_section_data_past_end_of_file(pe_bytes):
    with pytest.raises(ValueError, match="PE"):
        validate_pe(pe_bytes[:512])


def test_unmatched_file_has_no_exact_evidence(pe_bytes):
    result = hash_scan(pe_bytes, HashDatabase.from_records([]))
    assert result["exact"]["status"] == "no_match"
    assert result["exact"]["evidence"] == []
    assert result["fuzzy"]["status"] == "no_match"


def test_fuzzy_similarity_is_recorded_as_candidate_not_exact_hit(pe_bytes):
    fuzzy = compute_fuzzy(pe_bytes)
    assert fuzzy["tlsh"] and fuzzy["ssdeep"]
    assert fuzzy["tlsh"].startswith("T1")
    other_sha = "a" * 64
    db = HashDatabase.from_records([{"sha256": other_sha, "source": "fixture", "verdict": "malicious", **fuzzy}])
    result = hash_scan(pe_bytes, db)
    assert result["exact"]["status"] == "no_match"
    assert result["fuzzy"]["status"] == "matched"
    assert result["fuzzy"]["evidence"][0]["sha256"] == other_sha


def test_short_low_entropy_data_has_no_tlsh():
    assert compute_fuzzy(b"x" * 64)["tlsh"] is None


def test_rejects_duplicate_or_unattributed_hashes():
    entry = {"sha256": "a" * 64, "source": "fixture"}
    with pytest.raises(ValueError, match="Duplicate"):
        HashDatabase.from_records([entry, entry])
    with pytest.raises(ValueError, match="source"):
        HashDatabase.from_records([{"sha256": "b" * 64}])


def test_hash_database_loads_curated_json_file(tmp_path):
    path = tmp_path / "hashes.json"
    path.write_text(json.dumps([{"sha256": "a" * 64, "source": "authorized feed", "verdict": "malicious"}]), encoding="utf-8")
    database = HashDatabase.from_file(path)
    assert database.by_sha["a" * 64]["verdict"] == "malicious"


def test_hash_database_rejects_unrecognized_verdict():
    with pytest.raises(ValueError, match="verdict"):
        HashDatabase.from_records([{"sha256": "a" * 64, "source": "fixture", "verdict": "maybe"}])


def test_benign_reference_is_not_a_malicious_fuzzy_candidate(pe_bytes):
    db = HashDatabase.from_records([{"sha256": "a" * 64, "source": "fixture", "verdict": "benign",
                                     **compute_fuzzy(pe_bytes)}])
    assert hash_scan(pe_bytes, db)["fuzzy"]["status"] == "no_match"


@pytest.mark.parametrize("field", ["tlsh", "ssdeep"])
def test_invalid_reference_fuzzy_digest_is_rejected(field):
    with pytest.raises(ValueError, match=field):
        HashDatabase.from_records([{"sha256": "a" * 64, "source": "fixture", "verdict": "malicious",
                                    field: "nonsense"}])
