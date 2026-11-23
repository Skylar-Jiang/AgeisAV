"""Guard temporal independence and validation-only operating points."""
import importlib.util
import copy
from pathlib import Path
import sys

import pytest

MODULE = Path(__file__).resolve().parents[2] / "ml" / "ember_protocol.py"


def protocol():
    assert MODULE.exists(), "EMBER temporal/threshold protocol has not been implemented"
    spec = importlib.util.spec_from_file_location("ember_protocol", MODULE)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_time_split_holds_out_last_four_training_weeks_and_official_test():
    p = protocol()
    mapping = p.week_splits(list(range(52)), list(range(52, 64)))
    assert set(w for w, s in mapping.items() if s == "fit") == set(range(48))
    assert set(w for w, s in mapping.items() if s == "validation") == set(range(48, 52))
    assert set(w for w, s in mapping.items() if s == "test") == set(range(52, 64))


def test_time_split_rejects_overlap_or_nonchronological_official_membership():
    p = protocol()
    with pytest.raises(ValueError):
        p.week_splits(list(range(52)), list(range(51, 63)))
    with pytest.raises(ValueError):
        p.week_splits(list(range(12, 64)), list(range(12)))


def test_threshold_excludes_high_score_ties_when_they_exceed_fpr_budget():
    p = protocol()
    scores = [0.1] * 97 + [0.8] * 3 + [0.99]
    labels = [0] * 100 + [1]
    threshold = p.validation_threshold(labels, scores, 0.01)
    assert threshold > 0.8
    assert sum(s >= threshold for s, y in zip(scores, labels) if y == 0) == 0
    assert scores[-1] >= threshold


def test_threshold_inclusive_boundary_allows_exact_false_positive_budget():
    p = protocol()
    scores = [0.1] * 98 + [0.6, 0.9]
    threshold = p.validation_threshold([0] * 100, scores, 0.01)
    assert sum(s >= threshold for s in scores) == 1
    assert threshold > 0.6
    assert threshold <= 0.9


def test_metadata_allowlist_removes_outcome_and_collection_fields():
    p = protocol()
    raw = {name: {"value": 1} for name in p.FEATURE_KEYS}
    raw.update(sha256="a" * 64, label=1, week_id=63,
               first_submission_date=100, detection_ratio="70/70", caps=["bad"])
    assert set(p.feature_payload(raw)) == set(p.FEATURE_KEYS)
    assert "label" not in p.feature_payload(raw)


def test_cross_split_sha_duplicate_is_rejected():
    p = protocol()
    with pytest.raises(ValueError, match="duplicate"):
        p.assert_disjoint_hashes({"fit": ["a" * 64], "test": ["a" * 64]})


def duplicate_shaped_record(p):
    row = {key: {} for key in p.FEATURE_KEYS}
    row.update(sha256="a" * 64, label=0, week_id=0, file_type="Win64",
               first_submission_date=1695537027,
               general={"size": 1024, "entropy": 4.0, "is_pe": 1, "start_bytes": [77, 90, 0, 0]},
               histogram=[0] * 256, byteentropy=[0] * 256,
               header={"timestamp": 1695537000}, caps=[])
    return row


def test_identical_within_week_duplicate_is_counted_once():
    p = protocol()
    assert hasattr(p, "admit_unique_record"), "Repeated upstream JSON rows need integrity checking"
    row, seen = duplicate_shaped_record(p), {}
    assert p.admit_unique_record(row, seen)
    repeated = copy.deepcopy(row)
    repeated["caps"] = [{"Capability": "harmless fixture metadata"}]
    assert not p.admit_unique_record(repeated, seen)
    assert len(seen) == 1


@pytest.mark.parametrize("field,value", [("label", 1), ("week_id", 1),
                                        ("first_submission_date", 1695537028),
                                        ("general", {"size": 2048})])
def test_duplicate_with_conflicting_label_time_or_features_is_rejected(field, value):
    p = protocol()
    assert hasattr(p, "admit_unique_record"), "Repeated upstream JSON rows need integrity checking"
    row, seen = duplicate_shaped_record(p), {}
    p.admit_unique_record(row, seen)
    repeated = copy.deepcopy(row)
    repeated[field] = value
    with pytest.raises(ValueError, match="conflicting"):
        p.admit_unique_record(repeated, seen)


def test_test_date_audit_accepts_adjacent_week_within_official_test_period():
    p = protocol()
    assert hasattr(p, "test_calendar_week"), "Within-test calendar discrepancies must not discard official samples"
    # Real public metadata anomaly: assigned week 54, submitted on Saturday of week 53.
    assert p.test_calendar_week(1728105303) == 53


@pytest.mark.parametrize("timestamp", [1726963199, 1734220800, 0])
def test_test_date_audit_rejects_cross_partition_or_unknown_dates(timestamp):
    p = protocol()
    assert hasattr(p, "test_calendar_week"), "Cross-partition timestamps must still fail"
    with pytest.raises(ValueError, match="test period"):
        p.test_calendar_week(timestamp)


def test_cross_week_test_repeat_preserves_one_identity_and_rejects_conflicts():
    p = protocol()
    assert hasattr(p, 'unique_test_indices')
    keep, pairs = p.unique_test_indices(['a', 'b', 'a'], [0, 1, 0], [10, 20, 10])
    assert keep == [0, 1] and pairs == [(0, 2)]
    with pytest.raises(ValueError, match='conflict'):
        p.unique_test_indices(['a', 'a'], [0, 1], [10, 10])
    with pytest.raises(ValueError, match='conflict'):
        p.unique_test_indices(['a', 'a'], [0, 0], [10, 11])
