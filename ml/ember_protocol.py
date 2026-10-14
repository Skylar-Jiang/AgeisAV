"""Independence rules shared by the EMBER run and its regression tests."""
import math
import hashlib
import json

FEATURE_KEYS = (
    "general", "histogram", "byteentropy", "strings", "header", "section",
    "imports", "exports", "datadirectories", "richheader", "authenticode",
    "pefilewarnings",
)


def feature_payload(raw):
    return {key: raw[key] for key in FEATURE_KEYS}


def admit_unique_record(raw, seen):
    identity = {**feature_payload(raw), **{key: raw[key] for key in
                ("label", "first_submission_date", "week_id", "file_type")}}
    fingerprint = hashlib.sha256(json.dumps(identity, sort_keys=True,
                                           separators=(",", ":"), allow_nan=False).encode()).hexdigest()
    sha = raw["sha256"]
    if sha in seen:
        if seen[sha] != fingerprint:
            raise ValueError(f"SHA256 duplicate has conflicting label/time/features: {sha}")
        return False
    seen[sha] = fingerprint
    return True


def week_splits(train_weeks, test_weeks):
    train = sorted(set(train_weeks))
    test = sorted(set(test_weeks))
    if len(train) != 52 or len(test) != 12 or max(train) >= min(test):
        raise ValueError("Expected 52 chronological training weeks followed by 12 test weeks")
    return {**{w: "fit" for w in train[:-4]},
            **{w: "validation" for w in train[-4:]},
            **{w: "test" for w in test}}


def test_calendar_week(timestamp):
    # Official Win64 test period: 2024-09-22 inclusive through 2024-12-15 exclusive (UTC).
    start, end = 1726963200, 1734220800
    if type(timestamp) is not int or not start <= timestamp < end:
        raise ValueError('First submission outside official test period')
    return 52 + (timestamp - start) // (7 * 86400)


def unique_test_indices(hashes, labels, dates):
    if not len(hashes) == len(labels) == len(dates):
        raise ValueError('Test metadata lengths differ')
    seen, keep, repeats = {}, [], []
    for index, sha in enumerate(hashes):
        if sha in seen:
            first = seen[sha]
            if labels[first] != labels[index] or dates[first] != dates[index]:
                raise ValueError('Test duplicate label/date conflict')
            repeats.append((first, index))
        else:
            seen[sha] = index
            keep.append(index)
    return keep, repeats


def validation_threshold(labels, scores, target_fpr):
    if not 0 <= target_fpr < 1 or len(labels) != len(scores):
        raise ValueError("Invalid target FPR or score/label length")
    if any(y not in (0, 1) for y in labels) or any(not math.isfinite(s) for s in scores):
        raise ValueError("Threshold selection requires binary labels and finite scores")
    benign = sorted((float(s) for y, s in zip(labels, scores) if y == 0), reverse=True)
    if not benign:
        raise ValueError("Validation contains no benign examples")
    budget = math.floor(target_fpr * len(benign))
    return math.nextafter(benign[budget], math.inf)


def assert_disjoint_hashes(split_hashes):
    seen = set()
    for split, hashes in split_hashes.items():
        hashes = list(hashes)
        unique = set(hashes)
        if len(unique) != len(hashes) or seen.intersection(unique):
            raise ValueError(f"SHA256 duplicate detected in or across split {split}")
        seen.update(unique)
