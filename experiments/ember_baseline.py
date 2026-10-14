"""Train the complete Win64 EMBER2024 subset with a chronological holdout.

Run with .venv-ml/Scripts/python.exe -u experiments/ember_baseline.py.
Only public feature/label JSON is read; this program never opens PE sample bytes.
"""
import concurrent.futures
from datetime import datetime, timezone, timedelta
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import sys
import threading
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / "artifacts" / "ember2024"
sys.path.insert(0, str(ROOT / "ml"))
sys.path.insert(0, str(ART / "upstream" / "src"))
from ember_protocol import (FEATURE_KEYS, admit_unique_record, assert_disjoint_hashes,
                            feature_payload, validation_threshold, week_splits, test_calendar_week,
                            unique_test_indices)


def vectorize_week(task):
    archive_path, member = task
    import numpy as np
    import orjson
    from thrember import PEFeatureExtractor

    output = ART / "vectors" / Path(member).stem
    marker = output.with_suffix(".json")
    if marker.exists():
        return json.loads(marker.read_text())
    extractor = PEFeatureExtractor()
    if extractor.dim != 2568 or tuple(f.name for f in extractor.features) != FEATURE_KEYS:
        raise ValueError("Unexpected upstream feature layout")
    start = datetime.strptime(member[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
    lower, upper = int(start.timestamp()), int((start + timedelta(days=7)).timestamp())
    X = np.lib.format.open_memmap(output.with_suffix(".npy"), mode="w+",
                                 dtype=np.float32, shape=(10000, extractor.dim))
    y, weeks, dates, sha = [], [], [], []
    seen = {}
    serialized_rows = 0
    calendar_anomalies = []
    started = time.monotonic()
    with zipfile.ZipFile(archive_path) as archive, archive.open(member) as source:
        for line in source:
            serialized_rows += 1
            row = orjson.loads(line)
            if row["label"] not in (0, 1) or row["file_type"] != "Win64":
                raise ValueError(f"Invalid label/file type at {member}:{serialized_rows}")
            is_test = member.endswith('_test.jsonl')
            calendar_week = test_calendar_week(row['first_submission_date']) if is_test else row['week_id']
            outside_week = not lower <= row["first_submission_date"] < upper
            if outside_week and not is_test:
                raise ValueError(f"First submission outside collection week at {member}:{serialized_rows}")
            if not admit_unique_record(row, seen):
                continue
            if outside_week:
                calendar_anomalies.append({'sha256': row['sha256'], 'assigned_week': row['week_id'],
                                           'calendar_week': calendar_week, 'first_submission_date': row['first_submission_date']})
            index = len(y)
            if index >= 10000:
                raise ValueError(f"More than 10000 unique SHA256 files in {member}")
            vector = extractor.process_raw_features(feature_payload(row))
            if not np.all(np.isfinite(vector)):
                raise ValueError(f"Nonfinite vector at {member}:{index}")
            X[index] = vector
            y.append(row["label"])
            weeks.append(row["week_id"])
            dates.append(row["first_submission_date"])
            sha.append(row["sha256"])
    if len(y) != 10000 or len(set(weeks)) != 1:
        raise ValueError(f"Incorrect week/row count in {member}")
    X.flush()
    del X
    np.savez(output.with_suffix(".npz"), y=np.array(y, dtype=np.int8),
             week=np.array(weeks, dtype=np.int16), date=np.array(dates, dtype=np.int64),
             sha=np.array(sha, dtype="S64"))
    result = {"member": member, "week": weeks[0], "rows": len(y),
              "serialized_rows": serialized_rows,
              "duplicate_rows_excluded": serialized_rows - len(y),
              "duplicate_conflicts": 0,
              "within_test_calendar_anomalies": calendar_anomalies,
              "identity_audit_sha256": hashlib.sha256(json.dumps(sorted(seen.items())).encode()).hexdigest(),
              "benign": y.count(0), "malicious": y.count(1),
              "date_min": min(dates), "date_max": max(dates),
              "seconds": time.monotonic() - started}
    marker.write_text(json.dumps(result, indent=2))
    return result


def prepare():
    import numpy as np
    (ART / "vectors").mkdir(exist_ok=True)
    tasks = []
    for subset in ("train", "test"):
        path = ART / "downloads" / f"Win64_{subset}.zip"
        marker = path.with_suffix(".verified.json")
        while not marker.exists():
            print(f"Waiting for verified {path.name}", flush=True)
            time.sleep(30)
        with zipfile.ZipFile(path) as archive:
            members = archive.namelist()
            expected = 52 if subset == "train" else 12
            if len(members) != expected or any(Path(m).name != m or not m.endswith(f"_Win64_{subset}.jsonl") for m in members):
                raise ValueError("Archive members are not the expected feature JSON files")
            tasks = [(str(path), m) for m in sorted(members)]
        with concurrent.futures.ProcessPoolExecutor(max_workers=8) as pool:
            for row in pool.map(vectorize_week, tasks):
                print(f"VECTORIZED {row}", flush=True)
    stats = [json.loads(p.read_text()) for p in sorted((ART / "vectors").glob("*.json"))]
    mapping = week_splits([r["week"] for r in stats if "train" in r["member"]],
                          [r["week"] for r in stats if "test" in r["member"]])
    meta = {}
    for split in ("fit", "validation", "test"):
        members = [r for r in stats if mapping[r["week"]] == split]
        count = sum(r["rows"] for r in members)
        destination = ART / "vectors" / f"X_{split}.npy"
        X = np.lib.format.open_memmap(destination, mode="w+", dtype=np.float32, shape=(count, 2568))
        arrays = {k: [] for k in ("y", "week", "date", "sha")}
        offset = 0
        for row in members:
            base = ART / "vectors" / Path(row["member"]).stem
            X[offset:offset + row["rows"]] = np.load(base.with_suffix(".npy"), mmap_mode="r")
            with np.load(base.with_suffix(".npz")) as metadata:
                for key in arrays:
                    arrays[key].append(metadata[key])
            offset += row["rows"]
        X.flush()
        del X
        meta[split] = {k: np.concatenate(v) for k, v in arrays.items()}
        np.savez(ART / "vectors" / f"meta_{split}.npz", **meta[split])
    test_meta = meta['test']
    keep, repeats = unique_test_indices(test_meta['sha'].tolist(), test_meta['y'].tolist(), test_meta['date'].tolist())
    if repeats:
        audit_path = ART / 'cross_week_duplicate_audit.json'
        audit = json.loads(audit_path.read_text())
        if audit.get('cross_week_native_feature_conflicts') != 0:
            raise ValueError('Full native feature duplicate audit required')
        audited = {row['sha256'] for row in audit['test']['duplicates']}
        if audited != {test_meta['sha'][a].decode() for a, b in repeats}:
            raise ValueError('Test duplicate audit identities differ')
        destination = ART / 'vectors' / 'X_test.npy'
        original = np.load(destination, mmap_mode='r')
        if any(not np.array_equal(original[a], original[b]) for a, b in repeats):
            raise ValueError('Test duplicate vector conflict')
        temporary = destination.with_name('X_test_unique.npy')
        unique = np.lib.format.open_memmap(temporary, mode='w+', dtype=np.float32, shape=(len(keep), 2568))
        unique[:] = original[keep]
        unique.flush()
        unique._mmap.close()
        original._mmap.close()
        del unique, original
        os.replace(temporary, destination)
        meta['test'] = {key: value[keep] for key, value in test_meta.items()}
        np.savez(ART / 'vectors' / 'meta_test.npz', **meta['test'])
    assert_disjoint_hashes({s: a["sha"].tolist() for s, a in meta.items()})
    if max(meta["fit"]["date"]) >= min(meta["validation"]["date"]) or max(meta["validation"]["date"]) >= min(meta["test"]["date"]):
        raise ValueError("Chronological split dates overlap")
    archive_metadata = ROOT / "docs" / "benchmarks" / "user_archive_static_20261003.json"
    local = json.loads(archive_metadata.read_text(encoding="utf-8"))
    local_sha = {r["sha256"] for r in local["files"] if r.get("sha256")}
    overlap = {s: sorted(local_sha.intersection(x.decode() for x in a["sha"])) for s, a in meta.items()}
    provenance = {"feature_dim": 2568, "feature_keys": FEATURE_KEYS, "week_mapping": mapping,
                  "weeks": stats, "local_archive_sha_overlap": overlap,
                  "feature_archives": [json.loads(p.read_text()) for p in sorted((ART / "downloads").glob("*.verified.json"))],
                  "local_archive_metadata_sha256": hashlib.sha256(archive_metadata.read_bytes()).hexdigest(),
                  "local_archive_unique_sha_count": len(local_sha), "cross_split_sha_duplicates": 0}
    provenance['test_cross_week_duplicates_excluded'] = len(repeats)
    provenance['test_unique_rows'] = len(meta['test']['y'])
    provenance['installed_pe_overlaps'] = {}
    for name in ('benign_windows_pe_manifest.jsonl', 'benign_vendor_pe_manifest.jsonl', 'benign_expansion_manifest_20261010.jsonl'):
        manifest = ROOT / 'docs' / 'benchmarks' / name
        candidate = {json.loads(line)['sha256'] for line in manifest.read_text(encoding='utf-8').splitlines() if line.strip()}
        provenance['installed_pe_overlaps'][name] = {s: sorted(candidate.intersection(x.decode() for x in a['sha'])) for s, a in meta.items()}
    (ART / "dataset_provenance.json").write_text(json.dumps(provenance, indent=2))
    if any(overlap.values()):
        raise ValueError("Local archive overlaps EMBER; stop for contamination review")
    return meta, provenance


def wilson(success, total):
    import math
    if total == 0:
        return {"value": None, "ci95": [None, None], "numerator": success, "denominator": total}
    p, z = success / total, 1.959963984540054
    denom = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denom
    radius = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denom
    return {"value": p, "ci95": [max(0, center - radius), min(1, center + radius)],
            "numerator": success, "denominator": total}


def operating_point(y, scores, threshold):
    import numpy as np
    # NumPy otherwise casts the scalar threshold to a float32 score dtype,
    # defeating nextafter's inclusive-tie protection (notably just above 1).
    scores = np.asarray(scores, dtype=np.float64)
    predicted = scores >= threshold
    tp = int(np.sum((y == 1) & predicted))
    fp = int(np.sum((y == 0) & predicted))
    tn = int(np.sum((y == 0) & ~predicted))
    fn = int(np.sum((y == 1) & ~predicted))
    return {"threshold": threshold, "comparison": ">=", "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "recall": wilson(tp, tp + fn), "fpr": wilson(fp, fp + tn),
            "precision": wilson(tp, tp + fp), "specificity": wilson(tn, tn + fp),
            "accuracy": wilson(tp + tn, len(y)), "f1": 2 * tp / (2 * tp + fp + fn)}


def evaluate(y, scores, thresholds):
    import numpy as np
    from sklearn.metrics import average_precision_score, roc_auc_score
    auc = roc_auc_score(y, scores)
    ap = average_precision_score(y, scores)
    rng = np.random.default_rng(0)
    classes = [np.flatnonzero(y == label) for label in (0, 1)]
    bootstrap = []
    for _ in range(200):
        indices = np.concatenate([rng.choice(c, len(c), replace=True) for c in classes])
        bootstrap.append((roc_auc_score(y[indices], scores[indices]),
                          average_precision_score(y[indices], scores[indices])))
    return {"n": len(y), "benign": int(np.sum(y == 0)), "malicious": int(np.sum(y == 1)),
            "roc_auc": float(auc), "average_precision": float(ap),
            "roc_auc_ci95": np.quantile(np.array(bootstrap)[:, 0], [0.025, 0.975]).tolist(),
            "average_precision_ci95": np.quantile(np.array(bootstrap)[:, 1], [0.025, 0.975]).tolist(),
            "ci_method": "Wilson proportions; 200 label-stratified paired score/label bootstrap replicates seed0 for AUC/AP; sample-level only",
            "operating_points": {name: operating_point(y, scores, t) for name, t in thresholds.items()}}


def run():
    import lightgbm as lgb
    import numpy as np
    import psutil
    started = time.monotonic()
    meta, provenance = prepare()
    print(f"DATA_READY rss={psutil.Process().memory_info().rss}", flush=True)
    X = {s: np.load(ART / "vectors" / f"X_{s}.npy", mmap_mode="r") for s in meta}
    params = json.loads((ART / "upstream" / "examples" / "lgbm_config.json").read_text())
    params.update(num_threads=8, deterministic=True, force_col_wise=True, verbosity=1)
    categorical = [2, 3, 4, 5, 6, 701, 702]
    train = lgb.Dataset(X["fit"], meta["fit"]["y"], categorical_feature=categorical)
    validation = lgb.Dataset(X["validation"], meta["validation"]["y"], reference=train,
                             categorical_feature=categorical)
    model_path = ART / "models" / "ember2024_win64_temporal_local.model"
    model_path.parent.mkdir(exist_ok=True)
    fit_started = time.monotonic()
    model = lgb.train(params, train, valid_sets=[validation], valid_names=["validation"],
                      callbacks=[lgb.log_evaluation(25)])
    fit_seconds = time.monotonic() - fit_started
    model.save_model(str(model_path))
    print(f"TRAINED rounds={model.current_iteration()} seconds={fit_seconds:.1f}", flush=True)
    scores = {s: model.predict(v, num_threads=8) for s, v in X.items() if s != "fit"}
    thresholds = {"default_0.5": 0.5,
                  "validation_fpr_1pct": validation_threshold(meta["validation"]["y"], scores["validation"], .01),
                  "validation_fpr_0.1pct": validation_threshold(meta["validation"]["y"], scores["validation"], .001)}
    np.savez(ART / "local_predictions.npz", **{f"{s}_scores": v for s, v in scores.items()})
    result = {"experiment_id": "ember2024-win64-20261010", "status": "completed",
              "scope": "full Win64 platform, temporal fit48/validation4/test12; not all-platform reproduction",
              "code_revision": "0ef753e81d98bf209f71b03cd331dfc190b5b54d",
              "dataset_revision": "3d23efef7c0f0b702c5024400cfff4c3744a3832",
              "fit_rows": len(meta["fit"]["y"]), "params": params,
              "python": sys.version,
              "package_versions": {name: importlib.metadata.version(name) for name in
                                   ("lightgbm", "numpy", "scikit-learn", "pefile", "signify", "orjson")},
              "model_path": str(model_path.relative_to(ROOT)),
              "model_sha256": hashlib.sha256(model_path.read_bytes()).hexdigest(),
              "fit_seconds": fit_seconds, "feature_dim": 2568,
              "validation": evaluate(meta["validation"]["y"], scores["validation"], thresholds),
              "test": evaluate(meta["test"]["y"], scores["test"], thresholds),
              "dataset_provenance": provenance}
    official_path = ART / "models" / "EMBER2024_Win64.model"
    official = lgb.Booster(model_file=str(official_path))
    official_scores = official.predict(X["test"], num_threads=8)
    np.save(ART / "official_test_scores.npy", official_scores)
    result["official_pretrained"] = {"description": "Separate pretrained reproduction; not locally trained; training may include our temporal validation weeks",
                                     "model_sha256": hashlib.sha256(official_path.read_bytes()).hexdigest(),
                                     "test": evaluate(meta["test"]["y"], official_scores, {"default_0.5": 0.5})}
    result["total_seconds"] = time.monotonic() - started
    destination = ROOT / "docs" / "benchmarks" / "ember2024_win64_20261010.json"
    destination.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"COMPLETED {destination} rss={psutil.Process().memory_info().rss}", flush=True)


if __name__ == "__main__":
    def hard_timeout():
        print("HARD TIMEOUT: stopping this experiment after four hours", file=sys.stderr, flush=True)
        os._exit(124)

    watchdog = threading.Timer(4 * 60 * 60, hard_timeout)
    watchdog.daemon = True
    watchdog.start()
    run()
    watchdog.cancel()
