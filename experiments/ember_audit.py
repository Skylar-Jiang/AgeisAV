"""Audit local SHA manifests against persisted public EMBER split metadata."""
import hashlib
import json
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "docs" / "benchmarks"
VECTORS = ROOT / "artifacts" / "ember2024" / "vectors"


def run():
    split_sha = {}
    split_metadata = {}
    for split in ("fit", "validation", "test"):
        path = VECTORS / f"meta_{split}.npz"
        with np.load(path) as data:
            split_sha[split] = {s.decode() for s in data["sha"]}
        split_metadata[split] = {"path": str(path.relative_to(ROOT)),
                                 "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                                 "unique_samples": len(split_sha[split])}
    groups, sources = {}, []
    for filename, default in (
        ("benign_windows_pe_manifest.jsonl", "windows_installed"),
        ("benign_vendor_pe_manifest.jsonl", "vendor_installed"),
        ("benign_expansion_manifest_20261010.jsonl", "expansion_installed"),
    ):
        path = BENCH / filename
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
        sources.append({"path": str(path.relative_to(ROOT)), "rows": len(rows),
                        "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
        for row in rows:
            group = row.get("group", default)
            groups.setdefault(group, []).append(row["sha256"].lower())
    audit = {}
    for group, hashes in groups.items():
        unique = set(hashes)
        overlap = {s: sorted(unique.intersection(values)) for s, values in split_sha.items()}
        audit[group] = {"rows": len(hashes), "unique_sha": len(unique),
                        "overlap_counts": {s: len(v) for s, v in overlap.items()},
                        "overlap_sha256": overlap}
    result = {"scope": "SHA identity audit only; installed-file labels are benign proxies, not independent final ground truth",
              "official_data_changed": False, "sources": sources,
              "persistent_ember_sha_metadata": split_metadata, "groups": audit}
    destination = BENCH / "ember2024_local_sha_audit_20261010.json"
    destination.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    run()
