import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path

import ppdeep
import tlsh


@dataclass(frozen=True)
class HashDatabase:
    records: tuple[dict, ...]
    by_sha: dict[str, dict]
    fuzzy_records: tuple[dict, ...]

    @classmethod
    def from_records(cls, records: list[dict]) -> "HashDatabase":
        seen = set()
        for record in records:
            digest = record["sha256"]
            if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise ValueError("Invalid SHA-256 digest")
            if digest in seen:
                raise ValueError("Duplicate SHA-256 digest")
            if not record.get("source"):
                raise ValueError("Hash source is required")
            if record.get("verdict") not in {None, "malicious", "benign"}:
                raise ValueError("Invalid hash verdict")
            for field, compare in (("tlsh", tlsh.diff), ("ssdeep", ppdeep.compare)):
                value = record.get(field)
                if value is not None:
                    try:
                        if not isinstance(value, str):
                            raise ValueError()
                        compare(value, value)
                    except (ValueError, AssertionError, TypeError) as exc:
                        raise ValueError(f"Invalid {field} digest") from exc
            seen.add(digest)
        copies = tuple(dict(record) for record in records)
        return cls(copies, {r["sha256"]: r for r in copies},
                   tuple(r for r in copies if r.get("verdict") == "malicious" and
                         (r.get("tlsh") or r.get("ssdeep"))))

    @classmethod
    def from_file(cls, path: Path) -> "HashDatabase":
        records = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(records, list):
            raise ValueError("Hash database must be a JSON list")
        return cls.from_records(records)


def compute_fuzzy(data: bytes, ssdeep_hash=None) -> dict[str, str | None]:
    try:
        # The binding converts an update buffer into a native integer sequence.
        # Bound conversion memory for large PEs in the restricted analysis worker.
        hasher = tlsh.Tlsh()
        for offset in range(0, len(data), 1024 * 1024):
            hasher.update(data[offset:offset + 1024 * 1024])
        hasher.final()
        tlsh_hash = hasher.hexdigest(ver=1)
    except AssertionError:
        tlsh_hash = None
    return {"tlsh": tlsh_hash, "ssdeep": (ssdeep_hash or ppdeep.hash)(data) or None}


def hash_scan(data: bytes, database: HashDatabase, digest: str | None = None, ssdeep_hash=None) -> dict:
    exact_started = time.perf_counter()
    digest = digest or hashlib.sha256(data).hexdigest()
    found = database.by_sha.get(digest)
    exact_ms = (time.perf_counter() - exact_started) * 1000
    fuzzy_started = time.perf_counter()
    fuzzy = compute_fuzzy(data) if ssdeep_hash is None else compute_fuzzy(data, ssdeep_hash)
    candidates = []
    for record in database.fuzzy_records:
        if record["sha256"] == digest:
            continue
        if fuzzy["tlsh"] and record.get("tlsh"):
            distance = tlsh.diff(fuzzy["tlsh"], record["tlsh"])
            if distance <= 40:
                candidates.append({"sha256": record["sha256"], "source": record["source"], "method": "tlsh", "distance": distance})
        if fuzzy["ssdeep"] and record.get("ssdeep"):
            similarity = ppdeep.compare(fuzzy["ssdeep"], record["ssdeep"])
            if similarity >= 80:
                candidates.append({"sha256": record["sha256"], "source": record["source"], "method": "ssdeep", "similarity": similarity})
    return {
        "sha256": digest,
        "exact": {
            "status": "matched" if found else "no_match",
            "evidence": [found] if found else [],
            "elapsed_ms": exact_ms,
        },
        "fuzzy": {"status": "matched" if candidates else "no_match", "evidence": candidates,
                  "hashes": fuzzy, "elapsed_ms": (time.perf_counter() - fuzzy_started) * 1000},
    }
