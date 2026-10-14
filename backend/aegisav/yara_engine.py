import hashlib
import json
import re
import time
from dataclasses import dataclass
from importlib.metadata import version
from pathlib import Path

import yara_x


REQUIRED = {"rule_id", "family", "feature_type", "description", "author", "source", "version", "confidence", "scope"}
RULE_NAME = re.compile(r"^(?:[A-Za-z][A-Za-z0-9]*)_[A-Za-z][A-Za-z0-9]*_[A-Za-z][A-Za-z0-9_]*$")
DECLARATION = re.compile(r"^\s*rule\s+([A-Za-z_][A-Za-z0-9_]*)\b", re.MULTILINE)


@dataclass
class YaraEngine:
    rules: yara_x.Rules
    metadata: dict[str, dict]
    artifact_version: str
    timeout_seconds: int

    def scan(self, data: bytes) -> dict:
        started = time.perf_counter()
        evidence = []
        try:
            scanner = yara_x.Scanner(self.rules)
            scanner.set_timeout(self.timeout_seconds)
            for rule in scanner.scan(data).matching_rules:
                evidence.append({
                    "rule_id": rule.identifier,
                    "version": self.metadata[rule.identifier]["version"],
                    "source": self.metadata[rule.identifier]["source"],
                    "matches": [
                        {"pattern": pattern.identifier, "offset": match.offset, "length": match.length}
                        for pattern in rule.patterns for match in pattern.matches
                    ],
                })
            status = "matched" if evidence else "no_match"
        except yara_x.TimeoutError:
            status = "timeout"
        except yara_x.ScanError:
            status = "error"
        return {
            "engine_id": "yara_x", "engine_version": version("yara-x"),
            "artifact_version": self.artifact_version, "status": status,
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
            "risk_signal": "suspicious" if evidence else None, "evidence": evidence,
        }


def load_yara_engine(rule_dir: Path, metadata_file: Path, timeout_seconds: int = 2) -> YaraEngine:
    files = sorted(rule_dir.glob("*.yar"))
    metadata = json.loads(metadata_file.read_text(encoding="utf-8"))
    if not files or not isinstance(metadata, list):
        raise ValueError("Rules and metadata list are required")
    by_id = {}
    for item in metadata:
        if not isinstance(item, dict) or not REQUIRED <= item.keys():
            raise ValueError("Rule metadata is incomplete")
        name = item["rule_id"]
        if name in by_id:
            raise ValueError(f"Duplicate rule ID: {name}")
        if len(name) > 50 or not RULE_NAME.fullmatch(name) or name.split("_")[0] != item["family"] or name.split("_")[1] != item["feature_type"]:
            raise ValueError(f"Invalid rule name: {name}")
        by_id[name] = item
    sources = [file.read_text(encoding="utf-8") for file in files]
    names = [name for source in sources for name in DECLARATION.findall(source)]
    if len(names) != len(set(names)):
        raise ValueError("Duplicate rule declaration")
    if set(names) != set(by_id):
        raise ValueError("Rule IDs and metadata do not match")
    try:
        compiled = yara_x.compile("\n".join(sources))
    except yara_x.CompileError as exc:
        raise ValueError(f"Invalid YARA-X syntax: {exc}") from exc
    digest = hashlib.sha256(("\n".join(sources) + json.dumps(metadata, sort_keys=True)).encode()).hexdigest()[:16]
    return YaraEngine(compiled, by_id, digest, timeout_seconds)
