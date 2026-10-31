import hashlib
import io
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
    source_sha256: str

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


def load_yara_engine(rule_dir: Path, metadata_file: Path, timeout_seconds: int = 2,
                     *, compiled_file: Path | None = None, compiled_sha256: str | None = None) -> YaraEngine:
    if (compiled_file is None) != (compiled_sha256 is None):
        raise ValueError("Compiled file and trusted digest must be provided together")
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
    source = "\n".join(sources)
    digest = hashlib.sha256((source + json.dumps(metadata, sort_keys=True)).encode()).hexdigest()
    if compiled_file is None:
        try:
            compiled = yara_x.compile(source)
        except yara_x.CompileError as exc:
            raise ValueError(f"Invalid YARA-X syntax: {exc}") from exc
    else:
        # The digest comes from trusted deployment configuration, not the bundle.
        # Deserialize the exact verified bytes; never reopen the path afterwards.
        with Path(compiled_file).open('rb') as stream:
            raw = stream.read(8 * 1024**2 + 1)
        if len(raw) > 8 * 1024**2:
            raise ValueError('Compiled YARA bundle size limit')
        if hashlib.sha256(raw).hexdigest() != compiled_sha256:
            raise ValueError('Compiled YARA bundle digest mismatch')
        try:
            header, payload = raw.split(b'\n', 1)
            manifest = json.loads(header)
            if manifest['schema'] != 1 or manifest['yara_version'] != version('yara-x'):
                raise ValueError('Compiled YARA bundle version mismatch')
            if manifest['source_sha256'] != digest:
                raise ValueError('Compiled YARA bundle source mismatch')
            compiled = yara_x.Rules.deserialize_from(io.BytesIO(payload))
        except (KeyError, TypeError, yara_x.CompileError) as exc:
            raise ValueError('Invalid compiled YARA bundle') from exc
    return YaraEngine(compiled, by_id, digest[:16], timeout_seconds, digest)
