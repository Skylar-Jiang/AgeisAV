import json
import hashlib
from pathlib import Path

from aegisav.yara_engine import load_yara_engine


RULE_DIR = Path(__file__).resolve().parents[2] / "rules" / "yara"


def test_bundled_yara_rules_load_with_provenance_and_do_not_match_clean_pe(pe_bytes):
    metadata = json.loads((RULE_DIR / "metadata.json").read_text(encoding="utf-8"))
    audit = json.loads((RULE_DIR.parents[1] / 'docs' / 'benchmarks' /
                        'upstream_windows_rule_audit_20261003.json').read_text(encoding='utf-8'))
    assert len(metadata) == 246
    assert {item['upstream_path'] for item in metadata} == {item['source'] for item in audit['sources']}
    assert {'StealC_Code_Infostealer', 'TrickBot_Code_Trojan'} <= {item['rule_id'] for item in metadata}
    assert all(item["license"] == "MIT" and item["upstream_revision"] for item in metadata)
    assert all(item['reverse_transform_verified'] for item in metadata)
    assert all(hashlib.sha256((RULE_DIR / item['canonical_file']).read_bytes()).hexdigest() ==
               item['canonical_source_sha256'] for item in metadata)

    engine = load_yara_engine(RULE_DIR, RULE_DIR / "metadata.json")
    assert engine.scan(pe_bytes)["status"] == "no_match"
