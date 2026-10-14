import json

import pytest

from aegisav.yara_engine import load_yara_engine


RULE = 'rule Generic_Bytes_TestMarker { strings: $a = "AEGIS_SAFE_MARKER" condition: $a }'
META = {
    "rule_id": "Generic_Bytes_TestMarker",
    "family": "Generic",
    "feature_type": "Bytes",
    "description": "Harmless test marker",
    "author": "AegisAV",
    "source": "synthetic fixture",
    "version": "1.0.0",
    "confidence": "low",
    "scope": "test only",
}


def make_rules(tmp_path, rule=RULE, metadata=None):
    rule_dir = tmp_path / "rules"
    rule_dir.mkdir()
    (rule_dir / "test.yar").write_text(rule, encoding="utf-8")
    meta_path = tmp_path / "metadata.json"
    meta_path.write_text(json.dumps([META] if metadata is None else metadata), encoding="utf-8")
    return rule_dir, meta_path


def test_yara_rule_reports_specific_evidence_and_clean_fixture_is_negative(tmp_path, pe_bytes):
    engine = load_yara_engine(*make_rules(tmp_path))
    hit = engine.scan(pe_bytes + b"AEGIS_SAFE_MARKER")
    clean = engine.scan(pe_bytes)
    assert hit["status"] == "matched"
    assert hit["evidence"][0]["rule_id"] == META["rule_id"]
    assert hit["evidence"][0]["version"] == "1.0.0"
    assert clean["status"] == "no_match"


@pytest.mark.parametrize("rule", [
    'rule bad_name { condition: true }',
    'rule Generic_Bad { condition: true }',
    'rule Generic_Bytes_Broken { condition: }',
])
def test_rule_validation_rejects_bad_name_or_syntax(tmp_path, rule):
    with pytest.raises(ValueError):
        load_yara_engine(*make_rules(tmp_path, rule=rule))


def test_rule_validation_rejects_duplicate_rule_ids(tmp_path):
    with pytest.raises(ValueError, match="Duplicate"):
        load_yara_engine(*make_rules(tmp_path, metadata=[META, META]))


def test_rule_words_in_comments_are_not_rule_declarations(tmp_path):
    rule = '// rule Fake_Bytes_Comment\n' + RULE
    engine = load_yara_engine(*make_rules(tmp_path, rule=rule))
    assert engine.metadata[META["rule_id"]]["version"] == "1.0.0"
