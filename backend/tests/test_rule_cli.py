import json

from aegisav.rules_cli import main


def test_rule_cli_validates_registry(tmp_path, capsys):
    rule_dir = tmp_path / "rules"
    rule_dir.mkdir()
    (rule_dir / "one.yar").write_text("rule Generic_Bytes_Marker { condition: true }", encoding="utf-8")
    meta = tmp_path / "metadata.json"
    meta.write_text(json.dumps([{
        "rule_id": "Generic_Bytes_Marker", "family": "Generic", "feature_type": "Bytes",
        "description": "test", "author": "test", "source": "fixture", "version": "1",
        "confidence": "low", "scope": "test",
    }]), encoding="utf-8")
    assert main(["--rules", str(rule_dir), "--metadata", str(meta)]) == 0
    assert json.loads(capsys.readouterr().out)["rule_count"] == 1


def test_rule_cli_reports_empty_registry(tmp_path, capsys):
    rule_dir = tmp_path / "rules"
    rule_dir.mkdir()
    meta = tmp_path / "metadata.json"
    meta.write_text("[]", encoding="utf-8")
    assert main(["--rules", str(rule_dir), "--metadata", str(meta)]) == 0
    assert json.loads(capsys.readouterr().out)["rule_count"] == 0


def test_rule_cli_rejects_missing_rule_directory(tmp_path):
    meta = tmp_path / "metadata.json"
    meta.write_text("[]", encoding="utf-8")
    assert main(["--rules", str(tmp_path / "missing"), "--metadata", str(meta)]) == 1
