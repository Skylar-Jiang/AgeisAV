import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from aegisav.yara_engine import load_yara_engine
from test_yara_rules import RULE, make_rules


def bundle_for(tmp_path):
    from experiments.yara_bundle import build_bundle
    rules, metadata = make_rules(tmp_path)
    output = tmp_path / 'rules.bundle'
    digest = build_bundle(rules, metadata, output)
    return rules, metadata, output, digest


def test_bundle_reuses_compilation_with_identical_positive_and_negative_evidence(tmp_path, pe_bytes, monkeypatch):
    rules, metadata, output, digest = bundle_for(tmp_path)
    reference = load_yara_engine(rules, metadata)
    def unexpected_compile(*args, **kwargs):
        pytest.fail('A verified bundle must not compile rules again')
    monkeypatch.setattr('aegisav.yara_engine.yara_x.compile', unexpected_compile)
    candidate = load_yara_engine(rules, metadata, compiled_file=output, compiled_sha256=digest)
    for data in (b'', pe_bytes, pe_bytes + b'AEGIS_SAFE_MARKER', b'AEGIS_SAFE_MARKER' * 20):
        before, after = reference.scan(data), candidate.scan(data)
        before.pop('elapsed_ms'); after.pop('elapsed_ms')
        assert before == after


def test_bundle_rejects_changed_bytes(tmp_path):
    rules, metadata, output, digest = bundle_for(tmp_path)
    output.write_bytes(output.read_bytes() + b'changed')
    with pytest.raises(ValueError, match='digest'):
        load_yara_engine(rules, metadata, compiled_file=output, compiled_sha256=digest)


@pytest.mark.parametrize('change', ['source', 'metadata'])
def test_bundle_rejects_changed_rules_or_provenance(tmp_path, change):
    rules, metadata, output, digest = bundle_for(tmp_path)
    if change == 'source':
        (rules / 'test.yar').write_text(RULE.replace('AEGIS_SAFE_MARKER', 'ANOTHER_MARKER'))
    else:
        content = json.loads(metadata.read_text())
        content[0]['version'] = '2.0.0'
        metadata.write_text(json.dumps(content))
    with pytest.raises(ValueError, match='source'):
        load_yara_engine(rules, metadata, compiled_file=output, compiled_sha256=digest)


def test_bundle_rejects_runtime_version_mismatch(tmp_path):
    rules, metadata, output, _ = bundle_for(tmp_path)
    header, payload = output.read_bytes().split(b'\n', 1)
    header = json.loads(header)
    header['yara_version'] = 'unvalidated-version'
    raw = json.dumps(header).encode() + b'\n' + payload
    output.write_bytes(raw)
    with pytest.raises(ValueError, match='version'):
        load_yara_engine(rules, metadata, compiled_file=output, compiled_sha256=hashlib.sha256(raw).hexdigest())


def test_bundle_rejects_over_budget_and_incomplete_configuration(tmp_path):
    rules, metadata = make_rules(tmp_path)
    output = tmp_path / 'oversized.bundle'
    output.write_bytes(b'X' * (8 * 1024**2 + 1))
    with pytest.raises(ValueError, match='size'):
        load_yara_engine(rules, metadata, compiled_file=output, compiled_sha256='0' * 64)
    with pytest.raises(ValueError, match='together'):
        load_yara_engine(rules, metadata, compiled_file=output)
    with pytest.raises(ValueError, match='together'):
        load_yara_engine(rules, metadata, compiled_sha256='0' * 64)


def test_bundle_builder_preserves_existing_candidate(tmp_path):
    from experiments.yara_bundle import build_bundle
    rules, metadata, output, digest = bundle_for(tmp_path)
    assert hashlib.sha256(output.read_bytes()).hexdigest() == digest
    with pytest.raises(FileExistsError):
        build_bundle(rules, metadata, output)
    assert hashlib.sha256(output.read_bytes()).hexdigest() == digest


def test_experiment_worker_uses_declared_backend_and_explicit_ssdeep_mode(tmp_path):
    from experiments.yara_bundle import worker_command
    package = tmp_path / 'backend/aegisav'
    package.mkdir(parents=True)
    (package / '__init__.py').write_text('')
    (package / 'scan_process.py').write_text('MAX_REPORT=1024\ndef contain_worker(): pass\n')
    (package / 'runtime.py').write_text(
        'import os\nclass Scanner:\n def scan(self,data): return {"source":"declared-snapshot",'
        '"ssdeep_mode":os.environ["AEGISAV_SSDEEP_BACKEND"]}\n'
        'def build_scanner(): return Scanner()\n')
    completed = subprocess.run(worker_command(tmp_path, sys.executable), input=b'inert control',
        capture_output=True, timeout=10, env=dict(os.environ, AEGISAV_SSDEEP_BACKEND='unrecognized'))
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {'report': {'source': 'declared-snapshot', 'ssdeep_mode': 'python'}}


def test_comparison_rejects_conflicting_candidate_modes_before_scanning(tmp_path):
    root = Path(__file__).resolve().parents[2]
    command = [sys.executable, '-B', '-m', 'experiments.compare_task_latency',
               '--baseline-root', str(tmp_path / 'missing-backend'), '--output', str(tmp_path / 'result.json'),
               '--native-candidate', '--candidate-yara-bundle', str(tmp_path / 'bundle'),
               '--candidate-yara-sha256', '0' * 64]
    completed = subprocess.run(command, cwd=root, capture_output=True, timeout=10)
    assert completed.returncode != 0
    assert b'separate comparisons' in completed.stderr
