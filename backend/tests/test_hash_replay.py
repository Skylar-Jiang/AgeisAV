import hashlib
import json

import pytest

from aegisav.hashes import HashDatabase, compute_fuzzy
from experiments.evaluate_hash_replay import evaluate_replay


def replay_fixture(tmp_path, pe_bytes):
    digest = hashlib.sha256(pe_bytes).hexdigest()
    manifest = tmp_path / 'manifest.jsonl'
    manifest.write_text(json.dumps({'sha256': digest, 'label': 'benign', 'source': 'synthetic fixture'}) + '\n')
    report = {'manifest_sha256': hashlib.sha256(manifest.read_bytes()).hexdigest(),
              'reports': [{'sha256': digest, 'engines': {'fuzzy': {'hashes': compute_fuzzy(pe_bytes)}}}]}
    return manifest, report


def test_hash_replay_rejects_a_different_manifest(tmp_path, pe_bytes):
    manifest, report = replay_fixture(tmp_path, pe_bytes)
    report['manifest_sha256'] = 'a' * 64
    with pytest.raises(ValueError, match='manifest'):
        evaluate_replay(manifest, report, HashDatabase.from_records([]))


def test_hash_replay_measures_candidates_without_claiming_file_scan(tmp_path, pe_bytes):
    manifest, report = replay_fixture(tmp_path, pe_bytes)
    database = HashDatabase.from_records([{'sha256': 'a' * 64, 'verdict': 'malicious',
                                          'source': 'synthetic fixture', **compute_fuzzy(pe_bytes)}])
    result = evaluate_replay(manifest, report, database)
    assert result['method'] == 'precomputed_hash_replay'
    assert result['sha256']['fp'] == 0
    assert result['fuzzy']['fp'] == 1
