import json

import pytest

from vm.benign_checkpoint import load_checkpoint, save_checkpoint
from vm.static_benign import validate_resume


def state():
    return {'identity': {'manifest': 'a' * 64, 'tools': 'v1'},
            'sessions': [{'isolation': 'AEGISAV_ISOLATION PASS boot=a', 'resume_index': 0}],
            'report': {'files': [{'path': 'samples/a.exe', 'sha256': 'b' * 64}]}}


def test_roundtrip_and_changed_identity_refused(tmp_path):
    path = tmp_path / 'checkpoint.json'
    payload = state()
    save_checkpoint(path, payload)
    assert load_checkpoint(path, payload['identity']) == payload
    with pytest.raises(ValueError, match='identity'):
        load_checkpoint(path, {'manifest': 'a' * 64, 'tools': 'v2'})


def test_truncation_and_changed_record_refused(tmp_path):
    path = tmp_path / 'checkpoint.json'
    save_checkpoint(path, state())
    envelope = json.loads(path.read_text())
    envelope['payload']['report']['files'][0]['sha256'] = 'c' * 64
    path.write_text(json.dumps(envelope))
    with pytest.raises(ValueError, match='checksum'):
        load_checkpoint(path, state()['identity'])
    path.write_text('{')
    with pytest.raises(ValueError):
        load_checkpoint(path, state()['identity'])


def test_interrupted_atomic_replace_preserves_last_complete_record(tmp_path, monkeypatch):
    path = tmp_path / 'checkpoint.json'
    payload = state()
    save_checkpoint(path, payload)
    def interrupt(*args):
        raise OSError('simulated power interruption before replace')
    monkeypatch.setattr('vm.benign_checkpoint.os.replace', interrupt)
    with pytest.raises(OSError):
        save_checkpoint(path, dict(payload, report={'files': []}))
    assert load_checkpoint(path, payload['identity']) == payload


def test_unexpected_envelope_and_oversize_refused(tmp_path):
    path = tmp_path / 'checkpoint.json'
    save_checkpoint(path, state())
    envelope = json.loads(path.read_text())
    envelope['extra'] = 'untrusted'
    path.write_text(json.dumps(envelope))
    with pytest.raises(ValueError):
        load_checkpoint(path, state()['identity'])
    with pytest.raises(ValueError):
        save_checkpoint(path, dict(state(), padding='x' * (2 * 1024**2)))


def test_resume_requires_manifest_prefix_and_complete_count():
    engines = {name: {'status': 'no_match', 'engine_version': 'test', 'artifact_version': 'test',
                      'elapsed_ms': 1.0, 'evidence': []}
               for name in ('sha256', 'fuzzy', 'yara_x', 'clamav', 'lightgbm')}
    engines['fuzzy']['hashes'] = {'tlsh': None, 'ssdeep': '3:abc:abc'}
    engines['lightgbm'].update(score=.1, threshold=.5, feature_elapsed_ms=.8, inference_elapsed_ms=.2)
    row = {'path': 'samples/a.exe', 'sha256': 'b' * 64, 'size_bytes': 1024,
           'pe_valid': True, 'duplicate': False, 'elapsed_ms': 10., 'engines': engines}
    report = {'schema': 2, 'manifest_sha256': 'a' * 64, 'isolation': 'AEGISAV_ISOLATION PASS boot=x',
              'files': [row], 'errors': [], 'completed': False}
    rows = [dict(path=row['path'], sha256=row['sha256']), dict(path='samples/b.exe', sha256='c' * 64)]
    validate_resume(report, rows, 'a' * 64)
    with pytest.raises(ValueError, match='prefix'):
        validate_resume(report, list(reversed(rows)), 'a' * 64)
    with pytest.raises(ValueError, match='Incomplete'):
        validate_resume(dict(report, completed=True), rows, 'a' * 64)
