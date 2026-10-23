import hashlib
import json

import pytest

from aegisav.teaching_report import pe_details, export_workbook, attach_scan


def test_pe_details_are_static_and_bounded(pe_bytes):
    report = pe_details(pe_bytes)
    assert report['header']['machine'] == 0x14c
    assert report['sections'][0]['name'] == '.text'
    assert report['imports'] == [] and report['exports'] == []
    assert report['strings']['heuristic_only']


def test_workbook_keeps_missing_and_copies_original_evidence(tmp_path):
    source = tmp_path / 'source'
    source.mkdir()
    raw = b'\x89PNG\r\n\x1a\n' + b'harmless test fixture; not an actual screenshot'
    (source / 'defender.png').write_bytes(raw)
    manifest = {'schema': 1, 'source_kind': 'historical_course_evidence', 'samples': [
        {'sample_id': '01', 'name': '<sample>', 'sha256': 'a'*64, 'source': 'old chapter',
         'evidence': [{'path': 'defender.png', 'sha256': hashlib.sha256(raw).hexdigest(),
                       'kind': 'defender', 'identity_binding': 'chapter_order_only'}],
         'missing': ['current AegisAV scan']}]}
    output = tmp_path / 'out'
    export_workbook(manifest, source, output)
    data = json.loads((output / 'sample-01.json').read_text())
    assert data['engines']['clamav']['status'] == 'not_observed'
    assert data['defender']['status'] == 'imported_historical_evidence'
    assert data['defender']['identity_verified'] is False
    assert (output / data['evidence'][0]['path']).read_bytes() == raw
    assert '<sample>' not in (output / 'sample-01.md').read_text(encoding='utf-8')
    with pytest.raises(FileExistsError):
        export_workbook(manifest, source, output)


@pytest.mark.parametrize('path,digest', [('../outside.png', 'a'*64), ('defender.png', 'a'*64)])
def test_evidence_escape_and_mismatch_rejected(tmp_path, path, digest):
    (tmp_path / 'defender.png').write_bytes(b'inert')
    manifest = {'schema': 1, 'samples': [{'sample_id': '01', 'name': 'test', 'sha256': None,
                'evidence': [{'path': path, 'sha256': digest}]}]}
    with pytest.raises(ValueError):
        export_workbook(manifest, tmp_path, tmp_path / 'out')
    assert not (tmp_path / 'out').exists()


def test_scan_identity_must_match_and_absence_is_not_negative():
    sample = {'sha256': 'a'*64}
    with pytest.raises(ValueError):
        attach_scan(sample, {'sha256': 'b'*64, 'engines': {}})


def test_executable_disguised_as_evidence_is_refused(tmp_path):
    payload = b'MZ' + b'inert test bytes'
    (tmp_path / 'pretend.png').write_bytes(payload)
    manifest = {'schema': 1, 'samples': [{'sample_id': '01', 'sha256': None,
        'evidence': [{'path': 'pretend.png', 'sha256': hashlib.sha256(payload).hexdigest()}]}]}
    with pytest.raises(ValueError):
        export_workbook(manifest, tmp_path, tmp_path / 'out')
    assert not (tmp_path / 'out').exists()
