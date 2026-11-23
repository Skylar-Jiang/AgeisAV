import io
import struct
import zipfile

import pytest

from vm.static_archive import walk_archive, validate_export


def archive(entries):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w', zipfile.ZIP_DEFLATED) as output:
        for name, data in entries:
            output.writestr(name, data)
    return stream.getvalue()


def test_nested_archive_reads_bytes_without_extracting(tmp_path):
    outer = archive([('nested.zip', archive([('harmless.txt', b'hello')])),
                     ('zip-compatible.exe', archive([('resource.txt', b'resource')]))])
    files, errors = [], []
    walk_archive(outer, b'example', lambda name, data: files.append((name, data)), errors)
    assert files[0] == ('nested.zip!/harmless.txt', b'hello')
    assert files[1][0] == 'zip-compatible.exe'
    assert errors == []
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize('name', ['../escape.exe', '/absolute.exe', 'C:/escape.exe', 'safe/../../x.exe'])
def test_unsafe_archive_paths_are_rejected(name):
    files, errors = [], []
    walk_archive(archive([(name, b'hello')]), b'', lambda n, d: files.append(n), errors)
    assert files == []
    assert errors[0]['reason'] == 'unsafe_path'


def test_archive_budget_fails_before_reading_oversized_member():
    files, errors = [], []
    walk_archive(archive([('large.txt', b'a' * 50)]), b'', lambda n, d: files.append(n), errors,
                 budget={'bytes': 10, 'members': 10})
    assert files == []
    assert errors[0]['reason'] == 'size_limit'


def test_export_rejects_extra_binary_channel_and_invalid_digest():
    valid = {'schema': 1, 'archive_sha256': 'a' * 64, 'isolation': 'AEGISAV_ISOLATION PASS boot=x',
             'files': [], 'errors': [], 'completed': True}
    validate_export(valid)
    with pytest.raises(ValueError):
        validate_export(dict(valid, sample_base64='c2FtcGxl'))
    with pytest.raises(ValueError):
        validate_export(dict(valid, archive_sha256='invalid'))


def test_directory_entries_count_toward_archive_item_budget():
    files, errors = [], []
    walk_archive(archive([('one/', b''), ('two/', b''), ('three/', b''), ('leaf.txt', b'hello')]),
                 b'', lambda n, d: files.append(n), errors, budget={'bytes': 1000, 'members': 2})
    assert files == []
    assert errors[0]['reason'] == 'member_limit'


def test_nested_exhaustion_stops_parent_before_next_leaf():
    files, errors = [], []
    walk_archive(archive([('child.zip', archive([('one.txt', b'a'), ('two.txt', b'b')])),
                          ('later.txt', b'c')]), b'', lambda n, d: files.append(n), errors,
                 budget={'bytes': 1000, 'members': 2})
    assert files == []
    assert len(errors) == 1
    assert errors[0]['reason'] == 'member_limit'


def test_zip64_directory_override_hidden_in_comment_is_rejected():
    stream = io.BytesIO()
    item = zipfile.ZipInfo('harmless.txt')
    item.comment = struct.pack('<4sQ2H2L4Q', b'PK\x06\x06', 44, 45, 45, 0, 0, 0, 0, 0, 0)
    item.comment += struct.pack('<4sLQL', b'PK\x06\x07', 0, 0, 1)
    with zipfile.ZipFile(stream, 'w') as output:
        output.writestr(item, b'hello')
    errors = []
    walk_archive(stream.getvalue(), b'', lambda n, d: None, errors)
    assert errors == [{'path': '', 'reason': 'invalid_zip'}]


def test_exact_nested_budget_exhaustion_records_skipped_parent_members():
    files, errors = [], []
    walk_archive(archive([('child.zip', archive([('one.txt', b'a')])), ('later.txt', b'b')]),
                 b'', lambda n, d: files.append(n), errors, budget={'bytes': 1000, 'members': 2})
    assert files == ['child.zip!/one.txt']
    assert errors == [{'path': '', 'reason': 'member_limit'}]


def test_schema2_exports_only_bounded_fuzzy_digests_and_model_score():
    engines = {name: {'status': 'no_match', 'engine_version': 'test', 'artifact_version': 'test',
                      'elapsed_ms': 1.0, 'evidence': []}
               for name in ('sha256', 'fuzzy', 'yara_x', 'clamav', 'lightgbm')}
    engines['fuzzy']['hashes'] = {'tlsh': None, 'ssdeep': '3:abc:abc'}
    engines['lightgbm'].update(score=0.125, threshold=0.5, feature_elapsed_ms=0.8, inference_elapsed_ms=0.2)
    row = {'path': 'harmless.exe', 'sha256': 'b' * 64, 'size_bytes': 1024,
           'pe_valid': True, 'duplicate': False, 'elapsed_ms': 10.0, 'engines': engines}
    report = {'schema': 2, 'archive_sha256': 'a' * 64,
              'isolation': 'AEGISAV_ISOLATION PASS boot=x', 'files': [row], 'errors': [], 'completed': True}
    validate_export(report)
    engines['lightgbm']['score'] = float('nan')
    with pytest.raises(ValueError):
        validate_export(report)
    engines['lightgbm']['score'] = 0.125
    engines['fuzzy']['hashes']['ssdeep'] = 'binary data\n'
    with pytest.raises(ValueError):
        validate_export(report)


def test_relabelled_runtimebroker_is_unknown_and_cannot_be_a_negative():
    import json
    from pathlib import Path
    from experiments.summarize_static_archive import summarize
    root = Path(__file__).resolve().parents[2]
    if not (root / 'docs/benchmarks/user_archive_label_reference_20261010.json').exists() or not (root / 'docs/benchmarks/user_archive_static_20261003.json').exists():
        import pytest
        pytest.skip('Private archive evidence is excluded from the public source distribution')
    reference = json.loads((root / 'docs/benchmarks/user_archive_label_reference_20261010.json').read_text(encoding='utf-8'))
    report = json.loads((root / 'docs/benchmarks/user_archive_static_20261003.json').read_text(encoding='utf-8'))
    result = summarize(report, reference)
    assert result['pe_label_counts'] == {'malicious_proxy': 109, 'unknown': 1}
    assert result['proxy_engines']['clamav']['benign_count'] == 0
    assert result['proxy_engines']['clamav']['fpr'] is None


def test_non_pe_is_recorded_without_invoking_any_scanner():
    from vm.static_archive import scan_file
    class Forbidden:
        def scan(self, data):
            raise AssertionError('A non-PE reached a scanner')
    seen = set()
    result = scan_file('harmless.txt', b'hello', Forbidden(), Forbidden(), seen)
    assert result['pe_valid'] is False
    assert result['engines'] == {}
    assert result['sha256'] in seen
