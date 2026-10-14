import pytest

from experiments.summarize_static_archive import summarize


def test_summary_rejects_label_reference_for_different_archive():
    with pytest.raises(ValueError, match='archive'):
        summarize({'archive_sha256': 'a' * 64}, {'source_archive_sha256': 'b' * 64})


def test_unknown_labels_and_non_pe_do_not_enter_proxy_detection_denominator():
    engines = {name: {'status': 'matched', 'elapsed_ms': 1} for name in ('sha256', 'fuzzy', 'yara_x', 'clamav')}
    files = [{'sha256': 'a' * 64, 'pe_valid': True, 'duplicate': False, 'engines': engines, 'elapsed_ms': 2},
             {'sha256': 'b' * 64, 'pe_valid': True, 'duplicate': False, 'engines': engines, 'elapsed_ms': 2},
             {'sha256': 'c' * 64, 'pe_valid': False, 'duplicate': False, 'engines': {}, 'elapsed_ms': 0}]
    result = summarize({'archive_sha256': 'd' * 64, 'files': files, 'errors': []},
                       {'source_archive_sha256': 'd' * 64, 'samples': [{'sha256': 'a' * 64, 'label': 'malicious_proxy'}]})
    assert result['pe_label_counts'] == {'malicious_proxy': 1, 'unknown': 1}
    assert result['proxy_engines']['clamav']['malicious_count'] == 1
    assert result['formal_acceptance'] is False


def test_duplicate_keeps_first_scan_timing():
    engines = {name: {'status': 'no_match', 'elapsed_ms': 1} for name in ('sha256', 'fuzzy', 'yara_x', 'clamav')}
    first = {'sha256': 'a' * 64, 'pe_valid': True, 'duplicate': False, 'engines': engines, 'elapsed_ms': 50}
    repeated = dict(first, duplicate=True, elapsed_ms=2)
    result = summarize({'archive_sha256': 'd' * 64, 'files': [first, repeated], 'errors': []},
                       {'source_archive_sha256': 'd' * 64, 'samples': []})
    assert result['sequential_unique_pe_scan_ms'] == 50
