import hashlib
import random

import ppdeep
import tlsh

from aegisav.hashes import HashDatabase, compute_fuzzy
from experiments.hash_diagnostics import diagnose_report, functional_probe


def test_functional_probe_matches_real_changed_bytes_and_excludes_self(pe_bytes):
    data = pe_bytes + random.Random(42).randbytes(8192)
    result = functional_probe(data)
    assert result['test_only'] is True
    assert result['original_sha256'] == hashlib.sha256(data).hexdigest()
    assert result['changed_byte_count'] == 1
    assert result['exact']['status'] == 'matched'
    assert result['exact']['evidence_count'] == 1
    assert result['self_fuzzy']['status'] == 'no_match'
    assert result['self_fuzzy']['evidence_count'] == 0
    assert result['changed_exact']['status'] == 'no_match'
    assert result['changed_fuzzy']['status'] == 'matched'
    assert result['changed_fuzzy']['evidence_count'] == 2
    assert set(result['changed_fuzzy']['methods']) == {'tlsh', 'ssdeep'}
    assert result['benign_reference_fuzzy']['status'] == 'no_match'
    assert result['unlabelled_reference_fuzzy']['status'] == 'no_match'
    assert result['empty_database_exact']['status'] == 'no_match'
    original, changed = result['original_hashes'], result['changed_hashes']
    assert result['native_comparison']['tlsh_distance'] == tlsh.diff(original['tlsh'], changed['tlsh'])
    assert result['native_comparison']['ssdeep_similarity'] == ppdeep.compare(original['ssdeep'], changed['ssdeep'])


def test_report_diagnostics_separates_unexported_hashes_from_threshold_failure(pe_bytes):
    digest = hashlib.sha256(pe_bytes).hexdigest()
    db = HashDatabase.from_records([{'sha256': digest, 'source': 'fixture', 'verdict': 'malicious',
                                    **compute_fuzzy(pe_bytes)}])
    rows = [{'sha256': digest, 'pe_valid': True, 'engines': {'fuzzy': {'status': 'no_match'}}}] * 2
    result = diagnose_report({'files': rows}, db)
    assert result['sample_count'] == 1
    assert result['duplicate_rows'] == 1
    assert result['exact_reference_intersection'] == [digest]
    assert result['hash_export']['missing_hash_object'] == 1
    assert result['comparisons'][0]['self_excluded'] is True
    assert result['comparisons'][0]['tlsh_distance'] is None
    assert result['raw_comparison_summary']['tlsh_scored_pairs'] == 0
    assert result['raw_comparison_summary']['all_pairs_scored'] is False


def test_report_diagnostics_keeps_raw_values_even_for_threshold_failure(pe_bytes):
    query = compute_fuzzy(pe_bytes)
    reference = compute_fuzzy(random.Random(11).randbytes(80000))
    db = HashDatabase.from_records([{'sha256': 'a' * 64, 'source': 'fixture', 'verdict': 'malicious', **reference},
                                    {'sha256': 'b' * 64, 'source': 'benign', 'verdict': 'benign', **query}])
    report = {'reports': [{'sha256': hashlib.sha256(pe_bytes).hexdigest(),
                           'engines': {'fuzzy': {'hashes': query}}}]}
    result = diagnose_report(report, db)
    assert result['reference_count'] == 2
    assert result['malicious_fuzzy_reference_count'] == 1
    assert result['comparison_pair_count'] == 1
    pair = result['comparisons'][0]
    assert pair['tlsh_distance'] == tlsh.diff(query['tlsh'], reference['tlsh'])
    assert pair['ssdeep_similarity'] == ppdeep.compare(query['ssdeep'], reference['ssdeep'])
    assert pair['tlsh_pass'] is False
    assert pair['ssdeep_pass'] is False
    assert result['raw_comparison_summary']['tlsh_scored_pairs'] == 1
    assert result['raw_comparison_summary']['all_pairs_scored'] is True


def test_report_diagnostics_distinguishes_exported_null_hashes(pe_bytes):
    report = {'files': [{'sha256': hashlib.sha256(pe_bytes).hexdigest(), 'pe_valid': True,
                         'engines': {'fuzzy': {'hashes': {'tlsh': None, 'ssdeep': None}}}},
                        {'sha256': 'c' * 64, 'pe_valid': False}]}
    result = diagnose_report(report, HashDatabase.from_records([]))
    assert result['sample_count'] == 1
    assert result['non_pe_rows'] == 1
    assert result['hash_export']['missing_hash_object'] == 0
    assert result['hash_export']['tlsh_null'] == 1
    assert result['hash_export']['ssdeep_null'] == 1


def test_report_diagnostics_retains_first_scan_when_duplicate_omits_hashes(pe_bytes):
    digest = hashlib.sha256(pe_bytes).hexdigest()
    report = {'files': [{'sha256': digest, 'engines': {'fuzzy': {'hashes': compute_fuzzy(pe_bytes)}}},
                        {'sha256': digest, 'duplicate': True, 'engines': {'fuzzy': {}}}]}
    result = diagnose_report(report, HashDatabase.from_records([]))
    assert result['duplicate_rows'] == 1
    assert result['hash_export']['missing_hash_object'] == 0
    assert result['hash_export']['tlsh_available'] == 1


def test_report_timing_uses_parallel_critical_path_and_labels_quantiles():
    rows = [{'sha256': f'{index:064x}', 'size_bytes': index * 1024, 'elapsed_ms': index * 100,
             'engines': {name: {'elapsed_ms': index * scale} for name, scale in
                         [('sha256', 1), ('fuzzy', 30), ('yara_x', 5), ('clamav', 60)]}}
            for index in range(1, 11)]
    result = diagnose_report({'files': rows}, HashDatabase.from_records([]))['latency']
    assert result['total_ms']['p95_floor_index'] == 900
    assert result['total_ms']['p95_nearest_rank'] == 1000
    longest = result['longest_total_records'][0]
    assert longest['parallel_engine_max_ms'] == 600
    assert longest['estimated_critical_path_ms'] == 910
    assert longest['elapsed_minus_critical_path_ms'] == 90
    assert longest['fuzzy_fraction_of_total'] == .3
    assert result['longest_fuzzy_records'][0]['sha256'] == f'{10:064x}'


def test_model_inference_is_part_of_schema2_critical_path():
    row = {'sha256': 'f' * 64, 'pe_valid': True, 'elapsed_ms': 100,
           'engines': {name: {'status': 'no_match', 'elapsed_ms': elapsed}
                       for name, elapsed in [('sha256', 1), ('fuzzy', 10), ('yara_x', 5),
                                             ('clamav', 50), ('lightgbm', 30)]}}
    timing = diagnose_report({'files': [row]}, HashDatabase.from_records([]))['latency']
    longest = timing['longest_total_records'][0]
    assert longest['estimated_critical_path_ms'] == 91
    assert longest['elapsed_minus_critical_path_ms'] == 9
    assert timing['engines_ms']['lightgbm']['p50'] == 30


def test_fuzzy_digest_does_not_depend_on_unbounded_one_shot_binding(monkeypatch):
    from aegisav.hashes import compute_fuzzy
    data = bytes(range(256)) * 8192
    expected = tlsh.hexdigest(data, ver=1)
    def oversized_binding(*args, **kwargs):
        raise TypeError('Native full-sequence conversion exceeds address-space budget')
    monkeypatch.setattr(tlsh, 'hexdigest', oversized_binding)
    assert compute_fuzzy(data)['tlsh'] == expected
