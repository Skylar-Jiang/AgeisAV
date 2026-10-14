import pytest
from experiments.compare_static_rounds import compare_rounds


def rounds():
    def row(digest, clam='no_match', model=None):
        engines = {name: {'status': clam if name == 'clamav' else 'no_match', 'elapsed_ms': 1}
                   for name in ('sha256', 'fuzzy', 'yara_x', 'clamav')}
        if model is not None:
            engines['lightgbm'] = {'status': 'matched' if model >= .5 else 'no_match', 'score': model,
                                   'threshold': .5, 'elapsed_ms': 4, 'feature_elapsed_ms': 2,
                                   'inference_elapsed_ms': 1}
        return {'sha256': digest, 'pe_valid': True, 'size_bytes': 1024, 'elapsed_ms': 10, 'engines': engines}
    old = {'files': [row('a' * 64), row('b' * 64), row('c' * 64)], 'completed': True}
    new = {'files': [row('a' * 64, model=.5), row('b' * 64, clam='matched', model=.2),
                     row('c' * 64, model=.9)], 'completed': True}
    reference = {'samples': [{'sha256': 'a' * 64, 'label': 'malicious_proxy'},
                              {'sha256': 'b' * 64, 'label': 'malicious_proxy'},
                              {'sha256': 'c' * 64, 'label': 'unknown'}]}
    return old, new, reference


def test_comparison_excludes_unknown_and_measures_complementary_old_misses():
    old, new, reference = rounds()
    result = compare_rounds(old, new, reference)
    assert result['strict_final_test'] is False
    assert result['proxy_count'] == 2
    assert result['unknown_count'] == 1
    assert result['old_clam_proxy_misses']['count'] == 2
    assert result['old_clam_proxy_misses']['new_clam_hits']['count'] == 1
    assert result['old_clam_proxy_misses']['new_ml_hits']['count'] == 1
    assert result['old_clam_proxy_misses']['new_fusion_hits']['count'] == 2
    assert result['new']['engines']['lightgbm']['proxy_detection']['numerator'] == 1
    assert result['new']['fusion']['proxy_detection']['numerator'] == 2
    assert result['new']['latency_ms']['model_inference']['mean'] == 1
    assert result['new']['latency_ms']['model_engine_overhead']['mean'] == 1
    assert result['new']['latency_ms']['pipeline_total']['mean'] == 10


def test_comparison_rejects_different_cohorts_and_unmarked_duplicate():
    old, new, reference = rounds()
    new['files'].pop()
    with pytest.raises(ValueError, match='cohort'):
        compare_rounds(old, new, reference)
    old, new, reference = rounds()
    old['files'].append(dict(old['files'][0]))
    with pytest.raises(ValueError, match='duplicate'):
        compare_rounds(old, new, reference)


def test_comparison_accepts_explicit_consistent_duplicate_and_rejects_conflict():
    old, new, reference = rounds()
    old['files'].append(dict(old['files'][0], duplicate=True, elapsed_ms=2))
    result = compare_rounds(old, new, reference)
    assert result['old']['excluded_duplicate_rows'] == 1
    old['files'][-1]['size_bytes'] = 11
    with pytest.raises(ValueError, match='duplicate'):
        compare_rounds(old, new, reference)


def test_benign_fpr_has_wilson_interval_and_abstentions_are_not_negatives():
    old, new, reference = rounds()
    for row in reference['samples']:
        row['label'] = 'benign'
        row['source'] = 'Trusted installed software; presumed benign'
    new['files'][1]['engines']['lightgbm'] = {'status': 'error', 'elapsed_ms': 1, 'threshold': .5, 'score': None}
    result = compare_rounds(old, new, reference, cohort_role='presumed_installation_benign')
    model = result['new']['engines']['lightgbm']
    assert model['benign_false_positive']['numerator'] == 2
    assert model['benign_false_positive']['denominator'] == 3
    assert model['benign_abstain_count'] == 1
    assert model['status_counts']['error'] == 1
    assert model['completed_count'] == 2
    assert model['benign_decision_fpr']['denominator'] == 2
    assert 0 < model['benign_false_positive']['ci95'][0] < model['benign_false_positive']['ci95'][1] < 1


def test_rejects_threshold_tuning_or_inconsistent_model_status():
    old, new, reference = rounds()
    new['files'][0]['engines']['lightgbm']['threshold'] = .7
    with pytest.raises(ValueError, match='threshold'):
        compare_rounds(old, new, reference)
    new['files'][0]['engines']['lightgbm']['threshold'] = .5
    new['files'][0]['engines']['lightgbm']['status'] = 'no_match'
    with pytest.raises(ValueError, match='score'):
        compare_rounds(old, new, reference)


def test_error_model_still_requires_fixed_threshold_and_partial_fusion_abstains():
    old, new, reference = rounds()
    new['files'][0]['engines']['lightgbm'] = {'status': 'error', 'score': None, 'threshold': .7, 'elapsed_ms': 1}
    with pytest.raises(ValueError, match='threshold'):
        compare_rounds(old, new, reference)
    new['files'][0]['engines']['lightgbm']['threshold'] = .5
    result = compare_rounds(old, new, reference)
    assert result['new']['fusion']['status_counts']['abstain'] == 1
    assert result['new']['fusion']['proxy_abstain_count'] == 1


def test_benign_exact_reference_does_not_enter_malicious_or_fusion():
    old, new, reference = rounds()
    new['files'][1]['engines']['clamav']['status'] = 'no_match'
    new['files'][1]['engines']['sha256'] = {'status': 'matched', 'elapsed_ms': 1,
                                          'evidence': [{'verdict': 'benign'}]}
    result = compare_rounds(old, new, reference)
    assert result['new']['engines']['sha256']['matched_count'] == 0
    assert result['new']['fusion']['proxy_detection']['numerator'] == 1


def test_missing_model_timing_is_unavailable_without_invented_zero():
    old, new, reference = rounds()
    for row in new['files']:
        row['engines']['lightgbm'].pop('inference_elapsed_ms')
        row['engines']['lightgbm'].pop('feature_elapsed_ms')
    result = compare_rounds(old, new, reference)
    assert result['new']['latency_ms']['model_inference']['sample_count'] == 0
    assert result['new']['latency_ms']['model_inference']['mean'] is None
