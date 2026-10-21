import copy

import pytest

from experiments.compare_scan_latency import normalized


@pytest.mark.parametrize('field,value', [('status', 'matched'), ('score', .9),
                                        ('artifact_version', 'v2'), ('feature_sha256', 'changed'),
                                        ('evidence', ['new signal'])])
def test_report_comparison_ignores_only_timing_and_preserves_detection_differences(field, value):
    baseline = {'cached': False, 'engines': {'lightgbm': {
        'status': 'no_match', 'score': .2, 'artifact_version': 'v1', 'feature_sha256': 'same',
        'evidence': [], 'elapsed_ms': 20., 'feature_elapsed_ms': 10., 'inference_elapsed_ms': 1.}}}
    candidate = copy.deepcopy(baseline)
    candidate['engines']['lightgbm'].update(elapsed_ms=15., feature_elapsed_ms=8., inference_elapsed_ms=.5)
    assert normalized(candidate) == normalized(baseline)
    candidate['engines']['lightgbm'][field] = value
    assert normalized(candidate) != normalized(baseline)
