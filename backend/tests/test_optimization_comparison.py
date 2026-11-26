import copy
import os
import sys
from pathlib import Path

import pytest

from experiments.compare_scan_latency import normalized


def test_http_study_preserves_explicit_external_ml_components(tmp_path, monkeypatch):
    from experiments import compare_task_latency as study

    components = {'AEGISAV_MODEL_DIR': str(tmp_path / 'external-model'),
                  'AEGISAV_ML_PYTHON': str(tmp_path / 'external-python.exe')}
    for name, value in components.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv('AEGISAV_ML_PROFILE', 'general')
    monkeypatch.setenv('PYTHONDONTWRITEBYTECODE', '1')
    monkeypatch.setattr(sys, 'argv', ['study', '--baseline-root', str(study.ROOT),
                                    '--output', str(tmp_path / 'new-result.json')])
    monkeypatch.setattr(Path, 'read_bytes', lambda self: b'inert setup-only fixture')
    monkeypatch.setattr(study, 'ProcessScanner', lambda *args: None)

    class ConfigurationChecked(Exception):
        pass

    def check_before_starting_services():
        assert {name: os.environ[name] for name in components} == components
        raise ConfigurationChecked()

    monkeypatch.setattr(study, 'build_scanner', check_before_starting_services)
    with pytest.raises(ConfigurationChecked):
        study.main()


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
