import hashlib
import json
import pytest
from experiments.summarize_benign_round import summarize, general_training_control


def fixture():
    samples = [{'sha256': str(i) * 64, 'label': 'trusted_installation_benign_proxy',
                'source': 'trusted installation'} for i in range(1, 4)]
    manifest = ''.join(json.dumps(s) + '\n' for s in samples).encode()
    rows = []
    for i, sample in enumerate(samples):
        engines = {name: {'status': 'no_match', 'elapsed_ms': 1} for name in
                   ('sha256', 'fuzzy', 'yara_x', 'clamav')}
        engines['lightgbm'] = {'status': 'matched' if i == 0 else 'no_match',
                               'threshold': .5, 'score': .8 if i == 0 else .1, 'elapsed_ms': 2}
        rows.append({'sha256': sample['sha256'], 'pe_valid': True, 'engines': engines, 'elapsed_ms': 5})
    return {'manifest_sha256': hashlib.sha256(manifest).hexdigest(), 'files': rows, 'completed': True}, manifest


def test_benign_observation_excludes_training_identity_without_changing_full_cohort():
    report, manifest = fixture()
    result = summarize(report, manifest, {'1' * 64}, set())
    assert result['all_observed']['sample_count'] == 3
    assert result['all_observed']['engines']['lightgbm']['benign_false_positive']['numerator'] == 1
    assert result['win64_fit_validation_disjoint']['sample_count'] == 2
    assert result['win64_fit_validation_disjoint']['engines']['lightgbm']['benign_false_positive']['numerator'] == 0
    assert result['strict_final_test'] is False
    assert result['general_pe_pretrained_full_training_overlap_known'] is False


def test_benign_observation_rejects_wrong_manifest_or_unsupported_label():
    report, manifest = fixture()
    with pytest.raises(ValueError, match='manifest'):
        summarize(report, manifest + b'\n', set(), set())
    manifest = manifest.replace(b'trusted_installation_benign_proxy', b'malicious_proxy')
    report['manifest_sha256'] = hashlib.sha256(manifest).hexdigest()
    with pytest.raises(ValueError, match='label'):
        summarize(report, manifest, set(), set())


def test_benign_observation_rejects_missing_and_non_pe_rows():
    report, manifest = fixture()
    report['files'].pop()
    with pytest.raises(ValueError, match='cohort'):
        summarize(report, manifest, set(), set())
    report, manifest = fixture()
    report['files'][0]['pe_valid'] = False
    with pytest.raises(ValueError, match='PE'):
        summarize(report, manifest, set(), set())


def test_full_pe_training_control_retains_full_observation_and_excludes_known_identities():
    report, _ = fixture()
    audit = {'cohort_overlap': {'fixture': {'cohort_size': 3, 'overlap_count': 1,
             'matches': {'1' * 64: [{'file_type': 'Win32', 'label': 0}]}}}}
    result = general_training_control([report], audit, set())
    assert result['known_training_overlap_count'] == 1
    assert result['reported_training_disjoint']['sample_count'] == 2
    assert result['reported_training_disjoint']['engines']['lightgbm']['benign_false_positive']['numerator'] == 0
    assert result['strict_final_test'] is False
    audit['cohort_overlap']['fixture']['overlap_count'] = 2
    with pytest.raises(ValueError, match='audit'):
        general_training_control([report], audit, set())
