import pytest

from experiments.fusion_replay import policies


def test_fixed_fusion_truth_table_preserves_abstentions_and_complements():
    assert policies([False, False, False, False], True) == {
        'signature_or': False, 'ml_only': True, 'evidence_or': True, 'corroborated': False}
    assert policies([False, False, True, False], None) == {
        'signature_or': True, 'ml_only': None, 'evidence_or': True, 'corroborated': None}
    assert policies([False, False, False, False], None)['evidence_or'] is None
    assert policies([None, False, False, False], False)['corroborated'] is False
    assert policies([True, False, False, False], True)['corroborated'] is True


def test_fixed_fusion_rejects_missing_or_non_boolean_engine_outcomes():
    with pytest.raises(ValueError):
        policies([False], True)
    with pytest.raises(ValueError):
        policies([0, False, False, False], True)
