import pytest
from vm.expansion_scan_protocol import freeze_plan


def test_expansion_plan_is_development_only_and_retains_failed_acquisition():
    rows=[dict(sha256='a'*64,status='acquired',raw_sha_verified=True,report=None,size_bytes=10),
          dict(sha256='b'*64,status='error',reason='download_incomplete',report=None)]
    plan=freeze_plan(dict(identity={'manifest':'c'*64},detector_evaluation_performed=False,files=rows),'d'*64)
    assert plan['dataset_role']=='development_expansion'
    assert plan['strict_final_test'] is False and plan['thresholds_changed'] is False
    assert len(plan['files'])==2 and plan['files'][1]['acquired'] is False
    assert plan['labels']=='unknown'


def test_scored_or_unverified_input_cannot_be_frozen_as_unobserved():
    for row in (dict(sha256='a'*64,status='acquired',report={}),
                dict(sha256='a'*64,status='acquired',report=None,raw_sha_verified=False)):
        with pytest.raises(ValueError):
            freeze_plan(dict(identity={},detector_evaluation_performed=False,files=[row]),'b'*64)
