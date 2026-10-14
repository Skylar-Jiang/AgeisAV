import pytest
from experiments.audit_acquisition import audit


def state(rows):
    return dict(identity={},detector_evaluation_performed=False,files=rows)


def test_unavailable_raw_and_unknown_labels_cannot_become_final_evaluation():
    manifest=[dict(sha256='a',source_tlsh=None,source_ssdeep=None),dict(sha256='b')]
    rows=[dict(sha256='a',status='acquired',raw_sha_verified=True,report=None,detector_results_observed=False,
               fingerprints={'tlsh':None,'ssdeep':'3::'},pe={'strict_pe_valid':True,'scope':'win64'},size_bytes=100),
          dict(sha256='b',status='error',reason='download_incomplete',report=None)]
    result=audit(state(rows),manifest,dict(files=[dict(sha256='a',status='downloaded')]),{},[])
    assert result['status_counts']==dict(acquired=1,error=1)
    assert result['download_unattempted']==1 and result['raw_sha_verified']==1
    assert result['independent_final_eligible']==0 and result['accuracy_metrics'] is None
    assert result['model_scores_observed']==0


def test_scored_rows_or_undeclared_sha_fail_the_blind_audit():
    for row in (dict(sha256='a',report={'engines':{}}),dict(sha256='a',detector_results_observed=True),dict(sha256='b')):
        with pytest.raises(ValueError):
            audit(state([row]),[dict(sha256='a')],dict(files=[]),{},[])
