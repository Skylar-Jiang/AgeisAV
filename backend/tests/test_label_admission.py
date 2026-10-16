from copy import deepcopy
from experiments.label_admission import assess


def case():
    return dict(sha256='a'*64, evidence=[dict(sha256='a'*64, primary=True,
                source_url='https://analyst.example/case', kind='technical_analysis',
                locator='Technical analysis and exact-SHA IoC',
                behavior='credential_exfiltration', independent_of_aegisav=True)],
                review=dict(status='accepted', reviewer='research-agent', method='automated',
                            reviewed_at='2026-10-17T01:00:00+08:00'),
                raw=dict(sha256='a'*64, strict_pe_valid=True, integrity_verified=True),
                dual_use=False, family_conflict=False, source_disputed=False,
                dataset_role='validation_candidate', detector_results_observed=False)


def test_precise_case_evidence_admits_exploration_without_pretending_human_review():
    result=assess(case())
    assert result['grade']=='high-confidence' and result['exploratory_eligible']
    assert not result['formal_eligible'] and 'human_review_pending' in result['formal_exclusions']


def test_no_raw_is_probable_not_a_scannable_denominator():
    row=case();row['raw']=None
    result=assess(row)
    assert result['grade']=='probable' and not result['exploratory_eligible']


def test_detector_vote_source_or_wrong_sha_cannot_supply_technical_truth():
    for field,value in [('kind','detector_consensus'),('sha256','b'*64),('independent_of_aegisav',False)]:
        row=case();row['evidence'][0][field]=value
        assert assess(row)['grade']=='unknown'


def test_ambiguity_excludes_even_with_exact_report_and_verified_raw():
    for field in ('dual_use','family_conflict','source_disputed'):
        row=case();row[field]=True
        assert assess(row)['grade']=='unknown'


def test_observed_dev_is_never_promoted_to_final_by_new_label():
    row=case();row.update(dataset_role='development_expansion',detector_results_observed=True,
        split_frozen_before_scan=True, training_overlap_cleared=True, near_overlap_cleared=True,
        temporal_eligibility_verified=True)
    row['review'].update(method='human')
    assert assess(row)['grade']=='high-confidence'
    assert not assess(row)['formal_eligible']


def test_final_requires_every_predeclared_gate():
    row=case();row.update(dataset_role='final_candidate',split_frozen_before_scan=True,
        training_overlap_cleared=True,near_overlap_cleared=True,temporal_eligibility_verified=True)
    row['review']['method']='human'
    assert assess(row)['formal_eligible']
    for field in ('split_frozen_before_scan','training_overlap_cleared','near_overlap_cleared','temporal_eligibility_verified'):
        missing=deepcopy(row);missing.pop(field)
        assert not assess(missing)['formal_eligible']


def test_raw_integrity_mismatch_is_unknown_not_merely_probable():
    row=case();row['raw']['sha256']='b'*64
    assert assess(row)['grade']=='unknown'


def test_missing_identity_cannot_match_two_missing_hashes():
    row=case();row.pop('sha256');row['evidence'][0].pop('sha256');row['raw']=None
    assert assess(row)['grade']=='unknown'


def test_unlocatable_url_or_untraceable_review_never_admits_formal():
    for change in ('url','reviewer','time','locator'):
        row=case();row.update(dataset_role='final_candidate',split_frozen_before_scan=True,
            training_overlap_cleared=True,near_overlap_cleared=True,temporal_eligibility_verified=True)
        row['review']['method']='human'
        if change=='url': row['evidence'][0]['source_url']='https://'
        if change=='reviewer': row['review']['reviewer']='   '
        if change=='time': row['review'].pop('reviewed_at')
        if change=='locator': row['evidence'][0].pop('locator')
        assert not assess(row)['formal_eligible']
