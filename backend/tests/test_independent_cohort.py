from experiments.independent_cohort import plan_cohort


def sample(char, date, label='malicious'):
    return dict(sha256=char * 64, first_seen_utc=date, time_evidence='independent_telemetry',
                label=label, label_grade='independently_reviewed', source_url='https://example.org/source',
                label_evidence=['https://example.org/report'], detector_results_observed=False)


def test_near_duplicate_component_cannot_cross_time_boundary_or_prior_data():
    rows = [sample('a', '2026-10-01T00:00:00Z'), sample('b', '2026-10-20T00:00:00Z'),
            sample('c', '2026-10-21T00:00:00Z'), sample('d', '2026-10-02T00:00:00Z')]
    result = plan_cohort(rows, {'e' * 64}, [('a' * 64, 'b' * 64), ('c' * 64, 'e' * 64)],
                         '2026-10-01T00:00:00Z', '2026-10-15T00:00:00Z')
    assert result['validation_sha256'] == ['d' * 64]
    assert result['final_sha256'] == []
    assert result['quarantine']['a' * 64] == 'near_duplicate_cluster_crosses_time_split'
    assert result['quarantine']['b' * 64] == 'near_duplicate_cluster_crosses_time_split'
    assert result['quarantine']['c' * 64] == 'cluster_overlaps_observed_or_training'


def test_unknown_collection_time_and_observed_results_are_quarantined():
    rows = [sample('a', '2026-10-02T00:00:00Z', 'unknown'),
            dict(sample('b', '2026-10-20T00:00:00Z'), time_evidence='collection_only'),
            dict(sample('c', '2026-10-20T00:00:00Z'), detector_results_observed=True),
            sample('d', '2026-10-20T00:00:00Z', 'benign')]
    result = plan_cohort(rows, set(), [], '2026-10-01T00:00:00Z', '2026-10-15T00:00:00Z')
    assert result['validation_sha256'] == []
    assert result['final_sha256'] == ['d' * 64]
    assert len(result['quarantine']) == 3
    assert result['ready_for_paired_final_evaluation'] is False
