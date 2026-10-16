from copy import deepcopy

import pytest

from experiments.expansion_diagnostics import analyze


def fixture():
    identity = dict(manifest='manifest', release='release', release_manifest='assets')
    manifest = [dict(sha256=name, download_eligible=True, label='unknown',
                     reported_signature='family', first_seen_utc='2026-10-13T00:00:00Z')
                for name in ('a', 'b', 'c')]
    files = []
    for name, positives in [('a', ('lightgbm',)), ('b', ('clamav', 'lightgbm'))]:
        engines = {engine: dict(status='matched' if engine in positives else 'no_match',
                                risk_signal='suspicious' if engine in positives else None,
                                engine_version='1', artifact_version='asset', elapsed_ms=1)
                   for engine in ('sha256', 'fuzzy', 'yara_x', 'clamav', 'lightgbm')}
        engines['lightgbm'].update(score=.9, threshold=.5, model_id='general',
                                  feature_schema='schema', feature_implementation='chunked')
        files.append(dict(sha256=name, label='unknown', status='scanned', size_bytes=100,
                          elapsed_ms=10, report=dict(sha256=name, size_bytes=100,
                          pe_scope='win32', cached=False, engines=engines)))
    files.append(dict(sha256='c', label='unknown', status='error', reason='download_failed', report=None))
    scan = dict(identity=identity, completed=True, strict_final_test=False,
                dataset_role='development_expansion', files=files)
    acquisition = dict(identity=identity, strict_valid_pe=2,
                       components=[dict(candidates=['a', 'b'], previously_observed_peers=['old'])],
                       tlsh_max_distance=40, ssdeep_min_similarity=80)
    return scan, manifest, acquisition


def test_paired_unknowns_and_cluster_counts_are_not_accuracy_or_independent_samples():
    result = analyze(*fixture())
    assert result['counts'] == dict(candidates=3, scanned_pe=2, unscanned=1,
                                   independently_trusted_labels=0, independent_final_eligible=0)
    assert result['paired']['policies']['evidence_or'] == dict(positive=2, negative=0, abstained=1)
    assert result['paired']['exclusive_positive'] == dict(lightgbm=1)
    assert result['near_duplicates']['screening_components'] == 1
    assert result['near_duplicates']['previously_observed_linked_files'] == 2
    assert result['accuracy_metrics'] is None and result['fixed_low_fpr_recall'] is None
    assert result['without_previous_links']['files'] == 1  # unresolved download retained
    assert result['without_previous_links']['policies']['evidence_or']['abstained'] == 1


def test_timeout_abstains_even_when_other_engine_is_positive():
    scan, manifest, acquisition = fixture()
    scan['files'][1]['report']['engines']['lightgbm']['status'] = 'timeout'
    for key in ('score', 'threshold', 'model_id', 'feature_schema', 'feature_implementation'):
        scan['files'][1]['report']['engines']['lightgbm'].pop(key)
    result = analyze(scan, manifest, acquisition)
    assert result['paired']['engines']['lightgbm']['abstained'] == 2
    assert result['paired']['policies']['evidence_or']['positive'] == 2
    assert result['paired']['policies']['corroborated']['abstained'] == 2


def test_model_cost_residual_is_measured_without_claiming_worker_reuse_speedup():
    scan, manifest, acquisition = fixture()
    for row in scan['files'][:2]:
        row['report']['engines']['lightgbm'].update(elapsed_ms=100, feature_elapsed_ms=20, inference_elapsed_ms=1)
    result = analyze(scan, manifest, acquisition)
    assert result['model_timing_ms']['unattributed']['p50'] == 79
    assert result['model_timing_ms']['feature']['sample_count'] == 2
    scan['files'][0]['report']['engines']['lightgbm']['feature_elapsed_ms'] = float('nan')
    with pytest.raises(ValueError): analyze(scan, manifest, acquisition)


@pytest.mark.parametrize('change', ['duplicate', 'missing', 'identity', 'digest', 'threshold',
                                  'cluster_missing', 'cluster_duplicate', 'cluster_empty', 'label', 'cached',
                                  'version', 'score', 'file_nan', 'model_contract', 'ml_engine_version'])
def test_incompatible_or_ambiguous_evidence_fails_closed(change):
    scan, manifest, acquisition = deepcopy(fixture())
    report = scan['files'][0]['report']
    if change == 'duplicate': scan['files'].append(deepcopy(scan['files'][0]))
    if change == 'missing': scan['files'].pop()
    if change == 'identity': acquisition['identity'] = dict(manifest='other')
    if change == 'digest': report['sha256'] = 'other'
    if change == 'threshold': report['engines']['lightgbm']['threshold'] = .4
    if change == 'cluster_missing': acquisition['components'][0]['candidates'].pop()
    if change == 'cluster_duplicate': acquisition['components'].append(deepcopy(acquisition['components'][0]))
    if change == 'cluster_empty': acquisition['components'].append(dict(candidates=[], previously_observed_peers=[]))
    if change == 'label': manifest[0]['label'] = 'malicious'
    if change == 'cached': report['cached'] = True
    if change == 'version': report['engines']['clamav']['artifact_version'] = 'different'
    if change == 'score': report['engines']['lightgbm']['score'] = .1
    if change == 'file_nan': scan['files'][0]['elapsed_ms'] = float('nan')
    if change == 'model_contract':
        for row in scan['files'][:2]:
            for key in ('model_id', 'feature_schema', 'feature_implementation'):
                row['report']['engines']['lightgbm'].pop(key)
    if change == 'ml_engine_version': report['engines']['lightgbm']['engine_version'] = 'changed'
    with pytest.raises(ValueError): analyze(scan, manifest, acquisition)


def test_aggregate_contains_no_member_hashes():
    import json
    scan, manifest, acquisition = fixture()
    for index, row in enumerate(manifest):
        digest = ('abcdef0123456789' * 4)[:-1] + str(index)
        old = row['sha256']
        row['sha256'] = digest
        scan['files'][index]['sha256'] = digest
        if scan['files'][index]['report']:
            scan['files'][index]['report']['sha256'] = digest
        acquisition['components'][0]['candidates'] = [digest if x == old else x
                                                    for x in acquisition['components'][0]['candidates']]
    encoded = json.dumps(analyze(scan, manifest, acquisition))
    assert all(row['sha256'] not in encoded for row in manifest)


def test_cli_requires_exact_frozen_transfer_manifest(tmp_path, monkeypatch):
    import hashlib
    import json
    from experiments.expansion_diagnostics import main
    scan, manifest, acquisition = fixture()
    raw = json.dumps(manifest).encode()
    digest = hashlib.sha256(raw).hexdigest()
    scan['identity']['manifest'] = acquisition['identity']['manifest'] = digest
    for name, value in [('manifest', manifest), ('scan', scan), ('acquisition', acquisition)]:
        (tmp_path / name).write_text(json.dumps(value), encoding='utf-8')
    monkeypatch.setattr('sys.argv', ['audit', *[item for name in ('scan', 'manifest', 'acquisition', 'output')
                                             for item in ('--' + name, str(tmp_path / name))]])
    main()
    assert json.loads((tmp_path / 'output').read_text())['counts']['scanned_pe'] == 2
    (tmp_path / 'manifest').write_bytes(raw + b'\n')
    with pytest.raises(ValueError, match='Manifest bytes'): main()
