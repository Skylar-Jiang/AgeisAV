"""Small synthetic checks for the validation-only model experiment."""
import json

import pytest

from experiments import model_search_round2 as search


def test_fixed_budget_comparison_retains_losses_and_week_reversal():
    np = pytest.importorskip('numpy')
    labels = np.array([0] * 10 + [1] * 6)
    weeks = np.array([1] * 5 + [2] * 5 + [1] * 3 + [2] * 3)
    baseline = np.array([.1] * 9 + [.9] + [.95, .96, .1, .95, .1, .1])
    candidate = np.array([.1] * 9 + [.9] + [.1, .96, .1, .95, .96, .97])
    result = search.paired_comparison(labels, weeks, baseline, candidate, .9, .9)
    assert result['recall']['candidate_only_positive'] == 2
    assert result['recall']['baseline_only_positive'] == 1
    assert result['recall']['delta'] == pytest.approx(1 / 6)
    assert result['weeks'][0]['tp_delta'] == -1
    assert result['weeks'][1]['tp_delta'] == 2
    assert result['fpr']['delta'] == 0


def test_memory_failure_keeps_a_reviewable_artifact(tmp_path):
    output = tmp_path / 'result.json'
    with pytest.raises(MemoryError, match='6 GiB'):
        search.check_start_memory(3 * 1024**3, output)
    saved = json.loads(output.read_text())
    assert saved['status'] == 'resource_blocked'
    assert saved['test_data_read'] is False
    assert saved['available_bytes'] == 3 * 1024**3


def test_source_allowlist_excludes_final_and_raw_data(tmp_path):
    paths = search.source_paths(tmp_path)
    assert {path.name for path in paths} == {
        'X_fit.npy', 'X_validation.npy', 'meta_fit.npz', 'meta_validation.npz',
        'ember2024_win64_temporal_local.model', 'lgbm_config.json'}
    assert not any('test' in path.name.lower() for path in paths)


def test_streamed_feature_rows_and_training_match_in_memory_input(tmp_path):
    np = pytest.importorskip('numpy')
    lgb = pytest.importorskip('lightgbm')
    features = np.random.default_rng(0).normal(size=(512, 12)).astype(np.float32)
    features[:, 2] = np.arange(512) % 4
    labels = (features[:, 0] + features[:, 1] > 0).astype(int)
    path = tmp_path / 'fit.npy'
    np.save(path, features)
    sequence = search.fit_sequence(path)
    try:
        np.testing.assert_array_equal(sequence[17], features[17])
        np.testing.assert_array_equal(sequence[100:140], features[100:140])
        params = dict(objective='binary', num_leaves=8, min_data_in_leaf=5, max_bin=31,
                      bin_construct_sample_cnt=200, num_threads=1, deterministic=True,
                      force_col_wise=True, seed=0, verbosity=-1)
        direct = lgb.train(params, lgb.Dataset(features, labels, categorical_feature=[2]), num_boost_round=20)
        dataset = search.fit_dataset(sequence, labels, params, [2])
        assert dataset.get_params()['num_threads'] == 1
        assert dataset.get_params()['min_data_in_leaf'] == 5
        streamed = lgb.train(params, dataset, num_boost_round=20)
        np.testing.assert_array_equal(direct.predict(features), streamed.predict(features))
    finally:
        sequence.close()
