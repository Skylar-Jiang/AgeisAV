import pytest

np = pytest.importorskip('numpy')
lgb = pytest.importorskip('lightgbm')

from experiments.ember_ablation import project_columns


def test_disk_projection_keeps_values_and_training_predictions(tmp_path):
    rng = np.random.default_rng(0)
    data = rng.normal(size=(1200, 32)).astype(np.float32)
    data[:, 2] = rng.integers(0, 4, size=1200)
    labels = (data[:, 0] + data[:, 1] > 0).astype(int)
    source, target = tmp_path / 'source.npy', tmp_path / 'projected.npy'
    np.save(source, data)
    keep = [index for index in range(32) if index not in (5, 9)]
    projected = project_columns(source, target, keep, batch_rows=37)
    assert isinstance(projected, np.memmap)
    assert projected.flags.c_contiguous
    np.testing.assert_array_equal(projected, data[:, keep])
    params = dict(objective='binary', seed=0, deterministic=True, force_col_wise=True,
                  num_threads=2, verbosity=-1, num_leaves=8)
    regular = lgb.train(params, lgb.Dataset(data[:, keep], labels, categorical_feature=[2]), num_boost_round=15)
    bounded = lgb.train(params, lgb.Dataset(projected, labels, categorical_feature=[2]), num_boost_round=15)
    np.testing.assert_array_equal(regular.predict(data[:, keep]), bounded.predict(projected))
