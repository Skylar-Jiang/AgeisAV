"""Run with the isolated ML Python: -m unittest backend.tests.test_linear_baseline."""
import unittest
import importlib.util
from experiments.linear_baseline import fit_linear, score_linear


@unittest.skipUnless(importlib.util.find_spec('numpy') and importlib.util.find_spec('sklearn'), 'Use the isolated ML environment')
class FitIsolationTest(unittest.TestCase):
    def test_scaler_only_learns_fit_rows_and_scoring_cannot_update_statistics(self):
        import numpy as np
        X = np.array([[0., 1.], [1., 2.], [4., 0.], [5., 2.]])
        y = np.array([0, 0, 1, 1])
        model, scaler = fit_linear(X, y, batch_size=2, epochs=2)
        np.testing.assert_allclose(scaler.mean_, X.mean(axis=0))
        before = scaler.mean_.copy()
        scores = score_linear(model, scaler, np.full((3, 2), 1e6), batch_size=2)
        np.testing.assert_array_equal(scaler.mean_, before)
        self.assertTrue(np.isfinite(scores).all())
        self.assertEqual(scores.shape, (3,))

    def test_fixed_seed_and_batches_reproduce_scores(self):
        import numpy as np
        X = np.arange(24).reshape(12, 2).astype(float)
        y = np.array([0] * 6 + [1] * 6)
        a, sa = fit_linear(X, y, batch_size=4, epochs=2)
        b, sb = fit_linear(X, y, batch_size=4, epochs=2)
        np.testing.assert_array_equal(score_linear(a, sa, X), score_linear(b, sb, X))

    def test_threshold_above_one_does_not_round_down_to_float32_one(self):
        import math
        import numpy as np
        from experiments.ember_baseline import operating_point
        result = operating_point(np.array([0, 1]), np.array([1, 1], dtype=np.float32),
                                 math.nextafter(1.0, math.inf))
        self.assertEqual(result['fp'], 0)
        self.assertEqual(result['tp'], 0)

    def test_paired_week_bootstrap_preserves_same_week_sampling(self):
        from experiments.ember_time_analysis import paired_week_interval
        interval = paired_week_interval([20,20],[100,100],[10,10],[100,100])
        self.assertEqual(interval, [.1,.1])


if __name__ == '__main__':
    unittest.main()
