"""Exploratory fixed linear baseline using only already-verified EMBER vectors."""

import hashlib
import importlib.metadata
import json
from pathlib import Path
import time

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / 'artifacts/ember2024'


def fit_linear(X, y, batch_size=4096, epochs=5):
    import numpy as np
    from sklearn.linear_model import SGDClassifier
    from sklearn.preprocessing import StandardScaler
    scaler = StandardScaler()
    starts = list(range(0, len(X), batch_size))
    for start in starts:
        scaler.partial_fit(X[start:start + batch_size])
    model = SGDClassifier(loss='log_loss', penalty='l2', alpha=.0001,
                          average=True, random_state=0, tol=None)
    rng = np.random.default_rng(0)
    for epoch in range(epochs):
        for start in rng.permutation(starts):
            model.partial_fit(scaler.transform(X[start:start + batch_size]),
                              y[start:start + batch_size], classes=np.array([0, 1]))
        print('FIT_PASS', epoch + 1, flush=True)
    return model, scaler


def score_linear(model, scaler, X, batch_size=4096):
    import numpy as np
    scores = np.concatenate([model.decision_function(scaler.transform(X[start:start + batch_size]))
                             for start in range(0, len(X), batch_size)]).astype(np.float64)
    if not np.isfinite(scores).all():
        raise ValueError('Invalid linear model scores')
    return scores


def main():
    import numpy as np
    from experiments.ember_baseline import evaluate
    from ml.ember_protocol import assert_disjoint_hashes, validation_threshold
    meta = {s: dict(np.load(ART / 'vectors' / ('meta_' + s + '.npz'))) for s in ('fit', 'validation', 'test')}
    assert_disjoint_hashes({s: m['sha'].tolist() for s, m in meta.items()})
    if [len(meta[s]['y']) for s in meta] != [480000, 40000, 119993]:
        raise ValueError('Different frozen cohort')
    X = {s: np.load(ART / 'vectors' / ('X_' + s + '.npy'), mmap_mode='r') for s in meta}
    started = time.perf_counter()
    model, scaler = fit_linear(X['fit'], meta['fit']['y'])
    fit_seconds = time.perf_counter() - started
    print('TRAINED', fit_seconds, flush=True)
    model_path = ART / 'models/ember2024_win64_linear_sgd.npz'
    np.savez(model_path, coef=model.coef_, intercept=model.intercept_,
             scaler_mean=scaler.mean_, scaler_scale=scaler.scale_, scaler_var=scaler.var_)
    scores, score_seconds = {}, {}
    for split in ('validation', 'test'):
        started = time.perf_counter()
        scores[split] = score_linear(model, scaler, X[split])
        score_seconds[split] = time.perf_counter() - started
    thresholds = {'default_probability_0.5': 0.0, **{'validation_fpr_' + name: validation_threshold(
        meta['validation']['y'], scores['validation'], target) for name, target in [('1pct', .01), ('0.1pct', .001)]}}
    np.savez(ART / 'linear_predictions.npz', **{s + '_scores': v for s, v in scores.items()})
    inputs = [ROOT / 'docs/research/LINEAR_BASELINE_PROTOCOL_20261010.md', ART / 'dataset_provenance.json',
              *[ART / 'vectors' / ('meta_' + s + '.npz') for s in meta]]
    result = {'status': 'completed', 'strict_new_final_test': False,
              'scope': 'Exploratory simple linear comparison after observing LightGBM test results; no tuning',
              'fit_rows': len(meta['fit']['y']), 'feature_dim': 2568,
              'params': model.get_params(), 'epochs': 5, 'batch_size': 4096,
              'scaler_fitted_on': 'fit only', 'categorical_ids': 'standardized numerically; baseline limitation',
              'score_semantics': 'Raw logistic decision margin; threshold 0 corresponds to sigmoid probability 0.5. Avoids saturated probabilities.',
              'numerical_amendment': 'Use float64 comparisons and raw margins after validation tie-boundary failure; parameters/splits unchanged',
              'fit_seconds': fit_seconds, 'scoring_seconds_including_scaling': score_seconds,
              'scikit_learn': importlib.metadata.version('scikit-learn'),
              'numpy': importlib.metadata.version('numpy'),
              'model_sha256': hashlib.sha256(model_path.read_bytes()).hexdigest(),
              'input_sha256': {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs},
              **{s: evaluate(meta[s]['y'], scores[s], thresholds) for s in scores}}
    output = ROOT / 'docs/benchmarks/ember2024_linear_20261010.json'
    output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print('COMPLETED', output, flush=True)


if __name__ == '__main__':
    main()
