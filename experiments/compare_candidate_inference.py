"""Paired inference cost on reused validation features; excludes PE extraction and HTTP."""
import argparse
import hashlib
import json
from pathlib import Path
import time

ROOT = Path(__file__).resolve().parents[1]


def main():
    import lightgbm as lgb
    import numpy as np
    from experiments.compare_scan_latency import quantiles

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate-result', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError('Retain previous results')
    result = json.loads(args.candidate_result.read_text())
    if result['status'] != 'completed' or not result['validation_only']:
        raise ValueError('Requires a completed development experiment')
    paths = {'baseline': ROOT / 'artifacts/ember2024/models/ember2024_win64_temporal_local.model',
             'candidate': args.candidate_result.parent / 'coarse-leaves.model'}
    identities = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in paths.items()}
    inputs = {key.replace('\\', '/'): value for key, value in result['input_sha256'].items()}
    if (identities['candidate'] != result['model_sha256'] or identities['baseline'] !=
            inputs['artifacts/ember2024/models/ember2024_win64_temporal_local.model']):
        raise ValueError('Model identity changed')
    features = np.load(ROOT / 'artifacts/ember2024/vectors/X_validation.npy', mmap_mode='r', allow_pickle=False)
    if features.shape != (40000, 2568):
        raise ValueError('Frozen validation shape changed')
    models, loads = {}, {}
    for name, path in paths.items():
        started = time.perf_counter()
        models[name] = lgb.Booster(model_file=str(path))
        loads[name] = (time.perf_counter() - started) * 1000
    times = {name: [] for name in models}

    def predict(model):
        return np.concatenate([model.predict(features[start:start + 1024], num_threads=1)
                               for start in range(0, len(features), 1024)])

    with np.load(args.candidate_result.parent / 'validation-predictions.npz', allow_pickle=False) as expected:
        for name, model in models.items():
            np.testing.assert_array_equal(predict(model), expected[name])
        for repeat in range(5):
            for name in (('baseline', 'candidate') if repeat % 2 == 0 else ('candidate', 'baseline')):
                started = time.perf_counter()
                observed = predict(models[name])
                times[name].append((time.perf_counter() - started) * 1000)
                np.testing.assert_array_equal(observed, expected[name])
    args.output.write_text(json.dumps({
        'development_validation_only': True, 'test_data_read': False,
        'scope': 'Preloaded models and fixed 1024-row blocks, one warmup, five alternating rounds, one inference thread',
        'limitation': 'Model-only inference. Single warm load observation is not cold startup or end-to-end latency.',
        'model_sha256': identities, 'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'models': {name: {**quantiles(values), 'raw_ms': values, 'model_bytes': paths[name].stat().st_size,
                          'single_warm_load_ms': loads[name]} for name, values in times.items()},
        'all_predictions_equal_saved_scores': True}, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
