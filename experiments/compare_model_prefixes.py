"""Validation-only screening of existing model prefixes; never opens test data or raw PE."""
import argparse
import hashlib
import json
from pathlib import Path
import time

from experiments.ember_baseline import operating_point
from experiments.compare_scan_latency import quantiles
from ml.ember_protocol import validation_threshold

ROOT = Path(__file__).resolve().parents[1]
PREFIXES = (100, 200, 300, 400, 500)


def main():
    import lightgbm as lgb
    import numpy as np
    import psutil
    from sklearn.metrics import average_precision_score, roc_auc_score
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or psutil.virtual_memory().available < 2 * 1024**3:
        raise ValueError('Requires new output path and 2 GiB available memory')
    art = ROOT / 'artifacts/ember2024'
    sources = [art / 'vectors/X_validation.npy', art / 'vectors/meta_validation.npz',
               art / 'models/ember2024_win64_temporal_local.model',
               ROOT / 'docs/benchmarks/ember2024_win64_20261010.json']
    old = json.loads(sources[-1].read_bytes())
    if hashlib.sha256(sources[2].read_bytes()).hexdigest() != old['model_sha256']:
        raise ValueError('Frozen model identity mismatch')
    with np.load(sources[1], allow_pickle=False) as meta:
        labels, weeks, hashes = meta['y'].copy(), meta['week'].copy(), meta['sha'].copy()
    features = np.load(sources[0], mmap_mode='r', allow_pickle=False).copy()
    if (features.shape != (40000, 2568) or len(set(hashes.tolist())) != 40000 or
            sorted(np.unique(labels, return_counts=True)[1].tolist()) != [20000, 20000] or
            set(labels.tolist()) != {0, 1} or len(np.unique(weeks)) != 4 or not np.isfinite(features).all()):
        raise ValueError('Validation identity/shape/label/feature guard failed')
    model = lgb.Booster(model_file=str(sources[2]))
    if model.current_iteration() != 500 or model.num_feature() != 2568:
        raise ValueError('Changed frozen model structure')
    models, scores, timings, results = {}, {}, {}, {}
    for count in PREFIXES:
        text = model.model_to_string(num_iteration=count)
        models[count] = lgb.Booster(model_str=text)
        results[count] = {'trees': count, 'serialized_bytes': len(text.encode('utf-8'))}
        timings[count] = []

    def predict(count):
        return np.concatenate([models[count].predict(features[start:start + 1024], num_threads=1)
                               for start in range(0, len(features), 1024)])

    # Warm every prefix before the five timed passes; timing excludes metrics/serialization.
    for count in PREFIXES:
        scores[count] = predict(count)
    for repeat in range(5):
        for count in PREFIXES if repeat % 2 == 0 else tuple(reversed(PREFIXES)):
            started = time.perf_counter()
            observed = predict(count)
            timings[count].append((time.perf_counter() - started) * 1000)
            if not np.array_equal(observed, scores[count]):
                raise ValueError('Repeated model predictions changed')
        print('Inference round', repeat + 1, 'completed', flush=True)
    for count in PREFIXES:
        values = scores[count]
        thresholds = {'default_0.5': .5, 'validation_fpr_1pct': validation_threshold(labels, values, .01),
                      'validation_fpr_0.1pct': validation_threshold(labels, values, .001)}
        points = {name: operating_point(labels, values, threshold) for name, threshold in thresholds.items()}
        results[count].update(operating_points=points, roc_auc=float(roc_auc_score(labels, values)),
                              average_precision=float(average_precision_score(labels, values)),
                              inference={**quantiles(timings[count]), 'raw_batch_ms': timings[count],
                                         'files_per_second': len(features) * 5000 / sum(timings[count])})
        results[count]['weeks'] = [{'week': int(week), **operating_point(labels[weeks == week],
                                    values[weeks == week], thresholds['validation_fpr_0.1pct'])}
                                   for week in sorted(np.unique(weeks))]
    for name, expected in old['validation']['operating_points'].items():
        actual = results[500]['operating_points'][name]
        if any(actual[key] != expected[key] for key in ('tp', 'fp', 'tn', 'fn', 'threshold')):
            raise ValueError('Full-model validation no longer reproduces the frozen baseline')
    baseline = scores[500] >= results[500]['operating_points']['validation_fpr_0.1pct']['threshold']
    eligible = []
    for count in PREFIXES:
        candidate = scores[count] >= results[count]['operating_points']['validation_fpr_0.1pct']['threshold']
        paired = {}
        for label, metric in ((1, 'recall'), (0, 'fpr')):
            selected = labels == label
            differences = candidate[selected].astype(int) - baseline[selected].astype(int)
            counts = np.array([(differences == value).sum() for value in (-1, 0, 1)])
            draws = np.random.default_rng(0).multinomial(len(differences), counts / len(differences), 5000)
            interval = np.quantile((draws[:, 2] - draws[:, 0]) / len(differences), [.025, .975]).tolist()
            paired[metric] = {'candidate_only_positive': int(counts[2]), 'baseline_only_positive': int(counts[0]),
                              'delta': float(differences.mean()), 'sample_iid_bootstrap_ci95': interval}
        results[count]['paired_vs_500_at_validation_fpr_0.1pct'] = paired
        if (count < 500 and paired['recall']['delta'] >= 0 and
                results[count]['inference']['p50_ms'] < results[500]['inference']['p50_ms']):
            eligible.append(count)
    result = {'schema': 1, 'completed': True, 'validation_only': True, 'test_data_read': False,
              'production_changed': False, 'n': len(labels), 'benign': 20000, 'malicious': 20000,
              'scope': 'Exploratory reused Win64 validation; prefix and threshold selection on the same cohort',
              'timing_method': 'Preloaded features, single thread, 1024-row blocks, warmup + 5 alternating passes',
              'uncertainty': 'Wilson point intervals and 5000 paired multinomial sample bootstrap draws seed0; '
                             'no family independence, no selection correction, only four validation weeks; '
                             'equal FP counts are imposed by in-sample threshold selection, not evidence of equal deployment FPR',
              'candidate_prefixes_meeting_prespecified_screen': eligible,
              'candidates': list(results.values()),
              'input_sha256': {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources},
              'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'package_versions': {'lightgbm': lgb.__version__, 'numpy': np.__version__}}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    for count in PREFIXES:
        row = results[count]
        point = row['operating_points']['validation_fpr_0.1pct']
        print(count, 'TP', point['tp'], 'FP', point['fp'], 'median_ms', round(row['inference']['p50_ms'], 2), flush=True)


if __name__ == '__main__':
    main()
