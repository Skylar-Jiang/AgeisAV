"""One resource-bounded Win64 FIT-only candidate; validation is exploratory.

Run as a module with .venv-ml after the profiling coordinator grants COMPUTE GO.
No test metadata, test predictions, test vectors or raw PE paths are opened.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / 'artifacts/optimization-20261022-r2-model'
RESERVE = 1536 * 1024**2


def candidate_params(original):
    return {**original, 'num_leaves': 32, 'min_data_in_leaf': 200,
            'max_bin': 127, 'bin_construct_sample_cnt': 20000,
            'histogram_pool_size': 128, 'num_threads': 4,
            'deterministic': True, 'force_col_wise': True, 'verbosity': 1}


def source_paths(root):
    art = root / 'artifacts/ember2024'
    return [art / 'vectors' / name for name in
            ('X_fit.npy', 'X_validation.npy', 'meta_fit.npz', 'meta_validation.npz')] + [
                art / 'models/ember2024_win64_temporal_local.model',
                art / 'upstream/examples/lgbm_config.json']


def write_json(path, result):
    path.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')


def check_start_memory(available, output):
    if available < 6 * 1024**3:
        write_json(output, {'status': 'resource_blocked', 'available_bytes': available,
                            'required_start_bytes': 6 * 1024**3, 'test_data_read': False})
        raise MemoryError('Full-FIT candidate requires 6 GiB available before construction')


def fit_sequence(path):
    import lightgbm as lgb
    import numpy as np

    class NpySequence(lgb.Sequence):
        batch_size = 1024

        def __init__(self):
            header = np.load(path, mmap_mode='r', allow_pickle=False)
            try:
                if header.ndim != 2 or header.dtype != np.float32 or not header.flags.c_contiguous:
                    raise ValueError('Requires a contiguous float32 feature matrix')
                self.shape, self.dtype, self.offset = header.shape, header.dtype, header.offset
            finally:
                header._mmap.close()
            self.file = path.open('rb')

        def __len__(self):
            return self.shape[0]

        def __getitem__(self, index):
            single = isinstance(index, (int, np.integer))
            start, end = (int(index), int(index) + 1) if single else (index.start, index.stop)
            self.file.seek(self.offset + start * self.shape[1] * 4)
            values = np.frombuffer(self.file.read((end - start) * self.shape[1] * 4), dtype=np.float32)
            matrix = values.reshape(end - start, self.shape[1])
            return matrix[0].astype(np.float64) if single else matrix

        def close(self):
            self.file.close()

    return NpySequence()


def fit_dataset(features, labels, params, categorical_features):
    import lightgbm as lgb

    class StreamingDataset(lgb.Dataset):
        def get_params(self):
            # Sequence uses this for native construction; preserve the same
            # seed, prefilter and thread settings that ndarray receives.
            return dict(self.params or {})

    return StreamingDataset(features, labels, params=params, categorical_feature=categorical_features)


def paired_comparison(labels, weeks, baseline, candidate, baseline_threshold, candidate_threshold):
    import numpy as np
    before, after = baseline >= baseline_threshold, candidate >= candidate_threshold
    result = {}
    for label, metric in ((1, 'recall'), (0, 'fpr')):
        differences = after[labels == label].astype(int) - before[labels == label].astype(int)
        counts = np.array([(differences == value).sum() for value in (-1, 0, 1)])
        draws = np.random.default_rng(0).multinomial(len(differences), counts / len(differences), 5000)
        result[metric] = {'candidate_only_positive': int(counts[2]),
                          'baseline_only_positive': int(counts[0]), 'delta': float(differences.mean()),
                          'sample_iid_bootstrap_ci95': np.quantile(
                              (draws[:, 2] - draws[:, 0]) / len(differences), [.025, .975]).tolist()}
    result['weeks'] = [{'week': int(week), 'tp_delta': int(np.sum((after.astype(int) - before)[
        (weeks == week) & (labels == 1)])), 'fp_delta': int(np.sum((after.astype(int) - before)[
        (weeks == week) & (labels == 0)]))} for week in sorted(np.unique(weeks))]
    return result


def main():
    global OUTPUT
    import lightgbm as lgb
    import numpy as np
    import psutil
    from sklearn.metrics import average_precision_score, roc_auc_score
    from experiments.ember_baseline import operating_point
    from ml.ember_protocol import assert_disjoint_hashes, validation_threshold

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compute-go', action='store_true', help='Coordinator has granted this compute slot')
    parser.add_argument('--output-dir', type=Path, default=OUTPUT)
    args = parser.parse_args()
    if not args.compute_go:
        parser.error('Wait for coordinator COMPUTE GO, then pass --compute-go')
    OUTPUT = args.output_dir.resolve()
    OUTPUT.mkdir(parents=True, exist_ok=True)
    output = OUTPUT / 'result.json'
    if output.exists():
        raise ValueError('Existing result retained; choose a new experiment rather than overwrite it')
    check_start_memory(psutil.virtual_memory().available, output)
    started = time.monotonic()
    resource = {'peak_rss_bytes': 0, 'peak_private_bytes': 0,
                'minimum_available_bytes': psutil.virtual_memory().available, 'sampling_seconds': .1}
    stopped = threading.Event()
    phase = ['initialization']

    def monitor():
        process = psutil.Process()
        while not stopped.wait(.1):
            memory = process.memory_info()
            available = psutil.virtual_memory().available
            resource['peak_rss_bytes'] = max(resource['peak_rss_bytes'], memory.rss)
            resource['peak_private_bytes'] = max(resource['peak_private_bytes'], getattr(memory, 'private', 0))
            resource['minimum_available_bytes'] = min(resource['minimum_available_bytes'], available)
            timeout = time.monotonic() - started > 1800
            if available < RESERVE or timeout:
                write_json(output, {'status': 'timeout' if timeout else 'resource_abort',
                                    'phase': phase[0], 'test_data_read': False,
                                    'resource_usage': resource, 'elapsed_seconds': time.monotonic() - started})
                print('ABORT', phase[0], resource, flush=True)
                os._exit(124 if timeout else 75)

    threading.Thread(target=monitor, daemon=True).start()
    sources = source_paths(ROOT)
    meta = {}
    for split in ('fit', 'validation'):
        with np.load(sources[0].parent / ('meta_' + split + '.npz'), allow_pickle=False) as archive:
            meta[split] = {name: archive[name] for name in ('y', 'week', 'date', 'sha')}
    if ([len(meta[s]['y']) for s in ('fit', 'validation')] != [480000, 40000] or
            max(meta['fit']['date']) >= min(meta['validation']['date']) or
            len(np.unique(meta['validation']['week'])) != 4):
        raise ValueError('Frozen FIT/validation cohort changed')
    for split in meta:
        if set(meta[split]['y'].tolist()) != {0, 1}:
            raise ValueError('Expected binary labels')
    assert_disjoint_hashes({split: values['sha'].tolist() for split, values in meta.items()})
    X_fit = fit_sequence(sources[0])
    X_validation = np.load(sources[1], mmap_mode='r', allow_pickle=False)
    if X_fit.shape != (480000, 2568) or X_validation.shape != (40000, 2568) or X_fit.dtype != np.float32:
        raise ValueError('Frozen feature shape/dtype changed')
    params = candidate_params(json.loads(sources[-1].read_text()))
    write_json(OUTPUT / 'effective-params.json', params)
    phase[0] = 'dataset_construction'
    constructed = time.monotonic()
    train = fit_dataset(X_fit, meta['fit']['y'], params, [2, 3, 4, 5, 6, 701, 702])
    train.construct()
    construct_seconds = time.monotonic() - constructed
    if train.data is not None:
        raise RuntimeError('Expected constructed Dataset to release raw input ownership')
    X_fit.close()
    del X_fit
    print('CONSTRUCTED', construct_seconds, resource, flush=True)
    phase[0] = 'training'
    fit_started = time.monotonic()
    # Validation never participates in fitting, early stopping, bin construction or row weights.
    def progress(env):
        if (env.iteration + 1) % 50 == 0:
            print('TRAINING', env.iteration + 1, 'elapsed_seconds', time.monotonic() - fit_started, flush=True)

    model = lgb.train(params, train, callbacks=[progress])
    fit_seconds = time.monotonic() - fit_started
    model_path = OUTPUT / 'coarse-leaves.model'
    model.save_model(str(model_path))
    del train
    phase[0] = 'validation_prediction'
    baseline_model = lgb.Booster(model_file=str(sources[-2]))
    if baseline_model.current_iteration() != 500 or baseline_model.num_feature() != 2568:
        raise ValueError('Frozen baseline model structure changed')

    def predict(booster):
        return np.concatenate([booster.predict(X_validation[start:start + 1024], num_threads=4)
                               for start in range(0, len(X_validation), 1024)])

    baseline, candidate = predict(baseline_model), predict(model)
    np.savez(OUTPUT / 'validation-predictions.npz', baseline=baseline, candidate=candidate)
    labels, weeks = meta['validation']['y'], meta['validation']['week']
    result = {'status': 'completed', 'validation_only': True, 'test_data_read': False,
              'production_changed': False, 'fit_rows': len(meta['fit']['y']), 'validation_rows': len(labels),
              'feature_dim': 2568, 'params': params, 'candidate_rounds': model.current_iteration(),
              'dataset_construction_seconds': construct_seconds, 'fit_seconds': fit_seconds,
              'memory_strategy': 'Read-only NPY seek/read Sequence; float64 sample rows, 1024-row float32 push blocks; no resident full FIT mapping',
              'scope': 'One full-FIT composite coarser-leaf/coarser-bin candidate; reused validation exploration only',
              'uncertainty': 'Own thresholds chosen on this validation; no independent deployment FPR/recall claim. '
                             'Sample-level paired intervals omit family correlation and candidate/threshold selection.',
              'baseline': {}, 'candidate': {}, 'paired': {}}
    for name, scores in (('baseline', baseline), ('candidate', candidate)):
        result[name] = {'roc_auc': float(roc_auc_score(labels, scores)),
                        'average_precision': float(average_precision_score(labels, scores)), 'operating_points': {}}
        for budget, target in (('FP20', .001), ('FP100', .005), ('FP200', .01)):
            threshold = validation_threshold(labels, scores, target)
            result[name]['operating_points'][budget] = operating_point(labels, scores, threshold)
        result[name]['operating_points']['default_0.5'] = operating_point(labels, scores, .5)
    old = json.loads((ROOT / 'docs/benchmarks/ember2024_win64_20261010.json').read_text())
    if hashlib.sha256(sources[-2].read_bytes()).hexdigest() != old['model_sha256']:
        raise ValueError('Frozen model hash changed')
    for budget, old_name in (('FP20', 'validation_fpr_0.1pct'), ('FP200', 'validation_fpr_1pct')):
        expected, observed = old['validation']['operating_points'][old_name], result['baseline']['operating_points'][budget]
        if any(expected[key] != observed[key] for key in ('tp', 'fp', 'tn', 'fn', 'threshold')):
            raise ValueError('Frozen baseline validation did not reproduce')
    for budget in ('FP20', 'FP100', 'FP200'):
        result['paired'][budget] = paired_comparison(labels, weeks, baseline, candidate,
            result['baseline']['operating_points'][budget]['threshold'],
            result['candidate']['operating_points'][budget]['threshold'])
    phase[0] = 'provenance_hashing'
    result['input_sha256'] = {}
    for path in sources:
        digest = hashlib.sha256()
        with path.open('rb') as handle:
            for block in iter(lambda: handle.read(4 * 1024**2), b''):
                digest.update(block)
        result['input_sha256'][path.relative_to(ROOT).as_posix()] = digest.hexdigest()
    result['runner_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    result['model_sha256'] = hashlib.sha256(model_path.read_bytes()).hexdigest()
    result['model_bytes'] = model_path.stat().st_size
    result['package_versions'] = {'lightgbm': lgb.__version__, 'numpy': np.__version__}
    result['resource_usage'] = resource
    result['total_seconds'] = time.monotonic() - started
    stopped.set()
    write_json(output, result)
    print('COMPLETED', output, result['candidate']['operating_points']['FP20'], flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        OUTPUT.mkdir(parents=True, exist_ok=True)
        if not (OUTPUT / 'result.json').exists():
            write_json(OUTPUT / 'result.json', {'status': 'failed', 'test_data_read': False,
                                               'exception_type': type(error).__name__, 'message': str(error)})
        raise
