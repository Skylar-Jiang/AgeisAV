"""Paired max_bin255/127 study on a frozen balanced96k FIT subset.

Requires coordinator COMPUTE GO. Never reads final arrays or raw PE.
"""
import argparse
import gc
import hashlib
import json
import os
from pathlib import Path
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / 'artifacts/model-binning-20261022'
PUBLIC = ROOT / 'docs/benchmarks/model_binning_20261022.json'
ART = ROOT / 'artifacts/ember2024'
CATEGORICAL = [2, 3, 4, 5, 6, 701, 702]
RESERVE = 2 * 1024**3


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')


def file_sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for block in iter(lambda: handle.read(4 * 1024**2), b''):
            digest.update(block)
    return digest.hexdigest()


def study_params(original, max_bin):
    return {**original, 'max_bin': max_bin, 'num_leaves': 64, 'min_data_in_leaf': 100,
            'num_iterations': 500, 'bin_construct_sample_cnt': 20000,
            'histogram_pool_size': 128, 'num_threads': 4, 'deterministic': True,
            'force_col_wise': True, 'verbosity': 1}


def select_fit_rows(meta, per_stratum=1000):
    import numpy as np
    priority = np.array([hashlib.sha256(b'binning-study-seed0:' + bytes(sha)).digest()
                         for sha in meta['sha']], dtype='S32')
    selected, strata = [], []
    for week in sorted(np.unique(meta['week'])):
        for label in (0, 1):
            indices = np.flatnonzero((meta['week'] == week) & (meta['y'] == label))
            if len(indices) < per_stratum:
                raise ValueError('Insufficient FIT stratum for the prespecified balanced subset')
            chosen = indices[np.argsort(priority[indices], kind='stable')[:per_stratum]]
            selected.extend(chosen.tolist())
            strata.append({'week': int(week), 'label': label, 'available': len(indices), 'selected': len(chosen)})
    return np.array(sorted(selected), dtype=np.int64), strata


def selected_sequence(path, indices):
    import lightgbm as lgb
    import numpy as np

    class SelectedNpySequence(lgb.Sequence):
        batch_size = 1024

        def __init__(self):
            header = np.load(path, mmap_mode='r', allow_pickle=False)
            try:
                if header.ndim != 2 or header.dtype != np.float32 or not header.flags.c_contiguous:
                    raise ValueError('Requires contiguous float32 NPY')
                self.width, self.offset = header.shape[1], header.offset
                if indices.min() < 0 or indices.max() >= len(header):
                    raise ValueError('Selected FIT index outside source')
            finally:
                header._mmap.close()
            self.file = path.open('rb')

        def __len__(self):
            return len(indices)

        def __getitem__(self, index):
            single = isinstance(index, (int, np.integer))
            start, stop = (int(index), int(index) + 1) if single else (index.start or 0, index.stop)
            if not single and (index.step not in (None, 1) or stop - start > self.batch_size):
                raise ValueError('Only bounded contiguous Sequence requests are supported')
            rows = np.empty((stop - start, self.width), dtype=np.float32)
            for target, original in enumerate(indices[start:stop]):
                self.file.seek(self.offset + int(original) * self.width * 4)
                rows[target] = np.frombuffer(self.file.read(self.width * 4), dtype=np.float32)
            return rows[0].astype(np.float64) if single else rows

        def close(self):
            self.file.close()

    return SelectedNpySequence()


def self_check():
    import numpy as np
    from experiments.model_search_round2 import fit_dataset
    meta = {'sha': np.array([f'{i:064x}'.encode() for i in range(40)], dtype='S64'),
            'week': np.repeat([1, 2], 20), 'y': np.tile(np.repeat([0, 1], 10), 2)}
    selected, strata = select_fit_rows(meta, 3)
    assert len(selected) == 12 and all(row['selected'] == 3 for row in strata)
    np.testing.assert_array_equal(select_fit_rows(meta, 3)[0], selected)
    params255, params127 = study_params({}, 255), study_params({}, 127)
    assert {key for key in params255 if params255[key] != params127[key]} == {'max_bin'}
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / 'synthetic.npy'
        values = np.arange(40 * 12, dtype=np.float32).reshape(40, 12)
        np.save(path, values)
        sequence = selected_sequence(path, selected)
        try:
            np.testing.assert_array_equal(sequence[0], values[selected[0]].astype(np.float64))
            np.testing.assert_array_equal(sequence[2:5], values[selected[2:5]])
            dataset = fit_dataset(sequence, meta['y'][selected], params255, [])
            assert dataset.get_params() == params255
        finally:
            sequence.close()
    print('Self-check passed: balanced deterministic selection, one-factor params, streaming row parity, constructor params; no training')


def run():
    import lightgbm as lgb
    import numpy as np
    import psutil
    from sklearn.metrics import average_precision_score, roc_auc_score
    from experiments.ember_baseline import operating_point
    from experiments.model_search_round2 import fit_dataset, paired_comparison
    from experiments.course_evaluation_summary import quantiles
    from ml.ember_protocol import assert_disjoint_hashes, validation_threshold

    if OUTPUT.exists():
        raise ValueError('Retain previous output directory; this fixed study may not overwrite prior observations')
    OUTPUT.mkdir(parents=True)
    started = time.monotonic()
    result = {'status': 'started', 'development_validation_only': True, 'test_data_read': False,
              'production_changed': False, 'models': {}, 'phase': 'preflight'}
    available = psutil.virtual_memory().available
    resource = {'minimum_available_bytes': available, 'peak_rss_bytes': 0, 'peak_private_bytes': 0,
                'sampling_seconds': .1, 'required_start_bytes': 3 * 1024**3, 'reserve_bytes': RESERVE}
    result['resource_usage'] = resource
    if available < 3 * 1024**3:
        result.update(status='resource_blocked', elapsed_seconds=time.monotonic() - started)
        write_json(OUTPUT / 'result.json', result)
        write_json(PUBLIC, result)
        raise MemoryError('Requires3GiB available;2GiB reserve is not weakened')
    stopped = threading.Event()

    def monitor():
        process = psutil.Process()
        while not stopped.wait(.1):
            memory = process.memory_info()
            available = psutil.virtual_memory().available
            resource['minimum_available_bytes'] = min(resource['minimum_available_bytes'], available)
            resource['peak_rss_bytes'] = max(resource['peak_rss_bytes'], memory.rss)
            resource['peak_private_bytes'] = max(resource['peak_private_bytes'], getattr(memory, 'private', 0))
            timeout = time.monotonic() - started > 900
            if available < RESERVE or timeout:
                try:
                    result.update(status='timeout' if timeout else 'resource_abort', elapsed_seconds=time.monotonic() - started)
                    write_json(OUTPUT / 'result.json', result)
                    write_json(PUBLIC, result)
                    print('ABORT', result['phase'], resource, flush=True)
                finally:
                    os._exit(124 if timeout else 75)

    threading.Thread(target=monitor, daemon=True).start()
    try:
        fit_meta_path = ART / 'vectors/meta_fit.npz'
        with np.load(fit_meta_path, allow_pickle=False) as archive:
            fit_meta = {key: archive[key] for key in ('y', 'week', 'date', 'sha')}
        if len(fit_meta['y']) != 480000 or len(np.unique(fit_meta['week'])) != 48:
            raise ValueError('Frozen FIT metadata changed')
        indices, strata = select_fit_rows(fit_meta)
        if len(indices) != 96000 or [int(np.sum(fit_meta['y'][indices] == y)) for y in (0, 1)] != [48000, 48000]:
            raise ValueError('Prespecified balanced96k selection failed')
        np.savez(OUTPUT / 'selected-fit.npz', indices=indices, **{k: v[indices] for k, v in fit_meta.items()})
        cohort = hashlib.sha256()
        for index in indices:
            cohort.update(f"{index},{int(fit_meta['y'][index])},{int(fit_meta['week'][index])},".encode())
            cohort.update(bytes(fit_meta['sha'][index]) + b'\n')
        selection = {'selected_rows': 96000, 'benign': 48000, 'malicious': 48000, 'strata': strata,
                     'selection_rule': 'Lowest1000SHA256(seed0prefix+sampleSHA) per FITweek,label; sort originalrowindex',
                     'selected_cohort_sha256': cohort.hexdigest(), 'fit_metadata_sha256': file_sha(fit_meta_path),
                     'selection_manifest_sha256': file_sha(OUTPUT / 'selected-fit.npz'),
                     'frozen_before_validation_read': True}
        write_json(OUTPUT / 'selection-freeze.json', selection)
        result['selection'] = selection
        # Only after the persisted selection freeze may validation metadata/features be opened.
        with np.load(ART / 'vectors/meta_validation.npz', allow_pickle=False) as archive:
            validation_meta = {key: archive[key] for key in ('y', 'week', 'date', 'sha')}
        if (len(validation_meta['y']) != 40000 or len(np.unique(validation_meta['week'])) != 4 or
                int(np.sum(validation_meta['y'] == 0)) != 20000 or
                max(fit_meta['date']) >= min(validation_meta['date'])):
            raise ValueError('Frozen validation identity/chronology changed')
        assert_disjoint_hashes({'fit': fit_meta['sha'].tolist(), 'validation': validation_meta['sha'].tolist()})
        labels, weeks = validation_meta['y'], validation_meta['week']
        X_validation = np.load(ART / 'vectors/X_validation.npy', mmap_mode='r', allow_pickle=False)
        if X_validation.shape != (40000, 2568) or X_validation.dtype != np.float32:
            raise ValueError('Frozen validation feature shape changed')
        originals = json.loads((ART / 'upstream/examples/lgbm_config.json').read_text())
        model_paths, scores = {}, {}
        for bins in (255, 127):
            name = f'max_bin{bins}'
            params = study_params(originals, bins)
            result['phase'] = name + '_construction'
            sequence = selected_sequence(ART / 'vectors/X_fit.npy', indices)
            if sequence.width != 2568:
                raise ValueError('Frozen FIT feature dimension changed')
            construction = time.monotonic()
            dataset = fit_dataset(sequence, fit_meta['y'][indices], params, CATEGORICAL)
            dataset.construct()
            sequence.close()
            if dataset.data is not None:
                raise ValueError('Streaming Dataset did not release raw ownership')
            construct_seconds = time.monotonic() - construction
            result['phase'] = name + '_training'
            training = time.monotonic()

            def progress(env):
                if (env.iteration + 1) % 100 == 0:
                    print(name, env.iteration + 1, 'rounds', round(time.monotonic() - training, 1), 'seconds', flush=True)

            model = lgb.train(params, dataset, callbacks=[progress])
            fit_seconds = time.monotonic() - training
            model_paths[name] = OUTPUT / (name + '.model')
            model.save_model(str(model_paths[name]))
            model.free_dataset()
            del dataset
            result['phase'] = name + '_validation'
            scores[name] = np.concatenate([model.predict(X_validation[start:start + 1024], num_threads=1)
                                           for start in range(0, len(X_validation), 1024)])
            points = {budget: operating_point(labels, scores[name], validation_threshold(labels, scores[name], target))
                      for budget, target in (('FP20', .001), ('FP100', .005), ('FP200', .01))}
            result['models'][name] = {'params': params, 'rounds': model.current_iteration(),
                'dataset_construction_seconds': construct_seconds, 'fit_seconds': fit_seconds,
                'operating_points': points, 'roc_auc': float(roc_auc_score(labels, scores[name])),
                'average_precision': float(average_precision_score(labels, scores[name])),
                'model_sha256': file_sha(model_paths[name]), 'model_bytes': model_paths[name].stat().st_size}
            write_json(OUTPUT / 'partial-result.json', result)
            del model, sequence
            gc.collect()
        if {key for key in result['models']['max_bin255']['params'] if
                result['models']['max_bin255']['params'][key] != result['models']['max_bin127']['params'][key]} != {'max_bin'}:
            raise ValueError('Paired study must change max_bin only')
        result['paired'] = {budget: paired_comparison(labels, weeks, scores['max_bin255'], scores['max_bin127'],
            result['models']['max_bin255']['operating_points'][budget]['threshold'],
            result['models']['max_bin127']['operating_points'][budget]['threshold'])
            for budget in ('FP20', 'FP100', 'FP200')}
        np.savez(OUTPUT / 'validation-predictions.npz', **scores)
        result['phase'] = 'inference_cost'
        models, costs = {}, {}
        for name, path in model_paths.items():
            # Warm the file cache once; one following load measurement is not cold-start evidence.
            file_sha(path)
            load_started = time.perf_counter()
            models[name] = lgb.Booster(model_file=str(path))
            costs[name] = {'single_warm_file_load_ms': (time.perf_counter() - load_started) * 1000, 'raw_batch_ms': []}

        def predict(booster):
            return np.concatenate([booster.predict(X_validation[start:start + 1024], num_threads=1)
                                   for start in range(0, len(X_validation), 1024)])

        for name, model in models.items():
            np.testing.assert_array_equal(predict(model), scores[name])
        for repeat in range(5):
            for name in ('max_bin255', 'max_bin127') if repeat % 2 == 0 else ('max_bin127', 'max_bin255'):
                prediction_started = time.perf_counter()
                observed = predict(models[name])
                costs[name]['raw_batch_ms'].append((time.perf_counter() - prediction_started) * 1000)
                np.testing.assert_array_equal(observed, scores[name])
        for name, cost in costs.items():
            cost.update(quantiles(cost['raw_batch_ms']))
            result['models'][name]['inference_cost'] = cost
        result['phase'] = 'provenance'
        sources = [ART / 'vectors' / name for name in ('X_fit.npy', 'meta_fit.npz', 'X_validation.npy', 'meta_validation.npz')]
        sources += [ART / 'upstream/examples/lgbm_config.json', ROOT / 'experiments/model_search_round2.py',
                    ROOT / 'ml/ember_protocol.py', ROOT / 'experiments/ember_baseline.py']
        result.update(status='completed', input_sha256={p.relative_to(ROOT).as_posix(): file_sha(p) for p in sources},
            runner_sha256=file_sha(Path(__file__)), package_versions={'lightgbm': lgb.__version__, 'numpy': np.__version__},
            all_repeat_predictions_equal=True, total_seconds=time.monotonic() - started,
            scope='Single max_bin factor conditional on frozen96k balanced FIT subset and shared20k bin sampling. '
                  'Both controls are newly trained; comparison to full480k historical baseline is not a binning effect.',
            inference_method='Preloaded models, read-only validation mapping,1024row blocks,1thread,1warmup,5alternating rounds; '
                             'one warm-file load each, not cold startup or full application latency.',
            uncertainty='Reused40k development validation with own in-sample thresholds; paired sample-iid intervals '
                        'ignore family/source correlation and selection. Four weekly strata; no independent/deployment claim.')
        write_json(OUTPUT / 'result.json', result)
        write_json(PUBLIC, result)
        print('COMPLETED', OUTPUT, flush=True)
    except Exception as error:
        result.update(status='failed', error_type=type(error).__name__, error=str(error), total_seconds=time.monotonic() - started)
        write_json(OUTPUT / 'result.json', result)
        write_json(PUBLIC, result)
        raise
    finally:
        stopped.set()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compute-go', action='store_true')
    parser.add_argument('--self-check', action='store_true')
    args = parser.parse_args()
    if args.self_check:
        self_check()
    elif args.compute_go:
        run()
    else:
        parser.error('Requires explicit coordinator COMPUTE GO; then pass --compute-go')
