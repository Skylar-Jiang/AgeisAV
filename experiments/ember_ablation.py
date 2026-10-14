"""Validation-only feature ablations; this program never opens the test vectors."""

import argparse
import hashlib
import json
from pathlib import Path
import time
import os
import threading

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / 'artifacts/ember2024'
RANGES = {'strings': (519, 696), 'authenticode': (2472, 2480), 'pefilewarnings': (2480, 2568)}


def select_columns(group):
    start, end = RANGES[group]
    keep = [index for index in range(2568) if not start <= index < end]
    categorical = [keep.index(index) for index in (2, 3, 4, 5, 6, 701, 702)]
    return keep, categorical


def project_columns(source, target, keep, batch_rows=1024):
    """Copy selected columns in bounded blocks to a C-contiguous disk mapping."""
    import numpy as np
    original = np.load(source, mmap_mode='r')
    output = np.lib.format.open_memmap(target, mode='w+', dtype=original.dtype,
                                     shape=(len(original), len(keep)))
    for start in range(0, len(original), batch_rows):
        output[start:start + batch_rows] = original[start:start + batch_rows, keep]
    output.flush()
    del output, original
    return np.load(target, mmap_mode='r')


def main():
    import lightgbm as lgb
    import numpy as np
    import psutil
    from experiments.ember_baseline import evaluate
    from ml.ember_protocol import assert_disjoint_hashes, validation_threshold
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--drop-group', required=True, choices=RANGES)
    args = parser.parse_args()
    if psutil.virtual_memory().available < 4 * 1024**3:
        raise ValueError('Bounded ablation requires 4 GiB available RAM before starting')
    resource_usage = {'peak_rss_bytes': 0, 'peak_private_bytes': 0,
                      'minimum_available_bytes': psutil.virtual_memory().available}
    stopped = threading.Event()
    def monitor():
        process = psutil.Process()
        while not stopped.wait(.25):
            memory = process.memory_info()
            available = psutil.virtual_memory().available
            resource_usage['peak_rss_bytes'] = max(resource_usage['peak_rss_bytes'], memory.rss)
            resource_usage['peak_private_bytes'] = max(resource_usage['peak_private_bytes'], getattr(memory, 'private', 0))
            resource_usage['minimum_available_bytes'] = min(resource_usage['minimum_available_bytes'], available)
            if available < 1536 * 1024**2:
                print('RESOURCE_ABORT: available host memory below 1.5 GiB; no metrics published', flush=True)
                os._exit(75)
    threading.Thread(target=monitor, daemon=True).start()
    meta = {s: dict(np.load(ART / 'vectors' / ('meta_' + s + '.npz'))) for s in ('fit', 'validation')}
    if [len(meta[s]['y']) for s in meta] != [480000, 40000] or max(meta['fit']['date']) >= min(meta['validation']['date']):
        raise ValueError('Changed frozen fit/validation cohort')
    assert_disjoint_hashes({s: m['sha'].tolist() for s,m in meta.items()})
    keep, categorical = select_columns(args.drop_group)
    projected = ART / ('projection_' + args.drop_group + '.npy')
    projection_started = time.perf_counter()
    X_fit = project_columns(ART / 'vectors/X_fit.npy', projected, keep)
    projection_seconds = time.perf_counter() - projection_started
    # Validation is only 40k rows; prediction is also performed in bounded blocks below.
    validation_source = np.load(ART / 'vectors/X_validation.npy', mmap_mode='r')
    params = json.loads((ART / 'upstream/examples/lgbm_config.json').read_text())
    params.update(num_threads=8, deterministic=True, force_col_wise=True, verbosity=1)
    train = lgb.Dataset(X_fit, meta['fit']['y'], categorical_feature=categorical)
    started = time.perf_counter()
    # No early stopping or validation-dependent training exists in the frozen protocol.
    model = lgb.train(params, train, callbacks=[lgb.log_evaluation(100)])
    fit_seconds = time.perf_counter() - started
    model_path = ART / 'models' / ('ember2024_without_' + args.drop_group + '.model')
    model.save_model(str(model_path))
    scores = np.concatenate([model.predict(validation_source[start:start + 1024, keep], num_threads=8)
                             for start in range(0, len(validation_source), 1024)])
    np.save(ART / ('validation_without_' + args.drop_group + '_scores.npy'), scores)
    thresholds = {'default_0.5': .5, **{'validation_fpr_' + name: validation_threshold(meta['validation']['y'],scores,target)
                                    for name,target in [('1pct',.01),('0.1pct',.001)]}}
    sources = [ROOT / 'docs/research/FEATURE_ABLATION_PROTOCOL_20261010.md', ART / 'dataset_provenance.json',
               ART / 'vectors/meta_fit.npz', ART / 'vectors/meta_validation.npz', ART / 'upstream/src/thrember/features.py']
    result = {'status':'completed','validation_only':True,'test_vectors_read':False,
              'scope':'Exploratory feature research; no new final-test result and no deployment change',
              'drop_group':args.drop_group,'dropped_range_half_open':RANGES[args.drop_group],
              'feature_dim':len(keep),'retained_feature_indices':keep,'categorical_indices':categorical,
              'params':params,'rounds':model.current_iteration(),'fit_seconds':fit_seconds,
              'projection_seconds':projection_seconds,'memory_strategy':'1024-row disk projection; C-contiguous read-only memmap',
              'resource_usage':resource_usage,
              'model_sha256':hashlib.sha256(model_path.read_bytes()).hexdigest(),
              'validation':evaluate(meta['validation']['y'],scores,thresholds),
              'input_sha256':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}}
    output = ROOT / 'docs/benchmarks' / ('ember2024_ablation_' + args.drop_group + '_20261011.json')
    output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print('COMPLETED',output,flush=True)
    stopped.set()
    del train, X_fit, validation_source
    projected.unlink()


if __name__ == '__main__':
    main()
