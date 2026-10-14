"""Trusted inference worker. Input PE bytes are parsed only; never loaded or executed."""

import contextlib
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import sys
import time


def infer(root, profile, artifact, data):
    from aegisav.ml_engine import MLEngine, pe_scope
    registry = MLEngine(root, profile=profile)
    if not registry.ready or registry.artifact_version != artifact:
        return {'status': 'error', 'reason': 'worker_registry_mismatch'}
    try:
        import numpy as np
        import lightgbm as lgb
        from importlib.metadata import version
        for name, expected in {'lightgbm': '4.6.0', 'numpy': '2.2.6', 'pefile': '2024.8.26',
                               'scikit-learn': '1.6.1', 'signify': '0.7.1'}.items():
            if version(name) != expected:
                raise ImportError('Unvalidated feature runtime')
    except Exception:
        return {'status': 'unavailable', 'reason': 'ml_dependency_version_unavailable'}
    scope = pe_scope(data)
    selected = 'win64' if profile == 'win64_low_fpr' and scope == 'win64' else 'general'
    entry = registry.manifest['models'][selected]
    try:
        spec = importlib.util.spec_from_file_location('aegisav_pinned_ember_features', root / 'features.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        from aegisav.ember_features import build_extractor
        implementation = registry.manifest.get('feature_implementation', 'upstream-v3')
        extractor = build_extractor(module, implementation)
        model = lgb.Booster(model_file=str(root / entry['file']))
        if extractor.dim != 2568 or model.num_feature() != 2568:
            raise ValueError('Feature dimension mismatch')
        started = time.perf_counter()
        vector = extractor.feature_vector(data)
        feature_ms = (time.perf_counter() - started) * 1000
        if vector.shape != (2568,) or not np.isfinite(vector).all():
            raise ValueError('Invalid feature vector')
        started = time.perf_counter()
        score = float(model.predict(vector.reshape(1, -1), num_threads=1)[0])
        inference_ms = (time.perf_counter() - started) * 1000
        if not math.isfinite(score) or not 0 <= score <= 1:
            raise ValueError('Invalid prediction')
        return {'status': 'matched' if score >= entry['threshold'] else 'no_match',
                'reason': 'model_score_at_frozen_threshold', 'score': score, 'threshold': entry['threshold'],
                'model_id': selected, 'model_version': entry['version'], 'pe_scope': scope,
                'threshold_source': entry['threshold_source'],
                'feature_schema': registry.manifest['files']['features.py'],
                'feature_implementation': implementation,
                'feature_sha256': hashlib.sha256(vector.astype('<f4').tobytes()).hexdigest(),
                'feature_elapsed_ms': round(feature_ms, 3), 'inference_elapsed_ms': round(inference_ms, 3)}
    except Exception:
        return {'status': 'error', 'reason': 'feature_extraction_or_prediction_failed'}


def main():
    if sys.platform == 'linux':
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_AS, (1536 * 1024**2, 1536 * 1024**2))
        resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
        resource.setrlimit(resource.RLIMIT_FSIZE, (65536, 65536))
    root, profile, artifact = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
    data = sys.stdin.buffer.read(64 * 1024**2 + 1)
    if len(data) > 64 * 1024**2:
        result = {'status': 'error', 'reason': 'input_size_limit'}
    else:
        with open(os.devnull, 'w') as sink, contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
            result = infer(root, profile, artifact, data)
    sys.stdout.write(json.dumps(result, allow_nan=False))


if __name__ == '__main__':
    main()
