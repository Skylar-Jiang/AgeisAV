"""Pinned EMBER2024 static feature inference; no sample execution or network access."""

import hashlib
import importlib.util
import json
import math
import time


class EmberEngine:
    def __init__(self, root):
        import lightgbm
        import numpy
        self.np = numpy
        manifest = json.loads((root / 'manifest.json').read_text())
        for name, digest in manifest['files'].items():
            if name not in {'features.py', 'pefile_warnings.txt', 'EMBER2024_PE.model'}:
                raise ValueError('Unexpected model asset')
            if hashlib.sha256((root / name).read_bytes()).hexdigest() != digest:
                raise ValueError('Model asset digest mismatch')
        if set(manifest['files']) != {'features.py', 'pefile_warnings.txt', 'EMBER2024_PE.model'}:
            raise ValueError('Missing model asset')
        spec = importlib.util.spec_from_file_location('aegisav_ember_features', root / 'features.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.extractor = module.PEFeatureExtractor()
        self.model = lightgbm.Booster(model_file=str(root / 'EMBER2024_PE.model'))
        if self.extractor.dim != 2568 or self.model.num_feature() != 2568:
            raise ValueError('Unexpected EMBER feature dimension')
        self.artifact_version = ('official-pretrained-PE:' + manifest['files']['EMBER2024_PE.model']
                                 + ':' + manifest['upstream_revision'])

    def scan(self, data):
        started = time.perf_counter()
        feature_ms, inference_ms = 0.0, 0.0
        inference_started = None
        score, status = None, 'error'
        try:
            vector = self.extractor.feature_vector(data)
            if vector.shape != (2568,) or not self.np.isfinite(vector).all():
                raise ValueError('Invalid feature vector')
            inference_started = time.perf_counter()
            feature_ms = (inference_started - started) * 1000
            prediction = float(self.model.predict(vector.reshape(1, -1), num_threads=1)[0])
            if not math.isfinite(prediction) or not 0 <= prediction <= 1:
                raise ValueError('Invalid prediction')
            score = prediction
            status = 'matched' if score >= 0.5 else 'no_match'
        except Exception:
            # Parsing/prediction failures abstain; neither a benign decision nor raw exception text.
            pass
        finished = time.perf_counter()
        if inference_started is None:
            feature_ms = (finished - started) * 1000
        else:
            inference_ms = (finished - inference_started) * 1000
        return {'status': status, 'score': score, 'threshold': 0.5,
                'engine_version': 'LightGBM/4.6.0 EMBER2024/v3', 'artifact_version': self.artifact_version,
                'elapsed_ms': round((finished - started) * 1000, 3), 'evidence': [],
                'feature_elapsed_ms': round(feature_ms, 3), 'inference_elapsed_ms': round(inference_ms, 3)}
