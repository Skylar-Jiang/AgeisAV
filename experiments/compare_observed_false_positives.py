"""Rescore only previously observed benign development controls, without executing PE."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))


def main():
    import lightgbm as lgb
    import numpy as np
    from aegisav.ember_features import build_extractor
    from aegisav.ml_engine import MLEngine, pe_scope

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', required=True, type=Path)
    parser.add_argument('--candidate-result', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError('Retain previous observations')
    candidate_result = json.loads(args.candidate_result.read_text())
    if candidate_result['status'] != 'completed' or not candidate_result['validation_only']:
        raise ValueError('Requires completed development candidate')
    candidate_path = args.candidate_result.parent / 'coarse-leaves.model'
    if hashlib.sha256(candidate_path.read_bytes()).hexdigest() != candidate_result['model_sha256']:
        raise ValueError('Candidate model identity mismatch')
    registry = MLEngine(ROOT / 'models/ember2024')
    if not registry.ready:
        raise ValueError('Frozen production assets not ready')
    spec = importlib.util.spec_from_file_location('observed_ember_features', registry.root / 'features.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    extractor = build_extractor(module, registry.manifest['feature_implementation'])
    models = {name: lgb.Booster(model_file=str(registry.root / entry['file']))
              for name, entry in registry.manifest['models'].items()}
    models['coarse'] = lgb.Booster(model_file=str(candidate_path))
    thresholds = {name: entry['threshold'] for name, entry in registry.manifest['models'].items()}
    thresholds['coarse'] = candidate_result['candidate']['operating_points']['FP20']['threshold']
    manifest = json.loads(args.manifest.read_text())
    if manifest['development_only'] is not True:
        raise ValueError('Development controls only')
    # Every item must already be an observed positive in the frozen R7 records.
    observed = {}
    for name in ('guest-paired.json', 'guest-r4-paired.json'):
        for row in json.loads((ROOT / 'artifacts/stage-e-r7-20261019' / name).read_text())['files']:
            if row['label'] == 'presumed_benign_operational' and row.get('previously_observed') is True:
                engine = row.get('report', {}).get('engines', {}).get('lightgbm', {})
                if engine.get('status') == 'matched':
                    observed[row['sha256']] = engine
    allowed = [ROOT / 'artifacts' / name / 'samples' for name in
               ('r6-benign-20261018', 'official-diverse-pe-20261018-r5', 'official-multivendor-pe-20261017-r4')]
    result = {'development_only': True, 'selection_biased_positive_controls': True,
              'independent_test': False, 'production_changed': False, 'files': [],
              'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'registry_artifact': registry.artifact_version, 'candidate_sha256': candidate_result['model_sha256']}
    for row in manifest['files']:
        previous = observed[row['sha256']]
        path = (ROOT / row['path']).resolve()
        if not any(path.is_relative_to(base.resolve()) for base in allowed):
            raise ValueError('Input outside previously collected benign controls')
        data = path.read_bytes()
        if len(data) > 16 * 1024**2 or hashlib.sha256(data).hexdigest() != row['sha256']:
            raise ValueError('Control identity/size mismatch')
        vector = extractor.feature_vector(data)
        feature_sha = hashlib.sha256(vector.astype('<f4').tobytes()).hexdigest()
        if vector.shape != (2568,) or not np.isfinite(vector).all() or feature_sha != previous['feature_sha256']:
            raise ValueError('Previously observed feature identity changed')
        scope = pe_scope(data)
        scores = {name: float(model.predict(vector.reshape(1, -1), num_threads=1)[0])
                  for name, model in models.items() if name == 'general' or scope == 'win64'}
        if abs(scores['general'] - previous['score']) > 1e-12:
            raise ValueError('Frozen general prediction changed')
        result['files'].append({**{key: row[key] for key in ('sha256', 'source', 'category')},
                                'pe_scope': scope, 'feature_sha256': feature_sha, 'scores': scores,
                                'thresholds': {name: thresholds[name] for name in scores},
                                'alerts': {name: score >= thresholds[name] for name, score in scores.items()}})
        print(row['source'], scope, result['files'][-1]['alerts'], flush=True)
    result['completed'] = True
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
