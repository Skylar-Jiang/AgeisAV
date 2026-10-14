"""Compare the three fixed validation-only ablations; never load test vectors/scores."""

import hashlib
import json
from pathlib import Path

from experiments.ember_ablation import select_columns

ROOT = Path(__file__).resolve().parents[1]


def main():
    paths = [ROOT / 'docs/benchmarks/ember2024_win64_20261010.json']
    baseline = json.loads(paths[0].read_text())
    candidates = []
    identity = None
    for group in ('strings', 'authenticode', 'pefilewarnings'):
        path = ROOT / 'docs/benchmarks' / f'ember2024_ablation_{group}_20261011.json'
        report = json.loads(path.read_text())
        keep, categorical = select_columns(group)
        assert report['validation_only'] and not report['test_vectors_read']
        assert report['params'] == baseline['params'] and report['rounds'] == 500
        assert report['retained_feature_indices'] == keep and report['categorical_indices'] == categorical
        assert report['validation']['n'] == baseline['validation']['n'] == 40000
        if identity is None:
            identity = report['input_sha256']
        assert identity == report['input_sha256']
        points = report['validation']['operating_points']
        deltas = {}
        for name in ('validation_fpr_1pct', 'validation_fpr_0.1pct'):
            original = baseline['validation']['operating_points'][name]
            assert original['fp'] == points[name]['fp']
            deltas[name] = 100 * (points[name]['recall']['value'] - original['recall']['value'])
        candidates.append({'drop_group': group, 'feature_dim': report['feature_dim'],
                           'validation': report['validation'], 'recall_delta_percentage_points': deltas,
                           'fit_seconds': report['fit_seconds'], 'projection_seconds': report['projection_seconds'],
                           'resource_usage': report['resource_usage'], 'model_sha256': report['model_sha256']})
        paths.append(path)
    result = {'schema': 1, 'validation_only': True, 'strict_final_test': False,
              'test_vectors_or_scores_read': False, 'deployment_changed': False,
              'scope': 'Three predeclared candidates reuse validation; no unbiased selected-model performance',
              'baseline_validation': baseline['validation'], 'candidates': candidates,
              'timing_caveat': 'Host fits overlap VM scanning; different contention, no causal speed comparison',
              'input_sha256': {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},
              'runner_sha256': hashlib.sha256((ROOT / 'experiments/ember_ablation.py').read_bytes()).hexdigest()}
    output = ROOT / 'docs/benchmarks/ablation_validation_comparison_20261011.json'
    output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(output)


if __name__ == '__main__':
    main()
