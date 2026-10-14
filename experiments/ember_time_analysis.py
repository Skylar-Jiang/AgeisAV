"""Frozen-score calendar-week drift and paired cluster-bootstrap uncertainty."""

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / 'artifacts/ember2024'


def paired_week_interval(success, total, other_success=None, other_total=None):
    import numpy as np
    success, total = np.asarray(success), np.asarray(total)
    if success.shape != total.shape or not len(total) or (total <= 0).any():
        raise ValueError('Invalid week counts')
    rng = np.random.default_rng(0)
    draws = rng.integers(0,len(total),size=(10000,len(total)))
    rates = success[draws].sum(axis=1) / total[draws].sum(axis=1)
    if other_success is not None:
        other_success, other_total = np.asarray(other_success), np.asarray(other_total)
        if other_success.shape != success.shape or other_total.shape != total.shape or (other_total <= 0).any():
            raise ValueError('Unpaired week counts')
        rates -= other_success[draws].sum(axis=1) / other_total[draws].sum(axis=1)
    return np.quantile(rates,[.025,.975]).tolist()


def main():
    import numpy as np
    from experiments.ember_baseline import operating_point
    baseline = json.loads((ROOT / 'docs/benchmarks/ember2024_win64_20261010.json').read_text())
    linear = json.loads((ROOT / 'docs/benchmarks/ember2024_linear_20261010.json').read_text())
    meta = np.load(ART / 'vectors/meta_test.npz')
    weeks = 52 + (meta['date'] - 1726963200) // (7*86400)
    if set(weeks.tolist()) != set(range(52,64)):
        raise ValueError('Changed official test calendar')
    models = {
        'lightgbm_local': (np.load(ART / 'local_predictions.npz')['test_scores'],baseline['test']),
        'lightgbm_official_win64': (np.load(ART / 'official_test_scores.npy'),baseline['official_pretrained']['test']),
        'linear_sgd': (np.load(ART / 'linear_predictions.npz')['test_scores'],linear['test']),
    }
    output = {'scope':'Frozen temporal test error analysis; no threshold/model selection',
              'method':'10000 percentile bootstrap draws of 12 whole calendar weeks, seed0; paired models share each draw',
              'limitations':'Only 12 weeks; does not address within-family dependence across weeks, label noise or deployment shift',
              'models':{},'default_point_paired_gains':{}}
    for name,(scores,report) in models.items():
        points = {}
        for point,global_result in report['operating_points'].items():
            observed = operating_point(meta['y'],scores,global_result['threshold'])
            if any(observed[k] != global_result[k] for k in ('tp','fp','tn','fn')):
                raise ValueError('Frozen scores differ from original report')
            rows = []
            for week in range(52,64):
                selected = weeks == week
                result = operating_point(meta['y'][selected],scores[selected],global_result['threshold'])
                rows.append({'calendar_week':week,'n':int(selected.sum()),**{k:result[k] for k in ('tp','fp','tn','fn')},
                             'recall':result['recall']['value'],'fpr':result['fpr']['value']})
            points[point] = {'threshold':global_result['threshold'],'weeks':rows,
                             'recall_week_bootstrap_ci95':paired_week_interval([r['tp'] for r in rows],[r['tp']+r['fn'] for r in rows]),
                             'fpr_week_bootstrap_ci95':paired_week_interval([r['fp'] for r in rows],[r['fp']+r['tn'] for r in rows])}
        output['models'][name] = points
    a = output['models']['lightgbm_local']['default_0.5']['weeks']
    for name,point in [('linear_sgd','default_probability_0.5'),('lightgbm_official_win64','default_0.5')]:
        b = output['models'][name][point]['weeks']
        gains = {}
        for metric,numerator,negative in [('recall','tp','fn'),('fpr','fp','tn')]:
            gains[metric+'_local_minus_other_ci95'] = paired_week_interval(
                [r[numerator] for r in a],[r[numerator]+r[negative] for r in a],
                [r[numerator] for r in b],[r[numerator]+r[negative] for r in b])
        output['default_point_paired_gains'][name] = gains
    sources = [ART / 'local_predictions.npz',ART / 'linear_predictions.npz',ART / 'official_test_scores.npy',ART / 'vectors/meta_test.npz']
    output['input_sha256'] = {str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
    path = ROOT / 'docs/benchmarks/ember2024_week_analysis_20261010.json'
    path.write_text(json.dumps(output,indent=2)+'\n',encoding='utf-8')
    print('COMPLETED',path,flush=True)


if __name__ == '__main__':
    main()
