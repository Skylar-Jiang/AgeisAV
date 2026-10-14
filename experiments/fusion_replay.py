"""Post hoc fixed-policy replay of saved paired results; never calibrates or selects a policy."""

import hashlib
import json
from pathlib import Path

from experiments.compare_static_rounds import ENGINES, distribution, normalized_rows, outcome, wilson


def policies(signatures, ml):
    values = [*signatures, ml]
    if len(signatures) != 4 or any(value is not None and type(value) is not bool for value in values):
        raise ValueError('Expected five boolean or abstaining outcomes')
    signature = True if any(value is True for value in signatures) else (
        False if all(value is False for value in signatures) else None)
    union = True if signature is True or ml is True else (
        False if signature is False and ml is False else None)
    intersection = False if signature is False or ml is False else (
        True if signature is True and ml is True else None)
    return dict(signature_or=signature, ml_only=ml, evidence_or=union, corroborated=intersection)


def summarize(rows, malicious):
    results = [policies([outcome(row, name, malicious) for name in ENGINES[:-1]],
                        outcome(row, 'lightgbm', malicious)) for row in rows]
    return {name: dict(observed_positive=wilson(sum(item[name] is True for item in results), len(results)),
                       completed_decision_positive=wilson(sum(item[name] is True for item in results),
                                                         sum(item[name] is not None for item in results)),
                       abstentions=sum(item[name] is None for item in results))
            for name in ('signature_or', 'ml_only', 'evidence_or', 'corroborated')}


def main():
    base = Path('docs/benchmarks')
    inputs = [base / name for name in (
        'user_archive_static_20261010.json', 'user_archive_label_reference_20261010.json',
        'benign_windows_static_20261010.json', 'benign_vendor_static_20261011.json',
        'benign_expansion_static_20261010.json', 'general_pe_training_overlap_20261010.json')]
    inputs.append(Path('rules/hashes.json'))
    archive, labels, windows, vendor, expansion, audit, database = [json.loads(path.read_text()) for path in inputs]
    assert archive['archive_sha256'] == labels['source_archive_sha256']
    archive_rows, _ = normalized_rows(archive)
    label_map = {item['sha256']: item['label'] for item in labels['samples']}
    proxy = [row for sha, row in archive_rows.items() if row.get('pe_valid', True)
             and label_map[sha] == 'malicious_proxy']
    excluded = {sha for name, group in audit['cohort_overlap'].items() if name != 'archive' for sha in group['matches']}
    benign = {}
    for report in (windows, vendor, expansion):
        rows, _ = normalized_rows(report)
        if benign.keys() & rows.keys():
            raise ValueError('Overlapping benign cohorts')
        benign.update(rows)
    benign = [row for sha, row in benign.items() if sha not in excluded]
    malicious = {item['sha256'] for item in database if item['verdict'] == 'malicious'}
    result = dict(schema=1, strict_final_test=False, post_hoc_error_analysis=True,
                  policy_selection_performed=False, thresholds_changed=False,
                  fixed_low_fpr_fusion_recall=None,
                  missing_evidence='Fresh paired raw-PE validation and independent final cohorts with verifiable labels',
                  model_threshold=0.5, archive_proxy_count=len(proxy), benign_proxy_count=len(benign),
                  unknown_excluded=sum(row.get('pe_valid', True) and label_map[sha] == 'unknown'
                                       for sha, row in archive_rows.items()),
                  definitions=dict(signature_or='OR of SHA malicious, fuzzy, YARA and ClamAV',
                                   ml_only='Frozen general-PE score >= 0.5',
                                   evidence_or='signature_or OR ml_only',
                                   corroborated='signature_or AND ml_only; diagnostic only, never deployed'),
                  archive_development=summarize(proxy, malicious),
                  reported_training_disjoint_benign=summarize(benign, malicious),
                  input_sha256={str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs})
    result['vendor_latency_ms'] = {
        'pipeline': distribution([row['elapsed_ms'] for row in vendor['files']]),
        **{name: distribution([row['engines'][name]['elapsed_ms'] for row in vendor['files']]) for name in ENGINES}}
    result['timing_limitations'] = 'Saved sequential ML runner; no policy-specific rerun or counterfactual speedup; contention and resumes present'
    (base / 'fusion_fixed_policy_replay_20261011.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: result[key] for key in ('archive_proxy_count', 'benign_proxy_count', 'unknown_excluded')}))


if __name__ == '__main__':
    main()
