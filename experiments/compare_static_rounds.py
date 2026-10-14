"""Compare frozen static rounds on identical SHA cohorts without fitting or threshold tuning."""

import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import statistics


ENGINES = ('sha256', 'fuzzy', 'yara_x', 'clamav', 'lightgbm')
COMPLETED = {'matched', 'no_match'}


def wilson(success, total):
    if not total:
        return {'numerator': success, 'denominator': total, 'value': None, 'ci95': None}
    z = 1.959963984540054
    p = success / total
    denominator = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denominator
    radius = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    return {'numerator': success, 'denominator': total, 'value': p,
            'ci95': [max(0, center - radius), min(1, center + radius)]}


def distribution(values):
    values = sorted(value for value in values if value is not None)
    if not values:
        return {'sample_count': 0, 'mean': None, 'p50': None, 'p95_nearest_rank': None, 'max': None}
    return {'sample_count': len(values), 'mean': statistics.mean(values), 'p50': statistics.median(values),
            'p95_nearest_rank': values[math.ceil(.95 * len(values)) - 1], 'max': values[-1]}


def normalized_rows(report):
    if report.get('completed') is False:
        raise ValueError('Incomplete report')
    rows = report['reports'] if 'reports' in report else report['files']
    unique, duplicates = {}, 0
    for row in rows:
        digest = row['sha256']
        if digest in unique:
            def identity(item):
                return (item.get('size_bytes'), item.get('pe_valid', True),
                        {name: {k: v for k, v in engine.items() if not k.endswith('elapsed_ms')}
                         for name, engine in item['engines'].items()})
            if not row.get('duplicate', False) or identity(row) != identity(unique[digest]):
                raise ValueError('Unmarked or conflicting duplicate SHA row')
            duplicates += 1
        else:
            if row.get('duplicate', False):
                raise ValueError('Orphan duplicate SHA row')
            unique[digest] = row
    return unique, duplicates


def outcome(row, name, malicious_sha256):
    engine = row['engines'].get(name, {})
    status = engine.get('status', 'missing')
    if name == 'lightgbm' and engine and engine.get('threshold') != .5:
        raise ValueError('Only the fixed model threshold 0.5 is comparable')
    if status not in COMPLETED:
        return None
    if name == 'lightgbm':
        score = engine.get('score')
        if type(score) not in (int, float) or not math.isfinite(score) or not 0 <= score <= 1:
            raise ValueError('Invalid completed model score')
        if (score >= .5) != (status == 'matched'):
            raise ValueError('Model score and status disagree')
    if name == 'sha256' and status == 'matched':
        evidence = engine.get('evidence', [])
        if engine.get('risk_signal') == 'malicious' or any(isinstance(e, dict) and e.get('verdict') == 'malicious' for e in evidence):
            return True
        if malicious_sha256 is not None:
            return row['sha256'] in malicious_sha256
        if any(isinstance(e, dict) and e.get('verdict') == 'benign' for e in evidence):
            return False
        raise ValueError('Matched exact SHA requires malicious reference provenance')
    return status == 'matched'


def round_summary(rows, labels, duplicates, malicious_sha256):
    proxy = {sha for sha in rows if labels[sha] == 'malicious_proxy'}
    benign = {sha for sha in rows if labels[sha] in {'benign', 'presumed_benign'}}
    outcomes = {name: {sha: outcome(row, name, malicious_sha256) for sha, row in rows.items()} for name in ENGINES}
    active = ENGINES if any('lightgbm' in row['engines'] for row in rows.values()) else ENGINES[:-1]
    fusion = {sha: True if any(outcomes[name][sha] is True for name in active)
              else False if all(outcomes[name][sha] is False for name in active) else None for sha in rows}

    def metrics(values, statuses):
        matched = {sha for sha, value in values.items() if value is True}
        complete = {sha for sha, value in values.items() if value is not None}
        return {'status_counts': dict(Counter(statuses)), 'completed_count': len(complete),
                'coverage': len(complete) / len(rows) if rows else None, 'matched_count': len(matched),
                'matched_sha256': sorted(matched), 'proxy_detection': wilson(len(matched & proxy), len(proxy)),
                'proxy_abstain_count': len(proxy - complete),
                'proxy_completed_no_hit_count': len((proxy & complete) - matched),
                'benign_false_positive': wilson(len(matched & benign), len(benign)),
                'benign_decision_fpr': wilson(len(matched & benign), len(benign & complete)),
                'benign_abstain_count': len(benign - complete)}

    engines = {name: metrics(values, [row['engines'].get(name, {}).get('status', 'missing') for row in rows.values()])
               for name, values in outcomes.items()}
    fusion_metrics = metrics(fusion, ['matched' if value is True else 'no_match' if value is False else 'abstain'
                                      for value in fusion.values()])
    fusion_metrics['members'] = list(active)
    timing = {'pipeline_total': [], 'model_engine_inclusive': [], 'model_feature': [], 'model_inference': [],
              'model_engine_overhead': [], 'pipeline_without_model': [], 'pipeline_timer_residual': []}
    for row in rows.values():
        total = row.get('elapsed_ms', row.get('scan_elapsed_ms'))
        model = row['engines'].get('lightgbm', {})
        inclusive, feature, inference = (model.get(key) for key in ('elapsed_ms', 'feature_elapsed_ms', 'inference_elapsed_ms'))
        timing['pipeline_total'].append(total)
        timing['model_engine_inclusive'].append(inclusive)
        timing['model_feature'].append(feature)
        timing['model_inference'].append(inference)
        if all(value is not None for value in (inclusive, feature, inference)):
            timing['model_engine_overhead'].append(inclusive - feature - inference)
        if total is not None and inclusive is not None:
            timing['pipeline_without_model'].append(total - inclusive)
        base = [row['engines'].get(name, {}).get('elapsed_ms') for name in ENGINES[:-1]]
        if total is not None and all(value is not None for value in base):
            timing['pipeline_timer_residual'].append(total - base[0] - base[1] - max(base[2:]) - (inclusive or 0))
    return {'sample_count': len(rows), 'excluded_duplicate_rows': duplicates, 'engines': engines, 'fusion': fusion_metrics,
            'latency_ms': {name: distribution(values) for name, values in timing.items()},
            'engine_artifacts': {name: sorted({row['engines'].get(name, {}).get('artifact_version', 'missing') for row in rows.values()})
                                 for name in ENGINES}}


def compare_rounds(old, new, reference, cohort_role='archive_development', malicious_sha256=None):
    old_all, old_duplicates = normalized_rows(old)
    new_all, new_duplicates = normalized_rows(new)
    if set(old_all) != set(new_all) or any(old_all[sha].get('pe_valid', True) != new_all[sha].get('pe_valid', True) for sha in old_all):
        raise ValueError('Round cohort SHA sets or PE validity differ')
    if 'source_archive_sha256' in reference:
        if any(report.get('archive_sha256') != reference['source_archive_sha256'] for report in (old, new)):
            raise ValueError('Archive cohort provenance differs from reference')
    samples = reference['samples']
    if len({item['sha256'] for item in samples}) != len(samples):
        raise ValueError('Duplicate label-reference SHA')
    label_rows = {item['sha256']: item for item in samples}
    rows = {sha: row for sha, row in old_all.items() if row.get('pe_valid', True)}
    if not set(rows) <= label_rows.keys():
        raise ValueError('PE cohort has missing explicit labels')
    labels = {sha: label_rows[sha]['label'] for sha in rows}
    if any(label not in {'malicious_proxy', 'unknown', 'benign', 'presumed_benign'} for label in labels.values()):
        raise ValueError('Unsupported cohort label')
    new_rows = {sha: new_all[sha] for sha in rows}
    old_summary = round_summary(rows, labels, old_duplicates, malicious_sha256)
    new_summary = round_summary(new_rows, labels, new_duplicates, malicious_sha256)
    misses = {sha for sha in rows if labels[sha] == 'malicious_proxy' and rows[sha]['engines'].get('clamav', {}).get('status') == 'no_match'}

    def subset(values):
        return {'count': len(values), 'sha256': sorted(values)}

    hits = {name: set(new_summary['engines'][name]['matched_sha256']) for name in ('clamav', 'yara_x', 'lightgbm')}
    overlap = Counter('+'.join(name for name in hits if sha in hits[name]) or 'none' for sha in misses)
    cases = [{'sha256': sha, 'label': labels[sha],
              'old_statuses': {name: rows[sha]['engines'].get(name, {}).get('status', 'missing') for name in ENGINES},
              'new_statuses': {name: new_rows[sha]['engines'].get(name, {}).get('status', 'missing') for name in ENGINES},
              'new_model_score': new_rows[sha]['engines'].get('lightgbm', {}).get('score'),
              'historical_evidence': {key: label_rows[sha][key] for key in
                                       ('analysis_time', 'independent_vendor_malicious_count', 'raw_report_sha256', 'original_name')
                                       if key in label_rows[sha]}} for sha in sorted(rows)]
    deltas = [new_rows[sha].get('elapsed_ms', new_rows[sha].get('scan_elapsed_ms')) - row.get('elapsed_ms', row.get('scan_elapsed_ms'))
              for sha, row in rows.items() if new_rows[sha].get('elapsed_ms', new_rows[sha].get('scan_elapsed_ms')) is not None
              and row.get('elapsed_ms', row.get('scan_elapsed_ms')) is not None]
    return {'method': 'paired_frozen_cohort_static_comparison', 'cohort_role': cohort_role, 'strict_final_test': False,
            'formal_acceptance': False, 'model_threshold': .5, 'threshold_calibration_on_cohort': False,
            'label_reference_revision': reference.get('label_revision'),
            'protocol_frozen_before_aegisav_scan': reference.get('protocol_frozen_before_aegisav_scan', False),
            'sample_count': len(rows), 'non_pe_excluded_count': len(old_all) - len(rows),
            'proxy_count': sum(label == 'malicious_proxy' for label in labels.values()),
            'unknown_count': sum(label == 'unknown' for label in labels.values()),
            'benign_label_basis': 'Presumed benign from trusted installation/signature manifests; not curated formal ground truth',
            'label_source_counts': dict(Counter(item.get('source', 'historical independent vendor proxy') for item in samples)),
            'old': old_summary, 'new': new_summary,
            'old_clam_proxy_misses': {**subset(misses), 'new_clam_hits': subset(misses & hits['clamav']),
                                      'new_yara_hits': subset(misses & hits['yara_x']),
                                      'new_ml_hits': subset(misses & hits['lightgbm']),
                                      'new_fusion_hits': subset(misses & set(new_summary['fusion']['matched_sha256'])),
                                      'exclusive_overlap_bins': dict(overlap)},
            'paired_pipeline_delta_ms': distribution(deltas),
            'read_error_counts': {'old': len(old.get('errors', [])), 'new': len(new.get('errors', []))},
            'cases': cases}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('old', 'new', 'reference', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--database', type=Path, default=Path('rules/hashes.json'))
    for name in ('benign-old', 'benign-new', 'benign-manifest'):
        parser.add_argument('--' + name, action='append', default=[], type=Path)
    args = parser.parse_args()
    if not len(args.benign_old) == len(args.benign_new) == len(args.benign_manifest):
        parser.error('Benign old/new/manifest lists must have the same length')
    read = lambda path: json.loads(path.read_text(encoding='utf-8'))
    database = read(args.database)
    malicious = {item['sha256'] for item in database if item.get('verdict') == 'malicious'}
    result = {'schema': 1, 'archive': compare_rounds(read(args.old), read(args.new), read(args.reference), malicious_sha256=malicious),
              'benign_cohorts': [], 'input_sha256': {}}
    paths = {'old': args.old, 'new': args.new, 'reference': args.reference, 'database': args.database}
    for index, (old_path, new_path, manifest) in enumerate(zip(args.benign_old, args.benign_new, args.benign_manifest)):
        samples = [json.loads(line) for line in manifest.read_text(encoding='utf-8').splitlines() if line.strip()]
        if any(item['label'] not in {'benign', 'presumed_benign'} for item in samples):
            raise ValueError('Benign manifest contains other labels')
        old_report, new_report = read(old_path), read(new_path)
        manifest_sha = hashlib.sha256(manifest.read_bytes()).hexdigest()
        if any(report.get('manifest_sha256') != manifest_sha for report in (old_report, new_report)):
            raise ValueError('Benign report manifest provenance differs')
        if {item['sha256'] for item in samples} != set(normalized_rows(old_report)[0]):
            raise ValueError('Benign manifest cohort differs')
        result['benign_cohorts'].append(compare_rounds(old_report, new_report, {'samples': samples},
                                                      'presumed_installation_benign', malicious))
        paths.update({f'benign_{index}_old': old_path, f'benign_{index}_new': new_path, f'benign_{index}_manifest': manifest})
    result['input_sha256'] = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in paths.items()}
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'output': str(args.output), 'archive_sample_count': result['archive']['sample_count'],
                      'old_clam_proxy_misses': result['archive']['old_clam_proxy_misses']['count'],
                      'benign_cohort_count': len(result['benign_cohorts'])}, indent=2))


if __name__ == '__main__':
    main()
