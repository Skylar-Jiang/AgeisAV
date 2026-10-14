"""Summarize guest static results separately from formal curated-ground-truth metrics."""

import argparse
from collections import Counter
import hashlib
import json
import statistics
from pathlib import Path

from experiments.evaluate_stage1 import aggregate_engine_metrics
from vm.static_archive import validate_export


def summarize(report, reference):
    if report['archive_sha256'] != reference['source_archive_sha256']:
        raise ValueError('Label reference belongs to a different archive')
    labels = {item['sha256']: item['label'] for item in reference['samples']}
    unique = {}
    for item in report['files']:
        unique.setdefault(item['sha256'], item)
    pe = [item for item in unique.values() if item['pe_valid']]
    labelled = [item for item in pe if labels.get(item['sha256']) in {'malicious_proxy', 'presumed_benign'}]
    label_values = ['malicious' if labels[item['sha256']] == 'malicious_proxy' else 'benign' for item in labelled]
    engines, performance = {}, {}
    for name in ('sha256', 'fuzzy', 'yara_x', 'clamav'):
        engines[name] = aggregate_engine_metrics(label_values, [item['engines'][name]['status'] for item in labelled])
        times = sorted(item['engines'][name]['elapsed_ms'] for item in pe)
        performance[name] = {'status_counts': dict(Counter(item['engines'][name]['status'] for item in pe)),
                             'mean_ms': statistics.mean(times) if times else None,
                             'p50_ms': statistics.median(times) if times else None,
                             'p95_ms': times[int(.95 * (len(times) - 1))] if times else None,
                             'max_ms': max(times) if times else None}
    return {'method': 'historical_multivendor_proxy_labels_static_scan', 'formal_acceptance': False,
            'limitations': ['Archive provenance unavailable', 'Labels are historical vendor corroboration, not curated ground truth',
                            'No threshold tuning on this test archive', 'Frozen 4 SHA256 / 2 fuzzy references and 2 YARA rules have narrow coverage'],
            'leaf_files': len(report['files']), 'unique_files': len(unique),
            'duplicates': len(report['files']) - len(unique), 'unique_valid_pe': len(pe),
            'unique_non_pe_or_invalid_pe': len(unique) - len(pe), 'read_errors': report['errors'],
            'pe_label_counts': dict(Counter(labels.get(item['sha256'], 'unknown') for item in pe)),
            'unmatched_reference_hashes': sorted(set(labels) - set(unique)),
            'sequential_unique_pe_scan_ms': sum(item['elapsed_ms'] for item in pe),
            'proxy_engines': engines, 'engine_performance': performance}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--reference', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.report.stat().st_size > 2 * 1024**2:
        raise ValueError('Report size limit')
    report = json.loads(args.report.read_text(encoding='utf-8'))
    validate_export(report)
    if not report['completed']:
        raise ValueError('Incomplete report')
    result = summarize(report, json.loads(args.reference.read_text(encoding='utf-8')))
    result['input_sha256'] = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in
                              [('report', args.report), ('reference', args.reference)]}
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
