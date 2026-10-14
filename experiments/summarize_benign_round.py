"""Summarize fixed-threshold benign observations, explicitly auditing training overlap."""

import argparse
import hashlib
import json
from pathlib import Path

from experiments.compare_static_rounds import normalized_rows, round_summary


def summarize(report, manifest, fit_validation_sha, malicious_sha):
    if report.get('manifest_sha256') != hashlib.sha256(manifest).hexdigest():
        raise ValueError('Different manifest identity')
    samples = [json.loads(line) for line in manifest.decode('utf-8').splitlines() if line.strip()]
    allowed = {'benign', 'presumed_benign', 'trusted_installation_benign_proxy'}
    if any(row['label'] not in allowed or not row.get('source') for row in samples):
        raise ValueError('Unexpected benign source or label')
    rows, duplicates = normalized_rows(report)
    if len(samples) != len(rows) or {s['sha256'] for s in samples} != rows.keys():
        raise ValueError('Manifest cohort differs')
    if any(not row.get('pe_valid', True) for row in rows.values()):
        raise ValueError('Non-PE in benign cohort')
    labels = {sha: 'presumed_benign' for sha in rows}
    overlap = sorted(rows.keys() & fit_validation_sha)
    disjoint = {sha: row for sha, row in rows.items() if sha not in fit_validation_sha}
    return {'strict_final_test': False, 'model_threshold': .5, 'threshold_tuning': False,
            'label_basis': 'Trusted installed/signature benign proxies, not independently verified ground truth',
            'general_pe_pretrained_full_training_overlap_known': False,
            'training_overlap_scope': 'Win64 local fit and validation only; other PE training platforms unaudited',
            'win64_fit_validation_overlap_sha256': overlap,
            'all_observed': round_summary(rows, labels, duplicates, malicious_sha),
            'win64_fit_validation_disjoint': round_summary(disjoint, labels, 0, malicious_sha)}


def general_training_control(reports, audit, malicious_sha):
    known = set()
    for name, group in audit['cohort_overlap'].items():
        if name == 'archive':
            continue
        if group['overlap_count'] != len(group['matches']) or group['cohort_size'] < len(group['matches']):
            raise ValueError('Inconsistent training overlap audit')
        known.update(group['matches'])
    rows = {}
    for report in reports:
        cohort, _ = normalized_rows(report)
        if rows.keys() & cohort.keys():
            raise ValueError('Benign cohorts overlap')
        rows.update(cohort)
    overlap = sorted(rows.keys() & known)
    disjoint = {sha: row for sha, row in rows.items() if sha not in known}
    return {'strict_final_test': False, 'author_model_training_manifest_verified': False,
            'scope': 'Reported official Win32/Win64/Dot_Net training SHA membership; not independent ground truth',
            'known_training_overlap_count': len(overlap), 'overlap_sha256': overlap,
            'reported_training_disjoint': round_summary(disjoint, {sha: 'presumed_benign' for sha in disjoint}, 0, malicious_sha)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, action='append', required=True)
    parser.add_argument('--manifest', type=Path, action='append', required=True)
    parser.add_argument('--provenance', type=Path, required=True)
    parser.add_argument('--general-training-audit', type=Path)
    parser.add_argument('--database', type=Path, default=Path('rules/hashes.json'))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if len(args.report) != len(args.manifest):
        parser.error('One frozen manifest is required per report')
    read = lambda path: json.loads(path.read_text(encoding='utf-8'))
    provenance = read(args.provenance)
    overlap = {sha for item in provenance['installed_pe_overlaps'].values()
               for split in ('fit', 'validation') for sha in item[split]}
    malicious = {row['sha256'] for row in read(args.database) if row.get('verdict') == 'malicious'}
    cohorts = [summarize(read(report), manifest.read_bytes(), overlap, malicious)
               for report, manifest in zip(args.report, args.manifest)]
    combined_rows, combined_labels = {}, {}
    for report in args.report:
        rows, _ = normalized_rows(read(report))
        if combined_rows.keys() & rows.keys():
            raise ValueError('Benign cohorts overlap')
        combined_rows.update(rows)
        combined_labels.update({sha: 'presumed_benign' for sha in rows})
    paths = [args.provenance, args.database, *args.report, *args.manifest]
    result = {'schema': 1, 'strict_final_test': False, 'cohorts': cohorts,
              'all_observed': round_summary(combined_rows, combined_labels, 0, malicious),
              'known_win64_fit_validation_overlap_count': len(combined_rows.keys() & overlap),
              'input_sha256': {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}}
    if args.general_training_audit:
        result['general_pe_training_control'] = general_training_control(
            [read(path) for path in args.report], read(args.general_training_audit), malicious)
        result['input_sha256'][str(args.general_training_audit)] = hashlib.sha256(args.general_training_audit.read_bytes()).hexdigest()
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'output': str(args.output), 'samples': len(combined_rows),
                      'known_training_overlap': result['known_win64_fit_validation_overlap_count']}))


if __name__ == '__main__':
    main()
