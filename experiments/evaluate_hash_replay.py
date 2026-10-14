"""Compare a frozen reference library to hashes computed by an earlier PE scan."""

import argparse
import hashlib
import json
from pathlib import Path

import ppdeep
import tlsh

from aegisav.hashes import HashDatabase
from experiments.evaluate_stage1 import aggregate_engine_metrics


def evaluate_replay(manifest: Path, report: dict, database: HashDatabase) -> dict:
    if hashlib.sha256(manifest.read_bytes()).hexdigest() != report['manifest_sha256']:
        raise ValueError('Replay manifest does not match original report')
    rows = [json.loads(line) for line in manifest.read_text(encoding='utf-8').splitlines() if line.strip()]
    labels = {row['sha256']: row['label'] for row in rows}
    reports = report['reports']
    if len(labels) != len(reports) or {r['sha256'] for r in reports} != set(labels):
        raise ValueError('Replay report is incomplete or contains duplicate samples')
    exact, fuzzy = [], []
    for item in reports:
        digest = item['sha256']
        known = database.by_sha.get(digest)
        exact.append('matched' if known and known.get('verdict') == 'malicious' else 'no_match')
        hashes = item['engines']['fuzzy']['hashes']
        matched = False
        for reference in database.fuzzy_records:
            if reference['sha256'] == digest:
                continue
            if hashes['tlsh'] and reference.get('tlsh'):
                matched |= tlsh.diff(hashes['tlsh'], reference['tlsh']) <= 40
            if hashes['ssdeep'] and reference.get('ssdeep'):
                matched |= ppdeep.compare(hashes['ssdeep'], reference['ssdeep']) >= 80
        fuzzy.append('matched' if matched else 'no_match')
    ordered_labels = [labels[r['sha256']] for r in reports]
    return {'method': 'precomputed_hash_replay', 'sample_count': len(reports),
            'reference_count': len(database.records), 'fuzzy_reference_count': len(database.fuzzy_records),
            'thresholds': {'tlsh_max_distance': 40, 'ssdeep_min_similarity': 80},
            'sha256': aggregate_engine_metrics(ordered_labels, exact),
            'fuzzy': aggregate_engine_metrics(ordered_labels, fuzzy)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--database', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    result = evaluate_replay(args.manifest, json.loads(args.report.read_text(encoding='utf-8')),
                             HashDatabase.from_file(args.database))
    result['input_sha256'] = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in
                             [('manifest', args.manifest), ('report', args.report), ('database', args.database)]}
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
