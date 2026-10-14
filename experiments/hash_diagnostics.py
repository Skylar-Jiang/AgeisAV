"""Audit frozen hash reports and probe matching using harmless PE bytes only.

Run from the repository root with its environment: python -m experiments.hash_diagnostics
--database rules/hashes.json --report REPORT.json --benign-pe C:/Windows/System32/notepad.exe
--output docs/benchmarks/hash_diagnostics_20261010.json (PYTHONPATH=backend).
No supplied PE is executed, modified on disk, or added to the production database.
"""

import argparse
from collections import Counter
import hashlib
from importlib.metadata import version
import json
import math
from pathlib import Path
import statistics
import struct

import ppdeep
import tlsh

from aegisav.hashes import HashDatabase, compute_fuzzy, hash_scan
from aegisav.pe import validate_pe


def functional_probe(data: bytes) -> dict:
    validate_pe(data)
    changed = bytearray(data)
    timestamp_offset = struct.unpack_from('<I', data, 0x3c)[0] + 8
    changed[timestamp_offset] ^= 1
    changed = bytes(changed)
    validate_pe(changed)
    digest = hashlib.sha256(data).hexdigest()
    original_hashes, changed_hashes = compute_fuzzy(data), compute_fuzzy(changed)
    record = {'sha256': digest, 'source': 'in-memory engineering fixture only',
              'label': 'TEST ONLY: harmless PE assigned malicious marker to exercise matcher',
              'verdict': 'malicious', **original_hashes}
    database = HashDatabase.from_records([record])
    original_result, changed_result = hash_scan(data, database), hash_scan(changed, database)
    benign = hash_scan(changed, HashDatabase.from_records([{**record, 'verdict': 'benign'}]))
    unlabelled = hash_scan(changed, HashDatabase.from_records([{**record, 'verdict': None}]))

    def summary(engine):
        return {'status': engine['status'], 'evidence_count': len(engine['evidence']),
                'methods': [entry['method'] for entry in engine['evidence'] if 'method' in entry]}

    return {'test_only': True, 'interpretation': 'Engineering matching check; not malware recall evidence',
            'size_bytes': len(data), 'changed_byte_count': 1, 'changed_offset': timestamp_offset,
            'mutation': 'XOR one COFF timestamp byte in memory; PE code bytes are unchanged',
            'original_sha256': digest, 'changed_sha256': hashlib.sha256(changed).hexdigest(),
            'original_hashes': original_hashes, 'changed_hashes': changed_hashes,
            'native_comparison': {
                'tlsh_distance': tlsh.diff(original_hashes['tlsh'], changed_hashes['tlsh'])
                if original_hashes['tlsh'] and changed_hashes['tlsh'] else None,
                'ssdeep_similarity': ppdeep.compare(original_hashes['ssdeep'], changed_hashes['ssdeep'])
                if original_hashes['ssdeep'] and changed_hashes['ssdeep'] else None},
            'exact': summary(original_result['exact']), 'self_fuzzy': summary(original_result['fuzzy']),
            'changed_exact': summary(changed_result['exact']), 'changed_fuzzy': summary(changed_result['fuzzy']),
            'benign_reference_fuzzy': summary(benign['fuzzy']),
            'unlabelled_reference_fuzzy': summary(unlabelled['fuzzy']),
            'empty_database_exact': summary(hash_scan(data, HashDatabase.from_records([]))['exact'])}


def diagnose_report(report: dict, database: HashDatabase) -> dict:
    rows = report['reports'] if 'reports' in report else report['files']
    pe_rows = [row for row in rows if row.get('pe_valid', True)]
    unique = {}
    for row in pe_rows:
        unique.setdefault(row['sha256'], row)
    comparisons = []
    hash_export = Counter({'missing_hash_object': 0, 'tlsh_available': 0, 'tlsh_null': 0,
                           'ssdeep_available': 0, 'ssdeep_null': 0})
    for digest, row in unique.items():
        fuzzy_engine = row.get('engines', {}).get('fuzzy', {})
        hashes = fuzzy_engine.get('hashes')
        if hashes is None:
            hash_export['missing_hash_object'] += 1
        else:
            for method in ('tlsh', 'ssdeep'):
                hash_export[method + ('_available' if hashes.get(method) else '_null')] += 1
        for reference in database.fuzzy_records:
            distance = (tlsh.diff(hashes['tlsh'], reference['tlsh'])
                        if hashes and hashes.get('tlsh') and reference.get('tlsh') else None)
            similarity = (ppdeep.compare(hashes['ssdeep'], reference['ssdeep'])
                          if hashes and hashes.get('ssdeep') and reference.get('ssdeep') else None)
            comparisons.append({'query_sha256': digest, 'reference_sha256': reference['sha256'],
                                'self_excluded': digest == reference['sha256'],
                                'tlsh_distance': distance, 'ssdeep_similarity': similarity,
                                'tlsh_pass': distance <= 40 if distance is not None else None,
                                'ssdeep_pass': similarity >= 80 if similarity is not None else None})
    distances = [p['tlsh_distance'] for p in comparisons if p['tlsh_distance'] is not None]
    similarities = [p['ssdeep_similarity'] for p in comparisons if p['ssdeep_similarity'] is not None]
    candidates = [p for p in comparisons if not p['self_excluded'] and (p['tlsh_pass'] or p['ssdeep_pass'])]
    return {'sample_count': len(unique), 'input_rows': len(rows), 'non_pe_rows': len(rows) - len(pe_rows),
            'duplicate_rows': len(pe_rows) - len(unique), 'reference_count': len(database.records),
            'malicious_reference_count': sum(r.get('verdict') == 'malicious' for r in database.records),
            'malicious_fuzzy_reference_count': len(database.fuzzy_records),
            'reference_hash_availability': {method: sum(bool(r.get(method)) for r in database.fuzzy_records)
                                            for method in ('tlsh', 'ssdeep')},
            'exact_reference_intersection': sorted(set(unique) & database.by_sha.keys()),
            'reported_status_counts': {engine: dict(Counter(row.get('engines', {}).get(engine, {}).get('status', 'missing')
                                                           for row in unique.values()))
                                       for engine in ('sha256', 'fuzzy')},
            'hash_export': dict(hash_export), 'comparison_pair_count': len(comparisons),
            'latency': latency_diagnostics(list(unique.values())),
            'raw_comparison_summary': {'tlsh_scored_pairs': len(distances), 'ssdeep_scored_pairs': len(similarities),
                                       'all_pairs_scored': len(distances) == len(comparisons) == len(similarities),
                                       'minimum_tlsh_distance': min(distances, default=None),
                                       'maximum_ssdeep_similarity': max(similarities, default=None),
                                       'self_excluded_pairs': sum(p['self_excluded'] for p in comparisons),
                                       'candidate_pair_count': len(candidates),
                                       'samples_with_candidate': len({p['query_sha256'] for p in candidates})},
            'comparisons': comparisons}


def latency_diagnostics(rows: list[dict]) -> dict:
    def quantiles(values):
        ordered = sorted(value for value in values if value is not None)
        if not ordered:
            return {'sample_count': 0}
        return {'sample_count': len(ordered), 'p50': statistics.median(ordered),
                'p95_floor_index': ordered[int(.95 * (len(ordered) - 1))],
                'p95_nearest_rank': ordered[math.ceil(.95 * len(ordered)) - 1], 'max': ordered[-1]}

    records = []
    for row in rows:
        total = row.get('elapsed_ms', row.get('scan_elapsed_ms'))
        engines = {name: row.get('engines', {}).get(name, {}).get('elapsed_ms')
                   for name in ('sha256', 'fuzzy', 'yara_x', 'clamav')}
        complete = total is not None and all(value is not None for value in engines.values())
        parallel_max = max(engines['yara_x'], engines['clamav']) if complete else None
        model_ms = row.get('engines', {}).get('lightgbm', {}).get('elapsed_ms')
        if 'lightgbm' in row.get('engines', {}):
            engines['lightgbm'] = model_ms
            complete = complete and model_ms is not None
        critical = engines['sha256'] + engines['fuzzy'] + parallel_max + (model_ms or 0) if complete else None
        records.append({'sha256': row['sha256'], 'size_bytes': row.get('size_bytes'), 'total_ms': total,
                        'engines_ms': engines, 'parallel_engine_max_ms': parallel_max,
                        'estimated_critical_path_ms': critical,
                        'elapsed_minus_critical_path_ms': total - critical if complete else None,
                        'fuzzy_fraction_of_total': engines['fuzzy'] / total if complete and total else None})
    timed = [record for record in records if record['total_ms'] is not None]
    fuzzy_timed = [record for record in records if record['engines_ms']['fuzzy'] is not None]
    names = ('sha256', 'fuzzy', 'yara_x', 'clamav') + (('lightgbm',) if any('lightgbm' in r['engines_ms'] for r in records) else ())
    return {'model': 'SHA + fuzzy + max(YARA, ClamAV) + LightGBM if present + overhead; estimates from recorded engine timers',
            'quantile_conventions': {'floor_index': 'sorted[floor(0.95 * (n - 1))]',
                                     'nearest_rank': 'sorted[ceil(0.95 * n) - 1]'},
            'total_ms': quantiles(record['total_ms'] for record in records),
            'engines_ms': {name: quantiles(record['engines_ms'].get(name) for record in records) for name in names},
            'longest_total_records': sorted(timed, key=lambda record: record['total_ms'], reverse=True)[:3],
            'longest_fuzzy_records': sorted(fuzzy_timed, key=lambda record: record['engines_ms']['fuzzy'], reverse=True)[:3]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', required=True, type=Path)
    parser.add_argument('--report', action='append', default=[], type=Path)
    parser.add_argument('--benign-pe', type=Path, help='Known installed harmless PE; read-only, never executed')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    database = HashDatabase.from_file(args.database)
    output = {'schema': 1, 'method': 'frozen_hash_diagnostics_and_optional_harmless_pe_probe',
              'thresholds': {'tlsh_max_distance': 40, 'ssdeep_min_similarity': 80},
              'versions': {'tlsh-python': version('tlsh-python'), 'ppdeep': version('ppdeep'),
                           'native_tlsh': tlsh.version},
              'database_path': str(args.database), 'database_sha256': hashlib.sha256(args.database.read_bytes()).hexdigest(),
              'reports': {}}
    for path in args.report:
        result = diagnose_report(json.loads(path.read_text(encoding='utf-8')), database)
        result['input_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        output['reports'][str(path)] = result
    if args.benign_pe:
        output['functional_probe'] = functional_probe(args.benign_pe.read_bytes())
        output['functional_probe']['source_path'] = str(args.benign_pe)
    args.output.write_text(json.dumps(output, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'output': str(args.output), 'report_count': len(output['reports']),
                      'functional_probe': output.get('functional_probe')}, indent=2))


if __name__ == '__main__':
    main()
