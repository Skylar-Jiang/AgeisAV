"""Publish aggregate native RC evidence without input identities or private reports."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / 'artifacts/native-ssdeep-rc-20261022'


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def control_shapes():
    counts = Counter()
    for row in read(LAB / 'windows-controls/frozen-manifest.json')['rows']:
        if not row['eligible']:
            continue
        with Path(row['path']).open('rb') as stream:
            dos = stream.read(64)
            assert dos[:2] == b'MZ'
            stream.seek(struct.unpack_from('<I', dos, 60)[0])
            header = stream.read(264)
        assert header[:4] == b'PE\0\0'
        machine = struct.unpack_from('<H', header, 4)[0]
        flags = struct.unpack_from('<H', header, 22)[0]
        magic = struct.unpack_from('<H', header, 24)[0]
        directory = 24 + (112 if magic == 0x20b else 96)
        managed = bool(struct.unpack_from('<I', header, directory + 14 * 8)[0])
        counts[('win64' if machine == 0x8664 else 'win32' if machine == 0x14c else hex(machine)) +
               ('_managed' if managed else '_native') + ('_dll' if flags & 0x2000 else '_exe')] += 1
    return dict(counts)


def main():
    parity = read(LAB / 'parity-final.json')
    faults = read(LAB / 'faults/check.json')
    reports = read(LAB / 'reports-healthy-complete.json')
    browser = read(LAB / 'browser/check.json')
    delivery = read(LAB / 'delivery-faults/check.json')
    assert parity['completed'] and all(r['equal'] for r in parity['cases'])
    assert faults['completed'] and reports['completed'] and reports['all_cleanup_confirmed']
    assert not browser['failures'] and all(r['passed'] for r in browser['checks'])
    assert delivery['failed'] == 0 and delivery['passed'] == len(delivery['checks'])
    comparisons = {}
    for state in ('healthy', 'unavailable'):
        source = read(LAB / ('http-unavailable-complete.json' if state == 'unavailable' else 'http-healthy.json'))
        assert source['completed'] and source['all_report_pairs_equal'] and source['sqlite_reload_equal']
        assert source['services_and_workers_closed'] and source['clam_state'] == state
        comparisons[state] = {'scenarios': {}, 'observations': len(source['observations']),
                              'report_pairs_equal': True, 'cancel_recovery': source['fault_checks'],
                              'sqlite_reload_equal': True}
        # Retain actual paired variations; three repeats do not establish population P95.
        for scenario, values in source['summary'].items():
            before, after = values['baseline'], values['candidate']
            pairs = {}
            for row in source['observations']:
                if row['scenario'] == scenario:
                    pairs.setdefault(row['round'], {})[row['version']] = row['elapsed_ms']
            comparisons[state]['scenarios'][scenario] = {**values,
                'p50_reduction_percent': 100 * (1 - after['p50_ms'] / before['p50_ms']),
                'throughput_increase_percent': 100 * (after['throughput_inputs_per_second'] /
                                                    before['throughput_inputs_per_second'] - 1),
                'paired_elapsed_reduction_percent': [100 * (1 - p['candidate'] / p['baseline'])
                                                     for _, p in sorted(pairs.items())]}
    engines = {}
    for mode in ('python', 'native'):
        rows = [r for r in reports['rows'] if r['mode'] == mode]
        engines[mode] = {name: dict(Counter(r['report']['engines'][name]['status'] for r in rows))
                         for name in ('sha256', 'fuzzy', 'yara_x', 'clamav', 'lightgbm')}
    manifest = read(LAB / 'native/manifest.json')
    output = {'schema': 1, 'measurement_date': '2026-10-23', 'production_replaced': False,
              'independent_accuracy_evaluation': False, 'candidate_version': '0.2.1rc1',
              'native': {k: manifest[k] for k in ('abi', 'sha256', 'source_sha256', 'bytes', 'compiler')},
              'complete_hash_parity_cases': len(parity['cases']),
              'concurrent_hash_parity': parity['concurrent_equal'],
              'input_output_budget_rejections': parity['budget_rejections'],
              'native_fault_checks': faults['checks'],
              'report_parity': {'pairs_equal': reports['pairs_equal'], 'summary': reports['summary'],
                               'engine_status_counts': engines,
                               'clam_version': reports['clam_version'], 'clam_signature': reports['clam_signature'],
                               'separate_clam_max_sampled_rss_bytes': max(r['rss'] for r in reports['daemon_samples']),
                               'separate_clam_peak_wset_bytes': max(r['peak_wset'] for r in reports['daemon_samples'])},
              'http_packaged_workers': comparisons,
              'prospective_control_PE_categories': control_shapes(),
              'package': read(ROOT / 'artifacts/windows-delivery-20261022-rc1/build-summary.json'),
              'browser': {'checks': len(browser['checks']), 'failures': browser['failures'],
                          'checks_detail': browser['checks'],
                          'core_engine_statuses': browser.get('core_engine_statuses'),
                          'external_model_engine_statuses': browser.get('external_model_engine_statuses')},
              'delivery_faults': delivery['checks'],
              'limitations': ['Only explicit native RC; stable source/default ZIP remain unchanged.',
                'Hash equality covers generated bytes and benign PE; no new malicious PE experiment on Windows.',
                'Report equality excludes three timing fields and the asserted native engine-version suffix.',
                'HTTP uses identical authenticated controllers, actual packaged worker runtimes, and FULL/WAL SQLite; '
                'not two separately launched desktop services. Three alternating rounds/scenario, warmed daemon; '
                'small-sample P95 is the maximum, not a deployment percentile estimate.',
                'Worker RAM is sampled process-tree sums, can double-count shared pages and miss short peaks; '
                'external clamd is separate. One broad report pass is not an independent speed confirmation.',
                'Core portable ZIP excludes private ML/runtime and official ClamAV sidecar/databases; '
                'external components were actually integrated. Missing engines abstain.',
                'Research-only Python reference CPU allowance was extended to360s for unfinished pathological '
                'hash fixtures; product worker limits unchanged. Earlier deadline/harness failures retained.']}
    output['package'].pop('bundle', None)
    output['runner_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    target = ROOT / 'docs/benchmarks/native_rc_20261023.json'
    target.write_text(json.dumps(output, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'output': str(target), 'http': comparisons}))


if __name__ == '__main__':
    main()
