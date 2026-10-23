"""Freeze verified operational Windows controls, then explicitly authorize scoring."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))
ENGINES = ('sha256', 'fuzzy', 'yara_x', 'clamav', 'lightgbm')
DECISIONS = {'matched', 'no_match'}
LIMIT = 16 * 1024**2
SIDECAR = ROOT / 'artifacts/clamav/windows-1.5.4'
ARCHIVE_SHA256 = '0d9e0228b2674137ea1a2853566c98a0278ad52ab2582c3d6dbd75373848c395'
HISTORICAL = (
    'artifacts/stage-e-r7-20261019/guest-paired.json',
    'artifacts/stage-e-r7-20261019/guest-r4-paired.json',
    'artifacts/offline-results/benign-windows-86d0e601a34b4461862f030985ceee7e.json',
    'artifacts/offline-results/benign-expansion-ce340b2628e148eaaaf11a4f2e3ae712.json',
    'artifacts/offline-results/benign-vendor-cad68e47261e491899a2cf838f09aaff.json',
)
LIMITATIONS = ('Prospective new operational presumed-benign controls, not strict independent final data or a '
              'deployment FPR estimate. One publisher release includes third-party components. Full upstream '
              'training membership and near-training links remain unknown. No threshold or model selection. '
              'No-alert is not a clean verdict. ClamAV was warmed by earlier harmless scans; files are read '
              'before timing. No protected raw PE or final metadata/features are accessed.')


def read_json(path):
    return json.loads(path.read_text(encoding='utf-8'))


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def save(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')
    temporary.replace(path)


def policy(source):
    paths = sorted((source / 'backend/aegisav').glob('*.py'))
    paths += sorted(p for p in (source / 'rules').rglob('*') if p.is_file())
    paths += [source / 'native' / name for name in ('manifest.json', 'aegisav_ssdeep.dll')]
    model_root = ROOT / 'models/ember2024'
    registry = read_json(model_root / 'registry.json')
    if registry['models']['general']['threshold'] != .5:
        raise ValueError('Frozen general model threshold must be 0.5')
    for name, expected in registry['files'].items():
        if digest(model_root / name) != expected:
            raise ValueError('Model registry asset mismatch')
    native = read_json(source / 'native/manifest.json')
    if native['abi'] != 1 or digest(source / 'native' / native['file']) != native['sha256']:
        raise ValueError('Candidate DLL manifest mismatch')
    return {'source_root': str(source), 'source_assets': {str(p.relative_to(source)): digest(p) for p in paths},
            'model_registry_sha256': digest(model_root / 'registry.json'), 'model_files': registry['files'],
            'native_manifest': native, 'ml_profile': 'general', 'ml_threshold': .5,
            'runner_sha256': digest(Path(__file__)),
            'measurement_helper_sha256': digest(ROOT / 'experiments/compare_scan_latency.py'),
            'controller_process_scanner_sha256': digest(ROOT / 'backend/aegisav/scan_process.py')}


def audit(rows):
    import numpy as np
    identities = {row['sha256'] for row in rows}
    sources = []
    for relative in HISTORICAL:
        path = ROOT / relative
        entry = {'source': relative, 'available': path.is_file()}
        if path.is_file():
            historical = read_json(path)['files']
            known = {row['sha256'] for row in historical}
            entry.update(sha256=digest(path), rows=len(historical), matches=sorted(identities & known))
        sources.append(entry)
    # Deliberately fixed development-only names; never glob metadata or open features.
    for split in ('fit', 'validation'):
        relative = 'artifacts/ember2024/vectors/meta_' + split + '.npz'
        path = ROOT / relative
        entry = {'source': relative, 'available': path.is_file()}
        if path.is_file():
            with np.load(path, allow_pickle=False) as archive:
                hashes = archive['sha'].astype(str)
                known = set(hashes.tolist())
            entry.update(sha256=digest(path), rows=len(hashes), matches=sorted(identities & known))
        sources.append(entry)
    seen = set()
    for row in rows:
        row['exact_overlap_sources'] = [entry['source'] for entry in sources
                                        if row['sha256'] in entry.get('matches', [])]
        reasons = []
        if row['size_bytes'] > LIMIT:
            reasons.append('over_product_16MiB_limit')
        if row['sha256'] in seen:
            reasons.append('duplicate_within_release')
        if row['exact_overlap_sources']:
            reasons.append('known_historical_or_local_development_overlap')
        row['exclusion_reasons'] = reasons
        row['eligible'] = not reasons
        seen.add(row['sha256'])
    return sources


def prepare(source, output):
    runtime_manifest = SIDECAR / 'runtime-manifest.json'
    manifest = read_json(runtime_manifest)
    if manifest['version'] != '1.5.4' or manifest['archive_sha256'] != ARCHIVE_SHA256:
        raise ValueError('Requires the previously GPG-verified official ClamAV archive manifest')
    rows = []
    for item in sorted(manifest['files'], key=lambda row: row['path']):
        relative = Path(item['path'])
        if relative.suffix.lower() not in {'.exe', '.dll'}:
            continue
        path = (SIDECAR / 'runtime' / relative).resolve()
        if not path.is_relative_to((SIDECAR / 'runtime').resolve()):
            raise ValueError('Runtime path escapes the verified directory')
        if path.stat().st_size != item['bytes'] or digest(path) != item['sha256']:
            raise ValueError('Official runtime identity mismatch')
        rows.append({'id': len(rows), 'path': str(path), 'sha256': item['sha256'], 'size_bytes': item['bytes']})
    if len(rows) != 33 or sum(row['size_bytes'] <= LIMIT for row in rows) != 29:
        raise ValueError('Expected complete 33-PE release inventory with 29 size-eligible controls')
    frozen = {'schema': 1, 'prepared_utc': datetime.now(timezone.utc).isoformat(), 'rows': rows,
              'runtime_manifest_sha256': digest(runtime_manifest), 'archive_sha256': ARCHIVE_SHA256,
              'audit': audit(rows), 'policy': policy(source), 'limitations': LIMITATIONS,
              'historical_execution_disclosure': 'clamd/freshclam executed legitimately; these inputs were not detector-scored',
              'protected_scoring_authorized': False, 'final_data_read': False}
    output.mkdir(parents=True, exist_ok=True)
    with (output / 'frozen-manifest.json').open('x', encoding='utf-8') as stream:
        stream.write(json.dumps(frozen, indent=2) + '\n')
    save(output / 'checkpoint.json', {'status': 'prepared', 'rows': [],
                                     'frozen_manifest_sha256': digest(output / 'frozen-manifest.json')})
    return frozen


def summarize(frozen, result):
    from experiments.compare_scan_latency import quantiles
    rows = result['rows']
    successful = [row for row in rows if row['status'] == 'completed']
    values = [row['elapsed_ms'] for row in successful]
    engines = {}
    for name in ENGINES:
        items = [row.get('report', {}).get('engines', {}).get(name, {}) for row in rows]
        statuses = Counter(item.get('status', 'missing') for item in items)
        engines[name] = {'status_counts': dict(statuses), 'matched_count': statuses['matched'],
                         'risk_signal_alert_count': sum(bool(item.get('risk_signal')) for item in items),
                         'abstained_or_missing': sum(n for status, n in statuses.items() if status not in DECISIONS)}
    daemon = [row['clam_memory'] for row in rows if row.get('clam_memory')]
    audit_summary = [{'source_kind': 'local_development' if 'meta_' in entry['source'] else 'historical_report',
                      'available': entry['available'], 'rows': entry.get('rows'),
                      'exact_overlap_count': len(entry.get('matches', []))} for entry in frozen['audit']]
    return {'schema': 1, 'date': '2026-10-22', 'kind': 'prospective_operational_presumed_benign_controls',
            'status': result['status'], 'strict_independent_final': False, 'deployment_fpr_claim': False,
            'full_inventory': len(frozen['rows']), 'within_size_limit': sum(r['size_bytes'] <= LIMIT for r in frozen['rows']),
            'eligible_after_exact_audit': sum(r['eligible'] for r in frozen['rows']),
            'exclusion_reason_counts': dict(Counter(reason for row in frozen['rows'] for reason in row['exclusion_reasons'])),
            'exact_audit': audit_summary, 'attempts': len(rows), 'completed_reports': len(successful),
            'file_status_counts': dict(Counter(row['status'] for row in rows)), 'engines': engines,
            'fusion_alert_count': sum(r['report']['verdict'] in {'suspicious', 'malicious'} for r in successful),
            'fusion_malicious_only_count': sum(r['report']['verdict'] == 'malicious' for r in successful),
            'fusion_completed_without_alert': sum(r['report']['verdict'] not in {'suspicious', 'malicious'} for r in successful),
            'reports_with_engine_abstention': sum(bool(r['report']['fusion']['abstained_engines']) for r in successful),
            'latency': quantiles(values) if values else {},
            'completed_files_per_second': len(values) * 1000 / sum(values) if values else None,
            'max_sampled_owned_tree_rss_bytes': max((r['resources']['rss_bytes'] for r in successful), default=None),
            'separate_clam_max_sampled_rss_bytes': max((m['rss_bytes'] for m in daemon), default=None),
            'separate_clam_max_reported_peak_wset_bytes': max((m.get('peak_wset_bytes', 0) for m in daemon), default=None),
            'timing_scope': 'One native disposable worker per eligible input through cleanup; preloaded bytes, no HTTP. '
                            'Completed-report latency excludes failed attempts; no warmup/repeats. Daemon memory sampled '
                            'after each attempt, separate from owned-worker tree. Sampled maxima must not be summed.',
            'all_attempt_cleanup_confirmed': all(r['cleanup_confirmed'] for r in rows),
            'ml_profile': 'general', 'ml_threshold': .5, 'limitations': LIMITATIONS,
            'final_data_read': False, 'protected_raw_PE_read': False}


def score(source, output, clam_pid):
    import psutil
    from aegisav.clamav_engine import ClamAVEngine
    from aegisav.scan_process import ProcessScanner
    from experiments.compare_scan_latency import measure
    frozen = read_json(output / 'frozen-manifest.json')
    result = read_json(output / 'checkpoint.json')
    if (result['status'] != 'prepared' or result['rows'] or
            result['frozen_manifest_sha256'] != digest(output / 'frozen-manifest.json') or
            frozen['policy'] != policy(source)):
        raise ValueError('Requires an unchanged reviewed freeze with no prior scoring attempts')
    clam = ClamAVEngine()
    daemon = psutil.Process(clam_pid)
    if Path(daemon.exe()).resolve() != (SIDECAR / 'runtime/clamd.exe').resolve() or not clam.probe():
        raise ValueError('Requires the owned official ClamAV sidecar and healthy loopback probe')
    result.update(status='running', clam_pid=clam_pid, clam_create_time=daemon.create_time(),
                  clam_version=clam.engine_version, clam_signature=clam.artifact_version)
    os.environ['AEGISAV_MODEL_DIR'] = str(ROOT / 'models/ember2024')
    os.environ['AEGISAV_ML_PYTHON'] = str(ROOT / '.venv-ml/Scripts/python.exe')
    os.environ['AEGISAV_ML_PROFILE'] = 'general'
    command = (f'import sys,os;sys.path.insert(0,{str(source / "backend")!r});'
               'os.environ["AEGISAV_SSDEEP_BACKEND"]="native";from aegisav.scan_worker import main;main()')
    scanner = ProcessScanner([str(ROOT / '.venv/Scripts/python.exe'), '-B', '-c', command])
    save(output / 'checkpoint.json', result)
    try:
        for item in frozen['rows']:
            if not item['eligible']:
                continue
            started = time.perf_counter()
            row = {'id': item['id'], 'status': 'error', 'cleanup_confirmed': True}
            try:
                path = Path(item['path'])
                data = path.read_bytes()
                if len(data) != item['size_bytes'] or hashlib.sha256(data).hexdigest() != item['sha256']:
                    raise ValueError('Frozen input changed; refuse to score it')
                row.update(measure(scanner, data), status='completed')
            except Exception as error:
                row.update(exception_type=type(error).__name__, message=str(error),
                           failed_attempt_elapsed_ms=(time.perf_counter() - started) * 1000)
            finally:
                row['cleanup_confirmed'] = scanner.healthy and scanner.active_pid is None
                result['rows'].append(row)
                save(output / 'checkpoint.json', result)
            memory = daemon.memory_info()
            row['clam_memory'] = {'rss_bytes': memory.rss, 'peak_wset_bytes': getattr(memory, 'peak_wset', 0)}
            save(output / 'checkpoint.json', result)
            print('CONTROL', item['id'], row['status'], flush=True)
            if not scanner.healthy:
                raise RuntimeError('Worker cleanup failed; no subsequent input will be scored')
        result['status'] = 'completed' if all(r['status'] == 'completed' for r in result['rows']) else 'completed_with_errors'
    except BaseException as error:
        result.update(status='interrupted' if isinstance(error, KeyboardInterrupt) else 'failed',
                      exception_type=type(error).__name__, message=str(error))
        raise
    finally:
        save(output / 'checkpoint.json', result)
        save(output / 'aggregate.json', summarize(frozen, result))
    public = ROOT / 'docs/benchmarks/windows_controls_20261022.json'
    if public.exists():
        raise FileExistsError('Existing public aggregate retained; private aggregate is available')
    save(public, summarize(frozen, result))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'artifacts/native-ssdeep-rc-20261022/windows-controls')
    parser.add_argument('--clam-pid', type=int)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--prepare-only', action='store_true')
    action.add_argument('--compute-go', action='store_true', help='Parent coordinator granted this scoring slot')
    args = parser.parse_args()
    source, output = args.source_root.resolve(), args.output_dir.resolve()
    if not output.is_relative_to(ROOT / 'artifacts'):
        parser.error('Private output must remain under artifacts')
    if args.prepare_only:
        frozen = prepare(source, output)
        print('FROZEN', len(frozen['rows']), 'eligible', sum(row['eligible'] for row in frozen['rows']))
    elif args.clam_pid is None:
        parser.error('--compute-go requires the owned --clam-pid')
    else:
        score(source, output, args.clam_pid)


if __name__ == '__main__':
    main()
