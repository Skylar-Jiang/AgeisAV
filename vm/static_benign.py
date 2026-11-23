"""Offline non-root replay of immutable installed benign PE fixtures, without execution."""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

try:
    from .static_archive import scan_file, validate_export
    from .benign_checkpoint import load_checkpoint, save_checkpoint
except ImportError:
    from static_archive import scan_file, validate_export
    from benign_checkpoint import load_checkpoint, save_checkpoint


def validate_benign_export(report):
    if 'archive_sha256' in report or 'manifest_sha256' not in report:
        raise ValueError('Benign manifest identity required')
    converted = dict(report)
    converted['archive_sha256'] = converted.pop('manifest_sha256')
    validate_export(converted)


def sample_path(root, name):
    path = Path(name)
    root = root.resolve()
    if path.is_absolute() or ':' in name or path.parts[:1] != ('samples',):
        raise ValueError('Unexpected fixture path')
    target = (root / path).resolve()
    if not target.is_relative_to(root / 'samples'):
        raise ValueError('Fixture path escapes root')
    return target


def validate_resume(report, rows, manifest_sha256):
    validate_benign_export(report)
    if report['manifest_sha256'] != manifest_sha256 or report['errors'] or len(report['files']) > len(rows):
        raise ValueError('Checkpoint cohort mismatch')
    for observed, expected in zip(report['files'], rows):
        if (observed['path'], observed['sha256']) != (expected['path'], expected['sha256']):
            raise ValueError('Checkpoint is not the manifest prefix')
        if not observed['pe_valid'] or observed['duplicate']:
            raise ValueError('Unexpected checkpoint PE identity')
    if report['completed'] and len(report['files']) != len(rows):
        raise ValueError('Incomplete checkpoint marked completed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--group', choices=('windows', 'vendor', 'expansion'))
    parser.add_argument('--validate-export', type=Path)
    args = parser.parse_args()
    if args.validate_export:
        if args.validate_export.stat().st_size > 2 * 1024**2:
            raise ValueError('Export size limit')
        validate_benign_export(json.loads(args.validate_export.read_text(encoding='utf-8')))
        print('Benign JSON export schema PASS')
        return
    if sys.platform != 'linux' or os.getuid() == 0 or args.group is None:
        raise ValueError('Dedicated non-root guest operation required')
    os.environ['OPENBLAS_NUM_THREADS'] = '1'
    os.environ['OMP_NUM_THREADS'] = '1'
    import resource
    resource.setrlimit(resource.RLIMIT_AS, (1536 * 1024**2, 1536 * 1024**2))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (2 * 1024**2, 2 * 1024**2))
    import fcntl
    lock = (Path.home() / ('benign-' + args.group + '.lock')).open('a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    isolation = subprocess.run(['/usr/local/bin/aegisav-isolation-check'], check=True,
                               capture_output=True, text=True).stdout.strip()
    root = Path('/opt/aegisav-static')
    sys.path.insert(0, str(root / 'backend'))
    from aegisav.scanner import StaticScanner
    from aegisav.hashes import HashDatabase
    from aegisav.yara_engine import load_yara_engine
    from aegisav.clamav_engine import ClamAVEngine
    from static_ember import EmberEngine
    clam = ClamAVEngine()
    for _ in range(120):
        if clam.probe():
            break
        time.sleep(1)
    if not clam.probe():
        raise ValueError('ClamAV not ready before fixture scan')
    scanner = StaticScanner(HashDatabase.from_file(root / 'rules/hashes.json'),
                            load_yara_engine(root / 'rules/yara', root / 'rules/yara/metadata.json'),
                            clam, cache_capacity=0)
    model = EmberEngine(root / 'ember')
    fixture = Path('/opt/aegisav-benign') / args.group
    manifest = fixture / 'manifest.jsonl'
    rows = [json.loads(line) for line in manifest.read_text().splitlines() if line.strip()]
    expected = 300 if args.group == 'expansion' else 600
    if len(rows) != expected or len({row['sha256'] for row in rows}) != expected:
        raise ValueError('Unexpected frozen cohort size or duplicate')
    manifest_sha = hashlib.sha256(manifest.read_bytes()).hexdigest()
    from importlib.metadata import distributions
    tool_paths = [root / name for name in ('static_benign.py', 'benign_checkpoint.py', 'static_archive.py', 'static_ember.py')]
    tool_paths += list((root / 'backend/aegisav').glob('*.py'))
    tool_paths += list((root / 'rules').rglob('*.json')) + list((root / 'rules/yara').glob('*.yar'))
    tool_paths += list((root / 'ember').glob('*'))
    identity = {'manifest': manifest_sha, 'cache_capacity': 0, 'memory_limit_bytes': 1536 * 1024**2,
                'files': {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
                          for path in sorted(tool_paths) if path.is_file()},
                'packages': sorted((dist.metadata['Name'], dist.version) for dist in distributions()),
                'clamav': clam.artifact_version, 'yara': scanner.yara_engine.artifact_version,
                'ml': model.artifact_version}
    # JSON normalization makes tuples comparable after reloading.
    identity = json.loads(json.dumps(identity))
    report = {'schema': 2, 'manifest_sha256': manifest_sha,
              'isolation': isolation, 'files': [], 'errors': [], 'completed': False}
    checkpoint = Path.home() / ('benign-' + args.group + '.checkpoint.json')
    sessions = []
    if checkpoint.exists():
        saved = load_checkpoint(checkpoint, identity)
        report, sessions = saved['report'], saved['sessions']
        validate_resume(report, rows, manifest_sha)
        if not isinstance(sessions, list) or len(sessions) >= 100:
            raise ValueError('Checkpoint session boundary')
    resume_index = len(report['files'])
    sessions.append({'isolation': isolation, 'resume_index': resume_index, 'started_unix': time.time()})
    report['isolation'] = isolation
    print(f'Benign {args.group}: resume={resume_index}/{len(rows)}', flush=True)
    seen = {item['sha256'] for item in report['files']}
    for index, item in enumerate(rows, 1):
        expected_label = 'trusted_installation_benign_proxy' if args.group == 'expansion' else 'benign'
        if item['label'] != expected_label or not item.get('source'):
            raise ValueError('Unexpected fixture provenance')
        path = sample_path(fixture, item['path'])
        if path.stat().st_size > 64 * 1024**2:
            raise ValueError('Fixture size exceeds scanner boundary')
        content = path.read_bytes()
        if hashlib.sha256(content).hexdigest() != item['sha256']:
            raise ValueError('Fixture digest mismatch')
        # Recheck all preceding fixture bytes before trusting their recorded results.
        if index <= resume_index:
            continue
        report['files'].append(scan_file(item['path'], content, scanner, model, seen))
        if clam.artifact_version != identity['clamav']:
            raise ValueError('ClamAV artifact changed during scan')
        save_checkpoint(checkpoint, {'identity': identity, 'sessions': sessions, 'report': report})
        if index % 25 == 0:
            print(f'Benign {args.group}: {index}/{len(rows)}', flush=True)
            (Path.home() / ('benign-' + args.group + '.progress')).write_text(f'{index}/{len(rows)}\n')
    report['completed'] = True
    validate_benign_export(report)
    save_checkpoint(checkpoint, {'identity': identity, 'sessions': sessions, 'report': report})
    encoded = json.dumps(report, ensure_ascii=True, indent=2).encode()
    if len(encoded) > 2 * 1024**2:
        raise ValueError('Export size limit')
    output = Path.home() / ('benign-' + args.group + '.json')
    output.write_bytes(encoded)
    output.with_suffix('.json.sha256').write_text(hashlib.sha256(encoded).hexdigest() + '\n')


if __name__ == '__main__':
    main()
