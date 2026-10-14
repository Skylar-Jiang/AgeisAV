"""Guest-only bounded static inspection. Never extract or execute archive members."""

import argparse
import hashlib
import io
import json
import math
import re
import stat
import subprocess
import sys
import time
import zipfile
from pathlib import Path, PurePosixPath

MAX_MEMBER = 64 * 1024 * 1024


def clean_text(value, limit=1024):
    return ''.join(c if c.isprintable() else '?' for c in str(value))[:limit]


def walk_archive(data, password, visit, errors, prefix='', depth=0, budget=None):
    if budget is None:
        budget = {'bytes': 512 * 1024 * 1024, 'members': 2000}
    if depth > 8:
        errors.append({'path': clean_text(prefix), 'reason': 'depth_limit'})
        return
    # Check every central-directory entry before ZipFile allocates ZipInfo objects.
    # ZIP64 and multi-disk input are outside this bounded, small-archive workflow.
    end = data.rfind(b'PK\x05\x06', max(0, len(data) - 65557))
    if end < 0 or end + 22 > len(data) or end + 22 + int.from_bytes(data[end+20:end+22], 'little') != len(data):
        errors.append({'path': clean_text(prefix), 'reason': 'invalid_zip'})
        return
    if end >= 20 and data[end-20:end-16] == b'PK\x06\x07':
        errors.append({'path': clean_text(prefix), 'reason': 'invalid_zip'})
        return
    position = end - int.from_bytes(data[end+12:end+16], 'little')
    count = 0
    while position < end:
        if position < 0 or position + 46 > end or data[position:position+4] != b'PK\x01\x02':
            errors.append({'path': clean_text(prefix), 'reason': 'invalid_zip'})
            return
        count += 1
        if count > budget['members']:
            budget['members'] = 0
            errors.append({'path': clean_text(prefix), 'reason': 'member_limit'})
            return
        position += 46 + sum(int.from_bytes(data[position+i:position+i+2], 'little') for i in (28, 30, 32))
    if position != end or count != int.from_bytes(data[end+10:end+12], 'little') or data[end+4:end+8] != b'\x00'*4:
        errors.append({'path': clean_text(prefix), 'reason': 'invalid_zip'})
        return
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as package:
            for index, info in enumerate(package.infolist()):
                budget['members'] -= 1
                if info.is_dir():
                    continue
                name = info.filename.replace('\\', '/')
                full = clean_text(prefix + name)
                path = PurePosixPath(name)
                if budget['members'] < 0:
                    errors.append({'path': full, 'reason': 'member_limit'})
                    return
                if path.is_absolute() or '..' in path.parts or ':' in name or stat.S_ISLNK(info.external_attr >> 16):
                    errors.append({'path': full, 'reason': 'unsafe_path'})
                    continue
                if info.file_size > MAX_MEMBER or info.file_size > budget['bytes']:
                    errors.append({'path': full, 'reason': 'size_limit'})
                    continue
                budget['bytes'] -= info.file_size
                try:
                    with package.open(info, pwd=password) as member:
                        content = member.read(info.file_size + 1)
                    if len(content) != info.file_size:
                        raise ValueError('Size mismatch')
                except (RuntimeError, NotImplementedError, zipfile.BadZipFile, ValueError, OSError):
                    errors.append({'path': full, 'reason': 'read_or_password_error'})
                    continue
                if name.lower().endswith('.zip'):
                    walk_archive(content, password, visit, errors, full + '!/', depth + 1, budget)
                    if budget['members'] <= 0:
                        if index + 1 < count and (not errors or errors[-1]['reason'] != 'member_limit'):
                            errors.append({'path': clean_text(prefix), 'reason': 'member_limit'})
                        return
                else:
                    visit(full, content)
    except zipfile.BadZipFile:
        errors.append({'path': clean_text(prefix), 'reason': 'invalid_zip'})


def validate_export(report):
    def fields(obj, names):
        if not isinstance(obj, dict) or set(obj) != set(names.split()):
            raise ValueError('Unexpected report fields')

    def text(value, limit=1024):
        if not isinstance(value, str) or len(value) > limit or clean_text(value, limit) != value:
            raise ValueError('Invalid report text')

    def digest(value):
        if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value):
            raise ValueError('Invalid digest')

    fields(report, 'schema archive_sha256 isolation files errors completed')
    if type(report['schema']) is not int or report['schema'] not in (1, 2) or type(report['completed']) is not bool:
        raise ValueError('Invalid schema')
    digest(report['archive_sha256'])
    text(report['isolation'])
    if not report['isolation'].startswith('AEGISAV_ISOLATION PASS '):
        raise ValueError('Isolation did not pass')
    for name in ('files', 'errors'):
        if not isinstance(report[name], list) or len(report[name]) > 2000:
            raise ValueError('Report count limit')
    for item in report['errors']:
        fields(item, 'path reason')
        text(item['path'])
        if item['reason'] not in {'depth_limit', 'member_limit', 'unsafe_path', 'size_limit', 'read_or_password_error', 'invalid_zip'}:
            raise ValueError('Invalid error')
    for item in report['files']:
        fields(item, 'path sha256 size_bytes pe_valid duplicate elapsed_ms engines')
        text(item['path'])
        digest(item['sha256'])
        if type(item['size_bytes']) is not int or not 0 <= item['size_bytes'] <= MAX_MEMBER:
            raise ValueError('Invalid size')
        if type(item['pe_valid']) is not bool or type(item['duplicate']) is not bool:
            raise ValueError('Invalid file status')
        for elapsed in [item['elapsed_ms']] + [e.get('elapsed_ms') for e in item['engines'].values()]:
            if type(elapsed) not in (int, float) or not math.isfinite(elapsed) or not 0 <= elapsed <= 1e7:
                raise ValueError('Invalid elapsed time')
        expected = {'sha256', 'fuzzy', 'yara_x', 'clamav'}
        if report['schema'] == 2:
            expected.add('lightgbm')
        if set(item['engines']) != (expected if item['pe_valid'] else set()):
            raise ValueError('Invalid engines')
        for name, engine in item['engines'].items():
            extra = ''
            if report['schema'] == 2 and name == 'fuzzy':
                extra = ' hashes'
                fields(engine.get('hashes'), 'tlsh ssdeep')
                tlsh, ssdeep = engine['hashes']['tlsh'], engine['hashes']['ssdeep']
                if tlsh is not None and (not isinstance(tlsh, str) or not re.fullmatch(r'(?:T1)?[0-9A-Fa-f]{70}', tlsh)):
                    raise ValueError('Invalid TLSH digest')
                if ssdeep is not None and (not isinstance(ssdeep, str) or not re.fullmatch(r'[0-9]{1,10}:[A-Za-z0-9+/]{0,64}:[A-Za-z0-9+/]{0,64}', ssdeep)):
                    raise ValueError('Invalid SSDeep digest')
            if report['schema'] == 2 and name == 'lightgbm':
                extra = ' score threshold feature_elapsed_ms inference_elapsed_ms'
                for key in ('feature_elapsed_ms', 'inference_elapsed_ms'):
                    value = engine.get(key)
                    if type(value) not in (float, int) or not math.isfinite(value) or not 0 <= value <= 1e7:
                        raise ValueError('Invalid model timing')
                score = engine.get('score')
                if score is not None and (type(score) not in (float, int) or not math.isfinite(score) or not 0 <= score <= 1):
                    raise ValueError('Invalid model score')
                if engine.get('threshold') != 0.5 or (engine.get('status') in {'matched', 'no_match'} and score is None):
                    raise ValueError('Invalid model threshold or missing score')
            fields(engine, 'status engine_version artifact_version elapsed_ms evidence' + extra)
            if engine['status'] not in {'matched', 'no_match', 'unavailable', 'error', 'timeout'}:
                raise ValueError('Invalid engine status')
            text(engine['engine_version'], 200)
            text(engine['artifact_version'], 200)
            if not isinstance(engine['evidence'], list) or len(engine['evidence']) > 100:
                raise ValueError('Evidence limit')
            for evidence in engine['evidence']:
                text(evidence, 200)


def scan_file(name, content, scanner, model, seen):
    from aegisav.pe import validate_pe
    digest = hashlib.sha256(content).hexdigest()
    row = {'path': name, 'sha256': digest, 'size_bytes': len(content), 'pe_valid': False,
           'duplicate': digest in seen, 'elapsed_ms': 0.0, 'engines': {}}
    seen.add(digest)
    try:
        validate_pe(content)
    except ValueError:
        return row
    row['pe_valid'] = True
    started = time.perf_counter()
    result = scanner.scan(content)
    result['engines']['lightgbm'] = model.scan(content)
    row['elapsed_ms'] = round((time.perf_counter() - started) * 1000, 3)
    for name, engine in result['engines'].items():
        row['engines'][name] = {key: engine[key] for key in ('status', 'elapsed_ms')}
        row['engines'][name].update({key: clean_text(engine.get(key) or 'unknown', 200)
                                   for key in ('engine_version', 'artifact_version')})
        row['engines'][name]['evidence'] = [clean_text(e.get('rule_id') or e.get('signature') or e.get('sha256') or 'candidate', 200)
                                           for e in engine['evidence'][:100]]
        if name == 'fuzzy':
            row['engines'][name]['hashes'] = engine['hashes']
        if name == 'lightgbm':
            row['engines'][name].update({key: engine[key] for key in
                                        ('score', 'threshold', 'feature_elapsed_ms', 'inference_elapsed_ms')})
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--batch')
    parser.add_argument('--sha256')
    parser.add_argument('--validate-export', type=Path)
    args = parser.parse_args()
    if args.validate_export:
        if args.validate_export.stat().st_size > 2 * 1024**2:
            raise ValueError('Export size limit')
        validate_export(json.loads(args.validate_export.read_text(encoding='utf-8')))
        print('Static JSON export schema PASS')
        return
    if sys.platform != 'linux' or not re.fullmatch('[0-9a-f]{32}', args.batch or '') or not re.fullmatch('[0-9a-f]{64}', args.sha256 or ''):
        raise ValueError('Guest-only operation and fixed batch identifier required')
    import os
    import resource
    if os.getuid() == 0:
        raise ValueError('Never scan as root')
    resource.setrlimit(resource.RLIMIT_AS, (1536 * 1024**2, 1536 * 1024**2))
    resource.setrlimit(resource.RLIMIT_CPU, (1800, 1800))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (2 * 1024**2, 2 * 1024**2))
    os.environ['OPENBLAS_NUM_THREADS'] = '1'
    os.environ['OMP_NUM_THREADS'] = '1'
    isolation = subprocess.run(['/usr/local/bin/aegisav-isolation-check'], check=True, capture_output=True, text=True).stdout.strip()
    root = Path('/opt/aegisav-static')
    sys.path.insert(0, str(root / 'backend'))
    from aegisav.scanner import StaticScanner
    from aegisav.hashes import HashDatabase
    from aegisav.yara_engine import load_yara_engine
    from aegisav.clamav_engine import ClamAVEngine
    from static_ember import EmberEngine
    work = Path.home() / ('batch-' + args.batch)
    archive = work / 'input.zip'
    if archive.stat().st_size > 128 * 1024**2:
        raise ValueError('Archive size limit')
    raw = archive.read_bytes()
    if hashlib.sha256(raw).hexdigest() != args.sha256:
        raise ValueError('Archive digest mismatch')
    password_file = work / 'password.txt'
    password = password_file.read_bytes()
    password_file.unlink()
    clam = ClamAVEngine()
    for _ in range(120):
        if clam.probe():
            break
        time.sleep(1)
    if not clam.probe():
        raise ValueError('ClamAV not ready')
    scanner = StaticScanner(HashDatabase.from_file(root / 'rules/hashes.json'),
                            load_yara_engine(root / 'rules/yara', root / 'rules/yara/metadata.json'), clam,
                            cache_capacity=0)
    model = EmberEngine(root / 'ember')
    report = {'schema': 2, 'archive_sha256': args.sha256, 'isolation': isolation,
              'files': [], 'errors': [], 'completed': False}
    seen = set()

    def visit(name, content):
        row = scan_file(name, content, scanner, model, seen)
        report['files'].append(row)
        print(f"Static file {len(report['files'])}: {row['sha256']} PE={row['pe_valid']}", flush=True)

    walk_archive(raw, password, visit, report['errors'])
    report['completed'] = True
    validate_export(report)
    encoded = json.dumps(report, ensure_ascii=True, indent=2).encode()
    if len(encoded) > 2 * 1024**2:
        raise ValueError('Export size limit')
    output = work / 'result.json'
    output.write_bytes(encoded)
    (work / 'result.sha256').write_text(hashlib.sha256(encoded).hexdigest() + '\n')


if __name__ == '__main__':
    main()
