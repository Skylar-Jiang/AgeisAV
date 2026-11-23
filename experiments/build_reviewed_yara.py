"""Build the fixed 246-source reviewed Windows YARA pack; never select by scan hits."""

import argparse
from collections import Counter
import hashlib
from importlib.metadata import version
import json
import math
from pathlib import Path, PurePosixPath
import re
import statistics
import zipfile

import yara_x

from aegisav.pe import validate_pe
from aegisav.yara_engine import RULE_NAME, load_yara_engine


REVISION = 'e0a0be54aa1e11ccfd6854e4f19e9476f328fd84'
ARCHIVE_SHA256 = '8572f9efc8f5b196e8343a9bb74a5da2c403665670a891f1b0ac7d3fa54eefd0'
SCOPE = re.compile(r'^yara/[^/]+/(Win32|Win64|MSIL)\.[^/]+\.yara$')
DECLARATION = re.compile(rb'(?m)^\s*rule\s+([A-Za-z_][A-Za-z0-9_]*)\b')
EXISTING = {'yara/infostealer/Win32.Infostealer.StealC.yara': ('StealC_Code_Infostealer', 'stealc_code.yar'),
            'yara/trojan/Win32.Trojan.TrickBot.yara': ('TrickBot_Code_Trojan', 'trickbot_code.yar')}


def transform_source(source: bytes, path: str) -> tuple[bytes, dict]:
    if not SCOPE.fullmatch(path):
        raise ValueError(f'Source outside declared scope: {path}')
    declarations = list(DECLARATION.finditer(source))
    if len(declarations) != 1:
        raise ValueError(f'Expected one unqualified rule declaration: {path}')
    match = declarations[0]
    original_id = match[1]
    if len(re.findall(rb'\b' + re.escape(original_id) + rb'\b', source)) != 1:
        raise ValueError(f'Rule identifier occurs outside its declaration: {path}')
    family = re.sub('[^A-Za-z0-9]', '', PurePosixPath(path).stem.split('.')[2])
    if not family or not family[0].isalpha():
        family = 'Family' + family
    canonical_id = EXISTING[path][0] if path in EXISTING else family + '_Code_h' + hashlib.sha256(path.encode()).hexdigest()[:10]
    changed = source[:match.start(1)] + canonical_id.encode() + source[match.end(1):]
    restored = changed[:match.start(1)] + original_id + changed[match.start(1) + len(canonical_id):]
    if len(canonical_id) > 50 or not RULE_NAME.fullmatch(canonical_id) or restored != source:
        raise ValueError(f'Canonical name or reverse transformation failed: {path}')
    metadata = {'rule_id': canonical_id, 'family': family, 'feature_type': 'Code',
                'description': 'Reviewed upstream Windows rule; only declaration identifier renamed.',
                'author': 'ReversingLabs',
                'source': f'https://github.com/reversinglabs/reversinglabs-yara-rules/blob/{REVISION}/{path}',
                'version': REVISION[:8], 'confidence': 'Malicious recall unvalidated locally',
                'scope': 'Static Windows PE files; upstream Win32/Win64/MSIL source scope', 'license': 'MIT',
                'upstream_revision': REVISION, 'upstream_rule_id': original_id.decode(), 'upstream_path': path,
                'upstream_source_sha256': hashlib.sha256(source).hexdigest(),
                'canonical_source_sha256': hashlib.sha256(changed).hexdigest(),
                'reverse_transform_verified': True,
                'canonical_file': EXISTING[path][1] if path in EXISTING else canonical_id + '.yar'}
    return changed, metadata


def build_pack(archive: Path, audit_path: Path, output_dir: Path) -> dict:
    if hashlib.sha256(archive.read_bytes()).hexdigest() != ARCHIVE_SHA256:
        raise ValueError('Upstream source archive SHA-256 mismatch')
    audit = json.loads(audit_path.read_text(encoding='utf-8'))
    entries = audit['sources']
    if (audit['upstream_revision'] != REVISION or audit['source_archive_sha256'] != ARCHIVE_SHA256
            or len(entries) != 246 or len({entry['source'] for entry in entries}) != 246):
        raise ValueError('Expected the fixed audited 246-source scope')
    with zipfile.ZipFile(archive) as zipped:
        prefix = 'reversinglabs-yara-rules-' + REVISION + '/'
        scoped = {name[len(prefix):] for name in zipped.namelist() if name.startswith(prefix)
                  and SCOPE.fullmatch(name[len(prefix):])}
        if scoped != {entry['source'] for entry in entries}:
            raise ValueError('Audited scope differs from all upstream Win32/Win64/MSIL sources')
        sources = {entry['source']: zipped.read(prefix + entry['source']) for entry in entries}
        license_bytes = zipped.read(prefix + 'LICENSE')
    for entry in entries:
        if hashlib.sha256(sources[entry['source']]).hexdigest() != entry['sha256']:
            raise ValueError(f"Upstream source SHA mismatch: {entry['source']}")
    transformed = [transform_source(source, path) for path, source in sorted(sources.items())]
    metadata = [item for _, item in transformed]
    if len({item['rule_id'] for item in metadata}) != 246:
        raise ValueError('Canonical rule name collision')
    original_tokens = Counter(re.findall(rb'\b[A-Za-z_][A-Za-z0-9_]*\b', b'\n'.join(sources.values())))
    if any(original_tokens[item['upstream_rule_id'].encode()] != 1 for item in metadata):
        raise ValueError('An upstream rule identifier is referenced in another source')
    compiler = yara_x.Compiler()
    diagnostics = []
    for changed, item in transformed:
        before = len(compiler.warnings())
        compiler.add_source(changed.decode('utf-8'), origin=item['upstream_path'])
        diagnostics.append({'source': item['upstream_path'], 'rule_id': item['rule_id'],
                            'warnings': compiler.warnings()[before:], 'errors': []})
    compiler.build()
    if compiler.warnings() or compiler.errors():
        raise ValueError('Reviewed pack must compile with zero warnings and errors')
    expected_files = {item['canonical_file'] for item in metadata}
    unexpected = {path.name for path in output_dir.glob('*.yar')} - expected_files
    if unexpected:
        raise ValueError(f'Output contains unrelated rule files: {sorted(unexpected)}')
    output_dir.mkdir(parents=True, exist_ok=True)
    for changed, item in transformed:
        (output_dir / item['canonical_file']).write_bytes(changed)
    (output_dir / 'LICENSE.reversinglabs.txt').write_bytes(license_bytes)
    (output_dir / 'metadata.json').write_text(json.dumps(metadata, indent=2) + '\n', encoding='utf-8')
    engine = load_yara_engine(output_dir, output_dir / 'metadata.json')
    return {'schema': 1, 'method': 'fixed_scope_byte_preserving_upstream_rule_review',
            'upstream_revision': REVISION, 'source_archive_sha256': ARCHIVE_SHA256,
            'audit_sha256': hashlib.sha256(audit_path.read_bytes()).hexdigest(),
            'scope': 'Exactly all 246 audited Win32/Win64/MSIL source paths; excludes ByteCode.*; no selection by test outcomes',
            'source_count': len(metadata), 'rule_count': len(metadata), 'yara_x_version': version('yara-x'),
            'warning_count': 0, 'error_count': 0, 'all_reverse_transforms_verified': True,
            'license': 'MIT', 'artifact_version': engine.artifact_version, 'pack_path': str(output_dir),
            'metadata_sha256': hashlib.sha256((output_dir / 'metadata.json').read_bytes()).hexdigest(),
            'sources': metadata, 'compiler_diagnostics': diagnostics}


def scan_benign(rule_dir: Path, root: Path, manifest: Path) -> dict:
    rows = [json.loads(line) for line in manifest.read_text(encoding='utf-8').splitlines() if line.strip()]
    if any(row['label'] != 'benign' for row in rows) or len({row['sha256'] for row in rows}) != len(rows):
        raise ValueError('Benign scan requires unique benign-labelled manifest entries')
    engine = load_yara_engine(rule_dir, rule_dir / 'metadata.json')
    reports = []
    resolved_root = root.resolve()
    for row in rows:
        path = (root / row['path']).resolve()
        if not path.is_relative_to(resolved_root):
            raise ValueError('Benign manifest path escapes its declared root')
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != row['sha256']:
            raise ValueError('Benign fixture SHA-256 differs from frozen manifest')
        validate_pe(data)
        reports.append({'sha256': row['sha256'], 'size_bytes': len(data), **engine.scan(data)})
    times = sorted(row['elapsed_ms'] for row in reports)
    statuses = Counter(row['status'] for row in reports)
    return {'method': 'actual_bytes_benign_static_scan', 'sample_count': len(reports),
            'manifest': str(manifest), 'manifest_sha256': hashlib.sha256(manifest.read_bytes()).hexdigest(),
            'artifact_version': engine.artifact_version, 'status_counts': dict(statuses),
            'false_positive_count': statuses['matched'], 'fpr': statuses['matched'] / len(rows) if rows else None,
            'p50_ms': statistics.median(times) if times else None,
            'p95_ms_nearest_rank': times[math.ceil(.95 * len(times)) - 1] if times else None,
            'reports': reports}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', required=True, type=Path)
    parser.add_argument('--audit', required=True, type=Path)
    parser.add_argument('--rule-dir', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--benign-root', action='append', default=[], type=Path)
    parser.add_argument('--benign-manifest', action='append', default=[], type=Path)
    args = parser.parse_args()
    if len(args.benign_root) != len(args.benign_manifest):
        parser.error('Each benign root requires one frozen manifest')
    result = build_pack(args.archive, args.audit, args.rule_dir)
    result['benign_scans'] = [scan_benign(args.rule_dir, root, manifest)
                              for root, manifest in zip(args.benign_root, args.benign_manifest)]
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({key: value for key, value in result.items() if key not in {'sources', 'compiler_diagnostics', 'benign_scans'}}, indent=2))
    print(json.dumps([{key: value for key, value in scan.items() if key != 'reports'}
                      for scan in result['benign_scans']], indent=2))


if __name__ == '__main__':
    main()
