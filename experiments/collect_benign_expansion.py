"""Collect signed installed PE validation candidates; never execute candidate files."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from datetime import datetime, timezone

import pefile


REPO = Path(__file__).resolve().parents[1]
QUOTAS = {'dotnet_core': 80, 'dotnet_desktop': 40, 'dotnet_aspnet': 40,
          'framework': 60, 'python': 40, 'drivers': 40}
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 1024 * 1024 * 1024
SIGNATURE_COMMAND = r"""
$ErrorActionPreference = 'Stop'
$paths = ($input | Out-String | ConvertFrom-Json)
foreach ($path in $paths) {
    try {
        $item = Get-Item -LiteralPath $path
        $sig = Get-AuthenticodeSignature -LiteralPath $path
        [ordered]@{source_path=$path; signature_status=[string]$sig.Status;
            signer=[string]$sig.SignerCertificate.Subject;
            certificate_thumbprint=[string]$sig.SignerCertificate.Thumbprint;
            timestamp_signer=[string]$sig.TimeStamperCertificate.Subject;
            company_name=[string]$item.VersionInfo.CompanyName;
            product_name=[string]$item.VersionInfo.ProductName;
            file_version=[string]$item.VersionInfo.FileVersion;
            original_filename=[string]$item.VersionInfo.OriginalFilename
        } | ConvertTo-Json -Compress
    } catch {
        [ordered]@{source_path=$path; signature_status='InspectionError';
            inspection_error=[string]$_.Exception.Message} | ConvertTo-Json -Compress
    }
}
"""


def pe_metadata(data):
    pe = pefile.PE(data=data, fast_load=True)
    try:
        return {'machine': f'0x{pe.FILE_HEADER.Machine:04x}',
                'pe_format': 'PE32+' if pe.PE_TYPE == 0x20b else 'PE32',
                'is_dll': bool(pe.FILE_HEADER.Characteristics & 0x2000),
                'has_clr': bool(pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress)}
    finally:
        pe.close()


def select_rows(rows, prior_hashes, quotas, max_bytes):
    selected, exclusions, seen = [], [], set()
    counts = {group: 0 for group in quotas}
    total = 0
    for row in rows:
        digest, group = row['sha256'], row['group']
        reason = None
        if digest in prior_hashes:
            reason = 'overlap_prior_dataset'
        elif digest in seen:
            reason = 'duplicate_current_cohort'
        elif row['signature_status'] != 'Valid':
            reason = 'signature_not_valid'
        elif row['expected_publisher'] not in row.get('signer', ''):
            reason = 'unexpected_publisher'
        elif counts[group] >= quotas[group]:
            reason = 'group_quota_reached'
        elif total + row['size_bytes'] > max_bytes:
            reason = 'total_byte_budget'
        if reason:
            exclusions.append({'source_path': row['source_path'] if 'source_path' in row else None,
                               'sha256': digest, 'group': group, 'reason': reason})
            continue
        seen.add(digest)
        counts[group] += 1
        total += row['size_bytes']
        selected.append({**row, 'label': 'trusted_installation_benign_proxy',
                         'dataset_role': 'validation_candidate'})
    return selected, exclusions


def copy_verified(row, destination):
    source = Path(row['source_path'])
    data = source.read_bytes()
    if hashlib.sha256(data).hexdigest() != row['sha256']:
        raise ValueError(f'Source changed during collection: {source}')
    destination.mkdir(parents=True, exist_ok=True)
    target = destination / (row['sha256'] + source.suffix.lower())
    with target.open('xb') as stream:
        stream.write(data)
    if hashlib.sha256(target.read_bytes()).hexdigest() != row['sha256']:
        raise ValueError(f'Copy verification failed: {target}')
    return f'samples/{target.name}'


def inspect_signatures(shell, batch):
    proc = subprocess.run([shell, '-NoProfile', '-Command', SIGNATURE_COMMAND],
                          input=json.dumps([row['source_path'] for row in batch]),
                          text=True, capture_output=True, check=True, encoding='utf-8')
    signatures = {row['source_path']: row for line in proc.stdout.splitlines()
                  if line.strip() for row in [json.loads(line)]}
    return [{**row, **signatures[row['source_path']]} for row in batch]


def main():
    if os.name != 'nt':
        raise SystemExit('Collection is restricted to the installed Windows software roots.')
    output = REPO / 'artifacts/benign_expansion_20261010'
    manifest = REPO / 'docs/benchmarks/benign_expansion_manifest_20261010.jsonl'
    audit_path = REPO / 'docs/benchmarks/benign_expansion_audit_20261010.json'
    if output.exists() or manifest.exists() or audit_path.exists():
        raise SystemExit('Frozen cohort/output already exists; refusing to overwrite.')
    prior_paths = [REPO / 'docs/benchmarks' / name for name in (
        'benign_windows_pe_manifest.jsonl', 'benign_vendor_pe_manifest.jsonl',
        'user_archive_label_reference.json')]
    prior_hashes = set()
    for path in prior_paths:
        if path.suffix == '.jsonl':
            rows = [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line]
        else:
            rows = json.loads(path.read_text(encoding='utf-8'))['samples']
        prior_hashes.update(row['sha256'] for row in rows)
    roots = {
        'dotnet_core': [Path('C:/Program Files/dotnet/shared/Microsoft.NETCore.App')],
        'dotnet_desktop': [Path('C:/Program Files/dotnet/shared/Microsoft.WindowsDesktop.App')],
        'dotnet_aspnet': [Path('C:/Program Files/dotnet/shared/Microsoft.AspNetCore.App')],
        'framework': [Path('C:/Windows/Microsoft.NET/Framework64'), Path('C:/Windows/Microsoft.NET/Framework')],
        'python': [Path(os.environ['LOCALAPPDATA']) / 'Programs/Python/Python311',
                   Path(os.environ['LOCALAPPDATA']) / 'Programs/Python/Python312'],
        'drivers': [Path('C:/Windows/System32/drivers')],
    }
    acquired = datetime.now(timezone.utc).isoformat()
    inspected, excluded, discovery = [], [], {}
    shell = shutil.which('pwsh') or shutil.which('powershell')
    for group, group_roots in roots.items():
        candidates = sorted({p for root in group_roots if root.is_dir() for p in root.rglob('*')
                             if p.is_file() and p.suffix.lower() in {'.dll', '.exe', '.pyd', '.sys'}},
                            key=lambda p: hashlib.sha256(str(p).casefold().encode()).hexdigest())
        discovery[group] = {'candidate_paths': len(candidates), 'paths_examined': 0,
                            'signature_inspected': 0, 'quota': QUOTAS[group]}
        batch = []
        for index, source in enumerate(candidates):
            discovery[group]['paths_examined'] += 1
            try:
                stat = source.stat()
                if stat.st_file_attributes & 0x400:
                    raise ValueError('reparse_point')
                if stat.st_size > MAX_FILE_BYTES:
                    raise ValueError('file_size_limit')
                data = source.read_bytes()
                digest = hashlib.sha256(data).hexdigest()
                metadata = pe_metadata(data)
                if digest in prior_hashes:
                    excluded.append({'source_path': str(source), 'sha256': digest,
                                     'group': group, 'reason': 'overlap_prior_dataset'})
                    continue
                batch.append({'source_path': str(source), 'sha256': digest, 'group': group,
                              'expected_publisher': 'Python Software Foundation' if group == 'python' else 'Microsoft Corporation',
                              'size_bytes': stat.st_size, 'source_last_write_utc': datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
                              'acquired_utc': acquired, **metadata})
            except (OSError, ValueError, pefile.PEFormatError) as exc:
                excluded.append({'source_path': str(source), 'group': group, 'reason': str(exc)})
            if len(batch) >= 32 or index == len(candidates) - 1:
                if not batch:
                    continue
                inspected.extend(inspect_signatures(shell, batch))
                discovery[group]['signature_inspected'] += len(batch)
                batch.clear()
                selected, _ = select_rows(inspected, prior_hashes, QUOTAS, MAX_TOTAL_BYTES)
                count = sum(row['group'] == group for row in selected)
                print(f'{group}: selected {count}/{QUOTAS[group]}', flush=True)
                if count >= QUOTAS[group]:
                    break
        # A trailing batch can remain when all remaining paths were prior duplicates.
        if batch:
            inspected.extend(inspect_signatures(shell, batch))
            discovery[group]['signature_inspected'] += len(batch)
    selected, rejected = select_rows(inspected, prior_hashes, QUOTAS, MAX_TOTAL_BYTES)
    for row in selected:
        row['path'] = copy_verified(row, output / 'samples')
        row['source'] = 'Existing trusted software installation; valid expected-publisher Authenticode signature; original installer provenance not independently verified'
        row['independent_ground_truth_verified'] = False
    manifest.write_text(''.join(json.dumps(row, ensure_ascii=False) + '\n' for row in selected), encoding='utf-8')
    audit = {'schema': 1, 'collection_started_utc': acquired,
             'collection_completed_utc': datetime.now(timezone.utc).isoformat(),
             'tooling': {'collector_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                         'python': sys.version.split()[0], 'pefile': pefile.__version__,
                         'signature_inspection': 'PowerShell Get-AuthenticodeSignature; Windows trust evaluation at acquisition time'},
             'selection': 'Fixed group quotas; SHA256(case-folded source path) ordering; no AV outcome selection',
             'roots': {group: [str(p) for p in paths] for group, paths in roots.items()},
             'discovery': discovery, 'selected_count': len(selected),
             'selected_bytes': sum(row['size_bytes'] for row in selected),
             'manifest_sha256': hashlib.sha256(manifest.read_bytes()).hexdigest(),
             'prior_manifests': [{'path': str(path.relative_to(REPO)), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()} for path in prior_paths],
             'prior_unique_sha256_count': len(prior_hashes),
             'exclusions': excluded + rejected,
             'limitations': ['Valid signature is not proof of benignness.',
                            'Installed source and signer are proxy label evidence, not independent ground truth.',
                            'Validation candidate cohort; never an independent final test set.',
                            'Unexamined paths after fixed quotas are not silently asserted eligible.']}
    audit_path.write_text(json.dumps(audit, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'selected_count': len(selected), 'bytes': audit['selected_bytes'], 'manifest': str(manifest)}, indent=2))


if __name__ == '__main__':
    main()
