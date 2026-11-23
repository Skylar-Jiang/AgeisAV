"""Collect official Microsoft benign candidates without running files or observing detectors."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import urllib.request
import zipfile

from aegisav.ml_engine import pe_scope
from experiments.collect_benign_expansion import inspect_signatures, pe_metadata


def main():
    root = Path(__file__).resolve().parents[1]
    output = root / 'artifacts/official_benign_candidates_20261012'
    if output.exists():
        raise ValueError('Refusing to overwrite candidate acquisition')
    output.mkdir()
    samples = output / 'samples'
    samples.mkdir()
    archive_path = output / 'SysinternalsSuite.zip'
    url = 'https://download.sysinternals.com/files/SysinternalsSuite.zip'
    acquired = datetime.now(timezone.utc).isoformat()
    with urllib.request.urlopen(url, timeout=60) as response, archive_path.open('xb') as stream:
        headers = {key: response.headers.get(key) for key in ('Last-Modified', 'ETag', 'Content-Length')}
        total = 0
        while chunk := response.read(1024**2):
            total += len(chunk)
            if total > 300 * 1024**2:
                raise ValueError('Official archive download boundary')
            stream.write(chunk)
    prior = set()
    for name in ('benign_windows_pe_manifest.jsonl', 'benign_vendor_pe_manifest.jsonl', 'benign_expansion_manifest_20261010.jsonl'):
        prior.update(json.loads(line)['sha256'] for line in (root / 'docs/benchmarks' / name).read_text().splitlines())
    prior.update(item['sha256'] for item in json.loads((root / 'docs/benchmarks/user_archive_label_reference_20261010.json').read_text())['samples'])
    rows, exclusions, seen = [], [], set()
    expanded = 0
    with zipfile.ZipFile(archive_path) as archive:
        assert len(archive.infolist()) <= 2000
        for entry in archive.infolist():
            name = PurePosixPath(entry.filename)
            if name.suffix.lower() not in {'.exe', '.dll', '.sys'}:
                continue
            if entry.file_size > 64 * 1024**2 or expanded + entry.file_size > 600 * 1024**2:
                exclusions.append(dict(member=entry.filename, reason='size_limit'))
                continue
            # No archive paths are used on disk: only verified digest names.
            data = archive.read(entry)
            expanded += len(data)
            digest = hashlib.sha256(data).hexdigest()
            if digest in seen or digest in prior:
                exclusions.append(dict(member=entry.filename, sha256=digest, reason='duplicate_or_prior_observed'))
                continue
            seen.add(digest)
            scope = pe_scope(data)
            if scope == 'unsupported':
                exclusions.append(dict(member=entry.filename, sha256=digest, reason='unsupported_model_scope'))
                continue
            target = samples / (digest + name.suffix.lower())
            target.write_bytes(data)
            rows.append(dict(sha256=digest, size_bytes=len(data), original_member=entry.filename,
                             source_path=str(target), path='samples/' + target.name, pe_scope=scope,
                             acquired_utc=acquired, source_url=url, label='presumed_benign',
                             label_basis='Official Microsoft distribution plus valid publisher signature; authorized dual-use tools included',
                             dataset_role='unscored_candidate_quarantine', first_seen_utc=None,
                             time_evidence='Acquisition time only; bundle publication does not date each binary',
                             detector_results_observed=False, **pe_metadata(data)))
    shell = shutil.which('pwsh') or shutil.which('powershell')
    signed = []
    for offset in range(0, len(rows), 32):
        signed.extend(inspect_signatures(shell, rows[offset:offset + 32]))
    accepted = []
    for row in signed:
        if row['signature_status'] == 'Valid' and ('Microsoft' in row['signer']):
            accepted.append(row)
        else:
            exclusions.append(dict(sha256=row['sha256'], member=row['original_member'], reason='publisher_signature_not_valid',
                                   signature_status=row['signature_status']))
    manifest = root / 'docs/benchmarks/official_benign_candidates_manifest_20261012.jsonl'
    manifest.write_text(''.join(json.dumps(row, ensure_ascii=True) + '\n' for row in accepted))
    report = dict(schema=1, source_url=url, source_page='https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite',
                  acquired_utc=acquired, http_headers=headers, archive_sha256=hashlib.sha256(archive_path.read_bytes()).hexdigest(),
                  archive_bytes=archive_path.stat().st_size, candidate_count=len(accepted), excluded=exclusions,
                  detector_evaluation_performed=False, final_test_frozen=False,
                  unresolved=['Per-file trusted temporal evidence', 'Full model training membership',
                              'TLSH/SSDeep near-duplicate clusters against prior data and future validation/final split',
                              'Independent label review; signatures and official source are benign proxies'],
                  manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest())
    (root / 'docs/benchmarks/official_benign_candidates_acquisition_20261012.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(candidates=len(accepted), archive_bytes=archive_path.stat().st_size, excluded=len(exclusions))))


if __name__ == '__main__':
    main()
