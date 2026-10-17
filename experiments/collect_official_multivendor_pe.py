"""Fixed official multivendor PE acquisition, without execution or detector scoring."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import time
import urllib.request
import zipfile

from experiments.collect_official_runtime_pe import inspect_signatures, pe_metadata, pe_scope


SOURCES = [
    dict(name='7zip-x64', vendor='Igor Pavlov', version='26.04', kind='exe',
         url='https://github.com/ip7z/7zip/releases/download/26.04/7z2604-x64.exe',
         page='https://www.7-zip.org/download.html', release_date='2026-10-05',
         license='LGPL-2.1-or-later plus BSD-2-Clause, BSD-3-Clause and unRAR restrictions',
         license_url='https://www.7-zip.org/license.txt', purpose='archive_installer'),
    dict(name='7zip-x86', vendor='Igor Pavlov', version='26.04', kind='exe',
         url='https://github.com/ip7z/7zip/releases/download/26.04/7z2604.exe',
         page='https://www.7-zip.org/download.html', release_date='2026-10-05',
         license='LGPL-2.1-or-later plus BSD-2-Clause, BSD-3-Clause and unRAR restrictions',
         license_url='https://www.7-zip.org/license.txt', purpose='archive_installer'),
    dict(name='sumatrapdf-x64', vendor='Krzysztof Kowalczyk', version='3.6.1', kind='exe',
         url='https://www.sumatrapdfreader.org/dl/rel/3.6.1/SumatraPDF-3.6.1-64-install.exe',
         page='https://www.sumatrapdfreader.org/download-free-pdf-viewer', release_date='2026-04-06',
         license='GPL-3.0; bundled component licenses also apply',
         license_url='https://github.com/sumatrapdfreader/sumatrapdf/blob/3.6.1rel/COPYING', purpose='pdf_reader_installer'),
    dict(name='sumatrapdf-x86', vendor='Krzysztof Kowalczyk', version='3.6.1', kind='exe',
         url='https://www.sumatrapdfreader.org/dl/rel/3.6.1/SumatraPDF-3.6.1-install.exe',
         page='https://www.sumatrapdfreader.org/download-free-pdf-viewer', release_date='2026-04-06',
         license='GPL-3.0; bundled component licenses also apply',
         license_url='https://github.com/sumatrapdfreader/sumatrapdf/blob/3.6.1rel/COPYING', purpose='pdf_reader_installer'),
    dict(name='curl-x64', vendor='curl project', version='8.23.0_1', kind='zip',
         url='https://curl.se/windows/dl-8.23.0_1/curl-8.23.0_1-win64-mingw.zip',
         page='https://curl.se/windows/', release_date='2026-10-14',
         expected_sha256='752ff19c45be64af5b5f8d5222dce64e0f7b03d740a7362a4055c220fa9637c6',
         license='curl license; bundled dependency licenses also apply',
         license_url='https://curl.se/docs/copyright.html', purpose='network_transfer_utility'),
    dict(name='notepadpp-x64', vendor='Notepad++ project', version='8.9.8.1', kind='zip',
         url='https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.9.8.1/npp.8.9.8.1.portable.x64.zip',
         page='https://github.com/notepad-plus-plus/notepad-plus-plus/releases/tag/v8.9.8.1', release_date='2026-09-24',
         expected_sha256='beddf5548e75c97930d1575ba1c7d113e6e2b33d0a200310e734ca08e225f414',
         license='GPL-3.0; bundled component licenses also apply',
         license_url='https://github.com/notepad-plus-plus/notepad-plus-plus/blob/v8.9.8.1/LICENSE', purpose='text_editor'),
]


def prior_manifest_index(paths, root):
    index, records = {}, []
    for path in sorted(set(paths)):
        raw = path.read_bytes()
        relative = path.relative_to(root).as_posix()
        records.append(dict(path=relative, sha256=hashlib.sha256(raw).hexdigest()))
        if path.suffix == '.json':
            rows = json.loads(raw)['samples']
        else:
            rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
        for row in rows:
            if row.get('sha256'):
                index.setdefault(row['sha256'], []).append(relative)
    return index, records


def package_members(package, kind, max_pe_bytes=16 * 1024**2):
    files, failures = [], []
    if kind == 'exe':
        entries = [(package.name, package.stat().st_size, package.read_bytes)]
        archive = None
    else:
        archive = zipfile.ZipFile(package)
        info = archive.infolist()
        if len(info) > 1000 or sum(entry.file_size for entry in info) > 256 * 1024**2:
            archive.close()
            raise ValueError('archive_expansion_budget')
        entries = [(entry.filename, entry.file_size, lambda e=entry: archive.read(e)) for entry in info
                   if PurePosixPath(entry.filename).suffix.lower() in {'.exe', '.dll', '.pyd', '.sys'}]
    try:
        for name, size, read in entries:
            if not 0 < size <= max_pe_bytes:
                failures.append(dict(member=name, reason='pe_size_limit', size_bytes=size))
                continue
            try:
                files.append((name, read()))
            except Exception as error:
                failures.append(dict(member=name, reason=type(error).__name__, detail=str(error)[:200]))
    finally:
        if archive:
            archive.close()
    return files, failures


def main():
    root = Path(__file__).resolve().parents[1]
    output = root / 'artifacts/official-multivendor-pe-20261017-r4'
    if output.exists():
        raise SystemExit('Frozen acquisition already exists; refusing overwrite or silent retry')
    (output / 'samples').mkdir(parents=True)
    paths = list((root / 'docs/benchmarks').glob('*.jsonl'))
    paths += list((root / 'artifacts').glob('official*/manifest.jsonl'))
    paths += list((root / 'docs/benchmarks').glob('user_archive_label_reference*.json'))
    prior, prior_sources = prior_manifest_index(paths, root)
    rows, packages, errors, seen = [], [], [], set()
    acquired = datetime.now(timezone.utc).isoformat()
    downloaded = 0
    for source in SOURCES:
        package = output / (source['name'] + '.' + source['kind'])
        started = time.monotonic()
        try:
            request = urllib.request.Request(source['url'], headers={'User-Agent': 'AegisAV-benign-corpus-research/1.0'})
            with urllib.request.urlopen(request, timeout=60) as response, package.open('xb') as target:
                headers = {key: response.headers.get(key) for key in ('Content-Length', 'Last-Modified', 'ETag')}
                total = 0
                while chunk := response.read(65536):
                    total += len(chunk)
                    downloaded += len(chunk)
                    if total > 32 * 1024**2 or downloaded > 100 * 1024**2 or time.monotonic() - started > 120:
                        raise ValueError('download_size_or_walltime_budget')
                    target.write(chunk)
            if headers['Content-Length'] and total != int(headers['Content-Length']):
                raise ValueError('incomplete_package')
            digest = hashlib.sha256(package.read_bytes()).hexdigest()
            if source.get('expected_sha256') and digest != source['expected_sha256']:
                raise ValueError('published_package_sha256_mismatch')
            packages.append(dict(**source, bytes=total, sha256=digest, headers=headers,
                                 published_checksum_verified=bool(source.get('expected_sha256'))))
            members, failures = package_members(package, source['kind'])
            errors.extend(dict(package=source['name'], **failure) for failure in failures)
            for member, data in members:
                sha = hashlib.sha256(data).hexdigest()
                if sha in seen:
                    errors.append(dict(package=source['name'], member=member, reason='duplicate_current_cohort', sha256=sha))
                    continue
                try:
                    metadata = pe_metadata(data)
                except Exception as error:
                    errors.append(dict(package=source['name'], member=member, reason='invalid_pe', detail=str(error)[:200]))
                    continue
                seen.add(sha)
                target = output / 'samples' / (sha + PurePosixPath(member).suffix.lower())
                with target.open('xb') as stream:
                    stream.write(data)
                rows.append(dict(sha256=sha, size_bytes=len(data), source_path=str(target), path='samples/' + target.name,
                    source_url=source['url'], source_page=source['page'], vendor=source['vendor'],
                    product_version=source['version'], purpose=source['purpose'], original_member=member,
                    package_sha256=digest, package_release_date=source['release_date'], acquired_utc=acquired,
                    first_seen_utc=None, license=source['license'], license_url=source['license_url'],
                    published_package_checksum_verified=bool(source.get('expected_sha256')),
                    pe_scope=pe_scope(data), prior_exact_overlap=sha in prior, prior_overlap_manifests=prior.get(sha, []),
                    detector_results_observed=False, dataset_role='unscored_official_candidate',
                    label='presumed_benign', label_basis='Unmodified PE from pinned publisher HTTPS release; not independent proof of benignness',
                    **metadata))
            print(json.dumps(dict(package=source['name'], bytes=total, pe_candidates=len(members)), ensure_ascii=False), flush=True)
        except Exception as error:
            errors.append(dict(package=source['name'], reason=type(error).__name__, detail=str(error)[:240],
                               partial_bytes=package.stat().st_size if package.exists() else 0))
            print(json.dumps(errors[-1]), flush=True)
    signed = []
    shell = shutil.which('pwsh') or shutil.which('powershell')
    for offset in range(0, len(rows), 16):
        try:
            signed.extend(inspect_signatures(shell, rows[offset:offset + 16]))
        except Exception as error:
            errors.append(dict(stage='signature_inspection', reason=type(error).__name__, detail=str(error)[:240]))
            signed.extend(dict(**row, signature_status='InspectionError') for row in rows[offset:offset + 16])
    manifest = output / 'manifest.jsonl'
    manifest.write_text(''.join(json.dumps(row) + '\n' for row in signed), encoding='utf-8')
    result = dict(schema=1, started_utc=acquired, completed_utc=datetime.now(timezone.utc).isoformat(),
        packages=packages, files=len(signed), failures=errors, downloaded_bytes=downloaded,
        unique_vendors=sorted({row['vendor'] for row in signed}), prior_manifest_sources=prior_sources,
        prior_exact_overlap=sum(row['prior_exact_overlap'] for row in signed),
        valid_signatures=sum(row['signature_status'] == 'Valid' for row in signed),
        raw_malware_used=False, candidate_execution=False, detector_results_observed=False,
        manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),
        collector_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    (output / 'acquisition.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({key: result[key] for key in ('files', 'unique_vendors', 'prior_exact_overlap', 'valid_signatures', 'downloaded_bytes', 'manifest_sha256')}))


if __name__ == '__main__':
    main()
