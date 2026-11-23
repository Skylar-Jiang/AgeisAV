"""Audit overlap with official PE training features; never acquire raw executable files."""

from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import zipfile

import orjson

from experiments import ember_download

ROOT = Path(__file__).resolve().parents[1]
FILES = {
    'Dot_Net_train.zip': (937108923, 'b9f6e90ab75293a7ceb9339700586dd033a03d19766282755ee31dfa0836e625'),
    'Win32_train.zip': (12321281336, '6cf9dea847960115f65d405d38b6b09d38c87225c8288dafedf00fed2512b1d4'),
}


def main():
    cohorts = {'archive': {row['sha256'] for row in json.loads((ROOT / 'docs/benchmarks/user_archive_static_20261010.json').read_text())['files']}}
    for name in ('windows', 'vendor', 'expansion'):
        manifest = 'benign_expansion_manifest_20261010.jsonl' if name == 'expansion' else 'benign_' + name + '_pe_manifest.jsonl'
        cohorts[name] = {json.loads(line)['sha256'] for line in (ROOT / 'docs/benchmarks' / manifest).read_text().splitlines()}
    targets = set().union(*cohorts.values())
    found = {sha: [] for sha in targets}
    provenance = json.loads((ROOT / 'artifacts/ember2024/dataset_provenance.json').read_text())
    for manifest, splits in provenance['installed_pe_overlaps'].items():
        for split in ('fit', 'validation'):
            for sha in splits[split]:
                found[sha].append({'platform': 'Win64', 'local_split': split})
    stats = []
    temporary_root = Path(os.environ['LOCALAPPDATA']) / 'Temp'
    if shutil.disk_usage(temporary_root).free < max(size for size, digest in FILES.values()) + 10 * 1024**3:
        raise ValueError('Insufficient temporary space; no VM files changed')
    # Only feature JSON ZIPs are written here. No PE samples, extraction or execution.
    for filename, (size, digest) in FILES.items():
        with tempfile.TemporaryDirectory(prefix='aegisav-feature-audit-', dir=temporary_root) as temporary:
            if Path(temporary).resolve().parent != temporary_root.resolve():
                raise ValueError('Temporary cleanup target outside intended user Temp directory')
            ember_download.ROOT = Path(temporary)
            ember_download.download(filename, size, digest)
            source = Path(temporary) / 'downloads' / filename
            unique, rows, repeats = set(), 0, 0
            with zipfile.ZipFile(source) as archive:
                names = sorted(archive.namelist())
                if len(names) != 52 or any(Path(name).name != name or not name.endswith('_' + filename.replace('.zip', '.jsonl')) for name in names):
                    raise ValueError('Unexpected pinned training feature members')
                for name in names:
                    with archive.open(name) as stream:
                        for line in stream:
                            row = orjson.loads(line)
                            sha = row['sha256']
                            if row['label'] not in (0, 1) or not 0 <= row['week_id'] < 52:
                                raise ValueError('Unexpected training label/week')
                            rows += 1
                            if sha in unique:
                                repeats += 1
                                continue
                            unique.add(sha)
                            if sha in targets:
                                found[sha].append({key: row[key] for key in ('file_type', 'week_id', 'label', 'first_submission_date', 'family')})
                    print('AUDITED', name, flush=True)
            stats.append({'file': filename, 'sha256': digest, 'size': size,
                          'serialized_rows': rows, 'unique_sha': len(unique), 'repeats': repeats,
                          'temporary_feature_archive_removed': True})
            del unique
    result = {'dataset_revision': ember_download.REVISION, 'scope': 'All official Win32, Win64 and Dot_Net training SHA membership',
              'official_model_training_membership_assumption': 'Official PE model uses the official first-52-week PE training splits; no independent author training manifest supplied',
              'raw_executables_acquired': False, 'temporary_feature_storage': 'Windows user Temp; removed after audit',
              'additional_sources': stats, 'win64_provenance_sha256': hashlib.sha256((ROOT / 'artifacts/ember2024/dataset_provenance.json').read_bytes()).hexdigest(),
              'cohort_overlap': {name: {'cohort_size': len(shas), 'overlap_count': sum(bool(found[sha]) for sha in shas),
                                      'matches': {sha: found[sha] for sha in sorted(shas) if found[sha]}}
                                 for name, shas in cohorts.items()}}
    output = ROOT / 'docs/benchmarks/general_pe_training_overlap_20261010.json'
    output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print('COMPLETED', {name: group['overlap_count'] for name, group in result['cohort_overlap'].items()}, flush=True)


if __name__ == '__main__':
    main()
