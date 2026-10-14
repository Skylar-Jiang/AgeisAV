"""Candidate SHA membership only; never loads training/test vectors or predictions."""

import hashlib
import json
from pathlib import Path
import numpy as np


def main():
    root = Path(__file__).resolve().parents[1]
    manifest = root / 'docs/benchmarks/official_benign_candidates_manifest_20261012.jsonl'
    candidates = {json.loads(line)['sha256'] for line in manifest.read_text().splitlines()}
    matches, sources = {}, {}
    for split in ('fit', 'validation', 'test'):
        path = root / 'artifacts/ember2024/vectors' / ('meta_' + split + '.npz')
        with np.load(path, allow_pickle=False) as archive:
            identifiers = archive['sha']
            sha = {value.decode() if isinstance(value, bytes) else str(value) for value in identifiers}
            matches[split] = sorted(candidates & sha)
            sources[split] = dict(rows=len(identifiers), sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    output = dict(schema=1, candidate_count=len(candidates), matches=matches, sources=sources,
                  manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),
                  vectors_or_scores_read=False, author_training_membership_verified=False,
                  scope='Local EMBER2024 Win64 fit/validation/test SHA only; full Win32/.NET model training audit still required')
    (root / 'docs/benchmarks/official_benign_candidate_training_20261012.json').write_text(json.dumps(output, indent=2) + '\n')
    print(json.dumps({split: len(values) for split, values in matches.items()}))


if __name__ == '__main__':
    main()
