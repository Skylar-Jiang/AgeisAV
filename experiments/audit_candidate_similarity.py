"""Hash-only duplicate audit of official benign candidates; no detector database or model lookup."""

import hashlib
import json
from pathlib import Path
import ppdeep
import tlsh

from aegisav.hashes import compute_fuzzy
from experiments.independent_cohort import plan_cohort


def main():
    root = Path(__file__).resolve().parents[1]
    base = root / 'docs/benchmarks'
    manifest = base / 'official_benign_candidates_manifest_20261012.jsonl'
    rows = [json.loads(line) for line in manifest.read_text().splitlines()]
    prior = {}
    sources = [base / name for name in ('benign_windows_static_20261010.json', 'benign_vendor_static_20261011.json',
                                       'benign_expansion_static_20261010.json', 'user_archive_static_20261010.json')]
    for path in sources:
        for row in json.loads(path.read_text())['files']:
            hashes = row.get('engines', {}).get('fuzzy', {}).get('hashes')
            if hashes:
                prior[row['sha256']] = hashes
    current = {}
    for row in rows:
        data = (root / 'artifacts/official_benign_candidates_20261012' / row['path']).read_bytes()
        assert hashlib.sha256(data).hexdigest() == row['sha256']
        current[row['sha256']] = compute_fuzzy(data)
    edges = []
    pairs = 0
    def compare(left, right, a, b):
        nonlocal pairs
        pairs += 1
        if a['tlsh'] and b['tlsh']:
            distance = tlsh.diff(a['tlsh'], b['tlsh'])
            if distance <= 40:
                edges.append(dict(a=left, b=right, method='tlsh', value=distance))
        if a['ssdeep'] and b['ssdeep']:
            score = ppdeep.compare(a['ssdeep'], b['ssdeep'])
            if score >= 80:
                edges.append(dict(a=left, b=right, method='ssdeep', value=score))
    for index, (left, a) in enumerate(current.items()):
        for right, b in list(current.items())[:index]:
            compare(left, right, a, b)
        for right, b in prior.items():
            compare(left, right, a, b)
    result = dict(schema=1, detector_evaluation_performed=False, strict_final_test=False,
                  candidate_count=len(current), prior_hash_count=len(prior), pairs_compared=pairs,
                  tls_h_max_distance=40, ssdeep_min_similarity=80,
                  limits='Fixed near-duplicate screening thresholds, not proof of semantic independence; full training fuzzy metadata unavailable',
                  fingerprints=current, edges=edges,
                  candidate_to_prior_near_count=len({edge['a'] for edge in edges if edge['b'] in prior}),
                  metadata_gate=plan_cohort(rows, set(prior), [(edge['a'], edge['b']) for edge in edges],
                                            '2025-01-01T00:00:00Z', '2026-01-01T00:00:00Z'),
                  input_sha256={str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
                                for path in [manifest, *sources]})
    (base / 'official_benign_candidate_similarity_20261012.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: result[key] for key in ('candidate_count', 'pairs_compared', 'candidate_to_prior_near_count')}))


if __name__ == '__main__':
    main()
