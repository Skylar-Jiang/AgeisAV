"""Post-hoc coverage audit of public family metadata; never a family-disjoint test claim."""

from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import zipfile

import numpy as np
import orjson

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / 'artifacts/ember2024'


def main():
    provenance = json.loads((ART / 'dataset_provenance.json').read_text())
    mapping = {int(k): v for k, v in provenance['week_mapping'].items()}
    predictions = np.load(ART / 'local_predictions.npz')['test_scores']
    test = np.load(ART / 'vectors/meta_test.npz')
    test_scores = dict(zip((sha.decode() for sha in test['sha']), predictions.tolist()))
    families = {split: Counter() for split in ('fit', 'validation', 'test')}
    labels = {split: Counter() for split in families}
    no_family = Counter()
    seen, duplicated, family_conflicts = {}, Counter(), 0
    hits = defaultdict(Counter)
    for subset in ('train', 'test'):
        with zipfile.ZipFile(ART / 'downloads' / ('Win64_' + subset + '.zip')) as archive:
            for name in sorted(archive.namelist()):
                with archive.open(name) as source:
                    for line in source:
                        row = orjson.loads(line)
                        split, sha = mapping[row['week_id']], row['sha256']
                        family = row['family']
                        if family is not None and not isinstance(family, str):
                            raise ValueError('Unexpected family metadata type')
                        identity = (split, row['label'], family, row['family_confidence'])
                        if sha in seen:
                            if seen[sha] != identity:
                                family_conflicts += 1
                                raise ValueError('Duplicate family metadata conflict')
                            duplicated[split] += 1
                            continue
                        seen[sha] = identity
                        labels[split][str(row['label'])] += 1
                        if row['label'] == 1:
                            if family:
                                families[split][family] += 1
                            else:
                                no_family[split] += 1
                            if split == 'test':
                                if sha not in test_scores:
                                    raise ValueError('Test score identity missing')
                                hits[family or '<unassigned>']['n'] += 1
                                hits[family or '<unassigned>']['tp_at_fixed_0.5'] += test_scores[sha] >= .5
                print(name, flush=True)
    if {s: sum(c.values()) for s, c in labels.items()} != {'fit': 480000, 'validation': 40000, 'test': 119993}:
        raise ValueError('Family audit cohort differs from fitted model')
    unseen = sorted(set(families['test']) - set(families['fit']))
    result = {'scope': 'Full unique Win64 features; post-hoc family coverage/error analysis only',
              'family_labels': 'Upstream ClarAVy derived tags; not independently verified family truth',
              'family_disjoint_split': False, 'threshold': .5, 'threshold_tuning': False,
              'row_counts_by_label': labels, 'serialized_duplicates_excluded': duplicated,
              'family_metadata_conflicts': family_conflicts,
              'malicious_unassigned_family': no_family,
              'malicious_family_counts': families,
              'test_family_labels_absent_in_fit': unseen,
              'test_samples_with_family_absent_in_fit': sum(families['test'][f] for f in unseen),
              'test_family_fixed_threshold_outcomes': hits,
              'input_sha256': {name: hashlib.sha256((ART / name).read_bytes()).hexdigest() for name in
                               ('dataset_provenance.json', 'local_predictions.npz', 'vectors/meta_test.npz')}}
    output = ROOT / 'docs/benchmarks/ember2024_family_audit_20261010.json'
    output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print('COMPLETED', output, {s: len(c) for s, c in families.items()}, flush=True)


if __name__ == '__main__':
    main()
