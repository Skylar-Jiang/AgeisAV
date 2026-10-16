"""Aggregate frozen expansion evidence; no PE access, fitting or label promotion."""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
import math
from pathlib import Path

from experiments.compare_static_rounds import ENGINES, distribution, outcome
from experiments.fusion_replay import policies


def _unique(rows):
    indexed = {row['sha256']: row for row in rows}
    if len(indexed) != len(rows):
        raise ValueError('Duplicate SHA evidence; resolve journal separately')
    return indexed


def _decision(report, name):
    if report.get('engines', {}).get(name, {}).get('status') not in ('matched', 'no_match'):
        return None
    return outcome(report, name, None)


def _summary(rows):
    vectors = []
    for row in rows:
        scan = row.get('report') or {}
        vectors.append([_decision(scan, name) for name in ENGINES])
    counts = lambda values: dict(positive=sum(x is True for x in values),
                                 negative=sum(x is False for x in values),
                                 abstained=sum(x is None for x in values))
    replay = [policies(v[:4], v[4]) for v in vectors]
    exclusive = Counter(ENGINES[v.index(True)] for v in vectors
                        if sum(x is True for x in v) == 1 and all(x is not None for x in v))
    return dict(files=len(rows),
                engines={name: counts([v[i] for v in vectors]) for i, name in enumerate(ENGINES)},
                policies={name: counts([r[name] for r in replay])
                          for name in ('signature_or', 'ml_only', 'evidence_or', 'corroborated')},
                exclusive_positive=dict(exclusive),
                signatures_positive_ml_negative=sum(r['signature_or'] is True and r['ml_only'] is False for r in replay),
                latency_ms=distribution([r['elapsed_ms'] for r in rows if r['status'] == 'scanned']))


def analyze(state, manifest, acquisition):
    if state.get('completed') is not True or state.get('strict_final_test') is not False or state.get('dataset_role') != 'development_expansion':
        raise ValueError('Expected completed development expansion, never a final test')
    for key in ('manifest', 'release', 'release_manifest'):
        if not state['identity'].get(key) or state['identity'][key] != acquisition['identity'].get(key):
            raise ValueError('Acquisition and scan identity differ')
    candidates = _unique(manifest)
    eligible = {sha for sha, row in candidates.items() if row.get('download_eligible') is True}
    rows = _unique(state['files'])
    if rows.keys() != eligible or any(row.get('label') != 'unknown' for row in [*manifest, *rows.values()]):
        raise ValueError('Candidate disposition or unknown label provenance differs')
    scanned = {sha for sha, row in rows.items() if row['status'] == 'scanned'}
    versions = {name: set() for name in ENGINES}
    model_contracts = defaultdict(set)
    model_timing = {key: [] for key in ('inclusive', 'feature', 'inference', 'unattributed')}
    for sha, row in rows.items():
        report = row.get('report')
        if sha not in scanned:
            if report is not None or not row.get('reason'):
                raise ValueError('Unscanned row requires explicit reason and no report')
            continue
        if (not report or report.get('sha256') != sha or report.get('size_bytes') != row.get('size_bytes')
                or report.get('cached') is not False or not report.get('pe_scope')):
            raise ValueError('Raw identity, cache mode or PE scope mismatch')
        elapsed = row.get('elapsed_ms')
        if type(elapsed) not in (int, float) or not math.isfinite(elapsed) or elapsed < 0:
            raise ValueError('Invalid file cost')
        for name in ENGINES:
            engine = report['engines'].get(name, {})
            if not engine.get('engine_version') or not engine.get('artifact_version'):
                raise ValueError('Missing engine version')
            # Validates finite score, fixed threshold and score/status agreement.
            _decision(report, name)
            versions[name].add((engine['engine_version'], engine['artifact_version']))
            elapsed = engine.get('elapsed_ms')
            if type(elapsed) not in (int, float) or not math.isfinite(elapsed) or elapsed < 0:
                raise ValueError('Invalid engine cost')
        ml = report['engines']['lightgbm']
        if _decision(report, 'lightgbm') is not None:
            if any(not ml.get(key) for key in ('model_id', 'feature_schema', 'feature_implementation')):
                raise ValueError('Missing model contract')
            contract = tuple(ml[key] for key in ('engine_version', 'artifact_version', 'threshold', 'feature_schema', 'feature_implementation'))
            model_contracts[ml['model_id']].add(contract)
        if ml.get('feature_elapsed_ms') is not None and ml.get('inference_elapsed_ms') is not None:
            values = [ml['elapsed_ms'], ml['feature_elapsed_ms'], ml['inference_elapsed_ms']]
            if any(type(v) not in (int, float) or not math.isfinite(v) or v < 0 for v in values):
                raise ValueError('Invalid model component cost')
            for key, value in zip(model_timing, [*values, values[0]-values[1]-values[2]]):
                model_timing[key].append(value)
    if any(len(versions[name]) != 1 for name in ENGINES[:-1]) or any(len(v) != 1 for v in model_contracts.values()):
        raise ValueError('Mixed frozen engine/model versions')
    components = acquisition['components']
    members = [sha for component in components for sha in component['candidates']]
    if (any(not c['candidates'] for c in components) or len(members) != len(set(members))
            or set(members) != scanned or acquisition['strict_valid_pe'] != len(scanned)):
        raise ValueError('Near-duplicate coverage differs from scanned PE set')
    linked = {sha for component in components if component['previously_observed_peers'] for sha in component['candidates']}
    groupings = {key: defaultdict(list) for key in ('pe_scope', 'reported_family', 'source_first_seen_day', 'size_band')}
    for sha in sorted(scanned):
        row, metadata = rows[sha], candidates[sha]
        size = row['size_bytes']
        values = dict(pe_scope=row['report']['pe_scope'], reported_family=metadata.get('reported_signature') or 'unreported',
                      source_first_seen_day=(metadata.get('first_seen_utc') or 'unknown')[:10],
                      size_band='<1MiB' if size < 1024**2 else '1-4MiB' if size < 4*1024**2 else '>=4MiB')
        for key, value in values.items():
            groupings[key][value].append(row)
    cluster_patterns = Counter()
    for component in components:
        values = [_summary([rows[sha]])['policies']['evidence_or'] for sha in component['candidates']]
        pattern = 'all_positive' if all(v['positive'] for v in values) else (
            'all_negative' if all(v['negative'] for v in values) else 'mixed_or_abstained')
        cluster_patterns[pattern] += 1
    return dict(schema=1, method='frozen_saved_expansion_stratification', strict_final_test=False,
        thresholds_changed=False, policy_selection_performed=False, labels_changed=False,
        release=state['identity']['release'], accuracy_metrics=None, fixed_low_fpr_recall=None,
        counts=dict(candidates=len(rows), scanned_pe=len(scanned), unscanned=len(rows)-len(scanned),
                    independently_trusted_labels=0, independent_final_eligible=0),
        file_status_counts=dict(Counter(row['status'] for row in rows.values())),
        failure_reasons=dict(Counter(row['reason'] for row in rows.values() if row['status'] != 'scanned')),
        paired=_summary(list(rows.values())),
        strata={key: {value: _summary(group) for value, group in sorted(groups.items())} for key, groups in groupings.items()},
        near_duplicates=dict(screening_components=len(components), scanned_files=len(scanned),
            component_size_counts=dict(Counter(len(c['candidates']) for c in components)),
            previously_observed_linked_components=sum(bool(c['previously_observed_peers']) for c in components),
            previously_observed_linked_files=len(linked), evidence_or_component_patterns=dict(cluster_patterns),
            tlsh_max_distance=acquisition['tlsh_max_distance'], ssdeep_min_similarity=acquisition['ssdeep_min_similarity']),
        without_previous_links=_summary([row for sha, row in rows.items() if sha not in linked]),
        engine_versions={name: [list(v) for v in sorted(values)] for name, values in versions.items()},
        engine_latency_ms={name: distribution([rows[sha]['report']['engines'][name]['elapsed_ms'] for sha in scanned]) for name in ENGINES},
        model_timing_ms={key: distribution(values) for key, values in model_timing.items()},
        limitations=['All labels unknown: positive signals are not Recall; no FPR, Precision, F1 or low-FPR Recall.',
            'Source-reported family/date are not verified family/global first-seen.',
            'Components are a fixed single-link screen, not certified independent observations or confidence-interval units.',
            'Excluding prior links is post hoc sensitivity analysis, not creation of a final test set.',
            'Cold-cache historical per-file workers; overlapping engine timers cannot be summed or compared to new task guards.',
            'ML unattributed time includes integrity checks, scope parsing, imports, model loading, transport and shutdown; not a measured reusable-worker speedup.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('scan', 'manifest', 'acquisition', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    raw = {name: getattr(args, name).read_bytes() for name in ('scan', 'manifest', 'acquisition')}
    scan, acquisition = (json.loads(raw[name]) for name in ('scan', 'acquisition'))
    manifest_hash = hashlib.sha256(raw['manifest']).hexdigest()
    if scan['identity'].get('manifest') != manifest_hash or acquisition['identity'].get('manifest') != manifest_hash:
        raise ValueError('Manifest bytes differ from acquisition/scan provenance')
    result = analyze(scan, json.loads(raw['manifest']), acquisition)
    result['input_sha256'] = {name: hashlib.sha256(data).hexdigest() for name, data in raw.items()}
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(counts=result['counts'], near_duplicates=result['near_duplicates'])))


if __name__ == '__main__':
    main()
