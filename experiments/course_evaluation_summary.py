"""Reaggregate completed historical reports; never open PE or feature/prediction arrays."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENGINES = ('sha256', 'fuzzy', 'yara_x', 'clamav', 'lightgbm')
R7 = Path('artifacts/stage-e-r7-20261019')


def read_json(path):
    return json.loads(path.read_text(encoding='utf-8'))


def deduplicate(reports):
    unique, duplicate_rows = {}, 0
    for report in reports:
        for row in report['files']:
            identity = row['sha256']
            if identity in unique:
                if unique[identity] != row:
                    raise ValueError('Conflicting historical rows for the same SHA256')
                duplicate_rows += 1
            else:
                unique[identity] = row
    return list(unique.values()), duplicate_rows


def quantiles(values):
    values = sorted(values)
    def linear(q):
        position = (len(values) - 1) * q
        lower = int(position)
        upper = min(lower + 1, len(values) - 1)
        return values[lower] + (values[upper] - values[lower]) * (position - lower)
    return {'n': len(values), 'p50_ms': linear(.5), 'p95_ms': linear(.95)} if values else {'n': 0}


def engine_status(row, engine):
    return row.get('report', {}).get('engines', {}).get(engine, {}).get('status', 'not_recorded')


def signal_state(row, strategy):
    if strategy in ENGINES:
        return engine_status(row, strategy)
    if strategy == 'routed_or_alert':
        statuses = [engine_status(row, e) for e in ENGINES if e != 'lightgbm'] + [
            row.get('shadow', {}).get('status', 'not_recorded')]
        return 'matched' if 'matched' in statuses else (
            'no_match' if all(x == 'no_match' for x in statuses) else 'abstain')
    verdict = row.get('report', {}).get('verdict')
    if verdict not in ('malicious', 'suspicious', 'undetermined', 'clean'):
        return 'abstain'
    if verdict in ('undetermined', 'clean') and any(engine_status(row, e) not in
            ('matched', 'no_match') for e in ENGINES):
        return 'abstain'
    if strategy == 'general_malicious_only':
        return 'matched' if verdict == 'malicious' else 'no_match'
    return 'matched' if verdict in ('suspicious', 'malicious') else 'no_match'


def descriptive_metrics(rows, strategy):
    counts = Counter()
    for row in rows:
        label, state = row['evaluation_label'], signal_state(row, strategy)
        if label == 'unknown':
            counts['unknown_excluded'] += 1
        elif state not in ('matched', 'no_match'):
            counts['labelled_abstained'] += 1
        else:
            counts[('tp' if state == 'matched' else 'fn') if label == 'malicious_operational_proxy'
                   else ('fp' if state == 'matched' else 'tn')] += 1
    tp, fp, tn, fn = (counts[x] for x in ('tp', 'fp', 'tn', 'fn'))
    return {**{key: counts[key] for key in ('tp', 'fp', 'tn', 'fn', 'unknown_excluded', 'labelled_abstained')},
            'recall_descriptive': tp / (tp + fn) if tp + fn else None,
            'fpr_descriptive': fp / (fp + tn) if fp + tn else None,
            'precision_descriptive': tp / (tp + fp) if tp + fp else None,
            'f1_descriptive': 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None,
            'interpretation': 'Operational/proxy labels, completed decisions only; unknown excluded. '
                              'No independent accuracy or deployment estimate; no-alert is not a clean verdict.'}


def summarize(rows):
    result = {'files': len(rows), 'evaluation_labels': dict(Counter(r['evaluation_label'] for r in rows)),
              'verdict_counts': dict(Counter(r.get('report', {}).get('verdict', 'not_recorded') for r in rows)),
              'file_statuses': dict(Counter(r['status'] for r in rows)), 'engines': {}}
    for engine in ENGINES:
        statuses = Counter(engine_status(row, engine) for row in rows)
        result['engines'][engine] = {
            'status_counts': dict(statuses), 'positive_signals': statuses['matched'],
            'abstained_or_missing': sum(n for state, n in statuses.items() if state not in ('matched', 'no_match')),
            'latency': quantiles([r['report']['engines'][engine]['elapsed_ms'] for r in rows
                                 if engine in r.get('report', {}).get('engines', {})
                                 and 'elapsed_ms' in r['report']['engines'][engine]]),
            'versions': sorted({str(r['report']['engines'][engine].get('engine_version')) + ' / ' +
                                str(r['report']['engines'][engine].get('artifact_version')) for r in rows
                                if engine in r.get('report', {}).get('engines', {})}),
            'descriptive_operational_metrics': descriptive_metrics(rows, engine)}
    for strategy in ('general_or_alert', 'general_malicious_only', 'routed_or_alert'):
        result[strategy] = {'status_counts': dict(Counter(signal_state(r, strategy) for r in rows)),
                            'descriptive_operational_metrics': descriptive_metrics(rows, strategy)}
    result['research_pair_latency'] = quantiles([r['elapsed_ms'] for r in rows if 'elapsed_ms' in r])
    return result


def self_check():
    row = {'sha256': 'synthetic', 'status': 'completed', 'evaluation_label': 'malicious_operational_proxy',
           'report': {'verdict': 'suspicious', 'engines': {'lightgbm': {'status': 'matched'}}}}
    rows, duplicates = deduplicate([{'files': [row]}, {'files': [dict(row)]}])
    assert len(rows) == 1 and duplicates == 1
    try:
        deduplicate([{'files': [row, {**row, 'status': 'error'}]}])
    except ValueError:
        pass
    else:
        raise AssertionError('Conflicting repeated observations must not be pooled')
    assert descriptive_metrics(rows, 'lightgbm')['tp'] == 1
    assert descriptive_metrics(rows, 'clamav')['labelled_abstained'] == 1
    assert descriptive_metrics([{**row, 'evaluation_label': 'unknown'}], 'lightgbm')['tp'] == 0
    assert signal_state(row, 'general_or_alert') == 'matched'
    assert signal_state(row, 'general_malicious_only') == 'no_match'
    assert signal_state({**row, 'report': {'verdict': 'undetermined', 'engines': {}}},
                        'general_or_alert') == 'abstain'
    assert quantiles([0, 10])['p95_ms'] == 9.5
    print('Self-check passed: duplicate/conflict, missing-as-abstention, unknown exclusion, fusion semantics, quantiles')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-check', action='store_true')
    args = parser.parse_args()
    if args.self_check:
        self_check()
        return
    paths = [R7 / name for name in ('guest-paired.json', 'guest-r4-paired.json', 'compact-label-review.json',
                                   'evaluation-policy-v1.json', 'observation-ledger.json', 'paired-summary.json')]
    paths += [Path('docs/benchmarks') / name for name in ('stage_e6_summary_20261018.json',
        'stage_e7_summary_20261019.json', 'benign_five_engine_summary_20261011.json',
        'collection_summary_20261013.json', 'collection_expansion_summary_20261014.json',
        'user_archive_summary_relabelled_20261010.json')]
    paths += [Path('artifacts/ember2024/dataset_provenance.json')]
    data = [read_json(ROOT / path) for path in paths]
    main_report, supplement, reviews, policy, ledger, old, r6, r7, benign, pilot, expansion, archive, provenance = data
    rows, duplicate_rows = deduplicate([main_report, supplement])
    protected = set(policy['protected_sha256'])
    if protected.intersection(r['sha256'] for r in rows):
        raise ValueError('Historical scored cohort intersects protected identities')
    observed = {r['sha256'] for r in ledger['files'] if r['observed'] and r['dataset_role'] == 'observed_development'}
    if {r['sha256'] for r in rows} != observed or len(rows) != 298:
        raise ValueError('Historical paired rows do not match the observation ledger')
    grades = {r['sha256']: r['admission']['grade'] for r in reviews['malicious']}
    for row in rows:
        row['evaluation_label'] = ('presumed_benign_operational' if row['label'] == 'presumed_benign_operational'
            else 'malicious_operational_proxy' if row['label'] == 'technical_case_operational'
            or grades.get(row['sha256']) == 'high-confidence' else 'unknown')
        row['pe_scope'] = row['report']['engines']['lightgbm'].get('pe_scope', 'not_recorded')
    groups = {'presumed_benign': [r for r in rows if r['evaluation_label'] == 'presumed_benign_operational'],
              'technical_proxy_including_unknown': [r for r in rows if r['label'] != 'presumed_benign_operational']}
    summary = summarize(rows)
    for name, old_name in (('presumed_benign', 'benign'), ('technical_proxy_including_unknown', 'technical_proxy_cases')):
        actual = summarize(groups[name])
        expected = old[old_name]
        if actual['files'] != expected['files'] or any(actual['engines'][e]['positive_signals'] !=
                expected['engines'][e]['positive_signals'] for e in ENGINES):
            raise ValueError('Historical aggregate did not reproduce')
        if actual['general_or_alert']['status_counts'].get('matched', 0) != expected['general_or_positive_signals']:
            raise ValueError('Historical fusion aggregate did not reproduce')
    strata = {}
    for dimension in ('source_group', 'category', 'evaluation_label', 'pe_scope'):
        strata[dimension] = {value: summarize([r for r in rows if r.get(dimension, 'unknown') == value])
                             for value in sorted({r.get(dimension, 'unknown') for r in rows})}
    feature_roles = {}
    for split in ('fit', 'validation'):
        weeks = [w for w in provenance['weeks'] if provenance['week_mapping'][str(w['week'])] == split]
        feature_roles[split] = {'rows': sum(w['rows'] for w in weeks), 'benign': sum(w['benign'] for w in weeks),
                               'malicious': sum(w['malicious'] for w in weeks), 'weeks': len(weeks),
                               'raw_PE_end_to_end_scans': False, 'independent_confirmation': False}
    clean_legacy = lambda group: {'files': group['sample_count'],
        'engine_statuses': {e: v['status_counts'] for e, v in group['engines'].items()},
        'engine_positives': {e: v['matched_count'] for e, v in group['engines'].items()},
        'fusion_statuses': group['fusion']['status_counts'], 'latency_ms': group['latency_ms'],
        'engine_artifacts': group.get('engine_artifacts', {})}
    result = {'schema': 1, 'date': '2026-10-22', 'kind': 'historical_reaggregation_no_new_scans',
        'independent_accuracy_claim': False, 'raw_PE_read': False, 'feature_or_prediction_arrays_read': False,
        'teacher_target_raw_PE_per_class': 100000, 'strict_independent_admitted_per_class': {'malicious': 0, 'benign': 0},
        'strict_target_gap_per_class': {'malicious': 100000, 'benign': 100000},
        'feature_data_roles': feature_roles,
        'historical_test_inventory': {'reported_rows': r7['independence']['local_test_rows'],
            'role': 'previously observed historical final; protected against further candidate selection',
            'arrays_read_this_run': False, 'new_final_test': False},
        'r7_paired': {'summary': summary, 'strata': strata, 'main_rows': len(main_report['files']),
            'supplement_rows': len(supplement['files']), 'duplicate_rows_excluded': duplicate_rows,
            'prior_r4_r5_r6_not_added_again': True, 'strict_validation_admitted': 0, 'formal_final_admitted': 0,
            'operational_label_rule': '286 publisher-provenance controls;7old technical cases plus3new automated '
                'high-confidence technical cases counted as operational/proxy malicious;2family-disputed cases unknown',
            'resources': {'main': main_report['resources'], 'supplement': supplement['resources'],
                'separate_clamd_peak_bytes': r7['closeout']['clamd_peak_bytes'],
                'main_wall_ms': main_report['wall_ms_this_run'], 'supplement_wall_ms': supplement['wall_ms_this_run'],
                'throughput_files_per_second': len(rows) * 1000 /
                    (main_report['wall_ms_this_run'] + supplement['wall_ms_this_run'])},
            'caveat': 'ClamAV healthy historical Linux era, frozen versions recorded per engine. General stored verdicts '
                'and reconstructed routed OR signals are distinct. Pair latency includes both ML profiles; '
                'not current product HTTP latency. Separate memory maxima must not be summed.'},
        'unobserved_role_inventory': {'explicitly_protected_policy_identities': len(protected),
            'r6_reserved': r6['admission']['pending_validation_files'],
            'r6_sealed_source_held_candidates': r6['admission']['sealed_final_candidates'],
            'r5_quarantine': r6['admission']['protected_r5_quarantine_unchanged'],
            'r6_unscored_observed_source_release_siblings': r6['admission']['development_source_release_files'],
            'r7_new_controls': r7['benign_growth']['new_raw_pe'],
            'r7_source_candidates_subset_of_new37': r7['benign_growth']['unscored_source_candidates'],
            'r7_development_source_component_subset_of_new37': r7['benign_growth']['development_source_component_files_unscored'],
            'strict_admitted': 0, 'scored_this_run': 0,
            'caveat': 'Role counts from historical audited metadata; not a newly verified final cohort. '
                      'Untouched does not establish labels, independence, source diversity or scoring authorization.'},
        'legacy_panels_not_pooled': {
            'presumed_benign_observed1500': clean_legacy(benign['all_observed']),
            'reported_training_disjoint_subset1450': clean_legacy(benign['general_pe_training_control']['reported_training_disjoint']),
            'known_reported_generic_training_overlaps': benign['general_pe_training_control']['known_training_overlap_count'],
            'known_local_fit_validation_overlaps': benign['known_win64_fit_validation_overlap_count'],
            'pilot_and_expansion_frozen_release': {'pilot': pilot['identity']['release'],
                                                   'expansion': expansion['identity']['release']},
            'source_unknown_pilot': {k: pilot[k] for k in ('dataset_role', 'attempts', 'status_counts', 'engines', 'policies', 'costs', 'timing_limitations')},
            'source_unknown_expansion': {k: expansion[k] for k in ('dataset_role', 'attempts', 'status_counts', 'engines', 'policies', 'costs', 'timing_limitations')},
            'user_archive_proxy': {k: archive[k] for k in ('method', 'formal_acceptance', 'limitations', 'unique_valid_pe', 'pe_label_counts', 'proxy_engines')},
            'caveat': 'Overlapping/subset and different-era panels; never sum their sample counts or pool confusion matrices.'},
        'prospective_final_design': ['Lock detector/model/threshold/rule/reference/fusion versions before new scores.',
            'Reserve source/project/release groups and malicious family/source components disjoint from FIT and development.',
            'Document raw integrity, authorized provenance and independent label adjudication; disputed labels remain unknown.',
            'Audit exact and available near-duplicate links plus training membership residuals before admission.',
            'Use fresh admitted validation for any selection; freeze final manifest and scoring plan before final execution.',
            'Report engine/fusion alert and malicious-only counts, coverage/errors, fixed-threshold confusion and family/source strata.',
            'Keep malware in the existing isolated Ubuntu VM; any new raw final scoring requires root admission/authorization audit.'],
        'input_sha256': {str(path): hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in paths},
        'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    output = ROOT / 'docs/benchmarks/course_evaluation_20261022.json'
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print('WROTE', output)
    print('R7', summary['files'], summary['evaluation_labels'])
    print('General alert', summary['general_or_alert']['descriptive_operational_metrics'])
    print('Malicious only', summary['general_malicious_only']['descriptive_operational_metrics'])


if __name__ == '__main__':
    main()
