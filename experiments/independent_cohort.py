"""Metadata-only time/label/leakage gate; never reads PE bytes, scores, or chooses thresholds."""

from collections import Counter
from datetime import datetime
import re


def plan_cohort(rows, blocked_sha, near_pairs, validation_start, final_start):
    validation_time, final_time = [datetime.fromisoformat(value.replace('Z', '+00:00'))
                                  for value in (validation_start, final_start)]
    if not validation_time.tzinfo or not final_time.tzinfo or validation_time >= final_time:
        raise ValueError('Strict timezone-aware chronological boundary required')
    by_sha = {row['sha256']: row for row in rows}
    if len(by_sha) != len(rows) or any(not re.fullmatch('[a-f0-9]{64}', sha) for sha in by_sha):
        raise ValueError('Invalid or duplicate candidate SHA')
    parent = {sha: sha for sha in by_sha.keys() | set(blocked_sha)}
    def find(sha):
        while parent[sha] != sha:
            parent[sha] = parent[parent[sha]]
            sha = parent[sha]
        return sha
    for left, right in near_pairs:
        if left not in parent or right not in parent:
            raise ValueError('Unknown near-duplicate endpoint')
        parent[find(right)] = find(left)
    blocked_clusters = {find(sha) for sha in blocked_sha}
    groups = {}
    for sha in by_sha:
        groups.setdefault(find(sha), []).append(sha)
    validation, final, quarantine = [], [], {}
    for cluster, members in groups.items():
        times = {}
        reason = 'cluster_overlaps_observed_or_training' if cluster in blocked_clusters else None
        for sha in members:
            row = by_sha[sha]
            if row.get('label') not in {'benign', 'malicious'} or row.get('label_grade') != 'independently_reviewed':
                reason = reason or 'unverified_label'
            if row.get('detector_results_observed') is not False:
                reason = reason or 'already_observed_or_exposure_unknown'
            if row.get('time_evidence') != 'independent_telemetry' or not row.get('first_seen_utc'):
                reason = reason or 'unverified_first_seen_time'
            else:
                time = datetime.fromisoformat(row['first_seen_utc'].replace('Z', '+00:00'))
                if not time.tzinfo:
                    raise ValueError('Naive candidate time')
                times[sha] = time
            if not row.get('source_url', '').startswith('https://') or not row.get('label_evidence'):
                reason = reason or 'missing_source_or_label_evidence'
        if not reason:
            dates = list(times.values())
            if min(dates) < validation_time:
                reason = 'predates_independent_validation_window'
            elif min(dates) < final_time <= max(dates):
                reason = 'near_duplicate_cluster_crosses_time_split'
        if reason:
            quarantine.update({sha: reason for sha in members})
        elif min(times.values()) >= final_time:
            final.extend(members)
        else:
            validation.extend(members)
    counts = {role: dict(Counter(by_sha[sha]['label'] for sha in samples))
              for role, samples in [('validation', validation), ('final', final)]}
    return dict(schema=1, strict_final_test=False, detector_evaluation_performed=False,
                validation_start=validation_start, final_start=final_start,
                validation_sha256=sorted(validation), final_sha256=sorted(final), quarantine=quarantine,
                label_counts=counts, ready_for_paired_final_evaluation=False, minimum_counts_met=all(
                    counts[role].get('benign', 0) >= 20000 and counts[role].get('malicious', 0) >= 2000
                    for role in counts),
                limitations='Requires separately verified training membership, complete near-duplicate edges and held-out labels; counts alone do not certify independence')
