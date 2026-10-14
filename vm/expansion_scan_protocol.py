"""Freeze a development diagnostic plan before reading any new detector results."""
def freeze_plan(state,source_sha256):
    if state.get('detector_evaluation_performed') is not False:
        raise ValueError('acquisition_must_be_unscored')
    rows=list({row['sha256']:row for row in state['files']}.values())
    for row in rows:
        if row.get('report') is not None or row.get('detector_results_observed') is True:
            raise ValueError('already_scored')
        if row['status']=='acquired' and not row.get('raw_sha_verified'):
            raise ValueError('unverified_raw')
    return dict(schema=1,dataset_role='development_expansion',strict_final_test=False,labels='unknown',
                purpose='Frozen five-engine paired diagnostic; never an independent final test or tuning set for current thresholds',
                thresholds_changed=False,acquisition_sha256=source_sha256,acquisition_identity=state['identity'],
                files=[dict(sha256=row['sha256'],acquired=row['status']=='acquired',size_bytes=row.get('size_bytes'),
                            reason=row.get('reason')) for row in rows])
