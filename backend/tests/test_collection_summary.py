from experiments.summarize_collection import summarize


def row(sha,status='scanned',positive=()):
    engines={name:dict(status='matched' if name in positive else 'no_match',risk_signal='suspicious' if name in positive else None,elapsed_ms=1)
             for name in ('sha256','fuzzy','yara_x','clamav','lightgbm')}
    return dict(sha256=sha,status=status,label='unknown',label_grade='source_reported_only',elapsed_ms=10,
                report=dict(sha256=sha,engines=engines,worker_peak_rss_kib=100,worker_cpu_seconds=.1) if status=='scanned' else None)


def test_unknown_labels_never_become_recall_or_false_positive_rate():
    report=summarize(dict(identity={},files=[row('a',positive=('lightgbm',)),row('b',positive=('clamav',)),row('c','error')]))
    assert report['accuracy_metrics'] is None
    assert report['files']==3
    assert report['engines']['clamav']['positive']==1
    assert report['engines']['clamav']['abstained']==1
    assert report['policies']['evidence_or']==dict(positive=2,negative=0,abstained=1)
    assert report['policies']['corroborated']==dict(positive=0,negative=2,abstained=1)


def test_retries_keep_history_but_do_not_duplicate_evaluation_denominators():
    failed=row('a','error')
    good=row('a')
    report=summarize(dict(identity={},files=[failed,good]))
    assert report['attempts']==2 and report['files']==1
    assert report['previous_failed_attempts']==1
    assert report['engines']['clamav']==dict(positive=0,negative=1,abstained=0,status_counts={'no_match':1})


def test_engine_timeout_is_not_a_negative_and_or_can_still_be_positive():
    item=row('a',positive=('clamav',))
    item['report']['engines']['lightgbm']['status']='timeout'
    item['report']['engines']['lightgbm']['risk_signal']=None
    report=summarize(dict(identity={},files=[item]))
    assert report['engines']['lightgbm']['abstained']==1
    assert report['policies']['evidence_or']['positive']==1
    assert report['policies']['corroborated']['abstained']==1


def test_expansion_keeps_its_development_role_and_scan_timing_scope():
    report=summarize(dict(identity={},dataset_role='development_expansion',files=[row('a')]))
    assert report['dataset_role']=='development_expansion'
    assert 'excludes unpack' in report['timing_limitations']
