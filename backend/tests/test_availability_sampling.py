import copy
import ast
import json
from pathlib import Path
from types import SimpleNamespace
from experiments.availability_sampling import select_available
import pytest
from experiments import availability_sampling


def record(number,family='family',**changes):
    return dict(sha256_hash=f'{number:064x}',signature=family,file_type='exe',file_size=4096,**changes)


def test_available_selection_respects_prior_size_type_and_family_caps():
    rows=[record(i,'A') for i in range(1,14)]+[record(20,'B')]
    rows += [dict(record(30),file_size=16*1024**2+1),dict(record(31),file_type='elf')]
    result=select_available(rows,{f'{1:064x}'},limit=9,per_family=8)
    assert len(result['selected'])==9
    assert f'{1:064x}' not in {r['sha256'] for r in result['selected']}
    assert sum(r['family_proxy']=='A' for r in result['selected'])==8
    assert result['selected'][1]['family_proxy']=='B'
    assert result['exclusions']['prior_identity']==1
    assert result['exclusions']['size']==1 and result['exclusions']['type']==1


def test_selection_is_order_and_detector_outcome_independent():
    rows=[record(i,'A' if i%2 else 'B') for i in range(1,21)]
    altered=copy.deepcopy(rows[::-1])
    for r in altered:r.update(score=0.9999,vendor_intel={'vote':'malicious'},aegisav_result='matched')
    assert select_available(rows,set(),limit=8)==select_available(altered,set(),limit=8)


def test_repeated_identity_and_ambiguous_metadata_never_become_raw_truth():
    rows=[record(1),record(1),dict(record(2),file_size=True),dict(record(3),sha256_hash='bad')]
    result=select_available(rows,set())
    assert len(result['selected'])==1
    assert result['selected'][0]['label']=='proxy_malicious_unreviewed'
    assert result['selected'][0]['detector_results_observed'] is False
    assert result['selected'][0]['formal_eligible'] is False
    assert result['exclusions']=={'duplicate':1,'size':1,'identity':1}


def reviewed(number,**changes):
    return dict(sha256=f'{number:064x}',payload_role_reviewed=True,
        source_url='https://example.org/pinned-report',source_text_sha256='a'*64,
        locator='line 42: executable payload',reported_family='case-family',**changes)


def test_unreviewed_intelligence_never_authorizes_a_download():
    result=availability_sampling.select_reviewed_available(
        [record(1),record(2),record(3)],[reviewed(1),dict(reviewed(2),payload_role_reviewed=False)],set())
    assert [r['sha256'] for r in result['selected']]==[f'{1:064x}']
    assert result['exclusions']['role_not_reviewed']==2
    assert result['selected'][0]['technical_evidence']['reported_family']=='case-family'
    assert result['selected'][0]['formal_eligible'] is False


@pytest.mark.parametrize('change',[{'source_url':'http://example.org/'},
    {'source_text_sha256':'bad'},{'locator':''},{'source_url':'https://user:password@example.org/'}])
def test_incomplete_or_unsafe_primary_locator_fails_closed(change):
    with pytest.raises(ValueError,match='primary_evidence'):
        availability_sampling.select_reviewed_available([record(1)],[dict(reviewed(1),**change)],set())


def test_primary_selection_keeps_bounds_prior_exclusions_and_outcome_blindness():
    rows=[record(i,'A' if i%2 else 'B') for i in range(1,18)]
    primary=[reviewed(i) for i in range(1,18)]
    expected=availability_sampling.select_reviewed_available(rows,primary,{f'{1:064x}'},limit=9)
    changed=[dict(r,score=0.9999,aegisav_result='matched') for r in rows[::-1]]
    assert expected==availability_sampling.select_reviewed_available(changed,primary[::-1],{f'{1:064x}'},limit=9)
    assert len(expected['selected'])==9 and expected['exclusions']['prior_identity']==1
    assert all(r['detector_results_observed'] is False for r in expected['selected'])


def discovery_harness(tmp_path):
    source=Path(__file__).resolve().parents[2]/'vm/collect_available_cases.py'
    tree=ast.parse(source.read_text(encoding='utf-8'))
    function=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='discover')
    code=tmp_path/'code';code.mkdir();scope=tmp_path/'cohort';(scope/'incoming').mkdir(parents=True)
    (code/'primary.json').write_text(json.dumps([reviewed(1)]));(code/'exclude.json').write_text('[]')
    def save(p,value):p.write_text(json.dumps(value))
    namespace=dict(os=SimpleNamespace(getuid=lambda:1002,geteuid=lambda:1002),json=json,hashlib=__import__('hashlib'),
        CODE=code,SCOPE=scope,identity=lambda:dict(fixture='unchanged'),select_reviewed_available=availability_sampling.select_reviewed_available,
        collection=SimpleNamespace(network=lambda mode:None,save=save))
    exec(compile(ast.Module(body=[function],type_ignores=[]),str(source),'exec'),namespace)
    return namespace,scope


@pytest.mark.parametrize('status',[429,502])
def test_discovery_error_is_preserved_retryable_and_never_frozen_as_unavailable(tmp_path,status):
    ns,scope=discovery_harness(tmp_path);calls=[]
    def failing(query):calls.append(query);return dict(query=query,query_status='http_error',http_status=status,rows=[])
    ns['request_metadata']=failing
    with pytest.raises(RuntimeError):ns['discover']()
    assert not (scope/'incoming/selection.json').exists()
    assert len(json.loads((scope/'incoming/discovery.json').read_text())['queries'])==1
    def success(query):calls.append(query);return dict(query=query,query_status='hash_not_found',rows=[])
    ns['request_metadata']=success;ns['discover']()
    history=json.loads((scope/'incoming/discovery.json').read_text())['queries']
    assert len(calls)==4 and len(history)==4 and history[0]['http_status']==status
    assert json.loads((scope/'incoming/selection.json').read_text())['selected']==[]


def test_discovery_respects_active_backoff_and_bounds_explicit_retries(tmp_path):
    ns,scope=discovery_harness(tmp_path)
    ns['request_metadata']=lambda query:dict(query=query,query_status='http_error',http_status=429,rows=[])
    with pytest.raises(RuntimeError):ns['discover']()
    def backoff(query):raise RuntimeError('request_backoff_active')
    ns['request_metadata']=backoff
    with pytest.raises(RuntimeError,match='request_backoff_active'):ns['discover']()
    assert len(json.loads((scope/'incoming/discovery.json').read_text())['queries'])==1
    ns['request_metadata']=lambda query:dict(query=query,query_status='http_error',http_status=429,rows=[])
    with pytest.raises(RuntimeError):ns['discover']()
    calls=[];ns['request_metadata']=lambda query:calls.append(query)
    with pytest.raises(RuntimeError,match='metadata_queries_unresolved'):ns['discover']()
    assert not calls and not (scope/'incoming/selection.json').exists()


def test_shadow_rejects_unlisted_bytes_before_loading_a_model(monkeypatch):
    import io,sys
    import aegisav.scan_process
    source=Path(__file__).resolve().parents[2]/'vm/evaluate_paired_development.py'
    function=next(n for n in ast.parse(source.read_text(encoding='utf-8')).body if isinstance(n,ast.FunctionDef) and n.name=='shadow')
    monkeypatch.setattr(aegisav.scan_process,'contain_worker',lambda:None)
    monkeypatch.setattr(sys,'stdin',SimpleNamespace(buffer=io.BytesIO(b'inert-not-in-allowlist')))
    ns=dict(freeze=lambda:(dict(files=[dict(sha256='0'*64)]),'freeze'),sys=sys,hashlib=__import__('hashlib'))
    exec(compile(ast.Module(body=[function],type_ignores=[]),str(source),'exec'),ns)
    with pytest.raises(ValueError,match='input_not_in_frozen_development_cohort'):ns['shadow']()
