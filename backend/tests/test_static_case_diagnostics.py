from types import SimpleNamespace
import pytest
from vm.diagnose_static_case import aggregate_contributions,pattern_probes


def test_contribution_groups_cover_every_feature_once():
    groups=[SimpleNamespace(name='header',dim=2),SimpleNamespace(name='strings',dim=1)]
    actual=aggregate_contributions(groups,[1.0,-3.0,4.0,0.25])
    assert actual=={'groups':[{'name':'header','start':0,'end':2,'raw_margin_contribution':-2.0},{'name':'strings','start':2,'end':3,'raw_margin_contribution':4.0}],'expected_value':0.25,'sum_raw_margin':2.25}


@pytest.mark.parametrize('values',[[1,2],[1,float('nan'),2,3]])
def test_incomplete_or_nonfinite_contributions_rejected(values):
    with pytest.raises(ValueError):aggregate_contributions([SimpleNamespace(name='all',dim=3)],values)


def test_pattern_probes_retain_original_pattern_and_match_independently():
    import yara_x
    source='''rule Example {\n strings:\n $first = { 01 02 ?? 04 }\n $second = { FF EE }\n condition:\n all of them\n}'''
    probes=pattern_probes(source)
    assert list(probes)==['first','second']
    rules=yara_x.compile('\n'.join(probes.values()))
    assert [r.identifier for r in rules.scan(bytes([1,2,9,4])).matching_rules]==['Probe_first']


def test_unrecognized_rule_fails_closed():
    with pytest.raises(ValueError):pattern_probes('rule Empty { condition: true }')

def test_diagnostic_cannot_explain_baseline_with_different_assets():
    from vm.diagnose_static_case import bind_baseline
    baseline=dict(artifact_version='frozen:general',feature_schema='schema',feature_implementation='chunked-histogram-v1',feature_sha256='features',score=0.4,threshold=0.5,model_version='v1')
    result=dict(artifact_version='changed:general',feature_schema='schema',feature_implementation='chunked-histogram-v1',feature_sha256='features',models={'general':dict(score=0.4,threshold=0.5,model_version='v1')})
    bind_baseline(result,baseline)
    assert result['status']=='incompatible_baseline'
    assert result['baseline_mismatches']==['artifact_version']


def test_diagnostic_requires_threshold_and_feature_consistency():
    from vm.diagnose_static_case import bind_baseline
    baseline=dict(artifact_version='frozen:general',feature_schema='schema',feature_implementation='chunked-histogram-v1',feature_sha256='features',score=0.4,threshold=0.5,model_version='v1')
    result=dict(artifact_version='frozen:general',feature_schema='schema',feature_implementation='chunked-histogram-v1',feature_sha256='features',models={'general':dict(score=0.4,threshold=0.5,model_version='v1')})
    bind_baseline(result,baseline);assert result['status']=='completed'
    result['models']['general']['threshold']=0.3
    bind_baseline(result,baseline);assert result['status']=='incompatible_baseline'
    assert 'threshold' in result['baseline_mismatches']
