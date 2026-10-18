import copy
from experiments.availability_sampling import select_available


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
