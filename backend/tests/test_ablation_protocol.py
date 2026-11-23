import pytest
from experiments.ember_ablation import select_columns


def test_removed_string_columns_remap_native_categorical_indices():
    keep, categorical = select_columns('strings')
    assert len(keep) == 2568 - 177
    assert not set(range(519, 696)).intersection(keep)
    assert categorical == [2, 3, 4, 5, 6, 524, 525]
    assert [keep[index] for index in categorical] == [2, 3, 4, 5, 6, 701, 702]


@pytest.mark.parametrize('group,start,end', [('authenticode',2472,2480),('pefilewarnings',2480,2568)])
def test_tail_group_removal_preserves_categories(group,start,end):
    keep, categorical = select_columns(group)
    assert len(keep) == 2568 - (end-start)
    assert not set(range(start,end)).intersection(keep)
    assert categorical == [2, 3, 4, 5, 6, 701, 702]
