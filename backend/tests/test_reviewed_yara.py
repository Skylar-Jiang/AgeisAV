import hashlib

import pytest
from experiments.build_reviewed_yara import transform_source


def test_rename_preserves_every_source_byte_except_declaration():
    source = b'// fixture\r\nrule Win32_Trojan_Example : malicious { condition: false }\r\n'
    path = 'yara/trojan/Win32.Trojan.Example.yara'
    changed, metadata = transform_source(source, path)
    expected_id = 'Example_Code_h' + hashlib.sha256(path.encode()).hexdigest()[:10]
    assert metadata['rule_id'] == expected_id
    assert metadata['upstream_rule_id'] == 'Win32_Trojan_Example'
    assert changed.replace(expected_id.encode(), b'Win32_Trojan_Example', 1) == source
    assert metadata['upstream_source_sha256'] == hashlib.sha256(source).hexdigest()
    assert metadata['canonical_source_sha256'] == hashlib.sha256(changed).hexdigest()


def test_retains_existing_stealc_identifier():
    changed, metadata = transform_source(b'rule Win32_Infostealer_StealC { condition: false }',
                                                  'yara/infostealer/Win32.Infostealer.StealC.yara')
    assert metadata['rule_id'] == 'StealC_Code_Infostealer'
    assert changed.startswith(b'rule StealC_Code_Infostealer ')


@pytest.mark.parametrize('source', [b'rule Old { condition: Old }',
                                    b'rule Old { condition: false }\nrule Other { condition: false }'])
def test_rejects_self_reference_or_multiple_declarations(source):
    with pytest.raises(ValueError):
        transform_source(source, 'yara/trojan/Win32.Trojan.Example.yara')


def test_rejects_out_of_declared_scope_source():
    with pytest.raises(ValueError, match='scope'):
        transform_source(b'rule Old { condition: false }',
                                  'yara/trojan/ByteCode.MSIL.Trojan.Example.yara')
