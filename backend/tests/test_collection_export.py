import json
import pytest
from vm.export_collection_evidence import canonical_evidence


def test_export_serializes_only_valid_expected_json_not_original_binary():
    value=dict(identity={},files=[])
    result=canonical_evidence(json.dumps(value).encode(),'Download')
    assert result.startswith(b'{') and json.loads(result)==value
    for content in (b'MZ\x00harmless invalid document',b'[]',b'{"files":"not a list"}',b'{"files":[],"identity":NaN}'):
        with pytest.raises(ValueError):
            canonical_evidence(content,'Download')


def test_export_refuses_wrong_evidence_kind_or_oversized_input():
    with pytest.raises(ValueError):
        canonical_evidence(b'{}','RawSample')
    with pytest.raises(ValueError):
        canonical_evidence(b' '* (20*1024**2+1),'Probe')


def test_expansion_export_checks_journal_schema_and_preserves_abstentions():
    value=dict(identity={'manifest':'76816a606721f48e00f696a5f265409aa72b9d5182672f24f46952075dc4b221'},files=[dict(status='error',reason='TimeoutError')])
    for kind in ('ExpansionDownload','Acquisition','ExpansionScan'):
        assert json.loads(canonical_evidence(json.dumps(value).encode(),kind))==value
        with pytest.raises(ValueError):
            canonical_evidence(b'{"identity":{},"files":null}',kind)
