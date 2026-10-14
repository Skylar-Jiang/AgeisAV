import hashlib
import importlib.util
import struct
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[2] / 'experiments' / 'collect_benign_expansion.py'
spec = importlib.util.spec_from_file_location('benign_expansion', SCRIPT)
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


def test_classifies_native_and_managed_pe_without_execution(pe_bytes):
    assert collector.pe_metadata(pe_bytes) == {
        'machine': '0x014c', 'pe_format': 'PE32', 'is_dll': False, 'has_clr': False,
    }
    managed = bytearray(pe_bytes)
    struct.pack_into('<H', managed, 0x84 + 18, 0x2102)
    struct.pack_into('<II', managed, 0x98 + 96 + 14 * 8, 0x1000, 72)
    assert collector.pe_metadata(managed)['has_clr'] is True
    assert collector.pe_metadata(managed)['is_dll'] is True


def test_excludes_overlap_invalid_signature_and_preserves_unknown_label():
    def row(digest, status='Valid', signer='O=Microsoft Corporation'):
        return {'sha256': digest, 'group': 'framework', 'signature_status': status,
                'signer': signer, 'size_bytes': 10, 'expected_publisher': 'Microsoft Corporation'}
    rows = [row('existing'), row('new', 'NotSigned'), row('wrong', signer='O=Unrelated'),
            row('accepted'), row('accepted'), row('excess')]
    selected, exclusions = collector.select_rows(rows, {'existing'}, {'framework': 1}, 100)
    assert [r['sha256'] for r in selected] == ['accepted']
    assert selected[0]['label'] == 'trusted_installation_benign_proxy'
    assert selected[0]['dataset_role'] == 'validation_candidate'
    assert [r['reason'] for r in exclusions] == [
        'overlap_prior_dataset', 'signature_not_valid', 'unexpected_publisher',
        'duplicate_current_cohort', 'group_quota_reached',
    ]


def test_destination_copy_is_verified_and_no_overwrite(tmp_path):
    source = tmp_path / 'installed.dll'
    source.write_bytes(b'harmless placeholder')
    row = {'source_path': str(source), 'sha256': hashlib.sha256(source.read_bytes()).hexdigest()}
    destination = tmp_path / 'samples'
    result = collector.copy_verified(row, destination)
    assert (tmp_path / result).read_bytes() == source.read_bytes()
    import pytest
    with pytest.raises(FileExistsError):
        collector.copy_verified(row, destination)


def test_rejects_changed_source_before_copy(tmp_path):
    source = tmp_path / 'installed.dll'
    source.write_bytes(b'changed')
    import pytest
    with pytest.raises(ValueError, match='changed'):
        collector.copy_verified({'source_path': str(source), 'sha256': '0' * 64}, tmp_path / 'samples')
    assert not list((tmp_path / 'samples').glob('*'))
