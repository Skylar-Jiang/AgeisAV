import hashlib
import io
import zipfile

import pyzipper
import pytest

from vm.collection_boundary import unpack_verified, validate_manifest, require_mode, should_attempt, response_length, verify_transfer


def encrypted(data=b'harmless', name='sample.bin'):
    output = io.BytesIO()
    with pyzipper.AESZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as archive:
        archive.setpassword(b'infected')
        archive.writestr(name, data)
    return output.getvalue()


def test_encrypted_member_streams_to_hash_named_file_and_rejects_mismatch(tmp_path):
    data = b'harmless' * 10000
    sha = hashlib.sha256(data).hexdigest()
    path = tmp_path / (sha + '.bin')
    assert unpack_verified(encrypted(data), sha, path, len(data)) == len(data)
    assert path.read_bytes() == data
    with pytest.raises(ValueError):
        unpack_verified(encrypted(data), '0' * 64, tmp_path / 'wrong.bin', len(data))
    assert not (tmp_path / 'wrong.bin').exists()


def test_archive_rejects_plaintext_paths_extra_members_and_size_before_output(tmp_path):
    data = b'harmless'
    sha = hashlib.sha256(data).hexdigest()
    output = tmp_path / 'out.bin'
    for content in [encrypted(data, '../escape'), encrypted(data, '/absolute')]:
        with pytest.raises(ValueError):
            unpack_verified(content, sha, output, 100)
    with pytest.raises(ValueError):
        unpack_verified(encrypted(data), sha, output, 2)
    plain = io.BytesIO()
    with zipfile.ZipFile(plain, 'w') as package:
        package.writestr('x', data)
    with pytest.raises(ValueError):
        unpack_verified(plain.getvalue(), sha, output, 100)
    assert not output.exists()


def test_manifest_duplicate_identity_and_online_analysis_are_refused():
    row = dict(sha256='a' * 64, file_size=42, source_url='https://bazaar.abuse.ch/sample/'+'a'*64+'/')
    assert validate_manifest([row]) == [row]
    for rows in [[row, row], [dict(row, sha256='../escape')], [dict(row, file_size=200*1024**2)]]:
        with pytest.raises(ValueError):
            validate_manifest(rows)
    require_mode('offline', ['lo'], [], [])
    with pytest.raises(ValueError):
        require_mode('offline', ['lo', 'ens33'], [], [])
    with pytest.raises(ValueError):
        require_mode('offline', ['lo'], ['default via 192.168.1.1'], [])
    with pytest.raises(ValueError):
        require_mode('online', ['lo'], [], [])


def test_forged_single_entry_directory_is_rejected_before_zip_objects(tmp_path, monkeypatch):
    output = io.BytesIO()
    with pyzipper.AESZipFile(output, 'w', encryption=pyzipper.WZ_AES) as archive:
        archive.setpassword(b'infected')
        archive.writestr('a', b'harmless')
        archive.writestr('b', b'harmless')
    content = bytearray(output.getvalue())
    end = content.rfind(b'PK\x05\x06')
    content[end+8:end+12] = b'\x01\x00\x01\x00'
    monkeypatch.setattr(pyzipper, 'AESZipFile', lambda *a, **k: pytest.fail('ZIP objects allocated'))
    with pytest.raises(ValueError, match='directory_boundary'):
        unpack_verified(bytes(content), '0'*64, tmp_path/'out.bin', 100)


def test_resume_retains_failures_but_explicit_retry_can_revisit_them():
    attempts = [dict(sha256='a', status='error'), dict(sha256='b', status='downloaded')]
    assert should_attempt(attempts, 'c', False)
    assert not should_attempt(attempts, 'a', False)
    assert should_attempt(attempts, 'a', True)
    assert not should_attempt(attempts, 'b', True)
    attempts.append(dict(sha256='a', status='scanned'))
    assert not should_attempt(attempts, 'a', True)


def test_http_body_length_must_match_before_marking_transport_complete():
    assert response_length(None) is None
    assert response_length('123')==123
    verify_transfer(123,123)
    verify_transfer(123,None)
    for header in ('-1','invalid','0',str(130*1024**2)):
        with pytest.raises(ValueError):
            response_length(header)
    with pytest.raises(ValueError,match='incomplete_http_body'):
        verify_transfer(122,123)
