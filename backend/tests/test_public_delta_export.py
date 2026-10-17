import importlib.util
from pathlib import Path
import pytest


def module():
    spec=importlib.util.spec_from_file_location('public_delta',Path(__file__).resolve().parents[2]/'experiments/export_public_delta.py')
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result)
    return result


@pytest.mark.parametrize('data',[
    b'x = "'+b'9'*48+b'"',
    b'api_key = "'+b'Z'*40+b'"',
    b'-----BEGIN '+b'PRIVATE KEY-----',
    b'MZ'+bytes(100),
    b'x'*(2*1024**2+1),
],ids=['token_hex','token_assignment','private_key','pe','oversize'])
def test_changed_public_blob_rejects_sensitive_or_binary_content(data):
    with pytest.raises(ValueError,match='public_content_gate'):
        module().check_blob('vm/example.py',data,set())


def test_private_sample_hash_rejected_case_insensitively():
    with pytest.raises(ValueError,match='public_content_gate'):
        module().check_blob('docs/example.md',('a'*64).upper().encode(),{'a'*64})


def test_source_digests_and_runtime_credential_lookup_are_allowed():
    source=b"digest='"+b'a'*64+b"'\nsecret=Path('auth.key').read_text()\n"
    module().check_blob('vm/example.py',source,set())


def test_private_archive_path_rejected():
    with pytest.raises(ValueError,match='public_path_gate'):
        module().check_blob('vm/samples.zip',b'inert',set())



def test_json_credential_literal_rejected():
    data=b'{"api_key": "'+b'Z'*40+b'"}'
    with pytest.raises(ValueError,match='public_content_gate'):
        module().check_blob('vm/example.json',data,set())
