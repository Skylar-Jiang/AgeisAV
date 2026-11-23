import hashlib
import json
import struct

import pytest


def test_explicit_native_mode_rejects_missing_bundle(tmp_path):
    from aegisav.native_ssdeep import NativeBackendError, NativeSSDeep
    with pytest.raises(NativeBackendError):
        NativeSSDeep(tmp_path)


def test_native_loader_rejects_manifest_path_and_digest_before_execution(tmp_path):
    from aegisav.native_ssdeep import NativeBackendError, NativeSSDeep
    blob = b'inert bytes, never a DLL'
    (tmp_path / 'aegisav_ssdeep.dll').write_bytes(blob)
    manifest = {'schema': 1, 'abi': 1, 'file': '../outside.dll',
                'sha256': hashlib.sha256(blob).hexdigest(), 'source_sha256': '0' * 64}
    (tmp_path / 'manifest.json').write_text(json.dumps(manifest))
    with pytest.raises(NativeBackendError):
        NativeSSDeep(tmp_path)
    manifest['file'] = 'aegisav_ssdeep.dll'
    manifest['sha256'] = 'f' * 64
    (tmp_path / 'manifest.json').write_text(json.dumps(manifest))
    with pytest.raises(NativeBackendError):
        NativeSSDeep(tmp_path)


def test_fuzzy_provider_preserves_hash_evidence_and_reports_provenance(pe_bytes):
    import ppdeep
    from aegisav.hashes import HashDatabase
    from aegisav.scanner import StaticScanner

    class Provider:
        engine_version = 'native-ssdeep/abi1+inert-fixture'
        hash = staticmethod(ppdeep.hash)

    database = HashDatabase.from_records([])
    reference = StaticScanner(database).scan(pe_bytes)
    candidate = StaticScanner(database, ssdeep_backend=Provider()).scan(pe_bytes)
    assert reference['engines']['fuzzy']['hashes'] == candidate['engines']['fuzzy']['hashes']
    assert reference['verdict'] == candidate['verdict']
    assert candidate['engines']['fuzzy']['engine_version'].endswith(Provider.engine_version)


def test_backend_selection_requires_explicit_supported_mode(monkeypatch, tmp_path):
    from aegisav.native_ssdeep import NativeBackendError, select_backend
    monkeypatch.delenv('AEGISAV_SSDEEP_BACKEND', raising=False)
    assert select_backend(tmp_path) is None
    monkeypatch.setenv('AEGISAV_SSDEEP_BACKEND', 'unrecognized')
    with pytest.raises(NativeBackendError):
        select_backend(tmp_path)
    monkeypatch.setenv('AEGISAV_SSDEEP_BACKEND', 'native')
    with pytest.raises(NativeBackendError):
        select_backend(tmp_path)


@pytest.mark.skipif(__import__('os').name != 'nt', reason='Windows native candidate')
def test_service_verifies_asset_without_loading_native_code(monkeypatch, tmp_path):
    from aegisav import native_ssdeep
    data = bytearray(256)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3c, 128)
    data[128:132] = b'PE\0\0'
    struct.pack_into('<H', data, 132, 0x8664)
    struct.pack_into('<H', data, 152, 0x20b)
    (tmp_path / 'aegisav_ssdeep.dll').write_bytes(data)
    (tmp_path / 'manifest.json').write_text(json.dumps({'schema': 1, 'abi': 1,
        'file': 'aegisav_ssdeep.dll', 'sha256': hashlib.sha256(data).hexdigest()}))
    def load(*args, **kwargs):
        pytest.fail('Service must not load the DLL outside the disposable Job')
    monkeypatch.setattr(native_ssdeep.ctypes, 'CDLL', load)
    provider = native_ssdeep.NativeSSDeep(tmp_path)
    monkeypatch.delenv('AEGISAV_SCAN_JOB', raising=False)
    with pytest.raises(native_ssdeep.NativeBackendError):
        provider.hash(b'inert bytes')
