import pytest

from vm.static_benign import validate_benign_export, sample_path


def test_benign_export_uses_manifest_identity_and_strict_schema():
    report = {'schema': 2, 'manifest_sha256': 'a' * 64, 'isolation': 'AEGISAV_ISOLATION PASS boot=x',
              'files': [], 'errors': [], 'completed': True}
    validate_benign_export(report)
    with pytest.raises(ValueError):
        validate_benign_export(dict(report, sample_bytes='unexpected'))


def test_benign_fixture_paths_cannot_escape_the_fixed_root(tmp_path):
    for path in ('../outside.exe', '/etc/passwd', 'C:/outside.exe', 'samples/../../outside.exe'):
        with pytest.raises(ValueError):
            sample_path(tmp_path, path)
    assert sample_path(tmp_path, 'samples/harmless.exe') == tmp_path / 'samples/harmless.exe'
