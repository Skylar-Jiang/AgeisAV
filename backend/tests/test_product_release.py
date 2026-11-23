import hashlib
import io
import json
import tarfile

import pytest

from vm.install_product_release import verify_bundle


def bundle(tmp_path, filename='backend/aegisav/main.py', changed=False, link=False):
    path = tmp_path / 'release.tar.gz'
    data = b'trusted release fixture'
    manifest = json.dumps(dict(schema=1, files={filename: hashlib.sha256(data).hexdigest()})).encode()
    with tarfile.open(path, 'w:gz') as archive:
        for name, content in [('release.json', manifest), (filename, b'changed' if changed else data)]:
            entry = tarfile.TarInfo(name)
            entry.size = len(content)
            if link and name != 'release.json':
                entry.type = tarfile.SYMTYPE
                entry.linkname = '/etc/passwd'
                entry.size = 0
            archive.addfile(entry, io.BytesIO(content))
    return path


def test_release_rejects_tampering_traversal_and_links_before_install(tmp_path):
    assert verify_bundle(bundle(tmp_path))[1]['backend/aegisav/main.py'] == b'trusted release fixture'
    with pytest.raises(ValueError):
        verify_bundle(bundle(tmp_path, changed=True))
    with pytest.raises(ValueError):
        verify_bundle(bundle(tmp_path, filename='../outside.py'))
    with pytest.raises(ValueError):
        verify_bundle(bundle(tmp_path, link=True))
