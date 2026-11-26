"""Windows source checkouts must preserve bytes bound by model/native manifests."""
from pathlib import Path
import io
import shutil
import subprocess
import zipfile

import pytest


@pytest.mark.parametrize('name', ['backend/aegisav/ember_features.py', 'experiments/native_ssdeep.c'])
def test_autocrlf_checkout_preserves_frozen_source_bytes(tmp_path, name):
    if not shutil.which('git'):
        pytest.skip('Git required for source checkout regression')
    root = Path(__file__).resolve().parents[2]
    if not (root / '.git').exists():
        pytest.skip('Repository metadata required for checkout regression')
    original = subprocess.check_output(['git', 'show', 'HEAD:' + name], cwd=root)
    repository = tmp_path / 'checkout'
    repository.mkdir()
    subprocess.run(['git', 'init', '-q'], cwd=repository, check=True)
    (repository / '.gitattributes').write_bytes((root / '.gitattributes').read_bytes())
    target = repository / name
    target.parent.mkdir(parents=True)
    target.write_bytes(original)
    subprocess.run(['git', '-c', 'core.autocrlf=false', 'add', '.'], cwd=repository, check=True)
    target.unlink()
    subprocess.run(['git', '-c', 'core.autocrlf=true', 'checkout-index', '--', name],
                   cwd=repository, check=True)
    assert target.read_bytes() == original
    tree = subprocess.check_output(['git', 'write-tree'], cwd=repository).decode().strip()
    exported = subprocess.check_output(['git', '-c', 'core.autocrlf=true', 'archive', '--format=zip', tree],
                                       cwd=repository)
    with zipfile.ZipFile(io.BytesIO(exported)) as archive:
        assert archive.read(name) == original
