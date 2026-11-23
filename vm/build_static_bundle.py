"""Package trusted scanner code and pinned public model assets, never input samples."""

import hashlib
import io
import json
import tarfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = ROOT / 'artifacts/ember2024/upstream'
MODEL = ROOT / 'artifacts/ember2024/models/EMBER2024_PE.model'
MODEL_SHA = '4252027863492ac138785c8c18576f43dad77d00faddc14e8c0072e8db419f99'


def main():
    if hashlib.sha256(MODEL.read_bytes()).hexdigest() != MODEL_SHA:
        raise ValueError('Unexpected official model')
    assets = {name: UPSTREAM / 'src/thrember' / name for name in ('features.py', 'pefile_warnings.txt')}
    assets['EMBER2024_PE.model'] = MODEL
    manifest = {'upstream_revision': '0ef753e81d98bf209f71b03cd331dfc190b5b54d',
                'model_revision': 'e5b945dd90e1a1a1ec0cc07b3a17b52e9ba2d0c2',
                'model_role': 'official pretrained general PE; no local fit or threshold calibration',
                'files': {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in assets.items()}}
    output = ROOT / 'artifacts/static-guest-tools-20261010.tar.gz'
    with tarfile.open(output, 'w:gz') as bundle:
        files = list((ROOT / 'backend/aegisav').glob('*.py'))
        files += [p for p in (ROOT / 'rules').rglob('*') if p.is_file()]
        files += list((ROOT / 'vm').glob('*.py')) + list((ROOT / 'vm').glob('*.sh'))
        for path in sorted(files):
            bundle.add(path, arcname=path.relative_to(ROOT).as_posix(), recursive=False)
        for name, path in assets.items():
            bundle.add(path, arcname='ember/' + name, recursive=False)
        bundle.add(UPSTREAM / 'LICENSE', arcname='ember/LICENSE', recursive=False)
        raw = json.dumps(manifest, indent=2).encode()
        entry = tarfile.TarInfo('ember/manifest.json')
        entry.size = len(raw)
        bundle.addfile(entry, io.BytesIO(raw))
    print(json.dumps({'bundle': str(output), 'sha256': hashlib.sha256(output.read_bytes()).hexdigest(),
                      'assets': manifest}, indent=2))


if __name__ == '__main__':
    main()
