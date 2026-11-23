"""Build a content-addressed local release containing trusted code/rules/models only."""

import hashlib
import io
import json
from pathlib import Path
import tarfile


def main():
    root = Path(__file__).resolve().parents[1]
    paths = sorted((root / 'backend/aegisav').glob('*.py'))
    paths += [root / 'models/ember2024' / name for name in ('features.py', 'pefile_warnings.txt',
              'EMBER2024_PE.model', 'ember2024_win64_temporal_local.model', 'registry.json')]
    paths += sorted(path for path in (root / 'rules').rglob('*') if path.is_file()
                    and path.suffix in {'.json', '.yar', '.txt'})
    manifest = dict(schema=1, fusion_policy='evidence-or-v1',
                    registry_sha256=hashlib.sha256((root / 'models/ember2024/registry.json').read_bytes()).hexdigest(),
                    feature_implementation='chunked-histogram-v1',
                    files={path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths})
    raw = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()
    release_id = hashlib.sha256(raw).hexdigest()[:16]
    output = root / 'artifacts' / ('product-release-' + release_id + '.tar.gz')
    with tarfile.open(output, 'w:gz') as archive:
        entry = tarfile.TarInfo('release.json')
        entry.size, entry.mode = len(raw), 0o444
        archive.addfile(entry, io.BytesIO(raw))
        for path in paths:
            archive.add(path, arcname=path.relative_to(root).as_posix(), recursive=False)
    summary = dict(release_id=release_id, bundle=str(output), sha256=hashlib.sha256(output.read_bytes()).hexdigest())
    (root / 'artifacts/product-release-latest.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary))


if __name__ == '__main__':
    main()
