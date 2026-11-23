"""Bundle trusted product code and verified models, never sample files."""

from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    output = ROOT / 'artifacts/product-api-smoke-20261011.tar.gz'
    with tarfile.open(output, 'w:gz') as bundle:
        for path in sorted((ROOT / 'backend/aegisav').glob('*.py')):
            bundle.add(path, arcname=str(path.relative_to(ROOT)), recursive=False)
        for name in ('features.py', 'pefile_warnings.txt', 'EMBER2024_PE.model',
                     'ember2024_win64_temporal_local.model', 'registry.json'):
            path = ROOT / 'models/ember2024' / name
            bundle.add(path, arcname=str(path.relative_to(ROOT)), recursive=False)
        bundle.add(ROOT / 'vm/product_api_smoke.py', arcname='product_api_smoke.py', recursive=False)
    print(output)


if __name__ == '__main__':
    main()
