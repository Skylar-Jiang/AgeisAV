"""Assemble already acquired, verified weights and pinned extractor for static API inference."""

import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / 'artifacts/ember2024'


def main():
    baseline = json.loads((ROOT / 'docs/benchmarks/ember2024_win64_20261010.json').read_text())
    source = ART / 'guest_model_smoke'
    assets = {name: source / name for name in ('features.py', 'pefile_warnings.txt', 'EMBER2024_PE.model')}
    assets['ember2024_win64_temporal_local.model'] = ART / 'models/ember2024_win64_temporal_local.model'
    expected = json.loads((source / 'manifest.json').read_text())['files']
    expected['ember2024_win64_temporal_local.model'] = baseline['model_sha256']
    destination = ROOT / 'models/ember2024'
    destination.mkdir(parents=True, exist_ok=True)
    for name, path in assets.items():
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected[name]:
            raise ValueError('Pinned model or extractor mismatch')
        shutil.copyfile(path, destination / name)
    registry = {'schema': 1, 'feature_dim': 2568, 'files': expected,
                'feature_implementation': 'chunked-histogram-v1',
                'feature_adapter_sha256': hashlib.sha256((ROOT / 'backend/aegisav/ember_features.py').read_bytes()).hexdigest(),
                'upstream_revision': baseline['code_revision'], 'dataset_revision': baseline['dataset_revision'],
                'models': {
                    'general': {'file': 'EMBER2024_PE.model', 'scope': ['win32', 'win64', 'dot_net'],
                                'version': 'official-PE-e5b945dd-42520278', 'threshold': .5,
                                'threshold_source': 'frozen upstream default; no independently calibrated low-FPR claim'},
                    'win64': {'file': 'ember2024_win64_temporal_local.model', 'scope': ['win64'],
                              'version': 'local-Win64-temporal48-62d47a9b',
                              'threshold': baseline['validation']['operating_points']['validation_fpr_0.1pct']['threshold'],
                              'threshold_source': 'frozen temporal validation4 weeks target FPR 0.1%; deployment FPR not guaranteed'}},
                'training_report_sha256': hashlib.sha256((ROOT / 'docs/benchmarks/ember2024_win64_20261010.json').read_bytes()).hexdigest()}
    (destination / 'registry.json').write_text(json.dumps(registry, indent=2) + '\n', encoding='utf-8')
    print(destination)


if __name__ == '__main__':
    main()
