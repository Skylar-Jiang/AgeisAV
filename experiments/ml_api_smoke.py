"""Real HTTP-handler inference on installed benign fixtures only; not an accuracy estimate."""

import hashlib
import json
from pathlib import Path
import time

from fastapi.testclient import TestClient
from aegisav.api import create_app
from aegisav.hashes import HashDatabase
from aegisav.ml_engine import MLEngine, pe_scope
from aegisav.scanner import StaticScanner
from aegisav.yara_engine import load_yara_engine

ROOT = Path(__file__).resolve().parents[1]


def main():
    root = ROOT / 'models/ember2024'
    runtime = ROOT / '.venv-ml/Scripts/python.exe'
    fixture = ROOT / 'artifacts/benign_windows_pe_v2'
    manifest = [json.loads(line) for line in (ROOT / 'docs/benchmarks/benign_windows_pe_manifest.jsonl').read_text().splitlines()]
    win32 = manifest[0]
    assert win32['sha256'] == 'c77aa0bc43913e8da4d98f22c326d716617021bd2f6afbf1030749f296738cc5'
    win64 = next(item for item in manifest if pe_scope((fixture / item['path']).read_bytes()) == 'win64')
    results = []
    for profile, item in [('general', win32), ('win64_low_fpr', win32), ('win64_low_fpr', win64)]:
        model = MLEngine(root, profile=profile, python_executable=str(runtime))
        assert model.probe()
        scanner = StaticScanner(HashDatabase.from_file(ROOT / 'rules/hashes.json'),
                                yara_engine=load_yara_engine(ROOT / 'rules/yara', ROOT / 'rules/yara/metadata.json'),
                                ml_engine=model, cache_capacity=0)
        data = (fixture / item['path']).read_bytes()
        assert hashlib.sha256(data).hexdigest() == item['sha256']
        with TestClient(create_app(scanner)) as client:
            started = time.perf_counter()
            response = client.post('/v1/scan', content=data, headers={'content-type': 'application/octet-stream'})
            wall_ms = (time.perf_counter() - started) * 1000
            assert response.status_code == 200
            report = response.json()
            prediction = report['engines']['lightgbm']
            assert prediction['status'] in {'matched', 'no_match'}, prediction
            if item == win32:
                assert prediction['model_id'] == 'general'
                assert prediction['feature_sha256'] == '681f799a163f26c76e9a35226881d5e54ce43ab58bd8430226c521af48b2c0b5'
                assert prediction['score'] == .0016802954766119863
            else:
                assert prediction['model_id'] == 'win64'
                assert prediction['threshold'] == .9831222501035356
            results.append({'source': item['source'], 'source_path': item['source_path'],
                            'profile': profile, 'api_wall_ms': wall_ms, 'report': report,
                            'inventory': client.get('/v1/engines').json()})
    result = {'schema': 1, 'strict_final_test': False, 'raw_malware_used': False,
              'scope': 'Real API handler and disposable worker smoke; host ClamAV unavailable is explicit',
              'results': results, 'registry': json.loads((root / 'registry.json').read_text()),
              'code_sha256': {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                              for path in (ROOT / 'backend/aegisav').glob('*.py')}}
    output = ROOT / 'docs/benchmarks/ml_api_benign_smoke_20261011.json'
    output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(output)


if __name__ == '__main__':
    main()
