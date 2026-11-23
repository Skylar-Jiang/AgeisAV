"""Loopback HTTP smoke against the real five-engine API, using immutable benign fixtures."""

import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.request


def main():
    if sys.platform != 'linux' or os.getuid() != 1001:
        raise ValueError('Dedicated non-root guest required')
    isolation = subprocess.check_output(['/usr/local/bin/aegisav-isolation-check'], text=True).strip()
    root = Path('/home/aegisav-operator/product-api')
    assert root.resolve() == root and root.is_dir()
    fixture = Path('/opt/aegisav-benign/windows')
    item = json.loads((fixture / 'manifest.jsonl').read_text().splitlines()[0])
    assert item['sha256'] == 'c77aa0bc43913e8da4d98f22c326d716617021bd2f6afbf1030749f296738cc5'
    data = (fixture / item['path']).read_bytes()
    assert hashlib.sha256(data).hexdigest() == item['sha256']
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    env = dict(os.environ, PYTHONPATH=str(root / 'backend'), AEGISAV_MODEL_DIR=str(root / 'models/ember2024'),
               AEGISAV_ML_PROFILE='general', OPENBLAS_NUM_THREADS='1', OMP_NUM_THREADS='1')
    base = f'http://127.0.0.1:{port}'
    reports = []
    with open(os.devnull, 'wb') as sink:
        process = subprocess.Popen([sys.executable, '-m', 'uvicorn', 'aegisav.main:app', '--host', '127.0.0.1',
                                    '--port', str(port), '--no-access-log'], cwd=root, env=env, stdout=sink, stderr=sink)
        try:
            for _ in range(60):
                if process.poll() is not None:
                    raise ValueError('API exited before readiness')
                try:
                    inventory = json.load(urllib.request.urlopen(base + '/v1/engines', timeout=1))
                    break
                except OSError:
                    time.sleep(.5)
            else:
                raise ValueError('API readiness timeout')
            for _ in range(2):
                started = time.perf_counter()
                request = urllib.request.Request(base + '/v1/scan', data=data,
                                                 headers={'Content-Type': 'application/octet-stream'})
                with urllib.request.urlopen(request, timeout=90) as response:
                    report = json.load(response)
                reports.append({'api_wall_ms': (time.perf_counter() - started) * 1000, 'report': report})
            first, second = [item['report'] for item in reports]
            assert set(first['engines']) == {'sha256', 'fuzzy', 'yara_x', 'clamav', 'lightgbm'}
            assert all(engine['status'] in {'matched', 'no_match'} for engine in first['engines'].values())
            assert not first['cached'] and second['cached']
            assert first['engines']['lightgbm']['feature_sha256'] == '681f799a163f26c76e9a35226881d5e54ce43ab58bd8430226c521af48b2c0b5'
            assert first['engines']['lightgbm']['score'] == .0016802954766119863
            result = {'schema': 1, 'strict_final_test': False, 'raw_malware_used': False,
                      'isolation': isolation, 'inventory': inventory, 'results': reports,
                      'registry': json.loads((root / 'models/ember2024/registry.json').read_text()),
                      'code_sha256': {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                                      for path in (root / 'backend/aegisav').glob('*.py')}}
            (root / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == '__main__':
    main()
