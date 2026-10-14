"""Offline service, permissions, real ML fault and cache checks using known benign fixtures only."""

import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request


def main():
    assert sys.platform == 'linux' and os.getuid() == 1001
    isolation = subprocess.check_output(['/usr/local/bin/aegisav-isolation-check'], text=True).strip()
    root = Path('/opt/aegisav-product/current').resolve()
    assert root.parent == Path('/opt/aegisav-product/releases')
    manifest_raw = (root / 'release.json').read_bytes()
    manifest = json.loads(manifest_raw)
    assert root.name == hashlib.sha256(manifest_raw).hexdigest()[:16]
    assert all(hashlib.sha256((root / name).read_bytes()).hexdigest() == digest
               for name, digest in manifest['files'].items())
    assert all(path.stat().st_uid == 0 and not os.access(path, os.W_OK)
               for path in [root.parent.parent, root.parent, root, *root.rglob('*')])
    try:
        descriptor = os.open(root / 'models/ember2024/registry.json', os.O_WRONLY | os.O_APPEND)
    except PermissionError:
        denied = True
    else:
        os.close(descriptor)
        raise AssertionError('Service user can open model assets for writing')
    small = Path('/opt/aegisav-benign/windows/samples/c77aa0bc43913e8da4d98f22c326d716617021bd2f6afbf1030749f296738cc5.dll').read_bytes()
    large = Path('/opt/aegisav-benign/vendor/samples/4fbd024b8071aa5fa7315626c57ce5b820fc52bcddb64e8ab297f2206c83ebed.dll').read_bytes()
    base = 'http://127.0.0.1:8000'
    def request(endpoint, data=None):
        started = time.perf_counter()
        headers = {'Content-Type': 'application/json' if endpoint.endswith('batch') else 'application/octet-stream'}
        try:
            with urllib.request.urlopen(urllib.request.Request(base + endpoint, data=data, headers=headers), timeout=180) as response:
                return dict(http_status=response.status, wall_ms=(time.perf_counter() - started) * 1000,
                            body=json.load(response))
        except urllib.error.HTTPError as error:
            return dict(http_status=error.code, wall_ms=(time.perf_counter() - started) * 1000)
    for _ in range(60):
        try:
            inventory = request('/v1/engines')['body']
            break
        except OSError:
            time.sleep(.5)
    else:
        raise AssertionError('Installed service unavailable')
    assert inventory['service_release'] == root.name and inventory['ml']['assets_valid']
    sys.path.insert(0, str(root / 'backend'))
    from aegisav.clamav_engine import ClamAVEngine
    for _ in range(120):
        if ClamAVEngine().probe():
            break
        time.sleep(.5)
    else:
        raise AssertionError('ClamAV readiness timeout')
    cold, warm = request('/v1/scan', small), request('/v1/scan', small)
    (Path.home() / 'product-service-initial-calls.json').write_text(json.dumps(dict(cold=cold, warm=warm), indent=2))
    assert not cold['body']['cached'] and warm['body']['cached']
    assert set(cold['body']['engines']) == {'sha256', 'fuzzy', 'yara_x', 'clamav', 'lightgbm'}
    assert all(item['status'] == 'no_match' for item in cold['body']['engines'].values())
    assert cold['body']['engines']['lightgbm']['artifact_version'] == inventory['ml']['artifact_version']
    batch = request('/v1/scan/batch', json.dumps(dict(files=[base64.b64encode(small).decode()] * 2)).encode())
    assert batch['body']['results'][1]['duplicate_of'] == 0
    assert request('/v1/scan', b'not a PE')['http_status'] == 422
    oversized = request('/v1/scan', bytes(16 * 1024**2 + 1))
    assert oversized['http_status'] == 413
    sys.path.insert(0, str(root / 'backend'))
    from aegisav.ml_engine import MLEngine
    from aegisav.scanner import StaticScanner
    from aegisav.hashes import HashDatabase
    from aegisav.yara_engine import load_yara_engine
    from aegisav.clamav_engine import ClamAVEngine
    assets = root / 'models/ember2024'
    large_result = MLEngine(assets).scan(large)
    assert large_result['status'] == 'no_match'
    assert large_result['feature_sha256'] == 'cd78afa3afc33e0213ebfaee69368c4f85e67a411f9b5aa61b8f6d484c0e075f'
    assert large_result['score'] == 5.301385550531874e-05
    faults = {}
    with tempfile.TemporaryDirectory(prefix='aegisav-trusted-model-fault-') as scratch:
        copied = Path(scratch) / 'models'
        shutil.copytree(assets, copied)
        for path in copied.iterdir():
            path.chmod(0o600)
        model = MLEngine(copied)
        scanner = StaticScanner(HashDatabase.from_file(root / 'rules/hashes.json'),
            load_yara_engine(root / 'rules/yara', root / 'rules/yara/metadata.json'), ClamAVEngine(), ml_engine=model)
        first, cached = scanner.scan(small), scanner.scan(small)
        assert not first['cached'] and cached['cached']
        with (copied / 'features.py').open('ab') as target:
            target.write(b'\n# harmless integrity fault\n')
        corrupt = scanner.scan(small)
        assert not corrupt['cached'] and corrupt['engines']['lightgbm']['status'] == 'error'
        assert corrupt['engines']['lightgbm']['score'] is None
        assert 'lightgbm' in corrupt['fusion']['abstained_engines']
        faults['corrupt_asset_after_cache'] = corrupt
        faults['unavailable'] = MLEngine(Path(scratch) / 'missing').scan(small)
    faults['timeout'] = MLEngine(assets, timeout_seconds=.05).scan(small)
    assert faults['timeout']['status'] == 'timeout' and faults['timeout']['score'] is None
    faults['parse_error'] = MLEngine(assets).scan(b'not a PE')
    assert faults['parse_error']['status'] == 'error' and faults['parse_error']['score'] is None
    service = subprocess.check_output(['systemctl', 'show', 'aegisav-api.service',
                '--property=ActiveState,User,Group,MemoryMax,TasksMax,ProtectSystem,ProtectHome,NoNewPrivileges,MainPID'], text=True)
    report = dict(schema=1, raw_malware_used=False, strict_final_test=False, isolation=isolation,
                  release_id=root.name, release_manifest_sha256=hashlib.sha256(manifest_raw).hexdigest(),
                  assets_write_attempt_denied=denied, all_release_files_root_owned_nonwritable=True,
                  inventory=inventory, service_properties=service, cold=cold, warm=warm,
                  batch_duplicates=batch['body']['results'][1]['duplicate_of'], oversized_http=oversized['http_status'],
                  large_direct_ml=large_result, fault_results=faults)
    (Path.home() / 'product-service-verification.json').write_text(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
