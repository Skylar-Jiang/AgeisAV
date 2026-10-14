"""Root installer for a fixed dedicated guest. Does not execute any PE or modify benchmark code."""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import socket
import subprocess
import tarfile
import uuid


def verify_bundle(path):
    if path.stat().st_size > 32 * 1024**2:
        raise ValueError('Compressed release exceeds boundary')
    files = {}
    total = 0
    with tarfile.open(path, 'r:gz') as archive:
        for entry in archive:
            name = PurePosixPath(entry.name)
            allowed = (entry.name == 'release.json' or
                       (len(name.parts) == 3 and name.parts[:2] == ('backend', 'aegisav') and name.suffix == '.py') or
                       (len(name.parts) == 3 and name.parts[:2] == ('models', 'ember2024') and
                        name.name in {'features.py', 'pefile_warnings.txt', 'EMBER2024_PE.model',
                                      'ember2024_win64_temporal_local.model', 'registry.json'}) or
                       (name.parts[:1] == ('rules',) and name.suffix in {'.json', '.yar', '.txt'}))
            if (not allowed or name.is_absolute() or '..' in name.parts or '\\' in entry.name
                    or not entry.isfile() or entry.name in files or not 0 <= entry.size <= 32 * 1024**2):
                raise ValueError('Release member boundary')
            total += entry.size
            if total > 64 * 1024**2 or len(files) >= 1000:
                raise ValueError('Release expansion boundary')
            files[entry.name] = archive.extractfile(entry).read()
    raw = files.pop('release.json')
    if len(raw) > 256 * 1024:
        raise ValueError('Manifest boundary')
    manifest = json.loads(raw)
    if manifest['schema'] != 1 or set(manifest['files']) != files.keys():
        raise ValueError('Release manifest differs')
    if any(hashlib.sha256(data).hexdigest() != manifest['files'][name] for name, data in files.items()):
        raise ValueError('Release digest mismatch')
    return raw, files


def main():
    assert os.geteuid() == 0 and socket.gethostname() == 'aegisav-static'
    parser = argparse.ArgumentParser()
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    bundle = Path('/home/ubuntu/aegisav-product-release.tar.gz')
    assert hashlib.sha256(bundle.read_bytes()).hexdigest() == args.sha256
    assert Path('/var/lib/aegisav/managed-operator').exists()
    home = Path('/home/aegisav-operator')
    assert not list(home.glob('batch-*')) and not list(home.glob('*.zip')) and not list(home.glob('*.checkpoint.json'))
    raw, files = verify_bundle(bundle)
    release_id = hashlib.sha256(raw).hexdigest()[:16]
    base = Path('/opt/aegisav-product')
    releases = base / 'releases'
    releases.mkdir(parents=True, exist_ok=True, mode=0o755)
    destination = releases / release_id
    if destination.exists():
        assert (destination / 'release.json').read_bytes() == raw
        assert all((destination / name).read_bytes() == data for name, data in files.items())
    else:
        stage = releases / ('.staging-' + uuid.uuid4().hex)
        stage.mkdir(mode=0o755)
        for name, data in {**files, 'release.json': raw}.items():
            path = stage / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(0o444)
        for path in sorted(stage.rglob('*'), reverse=True):
            if path.is_dir():
                path.chmod(0o555)
        stage.chmod(0o555)
        stage.rename(destination)
    assert all(path.stat().st_uid == 0 and path.stat().st_mode & 0o222 == 0
               for path in [destination, *destination.rglob('*')])
    unit = Path('/etc/systemd/system/aegisav-api.service')
    marker = '# Managed AegisAV product service'
    if unit.exists() and not unit.read_text().startswith(marker):
        raise ValueError('Refusing to replace unmanaged service')
    unit.write_text(f'''{marker}
[Unit]
Description=AegisAV local five-engine static scan API
After=clamav-daemon.service
[Service]
Type=simple
User=aegisav-operator
Group=aegisav-operator
WorkingDirectory={destination}
Environment=PYTHONPATH={destination}/backend
Environment=AEGISAV_MODEL_DIR={destination}/models/ember2024
Environment=AEGISAV_ML_PROFILE=general
Environment=OPENBLAS_NUM_THREADS=1
Environment=OMP_NUM_THREADS=1
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=/opt/aegisav-static/venv/bin/python -m uvicorn aegisav.main:app --host 127.0.0.1 --port 8000 --limit-concurrency 8 --no-access-log
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=/opt/aegisav-product /opt/aegisav-static
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
IPAddressDeny=any
IPAddressAllow=localhost
MemoryMax=3G
TasksMax=96
LimitCORE=0
[Install]
WantedBy=multi-user.target
''')
    link = base / ('.current-' + uuid.uuid4().hex)
    link.symlink_to(destination, target_is_directory=True)
    os.replace(link, base / 'current')
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    subprocess.run(['systemctl', 'enable', 'aegisav-api.service'], check=True)
    print(json.dumps(dict(release_id=release_id, destination=str(destination), service_enabled=True,
                          root_owned_read_only=True, service_started=False)))


if __name__ == '__main__':
    main()
