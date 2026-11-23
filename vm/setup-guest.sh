#!/usr/bin/env bash
set -euo pipefail

if (( EUID != 0 )); then
    echo 'Run as root inside the dedicated AegisAV Ubuntu VM.' >&2
    exit 1
fi

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
config=/etc/clamav/clamd.conf
sed -i '/^TCPSocket /d; /^TCPAddr /d; /^StreamMaxLength /d; /^MaxFileSize /d; /^MaxScanSize /d; /^MaxEmbeddedPE /d; /^PCREMaxFileSize /d; /^AlertExceedsMax /d' "$config"
sed -i 's/^EnableVersionCommand false$/EnableVersionCommand true/' "$config"
printf 'TCPSocket 3310\nTCPAddr 127.0.0.1\nStreamMaxLength 64M\nMaxFileSize 64M\nMaxScanSize 128M\nMaxEmbeddedPE 64M\nPCREMaxFileSize 64M\nAlertExceedsMax yes\n' >> "$config"
install -m 0755 "$script_dir/guest-isolation-check.sh" /usr/local/bin/aegisav-isolation-check
python3 - <<'PY'
import configparser
from pathlib import Path
path = Path('/etc/vmware-tools/tools.conf')
config = configparser.ConfigParser(interpolation=None)
config.optionxform = str
config.read(path)
if not config.has_section('logging'):
    config.add_section('logging')
for key, value in {'log': 'true', 'hgfsclient.level': 'warning', 'hgfsclient.handler': 'std',
                   'hgfsClient.level': 'warning', 'hgfsClient.handler': 'std'}.items():
    config.set('logging', key, value)
with path.open('w') as stream:
    config.write(stream)
PY
install -m 0644 "$script_dir/aegisav-isolation-report.service" /etc/systemd/system/aegisav-isolation-report.service
systemctl daemon-reload
systemctl enable aegisav-isolation-report.service
systemctl disable --now clamav-freshclam.service

echo 'Guest configuration installed. Wait for official ClamAV databases before starting clamd.'
