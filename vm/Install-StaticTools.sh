#!/bin/bash
# Run only during benign guest preparation, before the clean snapshot.
set -euo pipefail
[[ $(id -u) == 0 ]] || { echo 'Root required to install immutable scanner code' >&2; exit 1; }
test -f /home/ubuntu/static-guest-tools.tar.gz
test -x /home/ubuntu/aegisav/.venv/bin/python
mkdir -p /opt/aegisav-static/venv
tar -xzf /home/ubuntu/static-guest-tools.tar.gz -C /opt/aegisav-static
cp -a /home/ubuntu/aegisav/.venv/. /opt/aegisav-static/venv/
cp /opt/aegisav-static/vm/static_archive.py /opt/aegisav-static/static_archive.py
cp /opt/aegisav-static/vm/static_ember.py /opt/aegisav-static/static_ember.py
cp /opt/aegisav-static/vm/static_benign.py /opt/aegisav-static/static_benign.py
chown -R root:root /opt/aegisav-static
chmod -R go-w,a+rX /opt/aegisav-static
sudo -u aegisav-operator /opt/aegisav-static/venv/bin/python -c 'import pefile,tlsh,ppdeep,yara_x'
sudo -u aegisav-operator test ! -w /opt/aegisav-static/static_archive.py
sudo -u aegisav-operator test ! -w /opt/aegisav-static/rules/hashes.json
echo 'Non-root scanner dependencies and immutable code PASS'
