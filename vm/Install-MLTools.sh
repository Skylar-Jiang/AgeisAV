#!/usr/bin/env bash
# Sample-free dedicated guest preparation only. Never enable network during analysis.
set -euo pipefail
[[ $EUID == 0 && $(hostname) == aegisav-static ]] || { echo 'Dedicated guest root required' >&2; exit 1; }
[[ -z $(find /home/aegisav-operator -maxdepth 1 -name 'batch-*' -print -quit) ]] || {
    echo 'Restore a known clean snapshot before online preparation' >&2; exit 1;
}
ip route show default | grep -q . || { echo 'Clean online preparation required' >&2; exit 1; }
export DEBIAN_FRONTEND=noninteractive
apt-get install -y --no-install-recommends libgomp1
python=/opt/aegisav-static/venv/bin/python
"$python" -m pip --isolated install --index-url https://pypi.org/simple \
    lightgbm==4.6.0 numpy==2.2.6 scikit-learn==1.6.1 scipy==1.18.1 signify==0.7.1
# Upstream oscrypto 1.3.0 has a single-digit OpenSSL version regex: 3.0.13 fails.
# Use fixed upstream source, retaining the original EMBER certificate feature extractor.
"$python" -m pip --isolated install --force-reinstall --no-deps \
    'https://codeload.github.com/wbond/oscrypto/zip/76bfdcb7285d856c44f8d0fbafe0ecca1c6d2f8b#sha256=0487384201929932548ad3da31fd65f12de1df86288aa50533b7efd96ae76b53'
"$python" -m pip check
"$python" -m pip freeze > /opt/aegisav-static/ember/guest-requirements-lock.txt
chown -R root:root /opt/aegisav-static
chmod -R a+rX,go-w /opt/aegisav-static
sudo -u aegisav-operator env PYTHONPATH=/opt/aegisav-static OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 \
    "$python" -c 'from pathlib import Path; from static_ember import EmberEngine; EmberEngine(Path("/opt/aegisav-static/ember")); print("Pinned EMBER model load PASS")'
