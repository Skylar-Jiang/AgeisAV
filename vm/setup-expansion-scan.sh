#!/usr/bin/env bash
set -euo pipefail
[[ $EUID == 0 && $(hostname) == aegisav-static ]]
/usr/local/bin/aegisav-isolation-check
[[ ! -e /home/aegisav-operator/mb-auth.key ]]
mountpoint -q /srv/aegisav-corpus
scope=/srv/aegisav-corpus/cohorts/76816a606721f48e00f696a5f265409aa72b9d5182672f24f46952075dc4b221
[[ $(sha256sum /opt/aegisav-expansion-scan/plan.json | cut -d' ' -f1) == f5a9958fb15c1bc3cde172f737b7aa3d559b5c3646bfe088c5a636c63be7b808 ]]
install -d -m 0700 -o aegisav-operator -g aegisav-operator "$scope/results/development-scan-v1"
cat > /etc/systemd/system/aegisav-expansion-scan.service <<UNIT
[Unit]
Description=AegisAV paired development expansion scan
RequiresMountsFor=/srv/aegisav-corpus
Requires=clamav-daemon.service
After=clamav-daemon.service
ConditionPathExists=!/home/aegisav-operator/mb-auth.key
[Service]
Type=oneshot
RemainAfterExit=yes
User=aegisav-operator
Group=aegisav-operator
SupplementaryGroups=aegisav-corpus
ExecStartPre=/opt/aegisav-static/venv/bin/python -I /opt/aegisav-expansion-scan/expansion_clam_ready.py
ExecStart=/opt/aegisav-static/venv/bin/python -I /opt/aegisav-expansion-scan/scan_expansion.py
TimeoutStartSec=90min
MemoryMax=3G
MemoryAccounting=yes
CPUAccounting=yes
CPUQuota=200%
TasksMax=64
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
IPAddressDeny=any
IPAddressAllow=localhost
ReadWritePaths=$scope/results/development-scan-v1
ReadOnlyPaths=$scope/raw
NoExecPaths=/srv/aegisav-corpus
UNIT
install -d -m 0755 /etc/systemd/system/clamav-daemon.service.d
cat > /etc/systemd/system/clamav-daemon.service.d/aegisav-resources.conf <<'LIMITS'
[Service]
MemoryMax=2560M
CPUQuota=200%
TasksMax=128
LIMITS
systemctl daemon-reload
systemd-analyze verify aegisav-expansion-scan.service
printf 'DEVELOPMENT_SCAN_SETUP PASS\n'
