#!/usr/bin/env bash
set -euo pipefail
[[ $EUID == 0 && $(hostname) == aegisav-static ]]
base=/opt/aegisav-collection
volume=/srv/aegisav-corpus
[[ -f $base/collect_malwarebazaar.py && -f $base/candidates.json ]]
if ! blkid /dev/sdb >/dev/null 2>&1; then
    [[ $(blockdev --getsize64 /dev/sdb) == 12884901888 ]]
    [[ -z $(lsblk -n -o FSTYPE /dev/sdb) && $(lsblk -n -o NAME /dev/sdb | wc -l) == 1 ]]
    mkfs.ext4 -L aegisav-corpus /dev/sdb
fi
[[ $(blkid -s LABEL -o value /dev/sdb) == aegisav-corpus ]]
uuid=$(blkid -s UUID -o value /dev/sdb)
mkdir -p "$volume"
if ! grep -q "UUID=$uuid " /etc/fstab; then
    printf 'UUID=%s %s ext4 defaults,nodev,nosuid,noexec 0 2\n' "$uuid" "$volume" >> /etc/fstab
fi
mountpoint -q "$volume" || mount "$volume"
[[ $(findmnt -n -o OPTIONS "$volume") == *noexec* ]]
id aegisav-fetch >/dev/null 2>&1 || useradd --uid 1002 --system --no-create-home --shell /usr/sbin/nologin aegisav-fetch
[[ $(id -u aegisav-fetch) == 1002 && $(id -u aegisav-operator) == 1001 ]]
getent group aegisav-corpus >/dev/null || groupadd aegisav-corpus
usermod -a -G aegisav-corpus aegisav-fetch
usermod -a -G aegisav-corpus aegisav-operator
chown root:aegisav-corpus "$volume"
chmod 0750 "$volume"
printf 'aegisav-corpus-v1\n' > "$volume/.aegisav-corpus"
chmod 0444 "$volume/.aegisav-corpus"
install -d -m 0750 -o aegisav-fetch -g aegisav-corpus "$volume/incoming"
install -d -m 0700 -o aegisav-operator -g aegisav-operator "$volume/raw" "$volume/results"
install -d -m 0700 -o root -g root "$volume/evidence"
chown -R root:root "$base"
find "$base" -type d -exec chmod 0755 {} +
find "$base" -type f -exec chmod 0444 {} +
cat > /etc/systemd/system/aegisav-fetch.service <<'UNIT'
[Unit]
Description=AegisAV encrypted-only MalwareBazaar collection
After=network-online.target
Wants=network-online.target
RequiresMountsFor=/srv/aegisav-corpus
[Service]
Type=oneshot
User=aegisav-fetch
Group=aegisav-corpus
LoadCredential=auth.key:/home/aegisav-operator/mb-auth.key
EnvironmentFile=-/run/aegisav-collection/fetch.env
ExecStart=/usr/bin/python3 -I /opt/aegisav-collection/collect_malwarebazaar.py download
TimeoutStartSec=90min
MemoryMax=256M
TasksMax=16
CPUQuota=100%
UMask=0027
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
ReadWritePaths=/srv/aegisav-corpus/incoming
UNIT
cat > /etc/systemd/system/aegisav-analysis.service <<'UNIT'
[Unit]
Description=AegisAV offline static pilot analysis
RequiresMountsFor=/srv/aegisav-corpus
[Service]
Type=oneshot
User=aegisav-operator
Group=aegisav-operator
SupplementaryGroups=aegisav-corpus
EnvironmentFile=-/run/aegisav-collection/analysis.env
ExecStart=/opt/aegisav-static/venv/bin/python -I /opt/aegisav-collection/collect_malwarebazaar.py analyze
TimeoutStartSec=90min
MemoryMax=3G
TasksMax=64
CPUQuota=200%
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
ReadWritePaths=/srv/aegisav-corpus/raw /srv/aegisav-corpus/results
NoExecPaths=/srv/aegisav-corpus
UNIT
cat > /usr/local/sbin/aegisav-collection <<'WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
[[ $EUID == 0 && $# == 1 && $(hostname) == aegisav-static ]]
mountpoint -q /srv/aegisav-corpus
install -d -m 0700 /run/aegisav-collection
retry=0
[[ $1 != *-retry ]] || retry=1
case "$1" in
download|download-retry)
    [[ -n $(ip -4 route show default) ]]
    systemctl stop aegisav-api.service aegisav-analysis.service clamav-daemon.service clamav-daemon.socket
    /usr/local/sbin/aegisav-online-firewall
    printf 'AEGISAV_RETRY_FAILED=%s\n' "$retry" > /run/aegisav-collection/fetch.env
    systemctl start --no-block aegisav-fetch.service
    ;;
analyze|analyze-retry)
    /usr/local/bin/aegisav-isolation-check
    [[ ! -e /home/aegisav-operator/mb-auth.key ]]
    systemctl stop aegisav-fetch.service
    printf 'AEGISAV_RETRY_FAILED=%s\n' "$retry" > /run/aegisav-collection/analysis.env
    systemctl start clamav-daemon.service
    /usr/bin/python3 - <<'PY'
import socket,time
for _ in range(60):
    try:
        with socket.create_connection(('127.0.0.1',3310),timeout=1) as s:
            s.sendall(b'zPING\0')
            if s.recv(32)==b'PONG\0':
                break
    except OSError:
        pass
    time.sleep(1)
else:
    raise SystemExit('ClamAV readiness failed')
PY
    systemctl start --no-block aegisav-analysis.service
    ;;
*) exit 2;;
esac
WRAPPER
cat > /usr/local/sbin/aegisav-online-firewall <<'FIREWALL'
#!/usr/bin/env bash
set -euo pipefail
[[ $EUID == 0 && $(hostname) == aegisav-static ]]
nft list table inet aegisav_collect >/dev/null 2>&1 && nft delete table inet aegisav_collect
nft -f - <<'RULES'
table inet aegisav_collect {
 chain input {
  type filter hook input priority -10; policy drop;
  iifname lo accept
  ct state established,related accept
  udp sport 67 udp dport 68 accept
 }
 chain output {
  type filter hook output priority -10; policy drop;
  oifname lo accept
  ct state established,related accept
  udp sport 68 udp dport 67 accept
  meta skuid { 1002, "systemd-resolve" } udp dport 53 accept
  meta skuid { 1002, "systemd-resolve" } tcp dport 53 accept
  ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4 } reject
  meta nfproto ipv6 reject
  meta skuid 1002 tcp dport 443 accept
 }
}
RULES
FIREWALL
chmod 0755 /usr/local/sbin/aegisav-collection /usr/local/sbin/aegisav-online-firewall
cat > /etc/systemd/system/aegisav-collection-firewall.service <<'UNIT'
[Unit]
Description=AegisAV collection guest network policy
DefaultDependencies=no
After=local-fs.target
Before=network-pre.target
Wants=network-pre.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/aegisav-online-firewall
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
UNIT
printf 'aegisav-operator ALL=(root) NOPASSWD: /usr/local/sbin/aegisav-collection download, /usr/local/sbin/aegisav-collection download-retry, /usr/local/sbin/aegisav-collection analyze, /usr/local/sbin/aegisav-collection analyze-retry\n' > /etc/sudoers.d/aegisav-collection
chmod 0440 /etc/sudoers.d/aegisav-collection
visudo -cf /etc/sudoers.d/aegisav-collection
systemctl daemon-reload
systemctl enable aegisav-collection-firewall.service
systemctl disable --now aegisav-api.service clamav-freshclam.service
systemctl disable --now ssh.service ssh.socket
systemctl disable clamav-daemon.service clamav-daemon.socket
printf 'COLLECTION_SETUP PASS uuid=%s\n' "$uuid"
