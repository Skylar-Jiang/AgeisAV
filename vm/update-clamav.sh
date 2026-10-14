#!/usr/bin/env bash
# Only after restoring a known clean, sample-free dedicated VM, while online.
set -euo pipefail
[[ $EUID == 0 && $(hostname) == aegisav-static ]] || { echo 'Dedicated guest root required' >&2; exit 1; }
[[ -z $(find /home/aegisav-operator -maxdepth 1 -name 'batch-*' -print -quit) ]] || {
    echo 'Restore the clean snapshot before connecting or updating' >&2; exit 1;
}
ip route show default | grep -q . || { echo 'Clean online preparation required' >&2; exit 1; }
report=/var/log/aegisav-clamav-update-$(date -u +%Y%m%dT%H%M%SZ)
mkdir -m 0755 "$report"
trap 'systemctl disable --now clamav-freshclam.service >/dev/null 2>&1 || true' EXIT
systemctl stop clamav-freshclam.service
clamscan --version > "$report/before.txt"
# Official freshclam performs signed database validation and incremental updates.
# Do not bypass CDN cooldowns, replace mirrors, or repeatedly retry failed downloads.
timeout 300 freshclam --stdout --checks=1 > "$report/update.txt" 2>&1
for db in /var/lib/clamav/*.cvd /var/lib/clamav/*.cld; do
    [[ -f $db ]] || continue
    sigtool --info "$db" >> "$report/databases.txt"
    sha256sum "$db" >> "$report/databases.sha256"
done
systemctl restart clamav-daemon.service
python3 - <<'PY'
import socket, time
for attempt in range(120):
    try:
        with socket.create_connection(('127.0.0.1', 3310), timeout=2) as sock:
            sock.sendall(b'zVERSION\0')
            result = sock.recv(4096).decode().strip('\0\n')
            if result.startswith('ClamAV '):
                print(result)
                break
    except OSError:
        pass
    time.sleep(1)
else:
    raise SystemExit('ClamAV readiness failed')
PY
clamconf > "$report/effective-config.txt"
clamscan --version > "$report/after.txt"
chmod -R a+rX,go-w "$report"
echo "Verified update and frozen database: $report"
