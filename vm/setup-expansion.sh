#!/usr/bin/env bash
set -euo pipefail
[[ $EUID == 0 && $(hostname) == aegisav-static ]]
base=/opt/aegisav-collection-v2
volume=/srv/aegisav-corpus
mountpoint -q "$volume"
[[ $(cat "$volume/.aegisav-corpus") == aegisav-corpus-v1 ]]
[[ $(findmnt -n -o OPTIONS "$volume") == *noexec* ]]
[[ $(id -u aegisav-fetch) == 1002 && $(id -u aegisav-operator) == 1001 ]]
systemctl stop aegisav-api.service aegisav-analysis.service aegisav-fetch.service clamav-daemon.service clamav-daemon.socket
cohort=$(sha256sum "$base/candidates.json" | cut -d' ' -f1)
scope=$volume/cohorts/$cohort
install -d -m 0750 -o root -g aegisav-corpus "$volume/cohorts" "$scope"
install -d -m 0750 -o aegisav-fetch -g aegisav-corpus "$scope/incoming"
install -d -m 0700 -o aegisav-operator -g aegisav-operator "$scope/raw" "$scope/results"
install -d -m 0700 -o aegisav-fetch -g aegisav-fetch "$volume/budget"
if [[ ! -f $volume/budget/request-budget.json ]]; then
    install -m 0600 -o aegisav-fetch -g aegisav-fetch "$volume/incoming/request-budget.json" "$volume/budget/request-budget.json"
fi
install -m 0444 -o root -g root "$base/candidates.json" "$scope/manifest.json"
# Completed pilot encrypted evidence is immutable to both nonprivileged roles.
chown root:aegisav-corpus "$volume/incoming"
find "$volume/incoming" -maxdepth 1 -type f -exec chown root:aegisav-corpus {} +
find "$volume/incoming" -maxdepth 1 -type f -exec chmod 0440 {} +
chown -R root:root "$base"
find "$base" -type d -exec chmod 0755 {} +
find "$base" -type f -exec chmod 0444 {} +
[[ -L $base/deps ]] || ln -s /opt/aegisav-collection/deps "$base/deps"
export AEGISAV_EXPANSION_SCOPE="$scope"
/usr/bin/python3 - <<'PY'
from pathlib import Path
import os
scope=os.environ['AEGISAV_EXPANSION_SCOPE']
for role in ('fetch','analysis'):
    source=Path('/etc/systemd/system/aegisav-'+role+'.service').read_text()
    source=source.replace('/opt/aegisav-collection/collect_malwarebazaar.py','/opt/aegisav-collection-v2/collect_malwarebazaar.py')
    if role=='fetch':
        source=source.replace('[Unit]','[Unit]\nOnSuccess=aegisav-expansion-key-cleanup.service\nOnFailure=aegisav-expansion-key-cleanup.service',1)
        source=source.replace('/srv/aegisav-corpus/incoming',scope+'/incoming /srv/aegisav-corpus/budget')
    else:
        source=source.replace('[Service]','[Service]\nRemainAfterExit=yes\nCPUAccounting=yes',1)
        source=source.replace('collect_malwarebazaar.py analyze','collect_malwarebazaar.py analyze --acquire-only')
        source=source.replace('/srv/aegisav-corpus/raw',scope+'/raw').replace('/srv/aegisav-corpus/results',scope+'/results')
    Path('/etc/systemd/system/aegisav-expansion-'+role+'.service').write_text(source)
PY
cat > /etc/systemd/system/aegisav-expansion-key-cleanup.service <<'UNIT'
[Unit]
Description=Remove temporary AegisAV API credential after collection
[Service]
Type=oneshot
ExecStart=/usr/bin/rm -f /home/aegisav-operator/mb-auth.key
NoNewPrivileges=yes
UNIT
cat > /usr/local/sbin/aegisav-expansion <<'WRAPPER'
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
    state=$(systemctl show aegisav-expansion-fetch.service -p ActiveState --value)
    [[ $state != active && $state != activating && $state != deactivating ]]
    systemctl stop aegisav-api.service aegisav-analysis.service aegisav-expansion-analysis.service clamav-daemon.service clamav-daemon.socket
    /usr/local/sbin/aegisav-online-firewall
    printf 'AEGISAV_RETRY_FAILED=%s\n' "$retry" > /run/aegisav-collection/fetch.env
    systemctl start --no-block aegisav-expansion-fetch.service
    ;;
acquire|acquire-retry)
    /usr/local/bin/aegisav-isolation-check
    [[ ! -e /home/aegisav-operator/mb-auth.key ]]
    systemctl stop aegisav-fetch.service aegisav-expansion-fetch.service aegisav-api.service clamav-daemon.service clamav-daemon.socket aegisav-expansion-analysis.service
    printf 'AEGISAV_RETRY_FAILED=%s\n' "$retry" > /run/aegisav-collection/analysis.env
    systemctl start --no-block aegisav-expansion-analysis.service
    ;;
*) exit 2;;
esac
WRAPPER
chmod 0755 /usr/local/sbin/aegisav-expansion
printf 'aegisav-operator ALL=(root) NOPASSWD: /usr/local/sbin/aegisav-expansion download, /usr/local/sbin/aegisav-expansion download-retry, /usr/local/sbin/aegisav-expansion acquire, /usr/local/sbin/aegisav-expansion acquire-retry\n' > /etc/sudoers.d/aegisav-expansion
chmod 0440 /etc/sudoers.d/aegisav-expansion
visudo -cf /etc/sudoers.d/aegisav-expansion
systemctl daemon-reload
systemd-analyze verify aegisav-expansion-fetch.service aegisav-expansion-analysis.service aegisav-expansion-key-cleanup.service
printf 'EXPANSION_SETUP PASS cohort=%s\n' "$cohort"
