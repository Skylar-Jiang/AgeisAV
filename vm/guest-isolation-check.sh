#!/usr/bin/env bash
set -uo pipefail

problems=()
for tool in find sort ip vmware-hgfsclient findmnt grep date; do
    if ! command -v "$tool" >/dev/null; then
        printf 'AEGISAV_ISOLATION FAIL required-tool-missing=%s\n' "$tool"
        exit 1
    fi
done
if ! interfaces=$(find /sys/class/net -mindepth 1 -maxdepth 1 -printf '%f\n' | sort); then
    problems+=("interface-query-failed")
fi
if [[ "$interfaces" != "lo" ]]; then problems+=("interfaces=$interfaces"); fi
for family in -4 -6; do
    if ! routes=$(ip "$family" route show); then problems+=("route-query-failed=$family");
    elif [[ -n "$routes" ]]; then problems+=("routes-present=$family"); fi
done
hgfs_state=none
shares=$(vmware-hgfsclient 2>&1)
share_status=$?
if (( share_status == 1 )) && [[ "$shares" == *"HGFS is disabled in the host"* && "$shares" != *"Failed"* && "$shares" != *"Error"* ]]; then
    hgfs_state=disabled
elif (( share_status != 0 )); then problems+=("share-query-failed");
elif [[ -n "$shares" ]]; then problems+=("shared-folders-visible"); fi
mounts=$(findmnt -rn -t vmhgfs,fuse.vmhgfs-fuse)
mount_status=$?
if (( mount_status > 1 )); then problems+=("mount-query-failed");
elif [[ -n "$mounts" ]]; then problems+=("hgfs-mounted"); fi
boot_id=$(< /proc/sys/kernel/random/boot_id)

if (( ${#problems[@]} == 0 )); then
    printf 'AEGISAV_ISOLATION PASS %s boot=%s interfaces=lo routes=none hgfs=%s\n' "$(date -u +%FT%TZ)" "$boot_id" "$hgfs_state"
else
    printf 'AEGISAV_ISOLATION FAIL %s %s\n' "$(date -u +%FT%TZ)" "${problems[*]}"
    exit 1
fi
