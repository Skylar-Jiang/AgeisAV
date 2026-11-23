#!/usr/bin/env bash
set -euo pipefail
checker=$(cd -- "$(dirname -- "$0")/.." && pwd)/guest-isolation-check.sh

# An unavailable network/share query must never produce PASS.
find() { printf 'lo\n'; }
ip() { return 1; }
vmware-hgfsclient() { return 1; }
findmnt() { return 1; }
export -f find ip vmware-hgfsclient findmnt
if output=$(bash "$checker" 2>&1); then
    printf 'FAIL: failed queries were accepted: %s\n' "$output" >&2
    exit 1
fi
if [[ "$output" != *AEGISAV_ISOLATION\ FAIL* ]]; then
    printf 'FAIL: checker did not report failure: %s\n' "$output" >&2
    exit 1
fi
printf 'PASS: failed queries block isolation approval\n'

# open-vm-tools explicitly reports disabled HGFS with exit status 1.
ip() { return 0; }
vmware-hgfsclient() { echo 'HGFS is disabled in the host' >&2; return 1; }
export -f ip vmware-hgfsclient
output=$(bash "$checker")
[[ "$output" == *AEGISAV_ISOLATION\ PASS* && "$output" == *hgfs=disabled* ]]
printf 'PASS: explicit disabled HGFS is distinguished from a query failure\n'

vmware-hgfsclient() { echo 'visible-share'; return 0; }
export -f vmware-hgfsclient
if output=$(bash "$checker"); then
    printf 'FAIL: a visible shared folder was accepted\n' >&2
    exit 1
fi
[[ "$output" == *shared-folders-visible* ]]
printf 'PASS: visible shares block isolation approval\n'
