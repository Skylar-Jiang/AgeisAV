param([Parameter(Mandatory)][ValidatePattern('^192\.168\.84\.\d+$')][string] $GuestAddress)
$ErrorActionPreference = 'Stop'
$vmx = 'D:\VMs\AegisAV-Ubuntu-24.04\guest\AegisAV-Static-Ubuntu\AegisAV-Static-Ubuntu.vmx'
if ((Get-Content -LiteralPath $vmx -Raw) -notmatch '(?im)^\s*ethernet0.connectionType\s*=\s*"hostonly"\s*$') {
    throw 'Deploy only to the clean dedicated guest in Host-only preparation mode.'
}
$connection = @('-i', "$env:USERPROFILE\.ssh\aegisav_vm_ed25519", '-o', 'BatchMode=yes',
    '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=D:\VMs\AegisAV-Ubuntu-24.04\media\known_hosts')
$target = "ubuntu@$GuestAddress"
& ssh @connection $target 'set -eu; test "$(hostname)" = aegisav-static; test -f /var/lib/aegisav/managed-operator; test -z "$(sudo find /home/aegisav-operator -maxdepth 1 \( -name "batch-*" -o -name "*.zip" -o -name "*.checkpoint.json" \) -print -quit)"'
if ($LASTEXITCODE) { throw 'Clean dedicated guest guard failed.' }
foreach ($name in @('benign_checkpoint.py', 'static_benign.py')) {
    & scp @connection (Join-Path $PSScriptRoot $name) "${target}:/home/ubuntu/$name"
    if ($LASTEXITCODE) { throw 'Trusted runner upload failed.' }
    $digest = (Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $name)).Hash.ToLowerInvariant()
    & ssh @connection $target "set -eu; echo '$digest  /home/ubuntu/$name' | sha256sum -c -; sudo install -o root -g root -m 0644 /home/ubuntu/$name /opt/aegisav-static/$name"
    if ($LASTEXITCODE) { throw 'Trusted runner install failed.' }
}
& ssh @connection $target 'sudo /opt/aegisav-static/venv/bin/python -m py_compile /opt/aegisav-static/static_benign.py /opt/aegisav-static/benign_checkpoint.py'
if ($LASTEXITCODE) { throw 'Guest Python validation failed.' }
