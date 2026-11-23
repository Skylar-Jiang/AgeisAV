param([Parameter(Mandatory)][ValidatePattern('^192\.168\.84\.\d+$')][string] $GuestAddress)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$vmx = 'D:\VMs\AegisAV-Ubuntu-24.04\guest\AegisAV-Static-Ubuntu\AegisAV-Static-Ubuntu.vmx'
if ((Get-Content -LiteralPath $vmx -Raw) -notmatch '(?im)^\s*ethernet0.connectionType\s*=\s*"hostonly"\s*$') {
    throw 'Publish only in sample-free Host-only preparation mode.'
}
$release = Get-Content -LiteralPath (Join-Path $repo 'artifacts/product-release-latest.json') -Raw | ConvertFrom-Json
$bundle = [IO.Path]::GetFullPath($release.bundle)
$expected = Join-Path $repo "artifacts\product-release-$($release.release_id).tar.gz"
if ($release.release_id -notmatch '^[a-f0-9]{16}$' -or $bundle -ne [IO.Path]::GetFullPath($expected) -or
    (Get-FileHash -LiteralPath $bundle).Hash.ToLowerInvariant() -ne $release.sha256) { throw 'Invalid trusted local release.' }
$connection = @('-i', "$env:USERPROFILE\.ssh\aegisav_vm_ed25519", '-o', 'BatchMode=yes',
    '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=D:\VMs\AegisAV-Ubuntu-24.04\media\known_hosts')
$target = "ubuntu@$GuestAddress"
& ssh @connection $target 'set -eu; test "$(hostname)" = aegisav-static; test -f /var/lib/aegisav/managed-operator; test -z "$(sudo find /home/aegisav-operator -maxdepth 1 \( -name "batch-*" -o -name "*.zip" -o -name "*.checkpoint.json" \) -print -quit)"'
if ($LASTEXITCODE) { throw 'Clean dedicated guest guard failed.' }
& scp @connection $bundle "${target}:/home/ubuntu/aegisav-product-release.tar.gz"
if ($LASTEXITCODE) { throw 'Trusted release upload failed.' }
$installer = Join-Path $PSScriptRoot 'install_product_release.py'
& scp @connection $installer "${target}:/home/ubuntu/install_product_release.py"
if ($LASTEXITCODE) { throw 'Installer upload failed.' }
$digest = (Get-FileHash -LiteralPath $installer).Hash.ToLowerInvariant()
& ssh @connection $target "set -eu; echo '$digest  /home/ubuntu/install_product_release.py' | sha256sum -c -; sudo python3 /home/ubuntu/install_product_release.py --sha256 $($release.sha256)"
if ($LASTEXITCODE) { throw 'Root release installation failed.' }
