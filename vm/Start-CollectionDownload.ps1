param([switch]$ClearCredential,[switch]$Expansion)
$ErrorActionPreference = 'Stop'
$vmx = 'D:\VMs\AegisAV-Ubuntu-24.04\guest\AegisAV-Static-Ubuntu\AegisAV-Static-Ubuntu.vmx'
$credential = Import-Clixml -LiteralPath 'D:\VMs\AegisAV-Ubuntu-24.04\media\operator.credential.xml'
$arguments = @('-T','ws','-gu',$credential.UserName,'-gp',$credential.GetNetworkCredential().Password)
if ($ClearCredential) {
    & D:\VM\vmrun.exe @arguments runScriptInGuest $vmx /bin/bash 'set -e; rm -f /home/aegisav-operator/mb-auth.key; test ! -e /home/aegisav-operator/mb-auth.key'
    if ($LASTEXITCODE) { throw 'Guest key removal failed.' }
    return
}
& "$PSScriptRoot/Manage-VM.ps1" -Action CheckNAT
$secretDir = Join-Path $env:USERPROFILE '.codex/secrets/aegisav'
$temporary = Join-Path $secretDir ('guest-transfer-'+[guid]::NewGuid().ToString('N')+'.key')
try {
    $secure = Import-Clixml -LiteralPath (Join-Path $secretDir 'malwarebazaar.auth.xml')
    $key = [Net.NetworkCredential]::new('',$secure).Password
    [IO.File]::WriteAllText($temporary,$key,[Text.UTF8Encoding]::new($false))
    & D:\VM\vmrun.exe @arguments CopyFileFromHostToGuest $vmx $temporary /home/aegisav-operator/mb-auth.key
    if ($LASTEXITCODE) { throw 'Restricted key transfer failed.' }
    $wrapper=if($Expansion){'/usr/local/sbin/aegisav-expansion'}else{'/usr/local/sbin/aegisav-collection'}
    & D:\VM\vmrun.exe @arguments runScriptInGuest $vmx /bin/bash "set -e; chmod 0600 /home/aegisav-operator/mb-auth.key; sudo $wrapper download"
    if ($LASTEXITCODE) { throw 'Collection service start failed.' }
} finally {
    $key = $null
    $secure = $null
    $credential = $null
    $arguments = $null
    Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
}
'Encrypted-only collection started. Clear guest credential before offline analysis.'
