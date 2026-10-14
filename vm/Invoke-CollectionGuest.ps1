param([Parameter(Mandatory)][string]$Script)
# Administration commands only. Never pass secrets or commands that print raw samples.
$ErrorActionPreference = 'Stop'
$vmx = 'D:\VMs\AegisAV-Ubuntu-24.04\guest\AegisAV-Static-Ubuntu\AegisAV-Static-Ubuntu.vmx'
$media = 'D:\VMs\AegisAV-Ubuntu-24.04\media'
$credential = Import-Clixml -LiteralPath (Join-Path $media 'admin.credential.xml')
if ($credential.UserName -ne 'ubuntu') { throw 'Unexpected administration identity.' }
$arguments = @('-T','ws','-gu',$credential.UserName,'-gp',$credential.GetNetworkCredential().Password)
$log = '/home/ubuntu/collection-operation.log'
& D:\VM\vmrun.exe @arguments runScriptInGuest $vmx /bin/bash "{ $Script; } > $log 2>&1"
$code = $LASTEXITCODE
& D:\VM\vmrun.exe @arguments CopyFileFromGuestToHost $vmx $log (Join-Path $media 'collection-operation.log')
if ($LASTEXITCODE) { throw 'Could not retrieve administration output.' }
$credential = $null
$arguments = $null
Get-Content -LiteralPath (Join-Path $media 'collection-operation.log') -TotalCount 120
if ($code) { throw "Guest administration failed, exit $code." }
