# Run with powershell.exe (5.1). Exercises native argument handling using guest-only inert text.
$ErrorActionPreference='Stop'
$vmx='D:\VMs\AegisAV-Ubuntu-24.04\guest\AegisAV-Static-Ubuntu\AegisAV-Static-Ubuntu.vmx'
$vmrun='D:\VM\vmrun.exe'
$tokens=$null;$parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Set-GuestKeyByHuman.ps1'),[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count){throw 'Human script parse failed'}
$strings=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.StringConstantExpressionAst]},$true) | ForEach-Object {$_.Value})
$preflight=@($strings | Where-Object {$_ -like 'set -e; /usr/local/bin/aegisav-isolation-check;*'})
$finalize=@($strings | Where-Object {$_ -like 'set -e; umask 077; chmod 0600 __TEMP__;*'})
$cleanup=@($strings | Where-Object {$_ -like 'set -e; rm -f -- __TEMP__;*'})
if($preflight.Count -ne 1 -or $finalize.Count -ne 1 -or $cleanup.Count -ne 1){throw 'Expected actual script constants'}
$id=[guid]::NewGuid().ToString('N')
$temporary='/home/aegisav-operator/.inert-native-'+$id
$result=$temporary+'.result'
$login=Import-Clixml -LiteralPath 'D:\VMs\AegisAV-Ubuntu-24.04\media\operator.credential.xml'
if($login.UserName -ne 'aegisav-operator'){throw 'Unexpected test identity'}
$argsVm=@('-T','ws','-gu',$login.UserName,'-gp',$login.GetNetworkCredential().Password)
try {
    & $vmrun @argsVm runScriptInGuest $vmx /bin/bash $preflight[0]
    if($LASTEXITCODE){throw 'Actual preflight native-argument regression'}
    & $vmrun @argsVm runScriptInGuest $vmx /bin/bash ('set -e; umask 077; printf INERT_NATIVE_ARGUMENT_FIXTURE > '+$temporary)
    if($LASTEXITCODE){throw 'Inert guest fixture creation failed'}
    $final=$finalize[0].Replace('__TEMP__',$temporary).Replace('/home/aegisav-operator/mb-auth.key',$result)
    & $vmrun @argsVm runScriptInGuest $vmx /bin/bash $final
    if($LASTEXITCODE){throw 'Actual finalization native-argument regression'}
    $verify='set -e; test -f '+$result+'; stat -c %a '+$result+' | grep -qx 600; stat -c %U '+$result+' | grep -qx aegisav-operator; grep -qx INERT_NATIVE_ARGUMENT_FIXTURE '+$result
    & $vmrun @argsVm runScriptInGuest $vmx /bin/bash $verify
    if($LASTEXITCODE){throw 'Inert result contents or permissions failed'}
    & $vmrun @argsVm runScriptInGuest $vmx /bin/bash ($cleanup[0].Replace('__TEMP__',$result))
    if($LASTEXITCODE){throw 'Actual cleanup native-argument regression'}
    Write-Output ('PASS: PowerShell '+$PSVersionTable.PSVersion.ToString()+' actual preflight/finalization/0600-owner/content/cleanup; no API key requested or transferred')
} finally {
    & $vmrun @argsVm runScriptInGuest $vmx /bin/bash ('rm -f -- '+$temporary+' '+$result) | Out-Null
    $login=$null;$argsVm=$null
}
