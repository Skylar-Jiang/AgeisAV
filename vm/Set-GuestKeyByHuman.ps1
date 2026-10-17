# Human-run only. Never invoke this script through the agent or put a key in arguments.
$ErrorActionPreference='Stop'
if([Console]::IsInputRedirected){throw 'Run personally in an interactive PowerShell terminal'}
$vmx='D:\VMs\AegisAV-Ubuntu-24.04\guest\AegisAV-Static-Ubuntu\AegisAV-Static-Ubuntu.vmx'
$vmrun='D:\VM\vmrun.exe'
& "$PSScriptRoot/Manage-VM.ps1" -Action CheckOffline
$running=@(& $vmrun -T ws list)
if($LASTEXITCODE -or $running -notcontains $vmx){throw 'The existing offline VM must already be running'}
$base=Join-Path $env:LOCALAPPDATA 'AegisAV'
[IO.Directory]::CreateDirectory($base) | Out-Null
if((Get-Item -LiteralPath $base).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Credential temporary base must not be a reparse point'}
$directory=Join-Path $base ('human-key-'+[guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($directory) | Out-Null
$acl=[Security.AccessControl.DirectorySecurity]::new()
$acl.SetAccessRuleProtection($true,$false)
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
$inherit=[Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
foreach($identity in @($sid,[Security.Principal.SecurityIdentifier]::new('S-1-5-18'))){
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($identity,'FullControl',$inherit,'None','Allow'))
}
Set-Acl -LiteralPath $directory -AclObject $acl
$temporary=Join-Path $directory 'input.key'
$guestTemporary='/home/aegisav-operator/.manual-key-'+[guid]::NewGuid().ToString('N')
$login=$null;$argsVm=$null;$secret=$null;$pointer=[IntPtr]::Zero
$guestTransferAttempted=$false
try {
    # Existing VM login only; the Windows MalwareBazaar DPAPI store is never read.
    $login=Import-Clixml -LiteralPath 'D:\VMs\AegisAV-Ubuntu-24.04\media\operator.credential.xml'
    if($login.UserName -ne 'aegisav-operator'){throw 'Unexpected VM identity'}
    $argsVm=@('-T','ws','-gu',$login.UserName,'-gp',$login.GetNetworkCredential().Password)
    & $vmrun @argsVm runScriptInGuest $vmx /bin/bash 'set -e; /usr/local/bin/aegisav-isolation-check; test ! -e /home/aegisav-operator/mb-auth.key; test ! -L /home/aegisav-operator/mb-auth.key; stat -c %a /home/aegisav-operator | grep -qx 700'
    if($LASTEXITCODE){throw 'Guest preflight failed; no API key requested'}
    Write-Host 'Paste the API key at the hidden prompt. A private temporary file will be deleted afterward.'
    $secret=Read-Host 'MalwareBazaar Auth-Key' -AsSecureString
    $pointer=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
    $plain=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    if($plain.Length -lt 16 -or $plain.Length -gt 4096 -or $plain -match '[^\x21-\x7e]'){throw 'Invalid key format; no transfer performed'}
    [IO.File]::WriteAllText($temporary,$plain,[Text.UTF8Encoding]::new($false))
    $plain=$null
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer);$pointer=[IntPtr]::Zero
    $guestTransferAttempted=$true
    & $vmrun @argsVm CopyFileFromHostToGuest $vmx $temporary $guestTemporary
    if($LASTEXITCODE){throw 'Guest temporary transfer failed'}
    Remove-Item -LiteralPath $temporary -Force
    $finalize='set -e; umask 077; chmod 0600 __TEMP__; test ! -e /home/aegisav-operator/mb-auth.key; test ! -L /home/aegisav-operator/mb-auth.key; ln -T -- __TEMP__ /home/aegisav-operator/mb-auth.key; rm -f -- __TEMP__; stat -c %F /home/aegisav-operator/mb-auth.key; stat -c %a /home/aegisav-operator/mb-auth.key; stat -c %U /home/aegisav-operator/mb-auth.key; stat -c %G /home/aegisav-operator/mb-auth.key'
    & $vmrun @argsVm runScriptInGuest $vmx /bin/bash ($finalize.Replace('__TEMP__',$guestTemporary))
    if($LASTEXITCODE){throw 'Guest finalization failed; report failure without key content'}
    Write-Host 'Configured in guest. Return to Codex and say: configured. Do not send the key.'
} finally {
    $plain=$null
    if($pointer -ne [IntPtr]::Zero){[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)}
    if($secret){$secret.Dispose()}
    if(Test-Path -LiteralPath $temporary){
        try {Remove-Item -LiteralPath $temporary -Force}
        catch {Write-Warning "Private host temporary file needs manual cleanup: $temporary"}
    }
    if(Test-Path -LiteralPath $directory){
        try {Remove-Item -LiteralPath $directory}
        catch {Write-Warning "Private host temporary directory needs manual cleanup: $directory"}
    }
    try {
      if($argsVm -and $guestTransferAttempted){
        try {
            $cleanup='set -e; rm -f -- __TEMP__; test ! -e __TEMP__; test ! -L __TEMP__'
            & $vmrun @argsVm runScriptInGuest $vmx /bin/bash ($cleanup.Replace('__TEMP__',$guestTemporary)) 2>$null | Out-Null
            if($LASTEXITCODE){Write-Warning 'Guest temporary cleanup could not be confirmed; host cleanup continues.'}
        } catch {
            Write-Warning 'Guest temporary cleanup could not be confirmed; host cleanup continues.'
        }
      }
    } finally {
        $login=$null;$argsVm=$null
    }
}
