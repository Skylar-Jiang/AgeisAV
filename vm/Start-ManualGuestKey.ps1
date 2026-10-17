# No API key arguments or Windows API-key reads. Human input stays in the guest VT.
$ErrorActionPreference='Stop'
$vmx='D:\VMs\AegisAV-Ubuntu-24.04\guest\AegisAV-Static-Ubuntu\AegisAV-Static-Ubuntu.vmx'
$vmrun='D:\VM\vmrun.exe'
& "$PSScriptRoot/Manage-VM.ps1" -Action CheckOffline
$running=@(& $vmrun -T ws list)
if($LASTEXITCODE){throw 'VM state query failed'}
if($running -notcontains $vmx){
    $ready=(& "$PSScriptRoot/Get-TaskGuardReadiness.ps1" | ConvertFrom-Json)
    if($ready.status -ne 'ready_for_guest_validation'){throw 'Original 10 GiB resource gate not met'}
    & $vmrun -T ws start $vmx gui
    if($LASTEXITCODE){throw 'VM start failed'}
}
if(([int64](Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory*1024) -lt 2GB){throw 'Host reserve below 2 GiB'}
$toolsReady=$false
for($attempt=0;$attempt -lt 20;$attempt++){
    $state=(& $vmrun -T ws checkToolsState $vmx)
    if($LASTEXITCODE -eq 0 -and $state -eq 'running'){$toolsReady=$true;break}
    Start-Sleep -Seconds 2
}
if(-not $toolsReady){throw 'VMware Tools not ready; no prompt source transferred'}
$source=Join-Path $PSScriptRoot 'manual_guest_key.py'
$digest=(Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
$stage='/home/ubuntu/manual-key-'+[guid]::NewGuid().ToString('N')+'.py'
# This is the existing VM administration login, never malwarebazaar.auth.xml.
$login=Import-Clixml -LiteralPath 'D:\VMs\AegisAV-Ubuntu-24.04\media\admin.credential.xml'
if($login.UserName -ne 'ubuntu'){throw 'Unexpected VM administration identity'}
$argsVm=@('-T','ws','-gu',$login.UserName,'-gp',$login.GetNetworkCredential().Password)
try {
    & $vmrun @argsVm CopyFileFromHostToGuest $vmx $source $stage
    if($LASTEXITCODE){throw 'Trusted prompt source transfer failed'}
    $script=@'
set -e
[[ $(hostname) == aegisav-static ]]
/usr/local/bin/aegisav-isolation-check
sudo -n /usr/bin/test ! -e /home/aegisav-operator/mb-auth.key
sudo -n /usr/bin/test ! -L /home/aegisav-operator/mb-auth.key
state=$(systemctl show aegisav-manual-key.service -p ActiveState --value)
[[ $state != active && $state != activating && $state != deactivating ]]
test -x /usr/bin/openvt && test -x /usr/bin/setpriv
sudo -n rm -f /home/aegisav-operator/manual-key-ready.flag
printf '%s  %s\n' '__DIGEST__' '__STAGE__' | sha256sum -c -
sudo -n install -d -m 0755 -o root -g root /opt/aegisav-manual-key
sudo -n install -m 0444 -o root -g root '__STAGE__' /opt/aegisav-manual-key/prompt.py
sudo -n systemd-run --unit=aegisav-manual-key --collect --property=RuntimeMaxSec=10min --property=MemoryMax=64M --property=MemorySwapMax=0 --property=TasksMax=8 --property=KillMode=control-group --property=NoNewPrivileges=yes --property=UMask=0077 --property=IPAddressDeny=any --property=InaccessiblePaths=/srv/aegisav-corpus /usr/bin/openvt -s -w -- /usr/bin/setpriv --reuid=1001 --regid=1001 --init-groups --no-new-privs /usr/bin/python3 -I /opt/aegisav-manual-key/prompt.py
for attempt in {1..30}; do
    if systemctl is-active --quiet aegisav-manual-key.service && sudo -n /usr/bin/test -f /home/aegisav-operator/manual-key-ready.flag; then exit 0; fi
    sleep 0.1
done
echo 'Guest console prompt not ready; no API key read by launcher' >&2
exit 1
'@
    $script=$script.Replace('__DIGEST__',$digest).Replace('__STAGE__',$stage)
    & $vmrun @argsVm runScriptInGuest $vmx /bin/bash $script
    if($LASTEXITCODE){throw 'Guest prompt launch failed; no API key handled'}
    Write-Output 'Guest Auth-Key prompt launched. Type only in VMware console; do not send the key to Codex. Expires after 10 minutes.'
} finally {
    $login=$null;$argsVm=$null
}
