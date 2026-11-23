param()
$ErrorActionPreference='Stop'
& "$PSScriptRoot/Manage-VM.ps1" -Action CheckOffline
$vmx='D:\VMs\AegisAV-Ubuntu-24.04\guest\AegisAV-Static-Ubuntu\AegisAV-Static-Ubuntu.vmx'
$credential=Import-Clixml -LiteralPath 'D:\VMs\AegisAV-Ubuntu-24.04\media\admin.credential.xml'
& "$PSScriptRoot/Invoke-CollectionGuest.ps1" -Script 'set -e; /usr/local/bin/aegisav-isolation-check; test ! -e /home/aegisav-operator/mb-auth.key; test "$(systemctl show aegisav-expansion-scan.service -p SubState --value)" != start; mkdir -p /home/ubuntu/expansion-scan-staging'
foreach($name in @('scan_expansion.py','expansion_clam_ready.py','setup-expansion-scan.sh')) {
    & D:\VM\vmrun.exe -T ws -gu $credential.UserName -gp ($credential.GetNetworkCredential().Password) CopyFileFromHostToGuest $vmx (Join-Path $PSScriptRoot $name) "/home/ubuntu/expansion-scan-staging/$name"
    if($LASTEXITCODE){throw 'Development scan code upload failed'}
}
& D:\VM\vmrun.exe -T ws -gu $credential.UserName -gp ($credential.GetNetworkCredential().Password) CopyFileFromHostToGuest $vmx (Join-Path $PSScriptRoot '../artifacts/collection-expansion-development-plan.json') /home/ubuntu/expansion-scan-staging/plan.json
if($LASTEXITCODE){throw 'Private diagnostic plan upload failed'}
$credential=$null
& "$PSScriptRoot/Invoke-CollectionGuest.ps1" -Script 'set -e; sudo install -d -m 0755 /opt/aegisav-expansion-scan; sudo install -m 0444 /home/ubuntu/expansion-scan-staging/scan_expansion.py /home/ubuntu/expansion-scan-staging/expansion_clam_ready.py /home/ubuntu/expansion-scan-staging/plan.json /opt/aegisav-expansion-scan/; sudo sed -i "s/\r$//" /home/ubuntu/expansion-scan-staging/setup-expansion-scan.sh; sudo bash -n /home/ubuntu/expansion-scan-staging/setup-expansion-scan.sh; sudo bash /home/ubuntu/expansion-scan-staging/setup-expansion-scan.sh'
