param()
$ErrorActionPreference='Stop'
$expected=@{
    'collect_malwarebazaar.py'='d68d3377bb4803e9933dbf27f3377d27ae02da702454ce467876ecbb7052e106'
    'collection_boundary.py'='4e4f968a16cd8132e06b08bfcb8c522697e7e0377c3130768705103aa560a5e7'
}
foreach($name in $expected.Keys){
    if((Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $name) -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected[$name]){
        throw 'Frozen cohort code changed. Preserve its checkpoint identity and deploy a separate version.'
    }
}
$manifest=Join-Path $PSScriptRoot '../artifacts/collection-expansion-candidates.json'
if((Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash.ToLowerInvariant() -ne '76816a606721f48e00f696a5f265409aa72b9d5182672f24f46952075dc4b221'){
    throw 'Frozen cohort manifest changed.'
}
& "$PSScriptRoot/Manage-VM.ps1" -Action CheckOffline
$vmx='D:\VMs\AegisAV-Ubuntu-24.04\guest\AegisAV-Static-Ubuntu\AegisAV-Static-Ubuntu.vmx'
$credential=Import-Clixml -LiteralPath 'D:\VMs\AegisAV-Ubuntu-24.04\media\admin.credential.xml'
$arguments=@('-T','ws','-gu',$credential.UserName,'-gp',$credential.GetNetworkCredential().Password)
& "$PSScriptRoot/Invoke-CollectionGuest.ps1" -Script 'set -e; /usr/local/bin/aegisav-isolation-check; mkdir -p /home/ubuntu/expansion-staging; test "$(systemctl show aegisav-expansion-fetch.service -p ActiveState --value)" != activating; test "$(systemctl show aegisav-expansion-analysis.service -p SubState --value)" != start'
foreach($name in @('collect_malwarebazaar.py','collection_boundary.py','setup-expansion.sh')) {
    & D:\VM\vmrun.exe @arguments CopyFileFromHostToGuest $vmx (Join-Path $PSScriptRoot $name) "/home/ubuntu/expansion-staging/$name"
    if($LASTEXITCODE){throw 'Trusted expansion code upload failed.'}
}
& D:\VM\vmrun.exe @arguments CopyFileFromHostToGuest $vmx $manifest /home/ubuntu/expansion-staging/candidates.json
if($LASTEXITCODE){throw 'Frozen expansion metadata upload failed.'}
$credential=$null
$arguments=$null
& "$PSScriptRoot/Invoke-CollectionGuest.ps1" -Script 'set -e; sudo install -d -m 0755 /opt/aegisav-collection-v2; sudo cp /home/ubuntu/expansion-staging/*.py /home/ubuntu/expansion-staging/setup-expansion.sh /home/ubuntu/expansion-staging/candidates.json /opt/aegisav-collection-v2/; sudo sed -i "s/\r$//" /opt/aegisav-collection-v2/setup-expansion.sh; sudo bash -n /opt/aegisav-collection-v2/setup-expansion.sh; sudo bash /opt/aegisav-collection-v2/setup-expansion.sh'
