param()
$ErrorActionPreference = 'Stop'
throw 'Pilot v1 is frozen. Use Provision-Expansion.ps1 for the separate v2 cohort; do not overwrite pilot code.'
$vmx = 'D:\VMs\AegisAV-Ubuntu-24.04\guest\AegisAV-Static-Ubuntu\AegisAV-Static-Ubuntu.vmx'
$credential = Import-Clixml -LiteralPath 'D:\VMs\AegisAV-Ubuntu-24.04\media\admin.credential.xml'
$arguments = @('-T','ws','-gu',$credential.UserName,'-gp',$credential.GetNetworkCredential().Password)
foreach ($name in @('export_collection_evidence.py','collection_environment.py','collection_probe.py','collect_malwarebazaar.py','collection_boundary.py','setup-collection.sh')) {
    & D:\VM\vmrun.exe @arguments CopyFileFromHostToGuest $vmx (Join-Path $PSScriptRoot $name) "/home/ubuntu/collection-staging/$name"
    if ($LASTEXITCODE) { throw 'Trusted code upload failed.' }
}
$credential = $null
$arguments = $null
& "$PSScriptRoot/Invoke-CollectionGuest.ps1" -Script 'set -e; sudo cp /home/ubuntu/collection-staging/*.py /home/ubuntu/collection-staging/*.sh /opt/aegisav-collection/; sudo sed -i "s/\r$//" /opt/aegisav-collection/*.sh; sudo chmod 0444 /opt/aegisav-collection/*.py /opt/aegisav-collection/*.sh'
