param()
$ErrorActionPreference = 'Stop'
throw 'Historical pilot v1 installer: reproduce from commit 80da02d. Current v2 uses Provision-Expansion.ps1 on the existing corpus volume.'
$media = 'D:\VMs\AegisAV-Ubuntu-24.04\media'
$credentialPath = Join-Path $media 'admin.credential.xml'
$sshArgs = @('-i', "$env:USERPROFILE\.ssh\aegisav_vm_ed25519", '-o', 'BatchMode=yes',
    '-o', 'StrictHostKeyChecking=yes', '-o', "UserKnownHostsFile=$media\known_hosts")
$guest = 'ubuntu@192.168.84.128'
$vmx = 'D:\VMs\AegisAV-Ubuntu-24.04\guest\AegisAV-Static-Ubuntu\AegisAV-Static-Ubuntu.vmx'
$config = [IO.File]::ReadAllText($vmx)
if ($config -notmatch '(?im)^\s*ethernet0.connectionType\s*=\s*"hostonly"\s*$') { throw 'Provision only in benign Host-only preparation.' }
$passwordPolicy = & ssh @sshArgs $guest 'sudo sshd -T'
if ($LASTEXITCODE -or $passwordPolicy -notcontains 'passwordauthentication no') { throw 'SSH password authentication must be disabled.' }
if (Test-Path -LiteralPath $credentialPath) {
    $credential = Import-Clixml -LiteralPath $credentialPath
    if ($credential.UserName -ne 'ubuntu') { throw 'Unexpected administration identity.' }
} else {
    $password = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
    $credential = [pscredential]::new('ubuntu',(ConvertTo-SecureString $password -AsPlainText -Force))
}
"ubuntu:$($credential.GetNetworkCredential().Password)" | & ssh @sshArgs $guest 'sudo sh -c ''tr -d "\r" | chpasswd'''
if ($LASTEXITCODE) { throw 'Guest Tools administration credential setup failed.' }
$credential | Export-Clixml -LiteralPath $credentialPath
$acl = Get-Acl -LiteralPath $credentialPath
$acl.SetAccessRuleProtection($true,$false)
foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRuleSpecific($rule) }
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.WindowsIdentity]::GetCurrent().User,'FullControl','Allow'))
[IO.FileSystemAclExtensions]::SetAccessControl([IO.FileInfo]::new($credentialPath),$acl)
$credential = $null
$password = $null
& ssh @sshArgs $guest 'mkdir -p /home/ubuntu/collection-staging/wheels'
if ($LASTEXITCODE) { throw 'Staging failed.' }
$repo = Split-Path -Parent $PSScriptRoot
foreach ($name in @('export_collection_evidence.py','collection_environment.py','collect_malwarebazaar.py','collection_boundary.py','collection_probe.py','setup-collection.sh')) {
    & scp @sshArgs (Join-Path $PSScriptRoot $name) "${guest}:/home/ubuntu/collection-staging/$name"
    if ($LASTEXITCODE) { throw 'Trusted source upload failed.' }
}
& scp @sshArgs (Join-Path $repo 'artifacts/collection-candidates.json') "${guest}:/home/ubuntu/collection-staging/candidates.json"
if ($LASTEXITCODE) { throw 'Metadata upload failed.' }
foreach ($wheel in Get-ChildItem -LiteralPath (Join-Path $repo 'artifacts/collection-wheels') -Filter '*.whl') {
    & scp @sshArgs $wheel.FullName "${guest}:/home/ubuntu/collection-staging/wheels/"
    if ($LASTEXITCODE) { throw 'Trusted wheel upload failed.' }
}
& ssh @sshArgs $guest 'set -e; sudo install -d -m 755 /opt/aegisav-collection/deps; sudo cp /home/ubuntu/collection-staging/*.py /home/ubuntu/collection-staging/*.sh /home/ubuntu/collection-staging/candidates.json /opt/aegisav-collection/; sudo sed -i "s/\r$//" /opt/aegisav-collection/*.sh; sudo /opt/aegisav-static/venv/bin/python -m pip install --no-index --target /opt/aegisav-collection/deps --find-links /home/ubuntu/collection-staging/wheels pyzipper==0.3.6; sudo bash -n /opt/aegisav-collection/setup-collection.sh; sudo bash /opt/aegisav-collection/setup-collection.sh'
if ($LASTEXITCODE) { throw 'Guest setup failed.' }
'Dedicated collection setup installed; no real sample downloaded.'
