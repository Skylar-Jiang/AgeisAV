param()
$ErrorActionPreference = 'Stop'
$vmx = 'D:\VMs\AegisAV-Ubuntu-24.04\guest\AegisAV-Static-Ubuntu\AegisAV-Static-Ubuntu.vmx'
$media = 'D:\VMs\AegisAV-Ubuntu-24.04\media'
$credentialPath = Join-Path $media 'operator.credential.xml'
$username = 'aegisav-operator'
$config = Get-Content -LiteralPath $vmx -Raw
if ($config -notmatch '(?im)^\s*ethernet0.connectionType\s*=\s*"hostonly"\s*$') {
    throw 'Provision guest access only during benign Host-only preparation.'
}
$address = & 'D:\VM\vmrun.exe' -T ws getGuestIPAddress $vmx
if ($LASTEXITCODE -ne 0 -or $address -notmatch '^192\.168\.84\.\d+$') { throw 'Dedicated Host-only guest address unavailable.' }
$sshArgs = @('-i', "$env:USERPROFILE\.ssh\aegisav_vm_ed25519", '-o', 'BatchMode=yes',
    '-o', 'StrictHostKeyChecking=yes', '-o', "UserKnownHostsFile=$media\known_hosts", "ubuntu@$address")
if (Test-Path -LiteralPath $credentialPath) {
    $credential = Import-Clixml -LiteralPath $credentialPath
    if ($credential.UserName -ne $username) { throw 'Unexpected credential identity.' }
} else {
    $password = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
    $credential = [pscredential]::new($username, (ConvertTo-SecureString $password -AsPlainText -Force))
}
& ssh @sshArgs 'set -e; if id -u aegisav-operator >/dev/null 2>&1; then test -f /var/lib/aegisav/managed-operator; else sudo useradd -m -s /bin/bash aegisav-operator; sudo mkdir -p /var/lib/aegisav; sudo touch /var/lib/aegisav/managed-operator; fi; sudo chmod 700 /home/aegisav-operator'
if ($LASTEXITCODE -ne 0) { throw 'Guest account provisioning failed; existing unmanaged accounts are never overwritten.' }
"${username}:$($credential.GetNetworkCredential().Password)" | & ssh @sshArgs 'sudo sh -c ''tr -d "\r" | chpasswd'''
if ($LASTEXITCODE -ne 0) { throw 'Guest credential setup failed.' }
$credential | Export-Clixml -LiteralPath $credentialPath
$acl = Get-Acl -LiteralPath $credentialPath
$acl.SetAccessRuleProtection($true, $false)
foreach ($rule in @($acl.Access)) { [void] $acl.RemoveAccessRuleSpecific($rule) }
foreach ($sid in @([Security.Principal.WindowsIdentity]::GetCurrent().User,
        [Security.Principal.SecurityIdentifier]::new('S-1-5-18'),
        [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))) {
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'Allow'))
}
[IO.FileSystemAclExtensions]::SetAccessControl([IO.FileInfo]::new($credentialPath), $acl)
$password = $null
$credential = $null
'Dedicated non-root guest account configured. Credential is DPAPI-protected for this Windows user.'
