$ErrorActionPreference = 'Stop'
$vmx = 'D:\VMs\AegisAV-Ubuntu-24.04\guest\AegisAV-Static-Ubuntu\AegisAV-Static-Ubuntu.vmx'
$credential = Import-Clixml -LiteralPath 'D:\VMs\AegisAV-Ubuntu-24.04\media\operator.credential.xml'
if ($credential.UserName -ne 'aegisav-operator') { throw 'Unexpected guest identity.' }
$script = @'
import json,re
from pathlib import Path
home=Path('/home/aegisav-operator')
progress={}
for name in ('windows','vendor','expansion'):
    path=home/('benign-'+name+'.progress')
    value=path.read_text().strip() if path.exists() else 'pending'
    if not re.fullmatch(r'(pending|[0-9]{1,3}/[0-9]{3})',value):
        raise ValueError('Invalid progress counter')
    progress[name]=value
(home/'static-progress.json').write_text(json.dumps(progress))
'@
try {
    & 'D:\VM\vmrun.exe' -T ws -gu $credential.UserName -gp ($credential.GetNetworkCredential().Password) runProgramInGuest $vmx /usr/bin/python3 -c $script
    if ($LASTEXITCODE) { throw 'Guest progress query failed.' }
    $output = Join-Path (Split-Path $PSScriptRoot -Parent) 'artifacts\static-progress.json'
    & 'D:\VM\vmrun.exe' -T ws -gu $credential.UserName -gp ($credential.GetNetworkCredential().Password) copyFileFromGuestToHost $vmx /home/aegisav-operator/static-progress.json $output
    if ($LASTEXITCODE -or (Get-Item -LiteralPath $output).Length -gt 256) { throw 'Invalid progress export.' }
    Get-Content -LiteralPath $output -Raw
} finally { $credential = $null }
