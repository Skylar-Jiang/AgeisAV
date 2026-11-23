$ErrorActionPreference = 'Stop'
$vmx = 'D:\VMs\AegisAV-Ubuntu-24.04\guest\AegisAV-Static-Ubuntu\AegisAV-Static-Ubuntu.vmx'
$credential = Import-Clixml -LiteralPath 'D:\VMs\AegisAV-Ubuntu-24.04\media\operator.credential.xml'
if ($credential.UserName -ne 'aegisav-operator') { throw 'Unexpected guest identity.' }
$script = @'
import hashlib,json,os
from pathlib import Path
root=Path('/opt/aegisav-static')
files={}
for name in ('static_archive.py','static_benign.py','static_ember.py','backend/aegisav/hashes.py','rules/hashes.json','rules/yara/metadata.json','ember/manifest.json'):
    path=root/name
    meta=path.stat()
    if meta.st_uid != 0 or meta.st_mode & 0o022 or os.access(path,os.W_OK):
        raise ValueError('Trusted tool ownership or write boundary failed')
    files[name]={'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'uid':meta.st_uid,'mode':oct(meta.st_mode & 0o777)}
report={'files':files,'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
Path('/home/aegisav-operator/tool-provenance.json').write_text(json.dumps(report))
'@
try {
    & 'D:\VM\vmrun.exe' -T ws -gu $credential.UserName -gp ($credential.GetNetworkCredential().Password) runProgramInGuest $vmx /usr/bin/python3 -c $script
    if ($LASTEXITCODE) { throw 'Guest trusted tool provenance check failed.' }
    $output = Join-Path (Split-Path $PSScriptRoot -Parent) 'docs\benchmarks\guest_tool_provenance_20261010.json'
    & 'D:\VM\vmrun.exe' -T ws -gu $credential.UserName -gp ($credential.GetNetworkCredential().Password) copyFileFromGuestToHost $vmx /home/aegisav-operator/tool-provenance.json $output
    if ($LASTEXITCODE -or (Get-Item -LiteralPath $output).Length -gt 4096) { throw 'Invalid provenance export.' }
    $report = Get-Content -LiteralPath $output -Raw | ConvertFrom-Json
    $repo = Split-Path $PSScriptRoot -Parent
    foreach ($name in @('static_archive.py','static_benign.py','static_ember.py','backend/aegisav/hashes.py','rules/hashes.json','rules/yara/metadata.json')) {
        $path = if ($name.StartsWith('rules/') -or $name.StartsWith('backend/')) { Join-Path $repo $name } else { Join-Path $PSScriptRoot $name }
        if ($report.files.$name.sha256 -ne (Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()) { throw "Guest tool differs: $name" }
    }
    $report
} finally { $credential = $null }
