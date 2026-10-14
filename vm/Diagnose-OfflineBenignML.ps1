param(
    [ValidateSet('full', 'ml')][string] $Context = 'full',
    [ValidateSet(1536, 2048)][int] $MemoryMiB = 1536
)
$ErrorActionPreference = 'Stop'
& "$PSScriptRoot\Manage-VM.ps1" -Action CheckOffline
$vmx = 'D:\VMs\AegisAV-Ubuntu-24.04\guest\AegisAV-Static-Ubuntu\AegisAV-Static-Ubuntu.vmx'
$credential = Import-Clixml -LiteralPath 'D:\VMs\AegisAV-Ubuntu-24.04\media\operator.credential.xml'
if ($credential.UserName -ne 'aegisav-operator') { throw 'Unexpected guest identity.' }
$repo = Split-Path $PSScriptRoot -Parent
$source = Join-Path $PSScriptRoot 'diagnose_benign_ml.py'
$guest = '/home/aegisav-operator/diagnose_benign_ml.py'
$output = Join-Path $repo "artifacts\offline-results\benign-ml-retry-$Context-$MemoryMiB-$([guid]::NewGuid().ToString('N')).json"
function Invoke-Operation([string[]] $OperationArgs) {
    & 'D:\VM\vmrun.exe' -T ws -gu $credential.UserName -gp ($credential.GetNetworkCredential().Password) @OperationArgs
    if ($LASTEXITCODE) { throw "Guest operation failed: $($OperationArgs[0])" }
}
try {
    Invoke-Operation -OperationArgs @('CopyFileFromHostToGuest', $vmx, $source, $guest)
    $digest = (Get-FileHash -LiteralPath $source).Hash.ToLowerInvariant()
    $verify = "import hashlib;from pathlib import Path;assert hashlib.sha256(Path('$guest').read_bytes()).hexdigest()=='$digest'"
    Invoke-Operation -OperationArgs @('runProgramInGuest', $vmx, '/usr/bin/python3', '-c', $verify)
    Invoke-Operation -OperationArgs @('runProgramInGuest', $vmx, '/opt/aegisav-static/venv/bin/python', $guest, '--context', $Context, '--memory-mib', "$MemoryMiB")
    Invoke-Operation -OperationArgs @('CopyFileFromGuestToHost', $vmx, "/home/aegisav-operator/benign-ml-retry-$Context-$MemoryMiB.json", $output)
    if ((Get-Item -LiteralPath $output).Length -gt 64KB) { throw 'Diagnostic result exceeds boundary.' }
    $report = Get-Content -LiteralPath $output -Raw | ConvertFrom-Json
    if ($report.sha256 -ne '4fbd024b8071aa5fa7315626c57ce5b820fc52bcddb64e8ab297f2206c83ebed' -or
        $report.context -ne $Context -or $report.memory_limit_bytes -ne ($MemoryMiB * 1MB) -or
        $report.original_batch_replaced -ne $false -or $report.isolation -notmatch '^AEGISAV_ISOLATION PASS ') {
        throw 'Diagnostic identity rejected.'
    }
    [pscustomobject]@{ Report=$output; Status=$report.status; ScriptSHA256=$digest; Supplemental=$true }
} finally { $credential = $null }
