param([Parameter(Mandatory)][ValidateSet('windows', 'vendor', 'expansion')][string] $Group,
      [switch] $CollectOnly)
$ErrorActionPreference = 'Stop'
& "$PSScriptRoot\Test-OfflineGuestOps.ps1"
$vmx = 'D:\VMs\AegisAV-Ubuntu-24.04\guest\AegisAV-Static-Ubuntu\AegisAV-Static-Ubuntu.vmx'
$credential = Import-Clixml -LiteralPath 'D:\VMs\AegisAV-Ubuntu-24.04\media\operator.credential.xml'
if ($credential.UserName -ne 'aegisav-operator') { throw 'Unexpected guest identity.' }
function Invoke-Operation([string[]] $OperationArgs) {
    & 'D:\VM\vmrun.exe' -T ws -gu $credential.UserName -gp ($credential.GetNetworkCredential().Password) @OperationArgs
    if ($LASTEXITCODE) { throw "Guest operation failed: $($OperationArgs[0])" }
}
$repo = Split-Path $PSScriptRoot -Parent
$manifestNames = @{
    windows = 'benign_windows_pe_manifest.jsonl'
    vendor = 'benign_vendor_pe_manifest.jsonl'
    expansion = 'benign_expansion_manifest_20261010.jsonl'
}
$manifest = Join-Path $repo "docs\benchmarks\$($manifestNames[$Group])"
$results = Join-Path $repo 'artifacts\offline-results'
New-Item -ItemType Directory -Path $results -Force | Out-Null
$output = Join-Path $results "benign-$Group-$([guid]::NewGuid().ToString('N')).json"
$guest = "/home/aegisav-operator/benign-$Group.json"
$guestLog = "/home/aegisav-operator/benign-$Group-run.log"
$launched = $false
try {
    # Only the fixed benign fixture runner can export diagnostic text; archive exports stay structured.
    $command = "/opt/aegisav-static/venv/bin/python /opt/aegisav-static/static_benign.py --group $Group > $guestLog 2>&1"
    $launched = $true
    if (-not $CollectOnly) {
        Invoke-Operation -OperationArgs @('runProgramInGuest', $vmx, '/bin/sh', '-c', $command)
    }
    Invoke-Operation -OperationArgs @('CopyFileFromGuestToHost', $vmx, $guest, $output)
    Invoke-Operation -OperationArgs @('CopyFileFromGuestToHost', $vmx, "$guest.sha256", "$output.sha256")
    Invoke-Operation -OperationArgs @('CopyFileFromGuestToHost', $vmx, "/home/aegisav-operator/benign-$Group.checkpoint.json", "$output.checkpoint.json")
    if ((Get-Item -LiteralPath $output).Length -gt 2MB -or (Get-Item -LiteralPath "$output.sha256").Length -gt 128) {
        throw 'Result size boundary exceeded.'
    }
    $expected = (Get-Content -LiteralPath "$output.sha256" -Raw).Trim()
    if ($expected -notmatch '^[a-f0-9]{64}$' -or (Get-FileHash -LiteralPath $output).Hash.ToLowerInvariant() -ne $expected) {
        throw 'Result digest mismatch.'
    }
    & "$repo\.venv\Scripts\python.exe" "$PSScriptRoot\static_benign.py" --validate-export $output
    if ($LASTEXITCODE) { throw 'Benign result schema rejected.' }
    & "$repo\.venv\Scripts\python.exe" "$PSScriptRoot\benign_checkpoint.py" --validate-export "$output.checkpoint.json" --manifest $manifest
    if ($LASTEXITCODE) { throw 'Benign checkpoint rejected.' }
    $report = Get-Content -LiteralPath $output -Raw | ConvertFrom-Json
    if (-not $report.completed -or $report.manifest_sha256 -ne (Get-FileHash -LiteralPath $manifest).Hash.ToLowerInvariant()) {
        throw 'Incomplete report or different frozen manifest.'
    }
    [pscustomobject]@{Group=$Group; Files=$report.files.Count; Report=$output; Isolation=$report.isolation}
} finally {
    if ($launched) {
        & 'D:\VM\vmrun.exe' -T ws -gu $credential.UserName -gp ($credential.GetNetworkCredential().Password) CopyFileFromGuestToHost $vmx $guestLog "$output.log"
        if ($LASTEXITCODE) { Write-Warning 'Benign diagnostic log export failed; retain the original run failure.' }
        elseif ((Get-Item -LiteralPath "$output.log").Length -gt 2MB) { throw 'Benign diagnostic log exceeds boundary.' }
    }
    $credential = $null
}
