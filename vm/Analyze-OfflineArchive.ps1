param(
    [Parameter(Mandatory)] [string] $SourceArchive,
    [Parameter(Mandatory)] [securestring] $ArchivePassword
)
$ErrorActionPreference = 'Stop'
# Repeat the harmless offline round trip before any user-provided archive enters.
& "$PSScriptRoot\Test-OfflineGuestOps.ps1"
$source = Get-Item -LiteralPath $SourceArchive
if ($source.PSIsContainer -or $source.Extension -ne '.zip' -or $source.Length -gt 128MB) {
    throw 'Existing ZIP archive up to 128 MiB required. Host extraction is never used.'
}
$digest = (Get-FileHash -LiteralPath $source.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
$vmx = 'D:\VMs\AegisAV-Ubuntu-24.04\guest\AegisAV-Static-Ubuntu\AegisAV-Static-Ubuntu.vmx'
$media = 'D:\VMs\AegisAV-Ubuntu-24.04\media'
$credential = Import-Clixml -LiteralPath (Join-Path $media 'operator.credential.xml')
if ($credential.UserName -ne 'aegisav-operator') { throw 'Unexpected guest identity.' }
function Invoke-Operation([string[]] $OperationArgs) {
    & 'D:\VM\vmrun.exe' -T ws -gu $credential.UserName -gp ($credential.GetNetworkCredential().Password) @OperationArgs
    if ($LASTEXITCODE) { throw "Guest operation failed: $($OperationArgs[0])" }
}
$batch = [guid]::NewGuid().ToString('N')
$guest = "/home/aegisav-operator/batch-$batch"
$passwordFile = Join-Path $media "archive-password-$batch.txt"
$repo = Split-Path $PSScriptRoot -Parent
$results = Join-Path $repo 'artifacts\offline-results'
New-Item -ItemType Directory -Path $results -Force | Out-Null
$output = Join-Path $results "$batch.json"
try {
    # Apply the credential's restricted ACL to the short-lived password file.
    $credentialAcl = Get-Acl -LiteralPath (Join-Path $media 'operator.credential.xml')
    New-Item -ItemType File -Path $passwordFile | Out-Null
    [IO.FileSystemAclExtensions]::SetAccessControl([IO.FileInfo]::new($passwordFile), $credentialAcl)
    $temporaryCredential = [pscredential]::new('archive', $ArchivePassword)
    [IO.File]::WriteAllText($passwordFile, $temporaryCredential.GetNetworkCredential().Password, [Text.UTF8Encoding]::new($false))
    $temporaryCredential = $null
    Invoke-Operation -OperationArgs @('runProgramInGuest', $vmx, '/bin/mkdir', '-m', '700', $guest)
    Invoke-Operation -OperationArgs @('CopyFileFromHostToGuest', $vmx, $source.FullName, "$guest/input.zip")
    Invoke-Operation -OperationArgs @('CopyFileFromHostToGuest', $vmx, $passwordFile, "$guest/password.txt")
    "Batch $batch; archive SHA-256 $digest. Running trusted static reader only."
    Invoke-Operation -OperationArgs @('runProgramInGuest', $vmx, '/opt/aegisav-static/venv/bin/python',
        '/opt/aegisav-static/static_archive.py', '--batch', $batch, '--sha256', $digest)
    Invoke-Operation -OperationArgs @('CopyFileFromGuestToHost', $vmx, "$guest/result.json", $output)
    Invoke-Operation -OperationArgs @('CopyFileFromGuestToHost', $vmx, "$guest/result.sha256", "$output.sha256")
    if ((Get-Item -LiteralPath "$output.sha256").Length -gt 128) { throw 'Invalid result digest size.' }
    $expected = (Get-Content -LiteralPath "$output.sha256" -Raw).Trim()
    if ($expected -notmatch '^[a-f0-9]{64}$' -or (Get-FileHash -LiteralPath $output).Hash.ToLowerInvariant() -ne $expected) {
        throw 'Result digest mismatch.'
    }
    & "$repo\.venv\Scripts\python.exe" "$PSScriptRoot\static_archive.py" --validate-export $output
    if ($LASTEXITCODE) { throw 'Result schema rejected.' }
    $report = Get-Content -LiteralPath $output -Raw | ConvertFrom-Json
    if ($report.archive_sha256 -ne $digest -or -not $report.completed) { throw 'Incomplete or wrong-archive result.' }
    [pscustomobject]@{ Batch = $batch; ArchiveSHA256 = $digest; Files = $report.files.Count;
        Errors = $report.errors.Count; Report = $output; Isolation = $report.isolation }
} finally {
    if (Test-Path -LiteralPath $passwordFile) { Remove-Item -LiteralPath $passwordFile }
    $credential = $null
}
