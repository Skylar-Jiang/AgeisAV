param(
    [string] $OutputDirectory = 'D:\2026fall\badcode\aegisav\artifacts\benign_windows_pe',
    [int] $MaxFiles = 600,
    [long] $MaxBytes = 1GB,
    [long] $MaxFileBytes = 64MB,
    [string[]] $Roots = @("$env:WINDIR\System32", "$env:WINDIR\SysWOW64"),
    [switch] $Recurse,
    [string] $SignerSubjectPattern = 'O=Microsoft Corporation',
    [string] $SourceLabel = 'Installed Windows system file with valid Microsoft Authenticode signature'
)

$ErrorActionPreference = 'Stop'
function Test-PEHeader([string] $path) {
    $stream = [IO.File]::OpenRead($path)
    try {
        if ($stream.Length -lt 64) { return $false }
        $reader = [IO.BinaryReader]::new($stream)
        if ($reader.ReadUInt16() -ne 0x5A4D) { return $false }
        $stream.Position = 0x3C
        $offset = $reader.ReadInt32()
        if ($offset -lt 64 -or $offset -gt ($stream.Length - 4)) { return $false }
        $stream.Position = $offset
        return $reader.ReadUInt32() -eq 0x00004550
    } finally {
        $stream.Dispose()
    }
}

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$samplesDirectory = Join-Path $OutputDirectory 'samples'
New-Item -ItemType Directory -Force -Path $samplesDirectory | Out-Null
$manifest = Join-Path $OutputDirectory 'manifest.jsonl'
if (Test-Path -LiteralPath $manifest) { throw "Manifest already exists: $manifest" }

$candidates = @($Roots | ForEach-Object {
    Get-ChildItem -LiteralPath $_ -File -Recurse:$Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -in '.exe', '.dll' }
})
$randomized = $candidates | Get-Random -Count $candidates.Count -SetSeed 20260928
$seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$totalBytes = 0L
$count = 0
$writers = [IO.StreamWriter]::new($manifest, $false, [Text.UTF8Encoding]::new($false))
try {
    foreach ($candidate in $randomized) {
        if ($count -ge $MaxFiles) { break }
        $candidate.Refresh()
        if ($candidate.Length -gt $MaxFileBytes) { continue }
        if ($candidate.Length -gt ($MaxBytes - $totalBytes)) { continue }
        if (-not (Test-PEHeader $candidate.FullName)) { continue }
        $signature = Get-AuthenticodeSignature -LiteralPath $candidate.FullName
        if ($signature.Status -ne 'Valid' -or
            $signature.SignerCertificate.Subject -notmatch $SignerSubjectPattern) { continue }
        $digest = (Get-FileHash -LiteralPath $candidate.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        if (-not $seen.Add($digest)) { continue }
        $destination = Join-Path $samplesDirectory ($digest + $candidate.Extension.ToLowerInvariant())
        Copy-Item -LiteralPath $candidate.FullName -Destination $destination
        $row = [ordered]@{
            path = 'samples/' + [IO.Path]::GetFileName($destination)
            sha256 = $digest
            label = 'benign'
            source = $SourceLabel
            source_path = $candidate.FullName
            signer = $signature.SignerCertificate.Subject
            split = 'test'
        }
        $writers.WriteLine(($row | ConvertTo-Json -Compress))
        $totalBytes += (Get-Item -LiteralPath $destination).Length
        $count++
    }
} finally {
    $writers.Dispose()
}
[pscustomobject]@{ Candidates = $candidates.Count; Selected = $count; Bytes = $totalBytes; Manifest = $manifest }
