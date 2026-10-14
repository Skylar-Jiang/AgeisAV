param()
$ErrorActionPreference = 'Stop'
& "$PSScriptRoot\Manage-VM.ps1" -Action CheckOffline
$vmx = 'D:\VMs\AegisAV-Ubuntu-24.04\guest\AegisAV-Static-Ubuntu\AegisAV-Static-Ubuntu.vmx'
$media = 'D:\VMs\AegisAV-Ubuntu-24.04\media'
$credential = Import-Clixml -LiteralPath (Join-Path $media 'operator.credential.xml')
if ($credential.UserName -ne 'aegisav-operator') { throw 'Unexpected guest credential identity.' }
function Invoke-GuestOperation([string[]] $OperationArgs) {
    & 'D:\VM\vmrun.exe' -T ws -gu $credential.UserName -gp ($credential.GetNetworkCredential().Password) @OperationArgs
    if ($LASTEXITCODE -ne 0) { throw "Guest operation failed: $($OperationArgs[0])" }
}
$probeId = [guid]::NewGuid().ToString('N')
$hostProbe = Join-Path $media "benign-probe-$probeId.txt"
$hostDigest = Join-Path $media "benign-probe-$probeId.sha256"
$hostIsolation = Join-Path $media "isolation-$probeId.txt"
$guestProbe = "/home/aegisav-operator/benign-probe-$probeId.txt"
[IO.File]::WriteAllText($hostProbe, "AegisAV harmless offline transfer probe $probeId`n")
Invoke-GuestOperation -OperationArgs @('CopyFileFromHostToGuest', $vmx, $hostProbe, $guestProbe)
Invoke-GuestOperation -OperationArgs @('runScriptInGuest', $vmx, '/bin/sh', "sha256sum $guestProbe > $guestProbe.sha256; /usr/local/bin/aegisav-isolation-check > $guestProbe.isolation")
Invoke-GuestOperation -OperationArgs @('CopyFileFromGuestToHost', $vmx, "$guestProbe.sha256", $hostDigest)
Invoke-GuestOperation -OperationArgs @('CopyFileFromGuestToHost', $vmx, "$guestProbe.isolation", $hostIsolation)
$expected = (Get-FileHash -LiteralPath $hostProbe -Algorithm SHA256).Hash.ToLowerInvariant()
$actual = (Get-Content -LiteralPath $hostDigest -Raw).Split(' ')[0]
if ($actual -ne $expected) { throw 'Offline transfer SHA-256 mismatch.' }
$isolation = Get-Content -LiteralPath $hostIsolation -Raw
if ($isolation -notmatch '^AEGISAV_ISOLATION PASS ') { throw "Guest isolation check did not pass: $isolation" }
$credential = $null
[pscustomobject]@{ Probe = $probeId; SHA256 = $actual; Isolation = $isolation.Trim(); Result = 'PASS'; EvidencePath = $hostIsolation }
