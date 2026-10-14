param([switch] $Apply)
$ErrorActionPreference = 'Stop'
$vmx = 'D:\VMs\AegisAV-Ubuntu-24.04\guest\AegisAV-Static-Ubuntu\AegisAV-Static-Ubuntu.vmx'
$vmrun = 'D:\VM\vmrun.exe'
$vmcli = 'D:\VM\vmcli.exe'
$keep = @('clean-tools-benign-off-20261003-v2', 'clean-tools-ml-off-20261010-v2')
# These historical checkpoints are superseded; never delete descendants.
$obsolete = @('clean-tools-benign-20261002', 'clean-tools-benign-off-20261003', 'clean-tools-ml-off-20261010')
$directory = Split-Path $vmx -Parent
function Get-Snapshots {
    $listing = @(& $vmrun -T ws listSnapshots $vmx)
    if ($LASTEXITCODE -ne 0 -or $listing[0] -notmatch '^Total snapshots: [0-9]+$') {
        throw 'Could not enumerate dedicated VM snapshots.'
    }
    return @($listing | Select-Object -Skip 1)
}
function Get-Inventory {
    $files = @(Get-ChildItem -LiteralPath $directory -File | Select-Object Name, Length)
    return @{ files = $files; apparent_bytes = ($files | Measure-Object Length -Sum).Sum;
        drive_free_bytes = (Get-PSDrive -Name D).Free; snapshots = @(Get-Snapshots) }
}
function Test-CleanBaseline([string] $Metadata) {
    $config = $Metadata.Replace("`r`n", "`n")
    $currents = [regex]::Matches($config, '(?m)^snapshot\.current = "([0-9]+)"$')
    $names = [regex]::Matches($config, ('(?m)^snapshot([0-9]+)\.displayName = "' + [regex]::Escape($keep[1]) + '"$'))
    if ($currents.Count -ne 1 -or $names.Count -ne 1) { return $false }
    $uids = [regex]::Matches($config, ('(?m)^snapshot' + $names[0].Groups[1].Value + '\.uid = "([0-9]+)"$'))
    return ($uids.Count -eq 1 -and $uids[0].Groups[1].Value -eq $currents[0].Groups[1].Value)
}
$before = Get-Inventory
if (@($keep | Where-Object { $_ -notin $before.snapshots }).Count) {
    throw 'A required baseline or rollback point is missing.'
}
$planned = @($obsolete | Where-Object { $_ -in $before.snapshots })
if (-not $Apply) {
    [pscustomobject]@{ Mode='ReadOnly'; Preserve=$keep; RemoveAfterExperiments=$planned; Inventory=$before }
    return
}
if (-not $planned.Count) {
    [pscustomobject]@{ Mode='NoChanges'; Preserve=$keep; Deleted=@() }
    return
}
$output = Join-Path (Split-Path $PSScriptRoot -Parent) ('docs\benchmarks\vm_snapshot_cleanup_' + [DateTime]::UtcNow.ToString('yyyyMMdd_HHmmss') + '.json')
$power = @(& $vmcli $vmx Power query)
if ($LASTEXITCODE -ne 0 -or $power -notcontains 'PowerState: off') {
    throw 'Finish exports and power off the dedicated VM; suspended or running is refused.'
}
$metadata = Get-Content -LiteralPath ([IO.Path]::ChangeExtension($vmx, '.vmsd')) -Raw
if (-not (Test-CleanBaseline $metadata)) {
    throw 'Restore the current clean ML baseline before consolidation.'
}
$diskBytes = ($before.files | Where-Object Name -Like '*.vmdk' | Measure-Object Length -Sum).Sum
if ($before.drive_free_bytes -lt (2 * $diskBytes + 1GB)) {
    throw 'Insufficient conservative free-space margin for VMware consolidation.'
}
$deleted = @()
@{ status='started'; timestamp_utc=[DateTime]::UtcNow.ToString('o'); before=$before; planned=$planned; preserved=$keep } |
    ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $output -Encoding utf8
foreach ($name in $planned) {
    & $vmrun -T ws deleteSnapshot $vmx $name
    if ($LASTEXITCODE -ne 0) { throw "VMware failed to delete snapshot: $name. No manual file cleanup attempted." }
    $remaining = @(Get-Snapshots)
    if ($name -in $remaining -or @($keep | Where-Object { $_ -notin $remaining }).Count) {
        throw 'Snapshot preservation verification failed; stop further changes.'
    }
    $deleted += $name
    @{ status='consolidating'; timestamp_utc=[DateTime]::UtcNow.ToString('o'); before=$before; deleted=$deleted; preserved=$keep } |
        ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $output -Encoding utf8
}
$after = Get-Inventory
$report = @{ status='completed'; timestamp_utc=[DateTime]::UtcNow.ToString('o'); vmx=$vmx; method='vmrun deleteSnapshot, without andDeleteChildren';
    preserved=$keep; deleted=$deleted; before=$before; after=$after;
    apparent_bytes_reduced=($before.apparent_bytes - $after.apparent_bytes);
    drive_free_bytes_increase=($after.drive_free_bytes - $before.drive_free_bytes);
    note='Apparent file lengths and volume free space differ for sparse files and concurrent host activity.' }
$report | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $output -Encoding utf8
[pscustomobject]@{Deleted=$deleted; Preserved=$keep; ApparentGiBReduced=[math]::Round($report.apparent_bytes_reduced/1GB,3); Report=$output}
