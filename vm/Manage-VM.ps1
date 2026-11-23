param(
    [Parameter(Mandatory)]
    [ValidateSet('Bootstrap', 'HostOnly', 'NAT', 'Offline', 'CheckOffline', 'CheckNAT', 'Start', 'Stop', 'Snapshot', 'Revert', 'Status')]
    [string] $Action,
    [string] $SnapshotName,
    [string] $SeedIso = 'D:\VMs\AegisAV-Ubuntu-24.04\media\seed\aegisav-seed.iso'
)

$ErrorActionPreference = 'Stop'
$vmx = 'D:\VMs\AegisAV-Ubuntu-24.04\guest\AegisAV-Static-Ubuntu\AegisAV-Static-Ubuntu.vmx'
$vmrun = 'D:\VM\vmrun.exe'
$vmcli = 'D:\VM\vmcli.exe'
if (-not (Test-Path -LiteralPath $vmx) -or -not (Test-Path -LiteralPath $vmrun) -or -not (Test-Path -LiteralPath $vmcli)) {
    throw 'The dedicated AegisAV VM or vmrun is missing.'
}

function Assert-Stopped {
    $running = & $vmrun -T ws list
    if ($LASTEXITCODE -ne 0) { throw 'Could not query running VMs.' }
    if ($running -contains $vmx) { throw 'Power off the dedicated VM before editing its settings.' }
    $power = & $vmcli $vmx Power query
    if ($LASTEXITCODE -ne 0 -or $power -notcontains 'PowerState: off') {
        throw 'The dedicated VM must be powered off, not suspended, before editing settings or taking/restoring a snapshot.'
    }
}

function Test-SafeSetting([string] $Config, [string] $Name, [string] $Value) {
    $key = [regex]::Escape($Name)
    $safe = [regex]::Escape($Value)
    return ([regex]::Matches($Config, "(?im)^\s*$key\s*=").Count -eq 1 -and
        $Config -match "(?im)^\s*$key\s*=\s*`"$safe`"\s*$")
}

function Set-Settings([hashtable] $settings) {
    Assert-Stopped
    $lines = [Collections.Generic.List[string]]::new()
    [IO.File]::ReadAllLines($vmx) | ForEach-Object { [void] $lines.Add($_) }
    foreach ($name in $settings.Keys) {
        $entry = "$name = `"$($settings[$name])`""
        $found = $false
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match ('(?i)^\s*' + [regex]::Escape($name) + '\s*=')) {
                $lines[$i] = $entry
                $found = $true
            }
        }
        if (-not $found) { $lines.Add($entry) }
    }
    [IO.File]::WriteAllLines($vmx, $lines, [Text.UTF8Encoding]::new($false))
}

$common = @{
    'sharedFolder.maxNum' = '0'
    'isolation.tools.hgfs.disable' = 'TRUE'
    'isolation.tools.copy.disable' = 'TRUE'
    'isolation.tools.paste.disable' = 'TRUE'
    'isolation.tools.dnd.disable' = 'TRUE'
    'usb.present' = 'FALSE'
    'floppy0.present' = 'FALSE'
    'serial0.present' = 'FALSE'
    'ethernet0.allowGuestConnectionControl' = 'FALSE'
}

switch ($Action) {
    'NAT' {
        $settings = $common + @{
            'ethernet0.connectionType' = 'nat'
            'ethernet0.present' = 'TRUE'; 'ethernet0.startConnected' = 'TRUE'
            'vmci0.present' = 'FALSE'
            'ide1:0.present' = 'FALSE'; 'ide1:0.startConnected' = 'FALSE'
        }
        1..9 | ForEach-Object { $settings["ethernet$_.present"] = 'FALSE'; $settings["ethernet$_.startConnected"] = 'FALSE' }
        Set-Settings $settings
    }
    'Bootstrap' {
        if (-not (Test-Path -LiteralPath $SeedIso)) { throw "Seed ISO missing: $SeedIso" }
        Set-Settings ($common + @{
            'numvcpus' = '4'; 'memsize' = '8192'
            'ethernet0.connectionType' = 'nat'
            'ethernet0.present' = 'TRUE'; 'ethernet0.startConnected' = 'TRUE'
            'ide1:0.fileName' = $SeedIso
            'ide1:0.deviceType' = 'cdrom-image'
            'ide1:0.clientDevice' = 'FALSE'; 'ide1:0.autodetect' = 'FALSE'
            'ide1:0.present' = 'TRUE'; 'ide1:0.startConnected' = 'TRUE'
        })
    }
    'HostOnly' {
        Set-Settings ($common + @{
            'ethernet0.connectionType' = 'hostonly'
            'ethernet0.present' = 'TRUE'; 'ethernet0.startConnected' = 'TRUE'
            'vmci0.present' = 'TRUE'
            'ide1:0.present' = 'FALSE'; 'ide1:0.startConnected' = 'FALSE'
        })
    }
    'Offline' {
        $settings = $common + @{
            'ethernet0.present' = 'FALSE'; 'ethernet0.startConnected' = 'FALSE'
            'vmci0.present' = 'FALSE'
            'ide1:0.present' = 'FALSE'; 'ide1:0.startConnected' = 'FALSE'
        }
        1..9 | ForEach-Object { $settings["ethernet$_.present"] = 'FALSE' }
        1..9 | ForEach-Object { $settings["ethernet$_.startConnected"] = 'FALSE' }
        Set-Settings $settings
    }
    { $_ -in 'CheckOffline','CheckNAT' } {
        $config = [IO.File]::ReadAllText($vmx)
        $required = @{
            'sharedFolder.maxNum' = '0'; 'isolation.tools.hgfs.disable' = 'TRUE'
            'isolation.tools.copy.disable' = 'TRUE'; 'isolation.tools.paste.disable' = 'TRUE'
            'isolation.tools.dnd.disable' = 'TRUE'; 'usb.present' = 'FALSE'
            'vmci0.present' = 'FALSE'; 'ethernet0.startConnected' = 'FALSE'
            'floppy0.present' = 'FALSE'; 'serial0.present' = 'FALSE'
            'ide1:0.present' = 'FALSE'; 'ide1:0.startConnected' = 'FALSE'
        }
        0..9 | ForEach-Object { $required["ethernet$_.present"] = 'FALSE' }
        1..9 | ForEach-Object { $required["ethernet$_.startConnected"] = 'FALSE' }
        if ($Action -eq 'CheckNAT') {
            $required['ethernet0.present'] = 'TRUE'
            $required['ethernet0.startConnected'] = 'TRUE'
            $required['ethernet0.connectionType'] = 'nat'
            $required['ethernet0.allowGuestConnectionControl'] = 'FALSE'
        }
        $bad = @($required.Keys | Where-Object {
            -not (Test-SafeSetting $config $_ $required[$_])
        })
        if ($bad.Count) { throw ("$Action VMX check failed: " + ($bad -join ', ')) }
        "$Action VMX settings pass. Guest network and data paths still require an in-guest check."
    }
    'Start' { & $vmrun -T ws start $vmx nogui; if ($LASTEXITCODE) { throw 'Start failed' } }
    'Stop' { & $vmrun -T ws stop $vmx soft; if ($LASTEXITCODE) { throw 'Soft stop failed' } }
    'Snapshot' {
        if (-not $SnapshotName) { throw 'SnapshotName is required.' }
        Assert-Stopped
        & $vmrun -T ws snapshot $vmx $SnapshotName
        if ($LASTEXITCODE) { throw 'Snapshot failed' }
    }
    'Revert' {
        if (-not $SnapshotName) { throw 'SnapshotName is required.' }
        Assert-Stopped
        & $vmrun -T ws revertToSnapshot $vmx $SnapshotName
        if ($LASTEXITCODE) { throw 'Revert failed' }
    }
    'Status' {
        & $vmrun -T ws list
        & $vmrun -T ws listSnapshots $vmx
    }
}
