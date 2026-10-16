# Read-only readiness for the existing VM; never boot, reconfigure or stop it.
$ErrorActionPreference='Stop'
$vmx='D:\VMs\AegisAV-Ubuntu-24.04\guest\AegisAV-Static-Ubuntu\AegisAV-Static-Ubuntu.vmx'
& "$PSScriptRoot\Manage-VM.ps1" -Action CheckOffline | Out-Null
$power=& 'D:\VM\vmcli.exe' $vmx Power query
if ($LASTEXITCODE) { throw 'Dedicated VM power query failed.' }
$memory=[regex]::Matches([IO.File]::ReadAllText($vmx),'(?im)^\s*memsize\s*=\s*"([0-9]+)"\s*$')
if ($memory.Count -ne 1) { throw 'Ambiguous guest memory configuration.' }
$guestBytes=[uint64]$memory[0].Groups[1].Value*1MB
$available=[uint64](Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory*1KB
$required=$guestBytes+2GB
$status=if ($power -notcontains 'PowerState: off') {'busy'} elseif ($available -lt $required) {'deferred_memory'} else {'ready_for_guest_validation'}
[ordered]@{schema=1;status=$status;read_only=$true;guest_validation_performed=$false;
    captured_at_utc=[DateTime]::UtcNow.ToString('o');
    guest_memory_bytes=$guestBytes;host_available_bytes=$available;required_available_bytes=$required;
    host_vmx_offline_passed=$true;vm_modified=$false} | ConvertTo-Json
