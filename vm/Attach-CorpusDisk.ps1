param()
$ErrorActionPreference = 'Stop'
$vmx = 'D:\VMs\AegisAV-Ubuntu-24.04\guest\AegisAV-Static-Ubuntu\AegisAV-Static-Ubuntu.vmx'
$diskDir = 'D:\VMs\AegisAV-Ubuntu-24.04\corpus'
$disk = Join-Path $diskDir 'aegisav-corpus.vmdk'
$power = & D:\VM\vmcli.exe $vmx Power query
if ($LASTEXITCODE -or $power -notcontains 'PowerState: off') { throw 'Power off dedicated VM first.' }
$config = [IO.File]::ReadAllText($vmx)
if ($config -match '(?im)^\s*scsi0:1\.') { throw 'Disk slot already configured; inspect existing attachment instead of overwriting.' }
if (Test-Path -LiteralPath $disk) { throw 'Existing corpus disk is never overwritten.' }
if ((Get-PSDrive D).Free -lt 25GB) { throw 'At least 25 GiB host disk headroom required.' }
[void](New-Item -ItemType Directory -Force -Path $diskDir)
& D:\VM\vmware-vdiskmanager.exe -c -s 12GB -a lsilogic -t 0 $disk
if ($LASTEXITCODE) { throw 'Corpus disk creation failed.' }
[IO.File]::WriteAllText((Join-Path $diskDir 'vmx-before-corpus.txt'), $config)
$addition = "`nscsi0:1.present = `"TRUE`"`nscsi0:1.deviceType = `"disk`"`nscsi0:1.fileName = `"$disk`"`nscsi0:1.mode = `"independent-persistent`"`nscsi0:1.allowGuestConnectionControl = `"FALSE`"`n"
[IO.File]::WriteAllText($vmx, $config + $addition, [Text.UTF8Encoding]::new($false))
[pscustomobject]@{ Disk = $disk; CapacityGiB = 12; Mode = 'independent-persistent'; OtherVMsChanged = $false }
