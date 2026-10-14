param([Parameter(Mandatory)][ValidateSet('ExpansionScan','ExpansionResources','NativeParity','FuzzyBenchmark','ExpansionDownload','Acquisition','Api','Failures','Checkpoint','Environment','Probe','OnlineProbe','Download','Analysis')][string]$Kind)
$ErrorActionPreference = 'Stop'
& "$PSScriptRoot/Invoke-CollectionGuest.ps1" -Script "set -e; sudo /usr/bin/python3 -I /opt/aegisav-collection/export_collection_evidence.py $Kind"
$credential = Import-Clixml -LiteralPath 'D:\VMs\AegisAV-Ubuntu-24.04\media\admin.credential.xml'
$vmx = 'D:\VMs\AegisAV-Ubuntu-24.04\guest\AegisAV-Static-Ubuntu\AegisAV-Static-Ubuntu.vmx'
$out = Join-Path $PSScriptRoot "../docs/benchmarks/collection_$($Kind.ToLowerInvariant())_20261013.json"
& D:\VM\vmrun.exe -T ws -gu $credential.UserName -gp ($credential.GetNetworkCredential().Password) CopyFileFromGuestToHost $vmx /home/ubuntu/collection-export.json $out
if ($LASTEXITCODE) { throw 'Structured evidence export failed.' }
$credential = $null
$null = Get-Content -LiteralPath $out -Raw | ConvertFrom-Json
Get-Item -LiteralPath $out | Select-Object Name,Length
