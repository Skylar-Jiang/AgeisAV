$ErrorActionPreference = 'Stop'
# Dot-source only the read-only check; no VM settings or power changes.
. "$PSScriptRoot\..\Manage-VM.ps1" -Action CheckOffline
$safe = 'isolation.tools.copy.disable = "TRUE"'
if (-not (Test-SafeSetting $safe 'isolation.tools.copy.disable' 'TRUE')) { throw 'Safe config rejected' }
foreach ($config in @("$safe`nisolation.tools.copy.disable = `"FALSE`"",
                      "$safe`nISOLATION.TOOLS.COPY.DISABLE = `"TRUE`"",
                      "$safe`nisolation.tools.copy.disable = FALSE",
                      'isolation.tools.copy.disable = "FALSE"')) {
    if (Test-SafeSetting $config 'isolation.tools.copy.disable' 'TRUE') {
        throw 'Conflicting, duplicate, or unsafe VMX setting accepted'
    }
}
'PASS: duplicate and unsafe VMX settings rejected'
