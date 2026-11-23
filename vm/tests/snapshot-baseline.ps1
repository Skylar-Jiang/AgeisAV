$ErrorActionPreference = 'Stop'
# Load only the default read-only inventory, never -Apply.
. "$PSScriptRoot\..\Prune-ObsoleteSnapshots.ps1" | Out-Null
$fixture = @'
snapshot.current = "5"
snapshot4.uid = "5"
snapshot4.displayName = "clean-tools-ml-off-20261010-v2"
'@
foreach ($metadata in @($fixture.Replace("`r`n", "`n"), $fixture.Replace("`r`n", "`n").Replace("`n", "`r`n"))) {
    if (-not (Test-CleanBaseline $metadata)) { throw 'Clean baseline rejected for valid line endings' }
    if (Test-CleanBaseline ($metadata.Replace('snapshot.current = "5"', 'snapshot.current = "3"'))) {
        throw 'Different current snapshot accepted'
    }
    if (Test-CleanBaseline ($metadata + "`nsnapshot.current = `"5`"")) {
        throw 'Duplicate current snapshot metadata accepted'
    }
}
'PASS: LF/CRLF clean baseline accepted; wrong and duplicate current identity rejected'
