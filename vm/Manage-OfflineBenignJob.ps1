param(
    [Parameter(Mandatory)][ValidateSet('Start', 'Status')][string] $Action,
    [Parameter(Mandatory)][ValidateSet('windows', 'vendor', 'expansion')][string] $Group
)
$ErrorActionPreference = 'Stop'
& "$PSScriptRoot\Manage-VM.ps1" -Action CheckOffline
$vmx = 'D:\VMs\AegisAV-Ubuntu-24.04\guest\AegisAV-Static-Ubuntu\AegisAV-Static-Ubuntu.vmx'
$credential = Import-Clixml -LiteralPath 'D:\VMs\AegisAV-Ubuntu-24.04\media\operator.credential.xml'
if ($credential.UserName -ne 'aegisav-operator') { throw 'Unexpected guest identity.' }
$script = @'
import hashlib,json,os,subprocess,sys,time
from pathlib import Path
assert os.getuid()==1001
isolation=subprocess.check_output(['/usr/local/bin/aegisav-isolation-check'],text=True).strip()
group='GROUP'
command=['/opt/aegisav-static/venv/bin/python','/opt/aegisav-static/static_benign.py','--group',group]
running=[]
for path in Path('/proc').glob('[0-9]*/cmdline'):
    try:
        if path.read_bytes().split(b'\0')[:4]==[part.encode() for part in command]:
            running.append(int(path.parent.name))
    except OSError:pass
assert len(running)<=1
if 'ACTION'=='Start' and not running:
    log=(Path.home()/('benign-'+group+'-run.log')).open('ab',buffering=0)
    process=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,
                             start_new_session=True,cwd=Path.home())
    running=[process.pid]
    (Path.home()/('benign-'+group+'-job.json')).write_text(json.dumps({'pid':process.pid,'mode':'detached_session','group':group}))
checkpoint=Path.home()/('benign-'+group+'.checkpoint.json')
state={'group':group,'pid':running[0] if running else None,'alive':bool(running),'count':0,'completed':False,
       'isolation':isolation,'observed_unix':time.time()}
if checkpoint.exists():
    sys.path.insert(0,'/opt/aegisav-static')
    from benign_checkpoint import load_checkpoint
    raw=checkpoint.read_bytes()
    identity=json.loads(raw)['payload']['identity']
    saved=load_checkpoint(checkpoint,identity)
    state.update(count=len(saved['report']['files']),completed=saved['report']['completed'],
                 checkpoint_sha256=hashlib.sha256(raw).hexdigest(),sessions=len(saved['sessions']))
(Path.home()/('benign-'+group+'-state.json')).write_text(json.dumps(state))
'@
$script = $script.Replace('GROUP', $Group).Replace('ACTION', $Action)
try {
    & 'D:\VM\vmrun.exe' -T ws -gu $credential.UserName -gp ($credential.GetNetworkCredential().Password) runProgramInGuest $vmx /usr/bin/python3 -c $script
    if ($LASTEXITCODE) { throw 'Offline benign job operation failed.' }
    $output = Join-Path (Split-Path $PSScriptRoot -Parent) "artifacts\offline-results\benign-$Group-state.json"
    & 'D:\VM\vmrun.exe' -T ws -gu $credential.UserName -gp ($credential.GetNetworkCredential().Password) CopyFileFromGuestToHost $vmx "/home/aegisav-operator/benign-$Group-state.json" $output
    if ($LASTEXITCODE -or (Get-Item -LiteralPath $output).Length -gt 4096) { throw 'Invalid job status export.' }
    Get-Content -LiteralPath $output -Raw | ConvertFrom-Json
} finally { $credential = $null }
