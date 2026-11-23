"""Guest resource/provenance metadata only; never opens sample contents or credentials."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0,'/opt/aegisav-collection')
from collect_malwarebazaar import identity, ROOT


def main():
    _, bound = identity()
    report = dict(captured_unix=time.time(),identity=bound,boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                  meminfo=Path('/proc/meminfo').read_text(),volumes={},services={},clamav_assets={},processes=[])
    for path in ('/',str(ROOT)):
        disk=os.statvfs(path)
        report['volumes'][path]=dict(total_bytes=disk.f_blocks*disk.f_frsize,available_bytes=disk.f_bavail*disk.f_frsize)
    for name in ('aegisav-fetch','aegisav-analysis','clamav-daemon','aegisav-api','ssh'):
        properties=subprocess.check_output(['systemctl','show',name+'.service','-p','ActiveState','-p','Result','-p','MemoryCurrent','-p','MemoryPeak','-p','CPUUsageNSec','-p','TasksCurrent','-p','MemoryMax','-p','CPUQuotaPerSecUSec','-p','TasksMax'],text=True)
        report['services'][name]=dict(line.split('=',1) for line in properties.splitlines() if '=' in line)
    for path in Path('/var/lib/clamav').glob('*'):
        if path.suffix in ('.cld','.cvd'):
            report['clamav_assets'][path.name]=dict(bytes=path.stat().st_size,sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    report['configuration_sha256']={}
    for name in ('/etc/clamav/clamd.conf','/etc/systemd/system/aegisav-analysis.service','/etc/systemd/system/aegisav-fetch.service','/etc/systemd/system/aegisav-analysis.service.d/accounting.conf'):
        path=Path(name)
        if path.exists():
            report['configuration_sha256'][name]=hashlib.sha256(path.read_bytes()).hexdigest()
    for path in Path('/proc').iterdir():
        if path.name.isdigit():
            try:
                report['processes'].append(dict(pid=int(path.name),comm=(path/'comm').read_text().strip()))
            except (FileNotFoundError,PermissionError,ProcessLookupError):
                pass
    print(json.dumps(report,indent=2))


if __name__=='__main__':
    main()
