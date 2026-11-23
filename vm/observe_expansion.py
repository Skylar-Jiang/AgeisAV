"""Observe only systemd accounting; never open sample files or terminate workloads."""
import json
from pathlib import Path
import subprocess
import time

OUTPUT=Path('/home/ubuntu/expansion-scan-resources.json')
SERVICES=('aegisav-expansion-scan.service','clamav-daemon.service')
PROPERTIES=('ActiveState','SubState','MemoryCurrent','MemoryPeak','CPUUsageNSec','TasksCurrent')


def main():
    report=dict(schema=1,scope='systemd cgroups including scan descendants and separate clamd',
                sampling_seconds=5,started_after_scan=True,samples=[])
    for _ in range(1080):
        sample=dict(utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),services={})
        for service in SERVICES:
            result=subprocess.run(['systemctl','show',service,'--property='+','.join(PROPERTIES)],
                                  check=True,capture_output=True,text=True,timeout=5)
            sample['services'][service]=dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
        report['samples'].append(sample)
        temporary=OUTPUT.with_suffix('.tmp')
        temporary.write_text(json.dumps(report)+'\n')
        temporary.replace(OUTPUT)
        status=sample['services'][SERVICES[0]]
        if status['SubState'] in ('exited','dead','failed'):
            break
        time.sleep(5)


if __name__=='__main__':
    main()
