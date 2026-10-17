import json
import runpy
import sys
import time
from pathlib import Path

client=Path('/opt/aegisav-stagee2-cases-v4/collect_analyst_cases.py')
action=sys.argv[1]
assert action in {'acquire','scan'}
output=Path('/srv/aegisav-corpus/cohorts/analyst-case-20261017-v2/results')/(action+'-resources.json')
assert not output.exists()
relative=next(x.split(':',2)[2] for x in Path('/proc/self/cgroup').read_text().splitlines() if x.startswith('0::'))
cgroup=Path('/sys/fs/cgroup')/relative.lstrip('/')
start=time.monotonic();sys.argv=[str(client),action]
try:
    runpy.run_path(str(client),run_name='__main__')
finally:
    record=dict(action=action,wall_ms=(time.monotonic()-start)*1000,
                memory_peak_bytes=int((cgroup/'memory.peak').read_text()),
                memory_max=(cgroup/'memory.max').read_text().strip(),
                memory_events=(cgroup/'memory.events').read_text(),
                cpu_stat=(cgroup/'cpu.stat').read_text(),
                scope='whole transient cgroup including wrapper, task parent, guardian and parser; separate clamd excluded')
    output.write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record))
