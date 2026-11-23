"""Only run in an explicitly capped 128 MiB acceptance cgroup; no file parsing."""
import os
from pathlib import Path
import subprocess
import sys

assert os.geteuid()==1001
relative=next(line.split(':',2)[2] for line in Path('/proc/self/cgroup').read_text().splitlines() if line.startswith('0::'))
group=Path('/sys/fs/cgroup')/relative.lstrip('/')
assert (group/'memory.max').read_text().strip()=='134217728'
assert (group/'memory.swap.max').read_text().strip()=='0'
assert (group/'memory.oom.group').read_text().strip()=='1'
code='import time; payload=bytearray(90*1024**2); time.sleep(30)'
children=[subprocess.Popen([sys.executable,'-c',code]) for _ in range(2)]
for child in children: child.wait()
raise AssertionError('Expected cgroup OOM tree kill did not occur')
