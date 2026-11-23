"""Readiness gate before any development sample is scored."""
import os
import subprocess
import sys
import time

assert os.getuid()==1001
subprocess.run(['/usr/local/bin/aegisav-isolation-check'],check=True)
sys.path.insert(0,'/opt/aegisav-product/releases/c699902f19640593/backend')
from aegisav.clamav_engine import ClamAVEngine
engine=ClamAVEngine()
for _ in range(60):
    if engine.probe() and engine.engine_version=='ClamAV 1.5.4' and engine.artifact_version=='28148':
        print('FROZEN_CLAMAV_READY PASS version=1.5.4 database=28148')
        break
    time.sleep(.5)
else:
    raise SystemExit('Frozen ClamAV engine/database readiness not confirmed')
