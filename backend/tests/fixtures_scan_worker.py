"""Inert process fault fixtures; not a detection engine and never used by production."""
import json
import os
import subprocess
import sys
import time
from aegisav.scan_process import contain_worker, MAX_REPORT

contain_worker()
mode = sys.argv[1]
if mode == 'no_read':
    time.sleep(2)
    sys.exit(0)
data = sys.stdin.buffer.read()
if mode == 'routing':
    mode = 'hang' if data.startswith(b'AEGISAV-INERT-HANG') else 'real'
if mode == 'hang':
    subprocess.Popen([sys.executable,'-c','import time; time.sleep(120)'])
    time.sleep(120)
elif mode == 'crash':
    os._exit(42)
elif mode == 'oversized':
    sys.stdout.buffer.write(b'x'*(MAX_REPORT+1))
elif mode == 'allocate':
    try:
        large = bytearray(768*1024**2)
        limited = False
    except MemoryError:
        limited = True
    print(json.dumps({'report':{'limited':limited}}))
elif mode == 'real':
    from aegisav.runtime import build_scanner
    try:
        print(json.dumps({'report':build_scanner().scan(data)}))
    except ValueError as error:
        print(json.dumps({'invalid':str(error)[:200]}))
else:
    print(json.dumps({'report':{'verdict':'undetermined','engines':{},'fixture':True}}))
