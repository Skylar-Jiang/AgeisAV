"""Opt-in local acceptance service with inert fault injection, never deployed."""
import os
from pathlib import Path
import sys

from aegisav.api import create_app
from aegisav.local_access import load_access_token
from aegisav.runtime import build_scanner
from aegisav.scan_process import ProcessScanner

if os.environ.get('AEGISAV_RELIABILITY_FIXTURE') != '1':
    raise RuntimeError('Acceptance fixture requires explicit opt-in')
root = Path(__file__).resolve().parents[1]
runner = ProcessScanner(command=[sys.executable,str(root/'backend/tests/fixtures_scan_worker.py'),'routing'])
app = create_app(build_scanner(),access_token=load_access_token(Path(os.environ['AEGISAV_ACCESS_TOKEN_FILE'])),
                 db_path=Path(os.environ['AEGISAV_TASK_DB']),runner=runner,
                 frontend_dir=root/'frontend/out',file_timeout=float(os.environ.get('AEGISAV_TEST_FILE_TIMEOUT','30')),
                 task_timeout=float(os.environ.get('AEGISAV_TEST_TASK_TIMEOUT','60')),
                 release_id='inert-fault-acceptance-only')


@app.get('/v1/test/resources')
def resources():
    import ctypes
    class Memory(ctypes.Structure):
        _fields_ = [('cb',ctypes.c_ulong),('faults',ctypes.c_ulong)]+[(key,ctypes.c_size_t) for key in
                    ('peak_ws','ws','peak_paged','paged','peak_nonpaged','nonpaged','pagefile','peak_pagefile')]
    memory = Memory()
    memory.cb = ctypes.sizeof(memory)
    if os.name == 'nt':
        from ctypes import wintypes as w
        kernel = ctypes.WinDLL('kernel32')
        kernel.GetCurrentProcess.restype=w.HANDLE
        psapi = ctypes.WinDLL('psapi')
        psapi.GetProcessMemoryInfo.argtypes=[w.HANDLE,ctypes.c_void_p,w.DWORD]
        psapi.GetProcessMemoryInfo(kernel.GetCurrentProcess(),ctypes.byref(memory),memory.cb)
    return {'pid':os.getpid(),'worker_pid':runner.active_pid,'pending':app.state.tasks.pending,
            'reserved_bytes':app.state.tasks.reserved_bytes,'rss_bytes':memory.ws,'peak_rss_bytes':memory.peak_ws}


# The acceptance-only route must precede the existing catch-all static mount.
app.router.routes.insert(0,app.router.routes.pop())
