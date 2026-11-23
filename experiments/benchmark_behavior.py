"""Fixed harmless log sizes, disposable workers, sampled owned-tree memory only."""
import argparse
import ctypes
import json
import os
from pathlib import Path
import statistics
import sys
import threading
import time

from aegisav.scan_process import ProcessScanner


def windows_tree(pid):
    # A Windows venv python.exe may launch a separate interpreter process.
    from ctypes import wintypes as w
    class Entry(ctypes.Structure):
        _fields_=[('size',w.DWORD),('usage',w.DWORD),('pid',w.DWORD),('heap',ctypes.c_size_t),
                  ('module',w.DWORD),('threads',w.DWORD),('parent',w.DWORD),('priority',w.LONG),
                  ('flags',w.DWORD),('exe',w.WCHAR*260)]
    kernel=ctypes.WinDLL('kernel32')
    kernel.CreateToolhelp32Snapshot.argtypes=[w.DWORD,w.DWORD]; kernel.CreateToolhelp32Snapshot.restype=w.HANDLE
    kernel.Process32FirstW.argtypes=[w.HANDLE,ctypes.POINTER(Entry)]
    kernel.Process32NextW.argtypes=[w.HANDLE,ctypes.POINTER(Entry)]
    kernel.CloseHandle.argtypes=[w.HANDLE]
    handle=kernel.CreateToolhelp32Snapshot(2,0)
    if handle==ctypes.c_void_p(-1).value: return [pid]
    parents={}
    try:
        row=Entry(); row.size=ctypes.sizeof(row)
        present=kernel.Process32FirstW(handle,ctypes.byref(row))
        while present:
            parents[row.pid]=row.parent
            present=kernel.Process32NextW(handle,ctypes.byref(row))
    finally: kernel.CloseHandle(handle)
    owned={pid}
    for _ in range(8):
        more={child for child,parent in parents.items() if parent in owned}
        if more<=owned: break
        owned.update(more)
    return owned


def process_memory(pid):
    if not pid: return 0
    if os.name=='nt':
        from ctypes import wintypes as w
        kernel=ctypes.WinDLL('kernel32')
        kernel.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD]; kernel.OpenProcess.restype=w.HANDLE
        kernel.CloseHandle.argtypes=[w.HANDLE]
        handle=kernel.OpenProcess(0x1000|0x10,False,pid)
        if not handle: return 0
        class Memory(ctypes.Structure):
            _fields_=[('cb',w.DWORD),('faults',w.DWORD)]+[(name,ctypes.c_size_t) for name in
                ('peak_ws','ws','peak_paged','paged','peak_nonpaged','nonpaged','pagefile','peak_pagefile')]
        try:
            info=Memory(); info.cb=ctypes.sizeof(info)
            api=ctypes.WinDLL('psapi'); api.GetProcessMemoryInfo.argtypes=[w.HANDLE,ctypes.c_void_p,w.DWORD]
            return info.peak_ws if api.GetProcessMemoryInfo(handle,ctypes.byref(info),info.cb) else 0
        finally: kernel.CloseHandle(handle)
    # Independent Linux lifetime supervisor plus its parser child.
    try:
        children=(Path(f'/proc/{pid}/task/{pid}/children').read_text()).split()
        total=0
        for child in [str(pid),*children]:
            for line in Path(f'/proc/{child}/status').read_text().splitlines():
                if line.startswith('VmRSS:'): total+=int(line.split()[1])*1024
        return total
    except OSError: return 0


def owned_memory(pid):
    if not pid: return 0
    return sum(process_memory(child) for child in windows_tree(pid)) if os.name=='nt' else process_memory(pid)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',type=Path)
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[1]; output=args.output.resolve()
    if not output.is_relative_to(root/'artifacts') or output.exists(): parser.error('Fresh artifacts path required')
    cases={}
    for count in (6,100,1000):
        rows=[dict(event_id=1,provider='Microsoft-Windows-Sysmon',computer='harmless-fixture.local',
            timestamp='2026-10-19T00:00:01Z',record_id=str(i),fields=dict(ProcessGuid='{inert-'+str(i)+'}',
            ProcessId=str(i+1),Image=r'C:\Windows\notepad.exe',CommandLine='notepad.exe')) for i in range(count)]
        cases[count]=json.dumps({'events':rows}).encode()
    results=[]
    for count,data in cases.items():
        runs=[]; digests=[]; peak=0
        for _ in range(5):
            runner=ProcessScanner([sys.executable,'-m','aegisav.behavior_worker'],memory_bytes=256*1024**2)
            done=threading.Event(); samples=[]
            def monitor():
                while not done.wait(.01): samples.append(owned_memory(runner.active_pid))
            thread=threading.Thread(target=monitor); thread.start()
            started=time.monotonic()
            try: report=runner.scan(data,threading.Event(),started+20)
            finally: done.set(); thread.join()
            runs.append((time.monotonic()-started)*1000)
            import hashlib
            digests.append(hashlib.sha256(json.dumps(report,sort_keys=True).encode()).hexdigest())
            peak=max([peak,*samples])
            assert len(report['events'])==count and report['status']=='no_match' and runner.active_pid is None and runner.healthy
        assert len(set(digests))==1
        results.append(dict(events=count,input_bytes=len(data),runs_ms=runs,p50_ms=statistics.median(runs),
            p95_nearest_rank_ms=max(runs),sampled_peak_working_set_bytes=peak,equivalent_reports=True,failures=0))
    output.mkdir(parents=True)
    summary=dict(schema=1,production_optimization=False,method='15 disposable worker runs; 5 per event count; OS page cache uncontrolled, no application cache',
        memory_limit_bytes=256*1024**2,memory_note='Windows sampled owned launcher+descendant PeakWorkingSet sums; Linux sampled supervisor+child RSS. Sampling can miss the final peak.',
        accuracy_evaluation=False,results=results)
    (output/'summary.json').write_bytes((json.dumps(summary,indent=2)+'\n').encode())
    print(json.dumps(summary))


if __name__=='__main__': main()
