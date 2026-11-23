"""Disposable static-parser process, with owned-tree termination and OS limits."""
import ctypes
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
from threading import Thread
from uuid import uuid4

from .tasks import ScanStopped

MAX_REPORT = 2*1024**2


def windows_api():
    from ctypes import wintypes as w
    api = ctypes.WinDLL('kernel32', use_last_error=True)
    for name, args, result in [
        ('CreateJobObjectW',[ctypes.c_void_p,w.LPCWSTR],w.HANDLE),
        ('OpenJobObjectW',[w.DWORD,w.BOOL,w.LPCWSTR],w.HANDLE),
        ('SetInformationJobObject',[w.HANDLE,ctypes.c_int,ctypes.c_void_p,w.DWORD],w.BOOL),
        ('AssignProcessToJobObject',[w.HANDLE,w.HANDLE],w.BOOL),
        ('GetCurrentProcess',[],w.HANDLE),('CloseHandle',[w.HANDLE],w.BOOL)]:
        function = getattr(api,name)
        function.argtypes, function.restype = args,result
    return api


def create_job(memory_bytes):
    from ctypes import wintypes as w
    class Basic(ctypes.Structure):
        _fields_ = [('process_time',ctypes.c_longlong),('job_time',ctypes.c_longlong),('flags',w.DWORD),
                    ('min_ws',ctypes.c_size_t),('max_ws',ctypes.c_size_t),('processes',w.DWORD),
                    ('affinity',ctypes.c_size_t),('priority',w.DWORD),('scheduling',w.DWORD)]
    class Extended(ctypes.Structure):
        _fields_ = [('basic',Basic),('io',ctypes.c_ulonglong*6),('process_memory',ctypes.c_size_t),
                    ('job_memory',ctypes.c_size_t),('peak_process',ctypes.c_size_t),('peak_job',ctypes.c_size_t)]
    api = windows_api()
    name = 'Local\\AegisAV-'+uuid4().hex
    handle = api.CreateJobObjectW(None,name)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    limits = Extended()
    limits.basic.flags = 0x2000 | 0x200 | 0x8 | 0x2  # kill on close, job RAM, processes, CPU
    limits.basic.processes = 8
    limits.basic.process_time = 120*10_000_000
    limits.job_memory = memory_bytes
    if not api.SetInformationJobObject(handle,9,ctypes.byref(limits),ctypes.sizeof(limits)):
        error = ctypes.WinError(ctypes.get_last_error())
        api.CloseHandle(handle)
        raise error
    return api,handle,name


def contain_worker():
    """Run before reading PE bytes/importing parsers. Failure aborts the worker."""
    if os.name == 'nt':
        if ctypes.WinDLL('shell32').IsUserAnAdmin():
            raise RuntimeError('Static scan worker must not run elevated')
        api = windows_api()
        handle = api.OpenJobObjectW(1,False,os.environ['AEGISAV_SCAN_JOB'])
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            if not api.AssignProcessToJobObject(handle,api.GetCurrentProcess()):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            api.CloseHandle(handle)  # Only the service retains the lifetime handle.
    else:
        import resource
        if sys.platform != 'linux' or os.geteuid() == 0:
            raise RuntimeError('Static scan worker requires non-root Linux or Windows')
        if os.environ.get('AEGISAV_SCAN_SUPERVISED') != '1':
            raise RuntimeError('Linux worker requires the independent lifetime supervisor')
        memory = int(os.environ['AEGISAV_SCAN_MEMORY'])
        resource.setrlimit(resource.RLIMIT_AS,(memory,memory))
        resource.setrlimit(resource.RLIMIT_CPU,(120,120))
        resource.setrlimit(resource.RLIMIT_CORE,(0,0))
        resource.setrlimit(resource.RLIMIT_NOFILE,(128,128))
        resource.setrlimit(resource.RLIMIT_FSIZE,(MAX_REPORT,MAX_REPORT))
        os.umask(0o077)


class ProcessScanner:
    def __init__(self, command=None, memory_bytes=2*1024**3):
        self.command = command or [sys.executable,'-m','aegisav.scan_worker']
        self.memory_bytes = memory_bytes
        self.active_pid = None
        self.healthy = True

    def scan(self, data, cancel, deadline):
        if not self.healthy:
            raise RuntimeError('Scan worker cleanup previously failed; restart and inspect resources')
        env = os.environ.copy()
        for key in list(env):
            if any(word in key.upper() for word in ('TOKEN','PASSWORD','SECRET','AUTH_KEY','API_KEY')) or key == 'AEGISAV_TASK_DB':
                env.pop(key,None)
        env['AEGISAV_SCAN_PARENT'] = str(os.getpid())
        env['AEGISAV_SCAN_MEMORY'] = str(self.memory_bytes)
        env['PYTHONPATH'] = str(Path(__file__).resolve().parents[1])
        for key in ('OMP_NUM_THREADS','OPENBLAS_NUM_THREADS','MKL_NUM_THREADS'):
            env[key] = '1'
        job = create_job(self.memory_bytes) if os.name == 'nt' else None
        if job:
            env['AEGISAV_SCAN_JOB'] = job[2]
        process = None
        writer = None
        output = None
        try:
            output = tempfile.TemporaryFile()
            command = self.command if os.name=='nt' else [sys.executable,'-m','aegisav.scan_supervisor',*self.command]
            process = subprocess.Popen(command,stdin=subprocess.PIPE,stdout=output,stderr=subprocess.DEVNULL,
                                       env=env,start_new_session=os.name!='nt',
                                       creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
            self.active_pid = process.pid
            failures = []
            def deliver():
                try:
                    process.communicate(data)
                except Exception as error:
                    failures.append(error)
            # Windows communicate() may block while writing stdin, even with a timeout.
            writer = Thread(target=deliver,name='aegisav-pipe',daemon=True)
            writer.start()
            while writer.is_alive():
                if cancel.is_set():
                    raise ScanStopped('cancelled')
                if time.monotonic() >= deadline:
                    raise ScanStopped('timed_out')
                if os.fstat(output.fileno()).st_size > MAX_REPORT:
                    raise RuntimeError('Scan worker report exceeded limit')
                writer.join(timeout=.05)
            output.seek(0)
            raw = output.read(MAX_REPORT+1)
            if failures or process.returncode != 0 or len(raw)>MAX_REPORT:
                raise RuntimeError('Scan worker exited without a complete bounded report')
            try:
                message = json.loads(raw)
            except ValueError as error:
                raise RuntimeError('Scan worker returned invalid JSON') from error
            if 'invalid' in message:
                raise ValueError(message['invalid'])
            return message['report']
        finally:
            cleanup_errors = []
            try:
                if job and not job[0].CloseHandle(job[1]):
                    cleanup_errors.append('job handle')
                if process:
                    if os.name != 'nt':
                        try:
                            os.killpg(process.pid,signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    if process.poll() is None:
                        process.kill()
                    process.wait(timeout=5)
                    if writer:
                        writer.join(timeout=2)
                        if writer.is_alive():
                            cleanup_errors.append('input writer')
                    if not writer or not writer.is_alive():
                        process.stdin.close()
            except Exception:
                cleanup_errors.append('process termination')
            finally:
                if output:
                    output.close()
                self.healthy = not cleanup_errors
                if self.healthy:
                    self.active_pid = None
            if cleanup_errors:
                raise RuntimeError('Scan worker cleanup not confirmed; further scanning disabled')
