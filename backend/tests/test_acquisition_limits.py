import importlib
import pytest

def module():
 return importlib.import_module('vm.acquisition_limits')

def test_writer_budget_is_separate_from_frozen_report_and_scan_limits():
 m=module()
 from aegisav.scan_process import MAX_REPORT
 assert m.MAX_ACQUIRED_PE==16*1024**2 and MAX_REPORT==2*1024**2

def test_acquisition_limits_require_dedicated_supervised_nonprivileged_guest(monkeypatch):
 m=module()
 monkeypatch.setattr(m.sys,'platform','win32')
 with pytest.raises(RuntimeError):m.contain_acquisition_worker()

@pytest.mark.parametrize('uid,supervised,memory',[(0,'1','536870912'),(1001,'0','536870912'),(1001,'1','2147483648'),(1001,'1','invalid')])
def test_unapproved_acquisition_context_is_refused(monkeypatch,uid,supervised,memory):
 m=module();monkeypatch.setattr(m.sys,'platform','linux');monkeypatch.setattr(m.os,'getuid',lambda:uid,raising=False);monkeypatch.setattr(m.os,'geteuid',lambda:uid,raising=False)
 monkeypatch.setenv('AEGISAV_SCAN_SUPERVISED',supervised);monkeypatch.setenv('AEGISAV_SCAN_MEMORY',memory)
 with pytest.raises(RuntimeError):m.contain_acquisition_worker()

def test_only_acquisition_file_limit_increases_with_tighter_cpu_and_fd_budget(monkeypatch):
 m=module()
 import sys,types
 resource=types.SimpleNamespace(RLIMIT_AS=0,RLIMIT_CPU=1,RLIMIT_CORE=2,RLIMIT_NOFILE=3,RLIMIT_FSIZE=4,setrlimit=lambda *args:None)
 monkeypatch.setitem(sys.modules,'resource',resource)
 calls={}
 monkeypatch.setattr(m.sys,'platform','linux');monkeypatch.setattr(m.os,'getuid',lambda:1001,raising=False);monkeypatch.setattr(m.os,'geteuid',lambda:1001,raising=False)
 monkeypatch.setenv('AEGISAV_SCAN_SUPERVISED','1');monkeypatch.setenv('AEGISAV_SCAN_MEMORY','536870912')
 monkeypatch.setattr(resource,'setrlimit',lambda name,value:calls.setdefault(name,value));monkeypatch.setattr(m.os,'umask',lambda _:0)
 m.contain_acquisition_worker()
 assert calls[resource.RLIMIT_FSIZE]==(16*1024**2,)*2
 assert calls[resource.RLIMIT_AS]==(512*1024**2,)*2
 assert calls[resource.RLIMIT_CPU]==(30,)*2 and calls[resource.RLIMIT_NOFILE]==(64,)*2
 assert calls[resource.RLIMIT_CORE]==(0,0)


def test_elevated_effective_identity_is_refused_even_with_operator_real_uid(monkeypatch):
 m=module();monkeypatch.setattr(m.sys,'platform','linux')
 monkeypatch.setattr(m.os,'getuid',lambda:1001,raising=False);monkeypatch.setattr(m.os,'geteuid',lambda:0,raising=False)
 monkeypatch.setenv('AEGISAV_SCAN_SUPERVISED','1');monkeypatch.setenv('AEGISAV_SCAN_MEMORY','536870912')
 with pytest.raises(RuntimeError):m.contain_acquisition_worker()
