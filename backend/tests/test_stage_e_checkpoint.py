import json
from pathlib import Path
import pytest

from vm.stage_e_checkpoint import persist,wait_terminal


def test_failed_json_write_cannot_destroy_last_checkpoint(tmp_path):
    path=tmp_path/'state.json'
    persist(path,dict(completed=False,files=[1]))
    with pytest.raises(ValueError): persist(path,dict(completed=True,value=float('nan')))
    assert json.loads(path.read_text())==dict(completed=False,files=[1])


def test_wait_budget_cancels_and_returns_actual_terminal_state(monkeypatch):
    import vm.stage_e_checkpoint as module
    clock=iter(range(50));monkeypatch.setattr(module.time,'monotonic',lambda: next(clock))
    monkeypatch.setattr(module.time,'sleep',lambda _:None)
    class Manager:
        cancelled=False
        def get(self,identity): return dict(status='cancelled' if self.cancelled else 'running')
        def cancel(self,identity): self.cancelled=True
    manager=Manager()
    assert wait_terminal(manager,'id',timeout=1,grace=5)['status']=='cancelled'


def test_unconfirmed_terminal_state_raises_instead_of_becoming_completed(monkeypatch):
    import vm.stage_e_checkpoint as module
    clock=iter(range(50));monkeypatch.setattr(module.time,'monotonic',lambda:next(clock))
    monkeypatch.setattr(module.time,'sleep',lambda _:None)
    class Manager:
        def get(self,identity): return dict(status='running')
        def cancel(self,identity): pass
    with pytest.raises(TimeoutError): wait_terminal(Manager(),'id',timeout=1,grace=1)


def test_acquisition_cleanup_failure_stops_following_sample(tmp_path,monkeypatch):
    import importlib
    import sys
    import types
    root=Path(__file__).resolve().parents[2]
    monkeypatch.syspath_prepend(str(root/'vm'));monkeypatch.syspath_prepend(str(root/'experiments'))
    # The tested offline control flow has no network or platform calls. Linux
    # imports are replaced here; actual Linux pidfd/cgroups are tested in the VM.
    monkeypatch.setitem(sys.modules,'fcntl',types.SimpleNamespace())
    monkeypatch.setitem(sys.modules,'collect_malwarebazaar',types.SimpleNamespace(network=lambda _:'inert',save=persist))
    module=importlib.import_module('vm.collect_analyst_cases')
    monkeypatch.setattr(module,'SCOPE',tmp_path)
    monkeypatch.setattr(module.os,'getuid',lambda:1001,raising=False)
    monkeypatch.setattr(module.collection,'network',lambda _:'inert')
    (tmp_path/'incoming').mkdir();(tmp_path/'results').mkdir()
    (tmp_path/'incoming/metadata.json').write_text('{"identity":{}}')
    rows=[dict(sha256='a'*64),dict(sha256='b'*64)]
    (tmp_path/'incoming/download.json').write_text(json.dumps(dict(identity={},files=[dict(sha256=r['sha256'],status='downloaded') for r in rows])))
    class Runner:
        calls=0
        healthy=True
        def __init__(self,*args,**kwargs): pass
        def scan(self,*args):
            Runner.calls+=1;self.healthy=False;raise RuntimeError('cleanup unconfirmed')
    monkeypatch.setattr('aegisav.scan_process.ProcessScanner',Runner)
    module.offline(rows,{},'acquire')
    result=json.loads((tmp_path/'results/acquire.json').read_text())
    assert Runner.calls==1 and result['completed'] is False
    assert result['files'][1]['status']=='not_attempted'
    assert module.retry_deadline('86400',1000)==87400
    assert module.retry_deadline(None,1000)==4600


def test_scan_unconfirmed_terminal_stops_following_sample(tmp_path,monkeypatch):
    import hashlib
    import importlib
    import sys
    import types
    root=Path(__file__).resolve().parents[2]
    monkeypatch.syspath_prepend(str(root/'vm'));monkeypatch.syspath_prepend(str(root/'experiments'))
    monkeypatch.setitem(sys.modules,'fcntl',types.SimpleNamespace())
    monkeypatch.setitem(sys.modules,'collect_malwarebazaar',types.SimpleNamespace(network=lambda _:'inert',save=persist))
    module=importlib.import_module('vm.collect_analyst_cases')
    monkeypatch.setattr(module,'SCOPE',tmp_path)
    monkeypatch.setattr(module.os,'getuid',lambda:1001,raising=False)
    monkeypatch.setattr(module.collection,'network',lambda _:'inert')
    monkeypatch.setattr(module,'assess',lambda _:dict(exploratory_eligible=True))
    for name in ('incoming','results','raw'): (tmp_path/name).mkdir()
    rows=[]
    for data in (b'inert-a',b'inert-b'):
        sha=hashlib.sha256(data).hexdigest();rows.append(dict(sha256=sha))
        (tmp_path/'raw'/(sha+'.bin')).write_bytes(data)
    (tmp_path/'incoming/metadata.json').write_text('{"identity":{}}')
    (tmp_path/'incoming/download.json').write_text(json.dumps(dict(identity={},files=[dict(sha256=r['sha256'],status='downloaded') for r in rows])))
    (tmp_path/'results/acquire.json').write_text(json.dumps(dict(identity={},files=rows)))
    class Manager:
        calls=0
        runner=types.SimpleNamespace(healthy=True)
        def __init__(self,*args,**kwargs): pass
        def submit(self,*args,**kwargs):
            Manager.calls+=1;return dict(id='inert-task',status='running')
        def close(self): pass
    monkeypatch.setattr('aegisav.tasks.ScanTasks',Manager)
    def unconfirmed(*args,**kwargs): raise TimeoutError('terminal unconfirmed')
    monkeypatch.setattr(module,'wait_terminal',unconfirmed)
    module.offline(rows,{},'scan')
    result=json.loads((tmp_path/'results/scan.json').read_text())
    assert Manager.calls==1 and result['completed'] is False
    assert result['files'][0]['reason']=='terminal_state_unconfirmed'
    assert result['files'][1]['status']=='not_attempted'
