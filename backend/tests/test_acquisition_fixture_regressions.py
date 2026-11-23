"""Regress the reviewed false-pass bug without creating a guest or child process."""
import json
from pathlib import Path
import pytest
from vm import verify_acquisition_v2 as fixture


@pytest.mark.parametrize('failure_mode',['crash','timeout'])
def test_fixture_rejects_import_failure_instead_of_counting_expected_stop(tmp_path,monkeypatch,failure_mode):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2]/'vm'))
    class Runner:
        healthy=True
        def __init__(self,command,**kwargs):self.mode=command[-2]
        def scan(self,*args):
            mode=self.mode
            if mode=='crash':
                if failure_mode=='timeout':(tmp_path/'recover.partial').write_bytes(b'inert-partial')
                raise ImportError('inert startup failure')
            if mode=='timeout':raise ImportError('inert startup failure')
            if mode=='memory':return dict(status='memory_rejected')
            if mode in {'old_writer','write_exhaust'}:return dict(status='write_rejected',bytes=0)
            if mode in {'large','at_limit','resume','recover'}:return dict(status='acquired',partial=False)
            return dict(status='rejected',committed=False,partial=False)
    monkeypatch.setattr('aegisav.scan_process.ProcessScanner',Runner)
    monkeypatch.setattr(fixture.os,'getuid',lambda:1001,raising=False)
    monkeypatch.setattr(fixture.subprocess,'run',lambda *a,**k:None)
    monkeypatch.setattr(fixture.sys,'argv',['fixture',str(tmp_path)])
    with pytest.raises(RuntimeError,match=failure_mode):fixture.main()
    last=json.loads((tmp_path/'fixtures.json').read_text())['files'][-1]
    assert last['mode']==failure_mode and last['passed'] is False
