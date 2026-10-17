import os
from pathlib import Path
import pytest
from vm import manual_guest_key as module

DUMMY='INERT_FIXTURE_NOT_AN_API_KEY'

def test_exclusive_private_write_without_key_output(tmp_path,capsys):
    path=tmp_path/'auth.key'
    module.save_key(path,DUMMY)
    assert path.read_text()==DUMMY+'\n'
    if os.name=='posix': assert path.stat().st_mode & 0o777==0o600
    assert DUMMY not in capsys.readouterr().out


def test_existing_file_not_overwritten(tmp_path):
    path=tmp_path/'auth.key';path.write_text('prior')
    with pytest.raises(FileExistsError): module.save_key(path,DUMMY)
    assert path.read_text()=='prior'


@pytest.mark.parametrize('value',['','short','A'*16+'\n','A'*16+' ','A'*4097])
def test_invalid_input_creates_no_file(tmp_path,value):
    path=tmp_path/'auth.key'
    with pytest.raises(ValueError): module.save_key(path,value)
    assert not path.exists()


def test_write_failure_removes_only_created_file(tmp_path,monkeypatch):
    path=tmp_path/'auth.key'
    def fail(_): raise OSError('inert failure')
    monkeypatch.setattr(module.os,'fsync',fail)
    with pytest.raises(OSError): module.save_key(path,DUMMY)
    assert not path.exists()


def test_wrong_identity_never_prompts(monkeypatch):
    monkeypatch.setattr(module.os,'getuid',lambda:0,raising=False)
    monkeypatch.setattr(module.getpass,'getpass',lambda *a,**k:pytest.fail('Must not request a key'))
    with pytest.raises(SystemExit): module.main()


def test_noninteractive_execution_never_prompts(monkeypatch):
    monkeypatch.setattr(module.os,'getuid',lambda:1001,raising=False)
    monkeypatch.setattr(module.os,'getgid',lambda:1001,raising=False)
    monkeypatch.setattr(module.os,'isatty',lambda _:False)
    monkeypatch.setattr(module.getpass,'getpass',lambda *a,**k:pytest.fail('Must not request a key'))
    with pytest.raises(SystemExit): module.main()


def test_guest_prompt_does_not_echo_key_and_clears_ready_marker(tmp_path,monkeypatch,capsys):
    monkeypatch.setattr(module.os,'getuid',lambda:1001,raising=False)
    monkeypatch.setattr(module.os,'getgid',lambda:1001,raising=False)
    monkeypatch.setattr(module.os,'isatty',lambda _:True)
    monkeypatch.setattr(module.subprocess,'run',lambda *a,**k:None)
    monkeypatch.setattr(module.getpass,'getpass',lambda *a,**k:DUMMY)
    monkeypatch.setattr(module,'KEY_PATH',tmp_path/'auth.key')
    monkeypatch.setattr(module,'READY_PATH',tmp_path/'ready.flag')
    module.main()
    assert module.KEY_PATH.read_text()==DUMMY+'\n'
    assert not module.READY_PATH.exists()
    assert DUMMY not in capsys.readouterr().out
