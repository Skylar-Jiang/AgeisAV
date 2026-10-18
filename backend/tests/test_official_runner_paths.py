import importlib
from pathlib import Path
import pytest


def runner(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2]/'vm'))
    return importlib.import_module('vm.scan_official_runtime_pe')


def test_official_runner_accepts_new_cohort_without_overwriting_frozen_defaults(monkeypatch):
    source,work=runner(monkeypatch).cohort_paths(['runner','/opt/aegisav-benign/official-multivendor-20261017-r4','/var/lib/aegisav-stagee2/official-multivendor-r4'])
    assert source.name=='official-multivendor-20261017-r4' and work.name=='official-multivendor-r4'
    old_source,old_work=runner(monkeypatch).cohort_paths(['runner'])
    assert old_source.name=='official-runtime-20261017' and old_work.name=='official-runtime-v1'


@pytest.mark.parametrize('source,work',[
    ('/tmp/unreviewed','/var/lib/aegisav-stagee2/target'),
    ('/opt/aegisav-benign/../outside','/var/lib/aegisav-stagee2/target'),
    ('/opt/aegisav-benign/official','/etc/target'),
])
def test_official_runner_rejects_uncontrolled_source_or_destination(monkeypatch,source,work):
    with pytest.raises(ValueError,match='cohort_path_boundary'):
        runner(monkeypatch).cohort_paths(['runner',source,work])

def test_orphan_database_is_rejected_before_opening_old_reports(tmp_path,monkeypatch):
    import json
    module=runner(monkeypatch)
    source=tmp_path/'source';source.mkdir();(source/'manifest.jsonl').write_text('')
    work=tmp_path/'work';work.mkdir();(work/'tasks.sqlite3').write_bytes(b'inert-old-db')
    monkeypatch.setattr(module.os,'getuid',lambda:1001,raising=False)
    monkeypatch.setattr(module,'cohort_paths',lambda _: (source,work))
    monkeypatch.setattr('subprocess.check_output',lambda *a,**k:'inert-isolation')
    monkeypatch.setattr(module,'ScanTasks',lambda *a,**k:pytest.fail('Must reject before opening old reports'))
    with pytest.raises(ValueError,match='orphan_task_store_without_checkpoint'):
        module.main()
    assert not (work/'scan.json').exists()


def test_checkpoint_is_persisted_before_first_task_database_open(tmp_path,monkeypatch):
    import json
    module=runner(monkeypatch)
    source=tmp_path/'source';source.mkdir();(source/'manifest.jsonl').write_text('')
    work=tmp_path/'work'
    monkeypatch.setattr(module.os,'getuid',lambda:1001,raising=False)
    monkeypatch.setattr(module,'cohort_paths',lambda _: (source,work))
    monkeypatch.setattr('subprocess.check_output',lambda *a,**k:'inert-isolation')
    class Manager:
        def __init__(self,*a,**k):
            state=json.loads((work/'scan.json').read_text())
            assert state['script_sha256'] and state['completed'] is False
        def close(self):pass
    monkeypatch.setattr(module,'ScanTasks',Manager)
    module.main()
