from pathlib import Path
import ast
import pytest
from vm.collection_boundary import unpack_verified
from test_collection_boundary import encrypted
import hashlib

def test_16mib_acquisition_streams_more_than_old_report_budget(tmp_path):
 data=b'harmless-static-padding'*150000
 p=tmp_path/'fixture.bin'
 assert len(data)>2*1024**2
 assert unpack_verified(encrypted(data),hashlib.sha256(data).hexdigest(),p,16*1024**2)==len(data)
 assert p.read_bytes()==data

@pytest.mark.parametrize('mode',['oversize','truncated','wrong_sha'])
def test_v2_archive_failures_do_not_commit_or_leave_partial(tmp_path,mode):
 data=b'harmless'*(2200000 if mode=='oversize' else 1000)
 content=encrypted(data);sha=hashlib.sha256(data).hexdigest()
 if mode=='truncated':content=content[:-10]
 if mode=='wrong_sha':sha='0'*64
 output=tmp_path/'out.bin'
 with pytest.raises(Exception):unpack_verified(content,sha,output,16*1024**2)
 assert not output.exists() and not output.with_suffix('.partial').exists()

def test_new_collector_preserves_old_boundary_and_has_prescore_quarantine_gate():
 root=Path(__file__).resolve().parents[2]
 old=(root/'vm/collect_analyst_cases.py').read_text();new=(root/'vm/collect_primary_cases_v2.py').read_text()
 ast.parse(new)
 assert 'excluded_worker_fsize_2mib' in old
 assert 'contain_acquisition_worker()' in new and 'MAX_ACQUIRED_PE)' in new
 assert "'unscored_final_quarantine'" in new and 'freeze/split.json' in new
 assert "'acquisition_limits.py'" in new
