"""Dedicated Linux VM acceptance: inert faults and a previously verified benign PE only."""
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import sqlite3
import subprocess
import sys
import time

from aegisav.scan_process import ProcessScanner
from aegisav.tasks import ScanTasks

ROOT=Path(__file__).resolve().parents[1]
FIXTURE=str(ROOT/'backend/tests/fixtures_scan_worker.py')


def wait_job(manager, identity):
    for _ in range(600):
        job=manager.get(identity)
        if job['status'] not in ('queued','running','cancelling'):
            return job
        time.sleep(.05)
    raise AssertionError('bounded acceptance task did not terminate')


def live_group(group):
    result=[]
    for path in Path('/proc').glob('[0-9]*/stat'):
        try:
            fields=path.read_text().rsplit(')',1)[1].split()
            if int(fields[2])==group and fields[0]!='Z': result.append(int(path.parent.name))
        except (OSError,ValueError,IndexError): pass
    return result


def child(db, mode):
    runner=ProcessScanner([sys.executable,FIXTURE,'hang'] if mode=='hang' else None)
    manager=ScanTasks(None,db_path=db,runner=runner,file_timeout=20,task_timeout=30)
    data=b'inert-crash-acceptance'
    if mode=='real':
        base=Path('/opt/aegisav-benign/windows')
        item=json.loads((base/'manifest.jsonl').read_text().splitlines()[0])
        data=(base/item['path']).read_bytes()
        assert hashlib.sha256(data).hexdigest()==item['sha256']
    job=manager.submit([('benign.dll' if mode=='real' else 'inert.txt',data)],idempotency_key=mode+'-v1')
    if mode=='real':
        result=wait_job(manager,job['id'])
        assert result['status']=='completed'
        print(json.dumps(result),flush=True)
        manager.close()
    else:
        for _ in range(100):
            if runner.active_pid and len(live_group(runner.active_pid))>=3: break
            time.sleep(.05)
        assert runner.active_pid and len(live_group(runner.active_pid))>=3
        print(json.dumps(dict(id=job['id'],group=runner.active_pid)),flush=True)
        time.sleep(60)


def main():
    assert sys.platform=='linux' and os.geteuid()==1001
    subprocess.run(['/usr/local/bin/aegisav-isolation-check'],check=True,stdout=subprocess.DEVNULL)
    # ProtectHome makes credentials inaccessible; absence is checked by the root
    # launcher before admission, rather than weakening this service boundary.
    if len(sys.argv)>1 and sys.argv[1]=='child':
        child(Path(sys.argv[2]),sys.argv[3]);return
    work=Path(sys.argv[1]).resolve()
    assert work.parent==Path('/var/lib/aegisav-stagee2') and work.is_dir()
    checks=[]
    guard=subprocess.check_output([sys.executable,str(ROOT/'experiments/check_linux_process_guard.py')],text=True,timeout=20)
    assert json.loads(guard)['passed'];checks.append('pidfd_stopped_parser_owner_death_and_deadlines')
    crash_db=work/'crash.sqlite3'
    owner=subprocess.Popen([sys.executable,__file__,'child',str(crash_db),'hang'],stdout=subprocess.PIPE,text=True)
    group=None
    try:
        assert select.select([owner.stdout],[],[],8)[0], 'owner readiness timed out'
        marker=json.loads(owner.stdout.readline());group=marker['group']
        owner.kill();owner.wait(timeout=3)
        for _ in range(60):
            if not live_group(group): break
            time.sleep(.05)
        assert not live_group(group)
        manager=ScanTasks(None,db_path=crash_db,runner=ProcessScanner())
        try:
            interrupted=manager.get(marker['id'])
            assert interrupted['status']=='interrupted'
            assert interrupted['files'][0]['report'] is None
            assert interrupted['files'][0]['error']=='resubmit_required'
            assert manager.submit([('inert.txt',b'inert-crash-acceptance')],idempotency_key='hang-v1')['id']==marker['id']
            assert manager.pending==manager.reserved_bytes==0
        finally: manager.close()
        checks.append('real_owner_SIGKILL_sqlite_interrupted_no_resume_and_pidfd_cleanup')
    finally:
        if owner.poll() is None: owner.kill();owner.wait()
        owner.stdout.close()
        if group and live_group(group): os.killpg(group,signal.SIGKILL)
    db=work/'faults.sqlite3'
    for mode,expected in [('hang','cancelled'),('crash','completed_with_errors')]:
        runner=ProcessScanner([sys.executable,FIXTURE,mode])
        manager=ScanTasks(None,db_path=db,runner=runner,file_timeout=2,task_timeout=5)
        try:
            job=manager.submit([('inert.txt',b'inert')])
            if mode=='hang':
                for _ in range(100):
                    if runner.active_pid: break
                    time.sleep(.01)
                manager.cancel(job['id'])
            result=wait_job(manager,job['id'])
            assert result['status']==expected and result['files'][0]['report'] is None
            assert manager.pending==manager.reserved_bytes==0 and runner.active_pid is None and runner.healthy
        finally: manager.close()
        restored=ScanTasks(None,db_path=db,runner=ProcessScanner())
        try: assert restored.get(job['id'])==result
        finally: restored.close()
        checks.append(mode+'_persisted_and_resources_released')
    benign_db=work/'benign.sqlite3'
    completed=json.loads(subprocess.check_output([sys.executable,__file__,'child',str(benign_db),'real'],text=True,timeout=40))
    report=completed['files'][0]['report']
    assert set(report['engines'])=={'sha256','fuzzy','yara_x','clamav','lightgbm'}
    assert all(e['status']=='no_match' for e in report['engines'].values())
    assert report['engines']['lightgbm']['score']==.0016802954766119863
    assert report['engines']['lightgbm']['feature_sha256']=='681f799a163f26c76e9a35226881d5e54ce43ab58bd8430226c521af48b2c0b5'
    manager=ScanTasks(None,db_path=benign_db,runner=ProcessScanner())
    try: assert manager.get(completed['id'])==completed
    finally: manager.close()
    checks.append('five_engines_real_process_benign_score_feature_parity_and_restart_query')
    for path in (crash_db,db,benign_db):
        assert path.stat().st_mode & 0o077==0
        connection=sqlite3.connect(path)
        assert connection.execute('pragma integrity_check').fetchone()[0]=='ok'
        assert connection.execute('pragma user_version').fetchone()[0]==1
        connection.close()
    checks.append('sqlite_schema_integrity_and_0600')
    result=dict(schema=1,passed=True,inert_faults_only=True,real_malware_used=False,
                checks=checks,benign_report=report,registry_sha256=hashlib.sha256(
                Path('/opt/aegisav-product/current/models/ember2024/registry.json').read_bytes()).hexdigest())
    (work/'acceptance.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(passed=True,checks=checks)))


if __name__=='__main__': main()
