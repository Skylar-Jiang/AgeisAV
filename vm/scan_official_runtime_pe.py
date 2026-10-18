"""Sequential, durable five-engine exploratory scan of fixed official benign PEs."""
import hashlib
import json
import os
from pathlib import Path
import sys
import time

from aegisav.scan_process import ProcessScanner
from aegisav.tasks import ScanTasks
from stage_e_checkpoint import ACTIVE,persist,wait_terminal


def cohort_paths(arguments):
    if len(arguments) not in {1,3}: raise ValueError('cohort_path_arguments')
    source=Path(arguments[1]) if len(arguments)==3 else Path('/opt/aegisav-benign/official-runtime-20261017')
    work=Path(arguments[2]) if len(arguments)==3 else Path('/var/lib/aegisav-stagee2/official-runtime-v1')
    if (not source.resolve().is_relative_to(Path('/opt/aegisav-benign').resolve()) or
        not work.resolve().is_relative_to(Path('/var/lib/aegisav-stagee2').resolve())):
        raise ValueError('cohort_path_boundary')
    return source.resolve(),work.resolve()


def main():
    assert os.getuid()==1001
    import subprocess
    isolation=subprocess.check_output(['/usr/local/bin/aegisav-isolation-check'],text=True).strip()
    source,work=cohort_paths(sys.argv)
    raw=(source/'manifest.jsonl').read_bytes()
    rows=[json.loads(line) for line in raw.splitlines()]
    work.mkdir(mode=0o700,exist_ok=True)
    output=work/'scan.json'
    if not output.exists() and any(work.glob('tasks.sqlite3*')):
        raise ValueError('orphan_task_store_without_checkpoint')
    identity=hashlib.sha256(raw).hexdigest()
    code=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    state=json.loads(output.read_bytes()) if output.exists() else dict(schema=1,manifest_sha256=identity,
        script_sha256=code,isolation=isolation,strict_final_test=False,dataset_role='exploratory_official_benign',files=[],completed=False)
    assert state['manifest_sha256']==identity and state.get('script_sha256')==code
    persist(output,state)
    manager=ScanTasks(None,db_path=work/'tasks.sqlite3',runner=ProcessScanner(),service_release='stage-e2-guard-frozen-engines')
    try:
        for row in rows:
            if any(r['sha256']==row['sha256'] for r in state['files']): continue
            path=source/row['path']
            assert path.resolve().is_relative_to(source)
            data=path.read_bytes();assert hashlib.sha256(data).hexdigest()==row['sha256']
            started=time.monotonic()
            job=manager.submit([(row['original_member'],data)],idempotency_key='official-runtime-v1:'+row['sha256'])
            restored_report=job['status'] not in ACTIVE
            job=wait_terminal(manager,job['id'])
            file=job['files'][0]
            state['files'].append(dict(sha256=row['sha256'],original_member=row['original_member'],
                pe_scope=row['pe_scope'],source_url=row['source_url'],prior_exact_overlap=row['prior_exact_overlap'],
                label='presumed_benign',status=file['status'],error=file['error'],report=file['report'],
                elapsed_ms=file.get('elapsed_ms'),wrapper_elapsed_ms=(time.monotonic()-started)*1000,
                restored_report=restored_report))
            persist(output,state)
            if not manager.runner.healthy:
                raise RuntimeError('Worker cleanup unconfirmed; experiment stopped')
        state['completed']=len(state['files'])==len(rows)
        persist(output,state)
    finally: manager.close()
    print(json.dumps(dict(files=len(state['files']),completed=state['completed'],failed=sum(r['status']!='completed' for r in state['files']))))


if __name__=='__main__': main()
