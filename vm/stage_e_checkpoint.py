"""Small durable evidence helpers for the Stage E experiment runners."""
import json
import os
import time

ACTIVE={'queued','running','cancelling'}


def persist(path,value):
    temporary=path.with_suffix('.tmp')
    with temporary.open('w',encoding='utf-8') as target:
        json.dump(value,target,indent=2,allow_nan=False)
        target.flush();os.fsync(target.fileno())
    os.replace(temporary,path)
    if os.name=='posix':
        fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)


def wait_terminal(manager,identity,timeout=125,grace=5):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        job=manager.get(identity)
        if job['status'] not in ACTIVE: return job
        time.sleep(.05)
    manager.cancel(identity)
    deadline=time.monotonic()+grace
    while time.monotonic()<deadline:
        job=manager.get(identity)
        if job['status'] not in ACTIVE: return job
        time.sleep(.05)
    raise TimeoutError('Terminal task state not confirmed; preserve incomplete checkpoint')
