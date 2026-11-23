"""Acquisition-v2 policy: dedicated guest writer; production parser limits unchanged."""
import os
import sys

MAX_ACQUIRED_PE=16*1024**2
POLICY_ID='bounded-acquisition-v2-16mib'


def contain_acquisition_worker():
    if sys.platform!='linux' or os.getuid()!=1001 or os.geteuid()!=1001 or os.environ.get('AEGISAV_SCAN_SUPERVISED')!='1':
        raise RuntimeError('Dedicated supervised operator guest required')
    try: memory=int(os.environ.get('AEGISAV_SCAN_MEMORY','0'))
    except ValueError: raise RuntimeError('Invalid acquisition memory budget') from None
    if not 64*1024**2<=memory<=512*1024**2:
        raise RuntimeError('Acquisition address-space budget outside reviewed range')
    import resource
    for name,value in [(resource.RLIMIT_AS,memory),(resource.RLIMIT_CPU,30),
                       (resource.RLIMIT_CORE,0),(resource.RLIMIT_NOFILE,64),
                       (resource.RLIMIT_FSIZE,MAX_ACQUIRED_PE)]:
        resource.setrlimit(name,(value,value))
    os.umask(0o077)
