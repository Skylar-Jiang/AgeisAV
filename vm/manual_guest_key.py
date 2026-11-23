"""Guest console only: hidden human input, never accepts a key through arguments."""
import getpass
import os
from pathlib import Path
import subprocess
import warnings

KEY_PATH=Path('/home/aegisav-operator/mb-auth.key')
READY_PATH=Path('/home/aegisav-operator/manual-key-ready.flag')


def save_key(path,key):
    if not 16<=len(key)<=4096 or any(not 33<=ord(c)<=126 for c in key):
        raise ValueError('invalid_key_format')
    os.umask(0o077)
    descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    identity=os.fstat(descriptor)
    try:
        with os.fdopen(descriptor,'w',encoding='utf-8') as handle:
            handle.write(key+'\n');handle.flush();os.fsync(handle.fileno())
    except BaseException:
        current=os.lstat(path)
        if (current.st_dev,current.st_ino)==(identity.st_dev,identity.st_ino): path.unlink()
        raise


def main():
    if os.getuid()!=1001 or os.getgid()!=1001:
        raise SystemExit('Operator identity required')
    if not os.isatty(0) or not os.isatty(1):
        raise SystemExit('Interactive guest console required; no stdin fallback')
    subprocess.run(['/usr/local/bin/aegisav-isolation-check'],check=True,
                   stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    if os.path.lexists(KEY_PATH): raise SystemExit('Credential file exists; not overwritten')
    warnings.simplefilter('error',getpass.GetPassWarning)
    with READY_PATH.open('x') as marker: marker.write('READY\n')
    try:
        print('AegisAV: enter MalwareBazaar Auth-Key once. Input is hidden. No Ubuntu login needed.',flush=True)
        key=getpass.getpass('Auth-Key: ')
        save_key(KEY_PATH,key)
        del key
        print('Credential configured in guest (0600). You may return to Codex.',flush=True)
    finally:
        READY_PATH.unlink(missing_ok=True)


if __name__=='__main__':
    try: main()
    except (OSError,ValueError,EOFError,getpass.GetPassWarning,subprocess.CalledProcessError):
        raise SystemExit('Credential setup failed; no key content recorded') from None
