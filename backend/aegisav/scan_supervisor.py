"""Linux-only lifetime guard. Never imports parsers or consumes uploaded bytes."""
import os
import select
import signal
import subprocess
import sys


def main():
    if sys.platform != 'linux' or os.geteuid() == 0:
        raise RuntimeError('Non-root Linux supervisor required')
    expected = int(os.environ['AEGISAV_SCAN_PARENT'])
    # pidfd is tied to the original process lifetime, not a reusable numeric PID.
    owner = os.pidfd_open(expected)
    if os.getppid() != expected:
        os.killpg(os.getpgrp(),signal.SIGKILL)
    env = dict(os.environ,AEGISAV_SCAN_SUPERVISED='1')
    worker = subprocess.Popen(sys.argv[1:],stdin=sys.stdin.buffer,stdout=sys.stdout.buffer,
                              stderr=subprocess.DEVNULL,env=env)
    try:
        while worker.poll() is None:
            if select.select([owner],[],[],.05)[0]:
                os.killpg(os.getpgrp(),signal.SIGKILL)
        sys.exit(worker.returncode if worker.returncode >= 0 else 1)
    finally:
        os.close(owner)


if __name__ == '__main__':
    main()
