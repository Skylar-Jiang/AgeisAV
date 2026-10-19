"""Stage G local replay/export entry point. Never executes imported event text."""
import argparse
import json
import os
from pathlib import Path
import sys
from threading import Event
import time

from .behavior import MAX_BYTES
from .scan_process import ProcessScanner
from .tasks import ScanStopped


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input',type=Path)
    parser.add_argument('--output',type=Path,required=True,help='New private report path outside source checkout')
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[2]
    output=args.output.resolve()
    if output.is_relative_to(root): parser.error('Keep private behavior reports outside source checkout')
    try:
        with args.input.open('rb') as stream: data=stream.read(MAX_BYTES+1)
        if len(data)>MAX_BYTES: raise ValueError('Behavior log exceeds 4 MiB')
        runner=ProcessScanner([sys.executable,'-m','aegisav.behavior_worker'],memory_bytes=256*1024**2)
        report=runner.scan(data,Event(),time.monotonic()+20)
        report['static_link']=dict(status='not_linked',reason='CLI did not select a static API report',authenticity_verified=False)
        output.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        descriptor=os.open(output,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(descriptor,'w',encoding='utf-8') as stream:
            json.dump(report,stream,ensure_ascii=False,indent=2)
            stream.write('\n')
    except (OSError,ValueError) as error:
        # No imported field values or arbitrary paths are printed on errors.
        print('Replay/export rejected; check format, limits and a new writable output path.',file=sys.stderr)
        return 2
    except (RuntimeError,ScanStopped):
        print('Bounded parser failed or timed out; no result.',file=sys.stderr)
        return 3
    print(json.dumps(dict(status=report['status'],events=len(report['events']),matches=len(report['matches']))))
    return 0


if __name__=='__main__': raise SystemExit(main())
