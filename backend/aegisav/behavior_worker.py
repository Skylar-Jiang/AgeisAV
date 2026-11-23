"""Disposable log parser: only bounded stdin -> JSON; no subprocess/log commands."""
import json
import sys

from .scan_process import MAX_REPORT, contain_worker


def main():
    contain_worker()
    from .behavior import MAX_BYTES, analyze
    try:
        message={'report':analyze(sys.stdin.buffer.read(MAX_BYTES+1))}
    except (ValueError, OverflowError, RecursionError) as error:
        message={'invalid':str(error)[:200]}
    raw=json.dumps(message,ensure_ascii=False).encode()
    if len(raw)>MAX_REPORT:
        raise ValueError('Behavior report exceeded output budget')
    sys.stdout.buffer.write(raw)


if __name__=='__main__':
    main()
