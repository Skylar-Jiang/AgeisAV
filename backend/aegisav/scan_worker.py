"""Static scanning entry point: stdin bytes, bounded JSON report, never execute PE."""
import json
import sys

from .scan_process import MAX_REPORT, contain_worker


def main():
    contain_worker()
    # Import the scanner factory without initializing an API or opening its database.
    from .runtime import build_scanner
    data = sys.stdin.buffer.read(16*1024**2+1)
    if len(data)>16*1024**2:
        raise ValueError('File too large')
    try:
        message = {'report':build_scanner().scan(data)}
    except ValueError as error:
        message = {'invalid':str(error)[:200]}
    raw = json.dumps(message,ensure_ascii=False).encode('utf-8')
    if len(raw)>MAX_REPORT:
        raise RuntimeError('Report too large')
    sys.stdout.buffer.write(raw)


if __name__ == '__main__':
    main()
