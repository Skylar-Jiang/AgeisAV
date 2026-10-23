"""Bounded static teaching analysis; untrusted bytes are never executed."""
import hashlib
import json
import sys

from .scan_process import MAX_REPORT, contain_worker


def main():
    contain_worker()
    from .runtime import build_scanner
    from .teaching_report import LIMIT, pe_details
    data = sys.stdin.buffer.read(LIMIT + 1)
    try:
        details = pe_details(data)
        scan = build_scanner().scan(data)
        report = {'sha256': hashlib.sha256(data).hexdigest(), 'size_bytes': len(data),
                  'pe_details': details, 'aegisav_scan': scan}
        message = {'report': report}
    except ValueError:
        message = {'invalid': 'Invalid PE or product size limit exceeded'}
    raw = json.dumps(message, ensure_ascii=False).encode('utf-8')
    if len(raw) > MAX_REPORT:
        raise RuntimeError('Teaching report budget exceeded')
    sys.stdout.buffer.write(raw)


if __name__ == '__main__':
    main()
