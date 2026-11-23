"""Export teaching evidence, or statically inspect benign/isolated-VM input."""
import argparse
import json
import os
import platform
from pathlib import Path
import sys
from threading import Event
import time

from .teaching_report import LIMIT, export_workbook
from .tasks import ScanStopped


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    template = sub.add_parser('template')
    template.add_argument('--output', type=Path, required=True)
    imported = sub.add_parser('import')
    imported.add_argument('--manifest', type=Path, required=True)
    imported.add_argument('--source-root', type=Path, required=True)
    imported.add_argument('--output', type=Path, required=True)
    analyze = sub.add_parser('analyze')
    analyze.add_argument('input', type=Path)
    analyze.add_argument('--source', required=True)
    analyze.add_argument('--output', type=Path, required=True)
    scope = analyze.add_mutually_exclusive_group(required=True)
    scope.add_argument('--benign-control', action='store_true', help='Operator confirms input is benign')
    scope.add_argument('--existing-isolated-ubuntu-vm', action='store_true',
                       help='Operator attests this is the existing authorized Ubuntu VM')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    output = args.output.resolve()
    if output.is_relative_to(root) and not output.is_relative_to(root / 'artifacts'):
        parser.error('Private teaching reports belong outside source or under ignored artifacts/')
    try:
        if args.action == 'template':
            data = {'schema': 1, 'source_kind': 'unfilled_teacher_slots', 'samples': [
                {'sample_id': f'{i:02d}', 'name': f'教师样本{i}（未提供）', 'sha256': None,
                 'source': '待填写真实来源', 'evidence': [],
                 'missing': ['教师原件身份', 'Defender原始证据', 'PE头/函数/字符串', '实际引擎报告']}
                for i in range(1, 6)]}
            output.parent.mkdir(parents=True, exist_ok=True)
            with output.open('x', encoding='utf-8') as stream:
                json.dump(data, stream, ensure_ascii=False, indent=2)
            return 0
        if args.action == 'import':
            with args.manifest.open('rb') as stream:
                data = stream.read(1024**2 + 1)
            if len(data) > 1024**2:
                raise ValueError('Manifest size limit')
            result = export_workbook(json.loads(data), args.source_root, output)
        else:
            if args.existing_isolated_ubuntu_vm:
                version = Path('/proc/version')
                if (sys.platform != 'linux' or not version.is_file() or
                        'microsoft' in version.read_text().lower() or
                        platform.freedesktop_os_release().get('ID') != 'ubuntu'):
                    raise ValueError('Real malware static analysis is restricted to the existing Ubuntu VM, never WSL')
            if output.exists():
                raise FileExistsError('Refuse existing output')
            with args.input.open('rb') as stream:
                data = stream.read(LIMIT + 1)
            if len(data) > LIMIT:
                raise ValueError('Existing product16MiB limit; use historical evidence for larger teaching input')
            from .scan_process import ProcessScanner
            os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
            runner = ProcessScanner([sys.executable, '-B', '-m', 'aegisav.teaching_worker'])
            report = runner.scan(data, Event(), time.monotonic() + 120)
            row = {'sample_id': '01', 'name': args.input.name, 'source': args.source,
                   'environment': 'operator_attested_existing_vm' if args.existing_isolated_ubuntu_vm else 'operator_attested_benign',
                   'evidence': [], 'missing': ['Defender原始证据（未导入）', '分析者结论'], **report}
            result = export_workbook({'schema': 1, 'source_kind': 'fresh_static_analysis', 'samples': [row]},
                                     args.input.parent, output)
        print(json.dumps({'status': 'exported', 'sample_count': result['sample_count']}))
        return 0
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, ScanStopped):
        print('Teaching export failed; verify identity, evidence digests, size, environment and a fresh output path.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
