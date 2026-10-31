"""Build an explicit YARA candidate; deserialize only in the disposable worker.

The emitted SHA256 must be pinned outside the bundle by trusted configuration.
No automatic cache, environment selection, or default production path changes.
"""
import argparse
import hashlib
import io
import json
from importlib.metadata import version
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))


def build_bundle(rule_dir, metadata_file, output):
    from aegisav.yara_engine import load_yara_engine
    engine = load_yara_engine(rule_dir, metadata_file)
    payload = io.BytesIO()
    engine.rules.serialize_into(payload)
    manifest = {'schema': 1, 'yara_version': version('yara-x'), 'source_sha256': engine.source_sha256}
    raw = json.dumps(manifest, sort_keys=True).encode() + b'\n' + payload.getvalue()
    if len(raw) > 8 * 1024**2:
        raise ValueError('Compiled YARA bundle size limit')
    with Path(output).open('xb') as stream:
        stream.write(raw)
    return hashlib.sha256(raw).hexdigest()


def worker(bundle=None, expected_sha256=None, native_root=None):
    from aegisav.scan_process import MAX_REPORT, contain_worker
    contain_worker()
    from aegisav import runtime
    if bundle is not None or expected_sha256 is not None:
        from functools import partial
        runtime.load_yara_engine = partial(runtime.load_yara_engine,
            compiled_file=Path(bundle) if bundle is not None else None, compiled_sha256=expected_sha256)
    if native_root is not None:
        from aegisav.native_ssdeep import NativeSSDeep
        runtime.select_backend = lambda root: NativeSSDeep(native_root)
    # Keep the production stdin, report budget, and invalid-input semantics.
    data = sys.stdin.buffer.read(16 * 1024**2 + 1)
    if len(data) > 16 * 1024**2:
        raise ValueError('File too large')
    try:
        message = {'report': runtime.build_scanner().scan(data)}
    except ValueError as error:
        message = {'invalid': str(error)[:200]}
    raw = json.dumps(message, ensure_ascii=False).encode('utf-8')
    if len(raw) > MAX_REPORT:
        raise RuntimeError('Report too large')
    sys.stdout.buffer.write(raw)


def worker_command(backend_root, python, bundle=None, expected_sha256=None, native_root=None):
    # The helper is current, but parser/engine code must come from the requested
    # comparison snapshot. Importing the helper must not override that selection.
    code = (f'import sys,os;sys.path.insert(0,{str(ROOT)!r});'
            'from experiments.yara_bundle import worker;'
            f'sys.path.insert(0,{str(Path(backend_root).resolve() / "backend")!r});'
            'os.environ["AEGISAV_SSDEEP_BACKEND"]="python";'
            f'worker({str(Path(bundle).resolve()) if bundle is not None else None!r},'
            f'{expected_sha256!r},{str(Path(native_root).resolve()) if native_root is not None else None!r})')
    return [str(python), '-B', '-c', code]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rule-dir', type=Path, default=ROOT / 'rules/yara')
    parser.add_argument('--metadata', type=Path, default=ROOT / 'rules/yara/metadata.json')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    digest = build_bundle(args.rule_dir, args.metadata, args.output)
    print(json.dumps({'path': str(args.output.resolve()), 'sha256': digest}))


if __name__ == '__main__':
    main()
