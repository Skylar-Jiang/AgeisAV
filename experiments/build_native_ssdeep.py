"""Build the explicit Windows x64 ABI1 candidate; never modify a stable bundle."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or not output.is_relative_to(ROOT / 'artifacts'):
        raise ValueError('Requires a fresh artifact directory')
    output.mkdir(parents=True)
    source = ROOT / 'experiments/native_ssdeep.c'
    target = output / 'aegisav_ssdeep.dll'
    command = [str(args.compiler.resolve()), '-O3', '-std=c11', '-Wall', '-Wextra', '-Werror',
               '-shared', '-static-libgcc', '-fno-ident', '-s', '-Wl,--no-insert-timestamp',
               str(source), '-o', str(target)]
    subprocess.run(command, check=True, capture_output=True)
    manifest = {'schema': 1, 'abi': 1, 'file': target.name,
                'sha256': hashlib.sha256(target.read_bytes()).hexdigest(),
                'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                'compiler': subprocess.check_output([str(args.compiler), '--version'], text=True).splitlines()[0],
                'command': command, 'bytes': target.stat().st_size}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    for name in ('native_ssdeep.c', 'NATIVE_SSDEEP_LICENSE.txt', 'NATIVE_SSDEEP_NOTICE.md'):
        shutil.copyfile(ROOT / 'experiments' / name, output / name)
    print(json.dumps(manifest))


if __name__ == '__main__':
    main()
