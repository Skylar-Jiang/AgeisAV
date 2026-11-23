"""Bounded, atomic checkpoints for benign fixtures; checksums detect corruption, not forgery."""

import hashlib
import json
import os

LIMIT = 2 * 1024**2


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def save_checkpoint(path, payload):
    encoded = canonical({'schema': 1, 'payload': payload,
                         'sha256': hashlib.sha256(canonical(payload)).hexdigest()})
    if len(encoded) > LIMIT:
        raise ValueError('Checkpoint size limit')
    temporary = path.with_suffix('.tmp')
    try:
        with temporary.open('wb') as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if os.name == 'posix':
            descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    finally:
        temporary.unlink(missing_ok=True)


def load_checkpoint(path, identity):
    if path.stat().st_size > LIMIT:
        raise ValueError('Checkpoint size limit')
    envelope = json.loads(path.read_bytes())
    if set(envelope) != {'schema', 'payload', 'sha256'} or envelope['schema'] != 1:
        raise ValueError('Checkpoint envelope rejected')
    payload = envelope['payload']
    if hashlib.sha256(canonical(payload)).hexdigest() != envelope['sha256']:
        raise ValueError('Checkpoint checksum mismatch')
    if set(payload) != {'identity', 'sessions', 'report'} or payload['identity'] != identity:
        raise ValueError('Checkpoint identity mismatch')
    return payload


def main():
    import argparse
    from pathlib import Path
    try:
        from .static_benign import validate_resume
    except ImportError:
        from static_benign import validate_resume
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--validate-export', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    args = parser.parse_args()
    if args.validate_export.stat().st_size > LIMIT:
        raise ValueError('Checkpoint size limit')
    identity = json.loads(args.validate_export.read_bytes())['payload']['identity']
    saved = load_checkpoint(args.validate_export, identity)
    manifest = args.manifest.read_bytes()
    rows = [json.loads(line) for line in manifest.splitlines() if line.strip()]
    digest = hashlib.sha256(manifest).hexdigest()
    if identity['manifest'] != digest:
        raise ValueError('Checkpoint manifest mismatch')
    validate_resume(saved['report'], rows, digest)
    previous = -1
    for session in saved['sessions']:
        if set(session) != {'isolation', 'resume_index', 'started_unix'}:
            raise ValueError('Unexpected session metadata')
        if not session['isolation'].startswith('AEGISAV_ISOLATION PASS '):
            raise ValueError('Session isolation absent')
        if not previous <= session['resume_index'] <= len(saved['report']['files']):
            raise ValueError('Session prefix invalid')
        previous = session['resume_index']
    print('Benign checkpoint checksum, manifest prefix and sessions PASS')


if __name__ == '__main__':
    main()
