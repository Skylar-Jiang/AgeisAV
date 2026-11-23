"""Boundaries shared by the dedicated guest collector; no sample execution."""
import hashlib
import io
import os
from pathlib import PurePosixPath
import re
import stat


def should_attempt(attempts, sha, retry_failed):
    previous = next((r for r in reversed(attempts) if r['sha256'] == sha), None)
    return previous is None or (retry_failed and previous['status'] not in ('downloaded', 'scanned', 'abstained', 'acquired'))


def response_length(value):
    if value is None:
        return None
    if not value.isascii() or not value.isdecimal() or len(value)>12:
        raise ValueError('archive_length_header')
    length=int(value)
    if not 0<length<=129*1024**2:
        raise ValueError('archive_size_limit')
    return length


def verify_transfer(size,expected):
    if expected is not None and size!=expected:
        raise ValueError('incomplete_http_body')


def validate_manifest(rows):
    if not isinstance(rows, list) or not 1 <= len(rows) <= 300:
        raise ValueError('manifest_count')
    seen = set()
    for row in rows:
        sha = row.get('sha256', '')
        if not re.fullmatch('[0-9a-f]{64}', sha) or sha in seen:
            raise ValueError('manifest_identity')
        if not isinstance(row.get('file_size'), int) or not 0 < row['file_size'] <= 128 * 1024**2:
            raise ValueError('manifest_size')
        if row.get('source_url') != 'https://bazaar.abuse.ch/sample/' + sha + '/':
            raise ValueError('manifest_source')
        seen.add(sha)
    return rows


def require_mode(mode, interfaces, routes4, routes6):
    offline = interfaces == ['lo'] and not routes4 and not routes6
    if (mode == 'offline' and not offline) or (mode == 'online' and (offline or not routes4)):
        raise ValueError('network_mode_mismatch')


def unpack_verified(content, expected_sha, destination, limit):
    import pyzipper
    if len(content) > 129 * 1024**2:
        raise ValueError('archive_size')
    end = content.rfind(b'PK\x05\x06', max(0, len(content) - 65557))
    if end < 0 or end + 22 > len(content) or content[end+4:end+8] != b'\0'*4:
        raise ValueError('archive_directory')
    if (int.from_bytes(content[end+10:end+12], 'little') != 1 or
            end + 22 + int.from_bytes(content[end+20:end+22], 'little') != len(content) or
            content[max(0, end-20):end-16] == b'PK\x06\x07'):
        raise ValueError('archive_member_count_or_zip64')
    position = end-int.from_bytes(content[end+12:end+16], 'little')
    if (position < 0 or content[position:position+4] != b'PK\x01\x02' or position+46 > end or
            position+46+sum(int.from_bytes(content[position+i:position+i+2], 'little') for i in (28,30,32)) != end):
        raise ValueError('archive_directory_boundary')
    with pyzipper.AESZipFile(io.BytesIO(content)) as archive:
        entries = archive.infolist()
        if len(entries) != 1:
            raise ValueError('archive_member_count')
        info = entries[0]
        name = PurePosixPath(info.filename)
        if (name.is_absolute() or '..' in name.parts or '\\' in info.filename or ':' in info.filename or
                info.is_dir() or stat.S_ISLNK(info.external_attr >> 16) or not info.flag_bits & 1 or
                not 0 < info.file_size <= min(limit, 128 * 1024**2)):
            raise ValueError('archive_member_boundary')
        temporary = destination.with_suffix('.partial')
        # Only this worker owns this hash-specific regeneratable partial file.
        temporary.unlink(missing_ok=True)
        digest, count = hashlib.sha256(), 0
        try:
            with archive.open(info, pwd=b'infected') as source, temporary.open('xb') as target:
                while chunk := source.read(65536):
                    count += len(chunk)
                    if count > limit or count > info.file_size:
                        raise ValueError('member_budget')
                    digest.update(chunk)
                    target.write(chunk)
                target.flush()
                os.fsync(target.fileno())
            if count != info.file_size or digest.hexdigest() != expected_sha:
                raise ValueError('member_sha_mismatch')
            if destination.exists():
                if hashlib.sha256(destination.read_bytes()).hexdigest() != expected_sha:
                    raise ValueError('existing_sample_mismatch')
            else:
                os.replace(temporary, destination)
                destination.chmod(0o400)
            return count
        finally:
            temporary.unlink(missing_ok=True)
