"""Explicit, integrity-checked Windows SSDeep candidate; Python stays the default."""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import struct


class NativeBackendError(RuntimeError):
    pass


class NativeSSDeep:
    def __init__(self, root):
        try:
            root = Path(root).resolve()
            manifest_path = root / 'manifest.json'
            if manifest_path.stat().st_size > 4096:
                raise ValueError('Manifest size limit')
            manifest = json.loads(manifest_path.read_bytes())
            if (manifest['schema'] != 1 or manifest['abi'] != 1 or
                    manifest['file'] != 'aegisav_ssdeep.dll'):
                raise ValueError('Unsupported native manifest')
            path = root / manifest['file']
            if path.is_symlink() or not 1 <= path.stat().st_size <= 1024**2:
                raise ValueError('Native asset path/size limit')
            data = path.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            if digest != manifest['sha256']:
                raise ValueError('Native asset digest mismatch')
            pe_offset = struct.unpack_from('<I', data, 0x3c)[0]
            if (data[:2] != b'MZ' or data[pe_offset:pe_offset + 4] != b'PE\0\0' or
                    struct.unpack_from('<H', data, pe_offset + 4)[0] != 0x8664 or
                    struct.unpack_from('<H', data, pe_offset + 24)[0] != 0x20b or
                    os.name != 'nt' or ctypes.sizeof(ctypes.c_void_p) != 8):
                raise ValueError('Native backend requires Windows x64 PE32+')
            self.path, self.digest, self.function = path, digest, None
            self.engine_version = 'native-ssdeep/abi1+' + digest[:16]
        except (OSError, ValueError, KeyError, TypeError, AttributeError, struct.error) as error:
            raise NativeBackendError('Requested native SSDeep failed integrity/ABI verification') from error

    def _load(self):
        try:
            from ctypes import wintypes as w
            from .scan_process import windows_api
            if not os.environ.get('AEGISAV_SCAN_JOB') or ctypes.WinDLL('shell32').IsUserAnAdmin():
                raise ValueError('Native parser requires an unelevated disposable worker')
            api = windows_api()
            job = api.OpenJobObjectW(4, False, os.environ['AEGISAV_SCAN_JOB'])
            if not job:
                raise ValueError('Owned worker Job missing')
            try:
                member = w.BOOL()
                api.IsProcessInJob.argtypes = [w.HANDLE, w.HANDLE, ctypes.POINTER(w.BOOL)]
                api.IsProcessInJob.restype = w.BOOL
                if not api.IsProcessInJob(api.GetCurrentProcess(), job, ctypes.byref(member)) or not member.value:
                    raise ValueError('Worker is not contained in its owned Job')
            finally:
                api.CloseHandle(job)
            if hashlib.sha256(self.path.read_bytes()).hexdigest() != self.digest:
                raise ValueError('Native asset changed before loading')
            # Absolute reviewed asset; dependencies are resolved only in System32.
            self.library = ctypes.CDLL(str(self.path), winmode=0x00000800)
            abi = self.library.aegisav_ssdeep_abi
            abi.argtypes, abi.restype = [], ctypes.c_uint32
            if abi() != 1:
                raise ValueError('Native ABI mismatch')
            self.function = self.library.aegisav_ssdeep
            self.function.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t]
            self.function.restype = ctypes.c_int
        except (OSError, ValueError, KeyError, AttributeError) as error:
            raise NativeBackendError('Native SSDeep worker containment/ABI verification failed') from error

    def hash(self, data):
        if not isinstance(data, bytes) or len(data) > 16 * 1024**2:
            raise NativeBackendError('Native SSDeep input budget/type')
        if self.function is None:
            self._load()
        output = ctypes.create_string_buffer(128)
        length = self.function(data, len(data), output, len(output))
        if not 0 <= length < len(output) or len(output.value) != length:
            raise NativeBackendError('Native SSDeep output budget')
        try:
            return output.value.decode('ascii')
        except UnicodeError as error:
            raise NativeBackendError('Native SSDeep output encoding') from error


def select_backend(root):
    mode = os.environ.get('AEGISAV_SSDEEP_BACKEND', 'python')
    if mode == 'python':
        return None
    if mode != 'native':
        raise NativeBackendError('Unsupported SSDeep backend')
    return NativeSSDeep(Path(root) / 'native')
