"""Research-only Linux native hashing; never selected by the frozen product."""
import ctypes
import importlib.util
import importlib
from pathlib import Path
import re
import sysconfig


class NativeFuzzy:
    def __init__(self):
        path=Path('/usr/lib/python3/dist-packages')/('tlsh'+sysconfig.get_config_var('EXT_SUFFIX'))
        spec=importlib.util.spec_from_file_location('_aegisav_native.tlsh',path)
        self.tlsh=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.tlsh)
        self.reference=importlib.import_module('tlsh')
        self.fuzzy=ctypes.CDLL('/lib/x86_64-linux-gnu/libfuzzy.so.2')
        self.fuzzy.fuzzy_new.argtypes=[]
        self.fuzzy.fuzzy_new.restype=ctypes.c_void_p
        self.fuzzy.fuzzy_set_total_input_length.argtypes=[ctypes.c_void_p,ctypes.c_uint64]
        self.fuzzy.fuzzy_set_total_input_length.restype=ctypes.c_int
        self.fuzzy.fuzzy_update.argtypes=[ctypes.c_void_p,ctypes.c_char_p,ctypes.c_size_t]
        self.fuzzy.fuzzy_update.restype=ctypes.c_int
        self.fuzzy.fuzzy_digest.argtypes=[ctypes.c_void_p,ctypes.c_char_p,ctypes.c_uint]
        self.fuzzy.fuzzy_digest.restype=ctypes.c_int
        self.fuzzy.fuzzy_free.argtypes=[ctypes.c_void_p]
        self.fuzzy.fuzzy_free.restype=None

    def compute(self,data):
        if len(data)>128*1024**2:
            raise ValueError('native_input_budget')
        state=self.fuzzy.fuzzy_new()
        if not state:
            raise MemoryError('native_hash_state')
        tlsh=self.tlsh.Tlsh()
        try:
            if self.fuzzy.fuzzy_set_total_input_length(state,len(data)):
                raise ValueError('native_input_length')
            for offset in range(0,len(data),1024*1024):
                chunk=data[offset:offset+1024*1024]
                tlsh.update(chunk)
                if self.fuzzy.fuzzy_update(state,chunk,len(chunk)):
                    raise ValueError('native_fuzzy_update')
            try:
                tlsh.final()
                digest=tlsh.hexdigest()
            except ValueError:
                digest=None
            if digest is None or len(data)<256:
                # Ubuntu's older binding requires 256 bytes; the frozen implementation accepts 50.
                reference=self.reference.Tlsh()
                try:
                    for offset in range(0,len(data),1024*1024):
                        reference.update(data[offset:offset+1024*1024])
                    reference.final()
                    digest=reference.hexdigest(ver=1)
                except AssertionError:
                    digest=None
            else:
                if not re.fullmatch('[A-F0-9]{70}',digest):
                    raise ValueError('native_digest_shape')
                digest='T1'+digest
            output=ctypes.create_string_buffer(148)
            if self.fuzzy.fuzzy_digest(state,output,0):
                raise ValueError('native_fuzzy_digest')
            return dict(tlsh=digest,ssdeep=output.value.decode('ascii') or None)
        finally:
            self.fuzzy.fuzzy_free(state)
