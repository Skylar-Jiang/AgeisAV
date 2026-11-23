import struct

import pytest


@pytest.fixture
def pe_bytes():
    """A synthetic PE header with harmless padding; it contains no executable code."""
    data = bytearray(1024)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0x102)
    struct.pack_into("<H", data, 0x98, 0x10B)
    struct.pack_into("<I", data, 0x98 + 92, 16)
    data[0x178:0x180] = b".text\0\0\0"
    struct.pack_into("<IIIIIIHHI", data, 0x180, 256, 0x1000, 256, 0x200, 0, 0, 0, 0, 0x60000020)
    data[0x200:0x300] = bytes(range(256))
    return bytes(data)
