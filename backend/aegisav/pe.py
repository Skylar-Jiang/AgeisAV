import pefile


def validate_pe(data: bytes) -> None:
    if not data.startswith(b"MZ"):
        raise ValueError("Input is not a PE file")
    try:
        pe = pefile.PE(data=data, fast_load=True)
        if not pe.OPTIONAL_HEADER or not pe.sections:
            raise ValueError("Input is not a complete PE file")
        if any(section.PointerToRawData + section.SizeOfRawData > len(data)
               for section in pe.sections if section.SizeOfRawData):
            raise ValueError("Input is a truncated PE file")
    except pefile.PEFormatError as exc:
        raise ValueError("Input is not a valid PE file") from exc
