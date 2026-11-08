import re
import struct
from pathlib import Path


core = (Path(__file__).parent / "files" / "relay.core").read_bytes()
if not core.startswith(b"\x7fELF\x02\x01"):
    raise ValueError("Expected a 64-bit little-endian ELF core")
headers, = struct.unpack_from("<Q", core, 32)
entry_size, count = struct.unpack_from("<HH", core, 54)
segments = []
for i in range(count):
    kind, _, offset, virtual, _, stored, _, _ = struct.unpack_from(
        "<II6Q", core, headers + i * entry_size
    )
    if kind == 1 and stored:
        segments.append((virtual, offset, stored))


def file_offset(address):
    for virtual, offset, size in segments:
        if virtual <= address < virtual + size:
            return offset + address - virtual
    raise ValueError("Pointer outside captured memory")


flags = set()
for marker in re.finditer(b"CSCTF", core):
    offset = marker.start() - 12
    seen = set()
    result = bytearray()
    while offset not in seen and len(seen) < 64:
        seen.add(offset)
        pointer, size = struct.unpack_from("<QI", core, offset)
        if not 1 <= size <= 32:
            break
        result.extend(core[offset + 12:offset + 12 + size])
        if not pointer:
            if re.fullmatch(rb"CSCTF\{[^}]+\}", result):
                flags.add(bytes(result))
            break
        try:
            offset = file_offset(pointer)
        except ValueError:
            break
flag, = flags
print(flag.decode("ascii"))
