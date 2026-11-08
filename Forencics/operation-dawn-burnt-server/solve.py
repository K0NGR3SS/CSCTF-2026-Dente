import gzip
import re
import struct
import sys
import tarfile
import zlib
from pathlib import Path


def deleted_register(image):
    if image[510:512] != b"\x55\xaa":
        raise ValueError("No FAT boot sector")
    sector_size = struct.unpack_from("<H", image, 11)[0]
    sectors_per_cluster = image[13]
    reserved_sectors = struct.unpack_from("<H", image, 14)[0]
    fat_count = image[16]
    entries = struct.unpack_from("<H", image, 17)[0]
    sectors_per_fat = struct.unpack_from("<H", image, 22)[0]
    root = (reserved_sectors + fat_count * sectors_per_fat) * sector_size
    root_sectors = (entries * 32 + sector_size - 1) // sector_size
    data = root + root_sectors * sector_size

    for offset in range(root, root + entries * 32, 32):
        entry = image[offset : offset + 32]
        if entry[:11] == b"\xe5RAIN   GZ ":
            cluster, size = struct.unpack_from("<HI", entry, 26)
            start = data + (cluster - 2) * sectors_per_cluster * sector_size
            return image[start : start + size]
    raise ValueError("Deleted RAIN.GZ entry missing")


def assemble(disks, symmetric):
    chunk_size = 65536
    image = bytearray()
    for stripe, start in enumerate(range(0, len(disks[0]), chunk_size)):
        parity = stripe % 3
        roles = (
            [(parity + 1) % 3, (parity + 2) % 3]
            if symmetric
            else [role for role in range(3) if role != parity]
        )
        for role in roles:
            image.extend(disks[role][start : start + chunk_size])
    return image


archive = (
    Path(sys.argv[1])
    if len(sys.argv) > 1
    else Path(__file__).with_name("files") / "server-remains.tar"
)
with tarfile.open(archive, "r:") as handout:
    with handout.extractfile("disk0.img") as first, handout.extractfile("disk2.img") as last:
        disk0, disk2 = first.read(), last.read()
if len(disk0) != len(disk2):
    raise ValueError("Surviving disk sizes differ")
disk1 = (int.from_bytes(disk0, "little") ^ int.from_bytes(disk2, "little")).to_bytes(
    len(disk0), "little"
)

flags = set()
for symmetric in (True, False):
    try:
        register = gzip.decompress(deleted_register(assemble((disk0, disk1, disk2), symmetric)))
    except (ValueError, EOFError, OSError, struct.error, zlib.error):
        continue
    match = re.search(rb"(?m)^MOVEMENT ORDER:\s*(CSCTF\{[^}\r\n]+\})", register)
    if match:
        flags.add(match[1].decode("ascii"))
if len(flags) != 1:
    raise ValueError("Expected one verified movement order")
print(flags.pop())
