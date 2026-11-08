import hashlib
import json
import re
import struct
from datetime import datetime, timezone
from itertools import permutations
from pathlib import Path
from zipfile import ZipFile

from ext4 import Ext4


files = Path(__file__).parent / "files"
with ZipFile(files / "ghost-in-the-historian.zip") as archive:
    for line in archive.read("manifest.sha256").decode("ascii").splitlines():
        expected, name = line.split(maxsplit=1)
        if hashlib.sha256(archive.read(name)).hexdigest() != expected:
            raise ValueError(f"Handout checksum mismatch: {name}")
    image = archive.read("evidence-flat.vmdk")
if b"\x7fELF" not in image:
    raise ValueError("Recovered encryptor signature absent")
fs = Ext4(image)
log = fs.file("var/log/historian.log")
minute, pid = re.search(rb"(\d{4}-\d\d-\d\d \d\d:\d\d) historian_enc\[(\d+)\]", log).groups()
inode = fs.inode(2)
for part in ("var", "historian"):
    inode = fs.inode(dict(fs.directory(inode))[part])
inventory = {}
timestamps = set()
for name, number in fs.directory(inode):
    if name.endswith(".enc"):
        record = fs.inode(number)
        timestamps.add(struct.unpack_from("<I", record, 16)[0])
        inventory[name] = fs.content(record)
timestamp, = timestamps
if datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y-%m-%d %H:%M") != minute.decode():
    raise ValueError("File modification time does not match the log")
seed = ((timestamp ^ int(pid)) * 0x9e3779b1) & 0xffffffff
flags = set()
for order in permutations(inventory):
    state = seed
    decoded = {}
    for name in order:
        data = inventory[name]
        stream = bytearray()
        for _ in range(0, len(data), 4):
            state ^= (state << 13) & 0xffffffff
            state ^= state >> 17
            state ^= (state << 5) & 0xffffffff
            stream.extend(struct.pack("<I", state))
        decoded[name] = bytes(a ^ b for a, b in zip(data, stream))
    match = re.search(rb"(?m)^SAFETY_INTERLOCK_TOKEN=(CSCTF\{[^}]+\})$", decoded["grid_topology.cfg.enc"])
    if not match:
        continue
    try:
        json.loads(decoded["node_status.json.enc"])
        decoded["historian_cache.dat.enc"].decode("ascii")
    except (ValueError, UnicodeError):
        continue
    flags.add(match[1])
flag, = flags
print(flag.decode("ascii"))
