#!/usr/bin/env python3
"""Operation Dawn: The Medic's Phone — CSCTF 2026 (Forensics).

Unpacks the Android .ab backup and recovers the withdrawn courier message
from the SQLite write-ahead log.

Usage: python3 solve.py files/medic-phone.ab
"""
import io
import re
import sys
import tarfile
import zlib


def read_ab(path):
    raw = open(path, "rb").read()
    # 4 header lines: "ANDROID BACKUP", version, compression, encryption
    i = 0
    for _ in range(4):
        i = raw.index(b"\n", i) + 1
    return zlib.decompress(raw[i:])


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "files/medic-phone.ab"
    tar = tarfile.open(fileobj=io.BytesIO(read_ab(path)))
    member = "apps/org.unit43.courier/db/messages.db-wal"
    wal = tar.extractfile(member).read()

    # Each message body is a raw-deflate blob inside a protobuf field. The
    # pre-withdrawal copy of message 14 still lives in the WAL, so brute-force
    # raw-inflate at every offset and keep whatever decompresses to the flag.
    seen = set()
    for off in range(len(wal)):
        try:
            text = zlib.decompressobj(-15).decompress(wal[off:])
        except Exception:
            continue
        m = re.search(rb"CSCTF\{[ -~]{1,60}\}", text)
        if m and m.group() not in seen:
            seen.add(m.group())
            print(text.decode("latin1"))
            print("\n[flag]", m.group().decode())


if __name__ == "__main__":
    main()
