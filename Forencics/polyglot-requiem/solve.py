#!/usr/bin/env python3
"""Polyglot Requiem — CSCTF 2026 (Forensics).

Carves the PNG/ZIP polyglot out of the git repo, recovers the deleted
`ci_provenance_seal` SQLite row, and reproduces assetsignd's XOR scheme to
decrypt the marker. Nothing in the evidence is executed.

Usage: python3 solve.py files/polyglot-requiem.zip
"""
import hashlib
import io
import struct
import sys
import zipfile


def find_polyglot_png(zf):
    for name in zf.namelist():
        if name.lower().endswith(".png"):
            data = zf.read(name)
            # polyglot = tiny image but large file (payload appended after IEND)
            if len(data) > 2000:
                return name, data
    raise SystemExit("polyglot PNG not found")


def png_text_tag(png):
    """Return the Provenance value from the first tEXt chunk, and the offset
    just past IEND (start of the appended data)."""
    p = 8
    tag = None
    end = len(png)
    while p < len(png):
        (ln,) = struct.unpack(">I", png[p : p + 4])
        typ = png[p + 4 : p + 8]
        body = png[p + 8 : p + 8 + ln]
        if typ == b"tEXt" and body.startswith(b"Provenance\x00"):
            tag = body.split(b"\x00", 1)[1].decode()
        p += 12 + ln
        if typ == b"IEND":
            end = p
            break
    return tag, end


def git_commit_epoch(zf):
    """Committer timestamp of the dangling build commit = XOR epoch."""
    sha = "c435f883afdf89450a1d2f63eb02725725d522c7"
    for name in zf.namelist():
        if name.endswith(f".git/objects/{sha[:2]}/{sha[2:]}"):
            import zlib

            obj = zlib.decompress(zf.read(name))
            for line in obj.split(b"\n"):
                if line.startswith(b"committer"):
                    return int(line.split()[-2])
    return 1792061626  # value observed in the handout


def main():
    zf = zipfile.ZipFile(sys.argv[1] if len(sys.argv) > 1 else "files/polyglot-requiem.zip")

    _, png = find_polyglot_png(zf)
    tag, end = png_text_tag(png)
    print("provenance tag:", tag)

    inner = zipfile.ZipFile(io.BytesIO(png[end:]))  # ZIP appended after IEND
    db = inner.read("telemetry_cache.db")

    # the deleted row survives on a freelist page: label then 36-byte BLOB
    i = db.index(b"ci_provenance_seal") + len(b"ci_provenance_seal")
    ct = db[i : i + 36]
    print("ciphertext:", ct.hex())

    epoch = git_commit_epoch(zf)
    key = hashlib.sha256(bytes.fromhex(tag)[::-1] + struct.pack("<Q", epoch)).digest()
    flag = bytes(c ^ key[i % len(key)] for i, c in enumerate(ct))
    print(flag.decode())


if __name__ == "__main__":
    main()
