#!/usr/bin/env python3
"""Shadow-Dispatch — CSCTF 2026 (Forensics).

Reassembles the secret exfiltrated 2 bytes at a time through the `correlation`
field of the authorizer's CloudWatch logs. The version-8 layer steals
/gridlink/order-hmac-key, which is the flag.

Usage: python3 solve.py files/shadow-dispatch.zip
"""
import collections
import hashlib
import json
import os
import re
import sys
import tempfile
import zipfile


def crc16_ccitt_false(data):
    c = 0xFFFF
    for b in data:
        c ^= b << 8
        for _ in range(8):
            c = ((c << 1) ^ 0x1021) & 0xFFFF if c & 0x8000 else (c << 1) & 0xFFFF
    return c


def decode(root):
    man = json.load(open(os.path.join(root, "cloudwatch/streams-manifest.json")))
    # res[(version, kind)][chunk_index] -> Counter of (plaintext_hex, crc_ok, index_ok)
    res = collections.defaultdict(lambda: collections.defaultdict(collections.Counter))
    pat = re.compile(r"\t([0-9a-f-]{36})\ttelemetry order_id=(\d+) correlation=([0-9a-f]+)")
    for m in man:
        ver = re.search(r"\[(\d+)\]", m["logStreamName"]).group(1)
        for line in open(os.path.join(root, "cloudwatch", m["file"]), encoding="utf-8", errors="replace"):
            mm = pat.search(line)
            if not mm:
                continue
            rid, oid, tok = mm.group(1), int(mm.group(2)), bytes.fromhex(mm.group(3))
            idx, ct, c, salt = tok[0], tok[1:3], int.from_bytes(tok[3:5], "big"), tok[5:]
            ks = hashlib.sha256(rid.encode() + salt).digest()[:2]
            pt = bytes(a ^ b for a, b in zip(ct, ks))
            ok = crc16_ccitt_false(bytes([idx]) + pt + salt) == c
            kind = "secret" if oid % 5 == 0 else "digest"
            res[(ver, kind)][idx][(pt.hex(), ok, idx == oid % 8)] += 1
    return res


def main():
    zpath = sys.argv[1] if len(sys.argv) > 1 else "files/shadow-dispatch.zip"
    with tempfile.TemporaryDirectory() as tmp:
        zipfile.ZipFile(zpath).extractall(tmp)
        root = os.path.join(tmp, "shadow-dispatch")
        if not os.path.exists(os.path.join(root, "cloudwatch")):
            root = tmp
        res = decode(root)

    for (ver, kind) in sorted(res, key=lambda x: (int(x[0]), x[1])):
        if kind != "secret":
            continue
        chunks = res[(ver, kind)]
        full = ""
        for i in range(8):
            good = {p for (p, ok, _iok), _n in chunks[i].items() if ok}
            full += good.pop() if len(good) == 1 else "????"
        label = "  <-- order-hmac-key (FLAG)" if ver == "8" else ""
        print(f"layer v{ver}: CSCTF{{{full}}}{label}")


if __name__ == "__main__":
    main()
