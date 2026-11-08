#!/usr/bin/env python3
"""Afterimage — CSCTF 2026 (Forensics).

aCropalypse (CVE-2023-21036) recovery: rebuild the pre-crop image from the
leftover IDAT data that follows the PNG's IEND marker.

Usage: python3 solve.py files/relay-capture.png recovered.png
Then read the flag off recovered.png.
"""
import struct
import sys
import zlib

W = 520  # pre-crop image width in pixels (RGB, 8-bit)


def end_of_iend(d):
    p = 8
    while p < len(d):
        (ln,) = struct.unpack(">I", d[p : p + 4])
        typ = d[p + 4 : p + 8]
        p += 12 + ln
        if typ == b"IEND":
            return p
    raise SystemExit("no IEND")


def trailing_stream(d, p):
    first_idat = d.find(b"IDAT", p)
    stream = d[p : first_idat - 8]
    q = first_idat - 4
    while q < len(d):
        (ln,) = struct.unpack(">I", d[q : q + 4])
        typ = d[q + 4 : q + 8]
        if typ == b"IDAT":
            stream += d[q + 8 : q + 8 + ln]
        q += 12 + ln
        if typ == b"IEND":
            break
    return stream


def shifted(buf, k):
    if k == 0:
        return buf
    n = int.from_bytes(buf, "little") >> k
    return n.to_bytes(len(buf), "little")


def paeth(a, b, c):
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    return a if pa <= pb and pa <= pc else (b if pb <= pc else c)


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else "files/relay-capture.png"
    out = sys.argv[2] if len(sys.argv) > 2 else "recovered.png"
    d = open(src, "rb").read()

    stream = trailing_stream(d, end_of_iend(d))
    stride = 1 + W * 3

    best = None
    for off in range(len(stream) - 100):
        for k in range(8):
            try:
                r = zlib.decompressobj(wbits=-15, zdict=b"\0" * 32768).decompress(
                    shifted(stream[off:], k)
                )
                if len(r) > 20000:
                    best = r
                    break
            except Exception:
                pass
        if best:
            break
    if not best:
        raise SystemExit("no inflatable block found")

    nrows = len(best) // stride
    data = best[len(best) - nrows * stride :]
    img = bytearray()
    prev = bytearray(W * 3)
    for i in range(nrows):
        row = data[i * stride : (i + 1) * stride]
        f = row[0] if row[0] <= 4 else 0
        cur = bytearray(row[1:])
        for x in range(len(cur)):
            a = cur[x - 3] if x >= 3 else 0
            b = prev[x]
            c = prev[x - 3] if x >= 3 else 0
            if f == 1:
                cur[x] = (cur[x] + a) & 255
            elif f == 2:
                cur[x] = (cur[x] + b) & 255
            elif f == 3:
                cur[x] = (cur[x] + (a + b) // 2) & 255
            elif f == 4:
                cur[x] = (cur[x] + paeth(a, b, c)) & 255
        img += cur
        prev = cur

    def chunk(t, b):
        return struct.pack(">I", len(b)) + t + b + struct.pack(">I", zlib.crc32(t + b) & 0xFFFFFFFF)

    raw = b"".join(b"\0" + img[i * W * 3 : (i + 1) * W * 3] for i in range(nrows))
    png = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", W, nrows, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )
    open(out, "wb").write(png)
    print(f"wrote {out} ({nrows} rows) — read the flag off it")


if __name__ == "__main__":
    main()
