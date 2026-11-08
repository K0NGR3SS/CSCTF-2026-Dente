#!/usr/bin/env python3
"""Carrier Shadow — CSCTF 2026 (Rev).

The payload is hidden in the gaps between function start addresses (taken from
the .eh_frame_hdr FDE table). Reconstruct it statically: xorshift32 sync marker,
header, canonical-Huffman symbols, XOR keystream -> raw DEFLATE -> stage-2 ELF,
whose .rodata holds the flag. Nothing is executed.

Usage: python3 solve.py files/carrier-shadow stage2.elf
"""
import re
import struct
import sys
import zlib

M = 0xFFFFFFFF
SEED = 0x6A2B3C4D
H = 0x9B600  # .eh_frame_hdr file offset (vaddr == off)
TABLES = {0: 0x9B340, 1: 0x9B240}  # Huffman code-length tables


def xs(x):
    x ^= (x << 13) & M
    x ^= x >> 17
    x ^= (x << 5) & M
    return x & M


def main():
    data = open(sys.argv[1] if len(sys.argv) > 1 else "files/carrier-shadow", "rb").read()
    out = sys.argv[2] if len(sys.argv) > 2 else "stage2.elf"

    assert data[H : H + 4] == b"\x01\x1b\x03\x3b"
    cnt = struct.unpack_from("<I", data, H + 8)[0]
    locs = [struct.unpack_from("<i", data, H + 12 + 8 * i)[0] + H for i in range(cnt)]
    gaps = [locs[i + 1] - locs[i] for i in range(cnt - 1)]

    x = SEED
    sync = []
    for _ in range(8):
        x = xs(x)
        sync.append(x % 61 + 34)

    dec = None
    for i in range(len(gaps) - 16):
        if gaps[i : i + 8] != sync:
            continue
        h = [g - 2 for g in gaps[i + 8 : i + 14]]
        if any(not 0 <= v <= 255 for v in h) or h[0] > 1:
            continue
        mode, ln, ck = h[0], h[1] | h[2] << 8 | h[3] << 16 | h[4] << 24, h[5]

        lens = data[TABLES[mode] : TABLES[mode] + 256]
        maxl = max(lens)
        blc = [0] * (maxl + 1)
        for l in lens:
            if l:
                blc[l] += 1
        nxt = [0] * (maxl + 2)
        code = 0
        for b in range(1, maxl + 1):
            nxt[b] = code
            code = (code + blc[b]) << 1
        codes = [0] * 256
        for s in range(256):
            if lens[s]:
                codes[s] = nxt[lens[s]]
                nxt[lens[s]] += 1

        bits, j = [], i + 14
        while len(bits) < ln * 8:
            s = gaps[j] - 2
            j += 1
            L = lens[s]
            bits += [(codes[s] >> (L - 1 - k)) & 1 for k in range(L)]
        bits = bits[: ln * 8]
        buf = bytearray(int("".join(map(str, bits[k : k + 8])), 2) for k in range(0, len(bits), 8))

        xr = 0
        for b in buf:
            xr ^= b
        assert xr == ck, "checksum mismatch"

        x = SEED
        for k in range(len(buf)):
            x = xs(x)
            buf[k] ^= x & 0xFF
        dec = zlib.decompress(bytes(buf), -15)
        break

    if not dec:
        sys.exit("payload not found")
    open(out, "wb").write(dec)
    print("stage-2 ELF:", len(dec), "bytes ->", out)
    m = re.search(rb"CSCTF\{[ -~]{1,60}\}", dec)
    if m:
        print("\n[FLAG]", m.group().decode())


if __name__ == "__main__":
    main()
