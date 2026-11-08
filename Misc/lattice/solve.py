#!/usr/bin/env python3
"""Invert the lattice toy cipher and recover the SECRET from the handout's TARGET.

Usage: python3 solve.py [path/to/lattice.py]
Defaults to files/lattice.py (unpack files/lattice.tar.gz first).

The handout ships only the forward cipher. This script imports its tables
(SBOX, RKEYS, TARGET) and the per-round rotate amount, then runs every round
backwards: inverse rotate -> inverse S-box -> subtract/xor the round key.
"""
import importlib.util
import os
import sys

default = os.path.join(os.path.dirname(__file__), "files", "lattice.py")
path = sys.argv[1] if len(sys.argv) > 1 else default

spec = importlib.util.spec_from_file_location("lat", path)
lat = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lat)

MASK64, SBOX, RKEYS = lat.MASK64, lat.SBOX, lat.RKEYS
INV = [0] * 256
for i, v in enumerate(SBOX):
    INV[v] = i


def rotr64(x, k):
    k &= 63
    return ((x >> k) | (x << (64 - k))) & MASK64


def dec_block(block):
    s = list(block)
    for r in range(15, -1, -1):
        x = int.from_bytes(bytes(s), "big")
        x = rotr64(x, lat._rot_amount(r))       # undo the left rotate
        s = list(x.to_bytes(8, "big"))
        s = [INV[b] for b in s]                  # undo the S-box
        rk = RKEYS[r]
        if r % 2 == 0:                           # even rounds added the key
            s = [(s[i] - rk[i]) & 0xFF for i in range(8)]
        else:                                    # odd rounds xored the key
            s = [s[i] ^ rk[i] for i in range(8)]
    return bytes(s)


ct = lat.TARGET
pt = b"".join(dec_block(ct[i:i + 8]) for i in range(0, len(ct), 8))
secret = pt[:-pt[-1]]                            # strip PKCS#7 padding

assert lat.encrypt(secret) == ct, "round-trip check failed"
print("SECRET:", secret.decode())
