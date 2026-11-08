#!/usr/bin/env python3
"""Calculate Shodan's signed favicon hash from the raw icon bytes."""

import base64
import hashlib
from pathlib import Path


def murmur3_x86_32(data: bytes, seed: int = 0) -> int:
    mask = 0xFFFFFFFF
    h = seed & mask
    c1, c2 = 0xCC9E2D51, 0x1B873593

    for offset in range(0, len(data) & ~3, 4):
        k = int.from_bytes(data[offset : offset + 4], "little")
        k = k * c1 & mask
        k = ((k << 15) | (k >> 17)) & mask
        k = k * c2 & mask
        h ^= k
        h = ((h << 13) | (h >> 19)) & mask
        h = (h * 5 + 0xE6546B64) & mask

    tail = data[len(data) & ~3 :]
    k = int.from_bytes(tail, "little")
    if tail:
        k = k * c1 & mask
        k = ((k << 15) | (k >> 17)) & mask
        k = k * c2 & mask
        h ^= k

    h ^= len(data)
    h ^= h >> 16
    h = h * 0x85EBCA6B & mask
    h ^= h >> 13
    h = h * 0xC2B2AE35 & mask
    h ^= h >> 16
    return h if h < 0x80000000 else h - 0x100000000


if __name__ == "__main__":
    assert murmur3_x86_32(b"") == 0
    assert murmur3_x86_32(b"foo") == -156908512
    icon = (Path(__file__).parent / "files" / "favicon.ico").read_bytes()
    print("SHA-256:", hashlib.sha256(icon).hexdigest())
    print("Shodan-style hash:", murmur3_x86_32(base64.encodebytes(icon)))
