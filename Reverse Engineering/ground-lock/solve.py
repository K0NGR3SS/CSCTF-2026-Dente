#!/usr/bin/env python3
"""Ground Lock (CSCTF 2026, rev, 133 pts) - recover the GRIFFON-FC service code.

Static analysis only; the Linux binary is never executed.

main() @0x4016da:
    argc must be 2 and strlen(argv[1]) must be BLOCKS*8 = 24.
    For each of the 3 blocks it loads 8 bytes little-endian, passes them through the function
    at 0x401655, and compares the result against a target. Any mismatch -> "ACCESS DENIED";
    all three match -> "Maintenance token: CSCTF{%.*s}" printed with the 24 input bytes.

The function at 0x401655 is MurmurHash3's fmix64, inlined constants and all:
    k ^= k >> 33;  k *= 0xff51afd7ed558ccd;  k ^= k >> 33;  k *= 0xc4ceb9fe1a85ec53;  k ^= k >> 33;
It is a bijection on 64 bits, so there is nothing to brute force:
  * x ^= x >> 33 is its own inverse here, because the shifted part keeps the top 31 bits intact;
  * both constants are odd, so each has a multiplicative inverse mod 2**64.
Inverting the three targets gives the three blocks, and their little-endian bytes are the code.

The parameter block sits in .rodata as seven consecutive qwords:
    C1, C2, shift(33), blocks(3), target0, target1, target2
solve.py locates it by searching for C1, so it reads the real values out of dist/fcunlock rather
than trusting anything transcribed by hand.

usage: solve.py [path to fcunlock]
"""
import os, struct, sys

C1, C2, MASK = 0xFF51AFD7ED558CCD, 0xC4CEB9FE1A85EC53, (1 << 64) - 1


def read_params(path):
    data = open(path, "rb").read()
    # the two constants also appear as immediates inside fmix64; the .rodata block is the
    # place where they sit adjacent
    at = data.find(struct.pack("<QQ", C1, C2))
    if at < 0:
        sys.exit("MurmurHash3 parameter block not found - wrong file?")
    c1, c2, shift, blocks, *targets = struct.unpack_from("<7Q", data, at)
    assert (c1, c2) == (C1, C2), "unexpected constants"
    return shift, blocks, targets[:blocks]


def unxorshift(x, s):
    return x ^ (x >> s)          # valid while 2*s >= 64, which holds for s = 33


def unfmix64(h, shift):
    inv1, inv2 = pow(C1, -1, 1 << 64), pow(C2, -1, 1 << 64)
    h = unxorshift(h, shift)
    h = (h * inv2) & MASK
    h = unxorshift(h, shift)
    h = (h * inv1) & MASK
    return unxorshift(h, shift)


def fmix64(k, shift):
    k = (k ^ (k >> shift)) & MASK
    k = (k * C1) & MASK
    k = (k ^ (k >> shift)) & MASK
    k = (k * C2) & MASK
    return (k ^ (k >> shift)) & MASK


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "dist", "fcunlock")
    shift, blocks, targets = read_params(path)
    print(f"[+] fmix64 shift {shift}, {blocks} blocks of 8 bytes = {blocks*8} code bytes")

    code = b""
    for i, t in enumerate(targets):
        k = unfmix64(t, shift)
        assert fmix64(k, shift) == t, "inversion failed"
        chunk = struct.pack("<Q", k)
        print(f"[+] block {i}: target {t:#018x} -> {k:#018x} -> {chunk!r}")
        code += chunk

    assert len(code) == blocks * 8
    text = code.decode("ascii")
    print(f"\n[+] service code ({len(code)} bytes): {text}")
    print("FLAG: CSCTF{" + text + "}")


if __name__ == "__main__":
    main()
