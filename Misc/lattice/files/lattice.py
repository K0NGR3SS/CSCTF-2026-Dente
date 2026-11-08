#!/usr/bin/env python3
# lattice (misc) - a toy block cipher and a target ciphertext.
#
# TARGET below is encrypt(SECRET). Invert the cipher to recover SECRET, then
# submit it to the service (nc HOST 9999) to receive the flag. There is no
# decrypt routine here; writing the inverse is the challenge.
#
#   python3 lattice.py 'your_guess'   # local check: prints match / no match

#!/usr/bin/env python3
# lattice cipher - the authoritative forward algorithm, shared by the baker
# (src/bake.py) and the service (src/serve.py). This is exactly what players see
# in the shipped handout dist/lattice.py. It has no decrypt routine on purpose.
#
# 8-byte blocks, 16 rounds, ECB. Every detail matters: round parity, the per-round
# rotate amount, the custom-LCG S-box, big-endian packing.
MASK64 = (1 << 64) - 1


def _lcg(state):
    # A 32-bit LCG. Not a standard one - use THESE constants.
    while True:
        state = (state * 0x19660D + 0x3C6EF35F) & 0xFFFFFFFF
        yield state


def _build_sbox():
    # Key-dependent permutation of 0..255 via Fisher-Yates over the LCG above
    # (seed 0x1A2B3C4D). NOT the AES S-box.
    g = _lcg(0x1A2B3C4D)
    box = list(range(256))
    for i in range(255, 0, -1):
        j = next(g) % (i + 1)
        box[i], box[j] = box[j], box[i]
    return box


SBOX = _build_sbox()


def _build_keys():
    # 16 rounds x 8 bytes from a second LCG stream (seed 0xCAFEB0BA).
    g = _lcg(0xCAFEB0BA)
    return [[next(g) & 0xFF for _ in range(8)] for _ in range(16)]


RKEYS = _build_keys()


def _rotl64(x, k):
    k &= 63
    return ((x << k) | (x >> (64 - k))) & MASK64


def _rot_amount(r):
    # per round r the block rotates left by this many bits (always 1..63)
    return (7 * r + 11) % 63 + 1


def encrypt_block(block):
    s = list(block)
    for r in range(16):
        rk = RKEYS[r]
        if r % 2 == 0:                    # even rounds ADD the key (mod 256)
            s = [(s[i] + rk[i]) & 0xFF for i in range(8)]
        else:                             # odd rounds XOR the key
            s = [s[i] ^ rk[i] for i in range(8)]
        s = [SBOX[b] for b in s]          # substitute
        x = int.from_bytes(bytes(s), "big")
        x = _rotl64(x, _rot_amount(r))    # diffuse across the whole block
        s = list(x.to_bytes(8, "big"))
    return bytes(s)


def encrypt(data):
    pad = 8 - (len(data) % 8)             # PKCS#7
    data = data + bytes([pad]) * pad
    return b"".join(encrypt_block(data[i:i + 8]) for i in range(0, len(data), 8))

TARGET = b'\xc4\x02\xfb,T3g6\xe6\xce\x04\xc5\x9ba\x0c\xa2\x95\xa9\xa9\x04\xbbX+\xd2\xe6\x11L\xcf\xc7\xbd<\x0b\xba;@\x8f\xb5\xd4\xbfbNE\x80\x8f\xb1;\x06K'

def check(guess):
    g = guess.encode() if isinstance(guess, str) else guess
    return encrypt(g) == TARGET

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        g = sys.argv[1]
    else:
        try:
            g = input("secret> ")
        except EOFError:
            g = ""
    print("match" if check(g) else "no match")
