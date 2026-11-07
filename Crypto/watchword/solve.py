#!/usr/bin/env python3
"""Usage: python3 solve.py files/watchword.zip (requires cryptography)."""
import base64
import json
import sys
import zipfile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

R = 0xe1000000000000000000000000000000
ONE = 1 << 127

def mul(a, b):
    result = 0
    value = b
    for i in range(128):
        if (a >> (127 - i)) & 1:
            result ^= value
        value = (value >> 1) ^ (R if value & 1 else 0)
    return result

def power(a, exponent):
    result = ONE
    while exponent:
        if exponent & 1:
            result = mul(result, a)
        a = mul(a, a)
        exponent >>= 1
    return result

with zipfile.ZipFile(sys.argv[1] if len(sys.argv) > 1 else 'files/watchword.zip') as z:
    bundle = json.loads(z.read('watchword/intercepts.json'))
rows = []
for item in bundle['intercepts']:
    c = bytes.fromhex(item['ciphertext_hex'])
    rows.append((int.from_bytes(c.ljust(16, b'\0'), 'big'), 8 * len(c), int(item['tag_hex'], 16)))
(c0, l0, t0), (c1, l1, t1), (c2, l2, t2) = rows
a, b, d = c0 ^ c1, l0 ^ l1, t0 ^ t1
u, v, e = c0 ^ c2, l0 ^ l2, t0 ^ t2
denominator = mul(u, b) ^ mul(a, v)
assert denominator
h = mul(mul(u, d) ^ mul(a, e), power(denominator, (1 << 128) - 2))
h2 = mul(h, h)
mask = t0 ^ mul(c0, h2) ^ mul(l0, h)
assert all(tag == mask ^ mul(c, h2) ^ mul(length, h) for c, length, tag in rows)
key = mask.to_bytes(16, 'big')
ciphertext = bytes.fromhex(bundle['sealed_master_order_ctr_hex'])
plain = Cipher(algorithms.AES(key), modes.CTR(bytes(16))).decryptor().update(ciphertext)
print(plain.decode())
