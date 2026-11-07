#!/usr/bin/env python3
"""Usage: python3 solve.py files/sealed-orders.der (requires cryptography)."""
import hashlib
import sys
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SPKI_HASH = '1c6b38a86c3ff8b1d295e02b884c457da537767b5fdf063cf6d7d733b683a6b3'

def tlv(data, pos=0):
    start = pos
    tag = data[pos]; pos += 1
    length = data[pos]; pos += 1
    if length & 0x80:
        count = length & 0x7f
        length = int.from_bytes(data[pos:pos + count], 'big')
        pos += count
    end = pos + length
    return tag, data[pos:end], end, data[start:end]

def children(data):
    out = []
    pos = 0
    while pos < len(data):
        tag, value, pos, raw = tlv(data, pos)
        out.append((tag, value, raw))
    assert pos == len(data)
    return out

def integer(node):
    assert node[0] == 2
    return int.from_bytes(node[1], 'big')

data = Path(sys.argv[1] if len(sys.argv) > 1 else 'files/sealed-orders.der').read_bytes()
tag, content, end, _ = tlv(data)
assert tag == 0x30 and end == len(data)
version, spki, orders, seal = children(content)
assert integer(version) == 1 and hashlib.sha256(spki[2]).hexdigest() == SPKI_HASH

rows = []
for record in children(orders[1]):
    seq, msg, signature = children(record[1])
    r, s = map(integer, children(signature[1]))
    z = int.from_bytes(hashlib.sha256(msg[1]).digest(), 'big') % N
    rows.append((integer(seq), z, r, s))
assert [row[0] for row in rows] == list(range(6))

# Solve s_i*k0 + i*s_i*stride - r_i*d = z_i, all modulo N.
matrix = [[s % N, i * s % N, -r % N, z] for i, z, r, s in rows[:3]]
for col in range(3):
    pivot = next(j for j in range(col, 3) if matrix[j][col] % N)
    matrix[col], matrix[pivot] = matrix[pivot], matrix[col]
    inverse = pow(matrix[col][col], -1, N)
    matrix[col] = [x * inverse % N for x in matrix[col]]
    for j in range(3):
        if j != col:
            factor = matrix[j][col]
            matrix[j] = [(a - factor * b) % N for a, b in zip(matrix[j], matrix[col])]
k0, stride, d = [matrix[i][3] for i in range(3)]
assert all((s * (k0 + i * stride) - r * d - z) % N == 0 for i, z, r, s in rows)

public = ec.derive_private_key(d, ec.SECP256K1()).public_key()
assert public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) == spki[2]
salt, nonce, ciphertext, auth_tag = [node[1] for node in children(seal[1])]
key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
           info=b'CSCTF26/TheSignet/v1/standing-order').derive(d.to_bytes(32, 'big'))
plain = AESGCM(key).decrypt(nonce, ciphertext + auth_tag, None)
print(plain.decode())
