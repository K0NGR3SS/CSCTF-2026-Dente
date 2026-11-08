#!/usr/bin/env python3
"""rollback-pair: ECDSA nonce reuse after a bad state restore (secp256k1, offline).

The service resumed from a stale nonce-state snapshot, so two dispatch records were signed
with the same per-signature nonce k. Equal r is the tell. From that pair, k and then the
long-term signing scalar d fall out directly; d is checked against the published public key.
"""
import base64, hashlib, json, sys
from itertools import combinations

P  = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
N  = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8

def add(p, q):
    if p is None: return q
    if q is None: return p
    if p[0] == q[0] and (p[1] + q[1]) % P == 0: return None
    if p == q: l = 3 * p[0] * p[0] * pow(2 * p[1], -1, P) % P
    else:      l = (q[1] - p[1]) * pow(q[0] - p[0], -1, P) % P
    x = (l * l - p[0] - q[0]) % P
    return (x, (l * (p[0] - x) - p[1]) % P)

def mul(k, p=(GX, GY)):
    r = None
    while k:
        if k & 1: r = add(r, p)
        p = add(p, p); k >>= 1
    return r

def verify(z, r, s, Q):
    if not (1 <= r < N and 1 <= s < N): return False
    w = pow(s, -1, N)
    pt = add(mul(z * w % N, (GX, GY)), mul(r * w % N, Q))
    return pt is not None and pt[0] % N == r

doc = json.load(open(sys.argv[1] if len(sys.argv) > 1 else 'dist/signing-export.json'))
Q = (int(doc['public_key']['x'], 16), int(doc['public_key']['y'], 16))
assert (Q[1] * Q[1] - Q[0] ** 3 - 7) % P == 0, 'public key is not on secp256k1'

recs = []
for rec in doc['records']:
    msg = base64.b64decode(rec['message_b64'])
    sig = bytes.fromhex(rec['signature_rs_hex'])
    recs.append({
        'id': rec['record_id'],
        'z': int.from_bytes(hashlib.sha256(msg).digest(), 'big') % N,
        'r': int.from_bytes(sig[:32], 'big'),
        's': int.from_bytes(sig[32:], 'big'),
    })

bad = [r['id'] for r in recs if not verify(r['z'], r['r'], r['s'], Q)]
print(f"{len(recs)} records, all verify against the published key: {not bad}")

# the exposure: two records sharing r were signed with the same nonce
pair = next(((a, b) for a, b in combinations(recs, 2) if a['r'] == b['r']), None)
if pair is None:
    sys.exit('no repeated r -> key not exposed by this export')
a, b = pair
print(f"nonce reuse: {a['id']} and {b['id']} share r = {a['r']:064x}")

d = None
for den in (a['s'] - b['s'], a['s'] + b['s']):       # sign of k is not observable
    k = (a['z'] - b['z']) * pow(den % N, -1, N) % N
    cand = (a['s'] * k - a['z']) * pow(a['r'], -1, N) % N
    if cand and mul(cand) == Q:
        d, nonce = cand, k
        break
assert d, 'scalar not recovered'

# independent check: d must reproduce every signature in the export
assert all(r['s'] == pow(nonce, -1, N) * (r['z'] + r['r'] * d) % N
           for r in (a, b)), 'recovered scalar does not reproduce the pair'
print(f'reused nonce k = {nonce:064x}')
print(f'signing scalar = {d:064x}  (verified: d*G == published public key)')
print(f'CSCTF{{{d:064x}}}')
