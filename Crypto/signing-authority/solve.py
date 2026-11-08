#!/usr/bin/env python3
"""signing-authority: ECDSA nonce reuse on secp256k1.

The service publishes release receipts. Two of them share the same r, so they were
signed with the same nonce k. That recovers k, then the long-term private key d, and
with d we sign the one message the service refuses to sign.
"""
import hashlib, json, sys, urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else open('work/INSTANCE').read().strip()

P  = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
N  = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8

def add(p, q):
    if p is None: return q
    if q is None: return p
    if p[0] == q[0] and (p[1] + q[1]) % P == 0: return None
    if p == q: l = (3 * p[0] * p[0]) * pow(2 * p[1], -1, P) % P
    else:      l = (q[1] - p[1]) * pow(q[0] - p[0], -1, P) % P
    x = (l * l - p[0] - q[0]) % P
    return (x, (l * (p[0] - x) - p[1]) % P)

def mul(k, p=(GX, GY)):
    r = None
    while k:
        if k & 1: r = add(r, p)
        p = add(p, p); k >>= 1
    return r

def get(path):
    with urllib.request.urlopen(BASE + path, timeout=20) as f:
        return json.load(f)

def z_of(message_hex):
    return int.from_bytes(hashlib.sha256(bytes.fromhex(message_hex)).digest(), 'big') % N

schema = get('/schema')
pub = bytes.fromhex(get('/pubkey')['sec1_uncompressed'])
Q = (int.from_bytes(pub[1:33], 'big'), int.from_bytes(pub[33:], 'big'))
receipts = get('/receipts')['receipts']

# 1. find two receipts that share a nonce
pair = next((a, b) for i, a in enumerate(receipts) for b in receipts[i + 1:] if a['r'] == b['r'])
a, b = pair
print(f"nonce reuse: {a['id']} and {b['id']} share r={a['r']}")

r = int(a['r'], 16)
s1, s2 = int(a['s'], 16), int(b['s'], 16)
z1, z2 = z_of(a['message_hex']), z_of(b['message_hex'])

# 2. k and d. The sign of k is not observable, so try both and keep the one matching the pubkey.
d = None
for num, den in ((z1 - z2, s1 - s2), (z1 - z2, s1 + s2)):
    k = num * pow(den, -1, N) % N
    cand = (s1 * k - z1) * pow(r, -1, N) % N
    if cand and mul(cand) == Q:
        d, nonce = cand, k
        break
assert d, 'private key not recovered'
print(f'private key d = {d:064x}   (verified: d*G == published pubkey)')

# 3. sign the master message the service will not sign for us
msg = schema['master_message_hex']
z = z_of(msg)
k = int.from_bytes(hashlib.sha256(b'k|' + bytes.fromhex(msg) + d.to_bytes(32, 'big')).digest(), 'big') % N
R = mul(k)
sr = R[0] % N
ss = pow(k, -1, N) * (z + sr * d) % N
if ss > N // 2: ss = N - ss                      # authorize_s_rule: low-s
assert 1 <= sr < N and 1 <= ss <= N // 2

# local verification before touching the service
w = pow(ss, -1, N)
assert add(mul(z * w % N), mul(sr * w % N, Q))[0] % N == sr, 'local verify failed'
print(f'forged signature r={sr:064x} s={ss:064x}  (verifies against their pubkey)')

# 4. submit, byte-exact per wire_json_rule
body = ('{"message_hex":"%s","r":"%064x","s":"%064x"}' % (msg, sr, ss)).encode()
req = urllib.request.Request(BASE + '/authorize', data=body,
                             headers={'Content-Type': 'application/json'})
with urllib.request.urlopen(req, timeout=20) as f:
    print(f.read().decode())
