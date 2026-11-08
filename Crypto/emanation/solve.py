#!/usr/bin/env python3
"""emanation: second-order CPA against a masked AES-128 first round.

Countermeasures in the corpus and how each is removed:
  random delay -> every row carries one huge trigger sample at index 0..16; align on it.
  byte mask    -> one fresh mask byte per row, leaked at its own point. First-order CPA
                  sees nothing, so correlate the centred product of two leakage points
                  against E_m[(HW(m)-4)(HW(Sbox(p^k)^m)-4)].
Then AES-128-CTR with an all-zero initial counter block decrypts the sealed order.
"""
from itertools import combinations
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util import Counter

SBOX = bytes.fromhex(
    '637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0'
    'b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275'
    '09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf'
    'd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2'
    'cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb'
    'e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08'
    'ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e'
    'e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16')

T = np.load('dist/traces.npy').astype(np.float64)
P = np.load('dist/plaintexts.npy')
ct = bytes.fromhex(open('dist/sealed_order.hex').read().strip())

# 1. align on the trigger spike -> the delay is simply its index
delay = T.argmax(1)
width = T.shape[1] - delay.max()
A = np.stack([T[i, delay[i]:delay[i] + width] for i in range(len(T))])

# 2. leakage points stand out: mean ~4 and variance of HW + noise, the rest is pure noise
sig = np.flatnonzero(A.std(0) > 1.3 * np.median(A.std(0)))
sig = sig[sig != 0]                                   # drop the trigger itself

# 3. second-order model and centred products of every point pair
hw = np.array([bin(x).count('1') for x in range(256)], float)
m = np.arange(256)
model = np.array([((hw[m] - 4) * (hw[z ^ m] - 4)).mean() for z in range(256)])
pairs = list(combinations(sig, 2))
C = np.stack([(A[:, a] - A[:, a].mean()) * (A[:, b] - A[:, b].mean()) for a, b in pairs], 1)
C -= C.mean(0); C /= np.linalg.norm(C, axis=0)

sb = np.frombuffer(SBOX, dtype=np.uint8)
key = bytearray(16)
for b in range(16):
    M = model[sb[P[:, b][:, None] ^ np.arange(256)[None, :]]]
    M -= M.mean(0); M /= np.linalg.norm(M, axis=0)
    R = np.abs(C.T @ M)
    i, k = np.unravel_index(R.argmax(), R.shape)
    key[b] = k
    ranked = np.sort(R.max(0))
    print(f'byte {b:2d}: 0x{k:02x}  points {pairs[i]}  r={ranked[-1]:.3f} '
          f'(runner-up {ranked[-2]:.3f}, {ranked[-1]/ranked[-2]:.1f}x)')
key = bytes(key)
print('key =', key.hex())

def ctr():
    return AES.new(key, AES.MODE_CTR, counter=Counter.new(128, initial_value=0))

pt = ctr().decrypt(ct)
assert ctr().encrypt(pt) == ct, 're-encryption mismatch'
print('order:', pt.decode())
