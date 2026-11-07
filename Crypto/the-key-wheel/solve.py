#!/usr/bin/env python3
"""Usage: python3 solve.py files/key-unit-journal.cbor"""
import hashlib
import sys
from pathlib import Path

data = Path(sys.argv[1] if len(sys.argv) > 1 else 'files/key-unit-journal.cbor').read_bytes()

def decode(pos):
    head = data[pos]; pos += 1
    major, size = head >> 5, head & 31
    if size < 24:
        length = size
    elif size == 24:
        length = data[pos]; pos += 1
    elif size == 25:
        length = int.from_bytes(data[pos:pos + 2], 'big'); pos += 2
    elif size == 26:
        length = int.from_bytes(data[pos:pos + 4], 'big'); pos += 4
    else:
        raise ValueError('unsupported CBOR length')
    if major in (0, 1):
        return (length if major == 0 else -1 - length), pos
    if major in (2, 3):
        value = data[pos:pos + length]
        return (value if major == 2 else value.decode()), pos + length
    if major == 4:
        result = []
        for _ in range(length):
            value, pos = decode(pos); result.append(value)
        return result, pos
    if major == 5:
        result = {}
        for _ in range(length):
            key, pos = decode(pos)
            value, pos = decode(pos)
            result[key] = value
        return result, pos
    raise ValueError('unsupported CBOR type')

bundle, end = decode(0)
assert end == len(data)

def temper(y):
    y ^= y >> 11
    y ^= (y << 7) & 0x9d2c5680
    y ^= (y << 15) & 0xefc60000
    return (y ^ (y >> 18)) & 0xffffffff

def untemper(y):
    for shift, mask, left in [(18, 0xffffffff, False), (15, 0xefc60000, True),
                              (7, 0x9d2c5680, True), (11, 0xffffffff, False)]:
        out = y
        for _ in range(6):
            out = y ^ (((out << shift) & mask) if left else (out >> shift))
        y = out & 0xffffffff
    return y

def twist(old):
    state = old.copy()
    for i in range(624):
        y = (state[i] & 0x80000000) | (state[(i + 1) % 624] & 0x7fffffff)
        state[i] = (state[(i + 397) % 624] ^ (y >> 1) ^ ((y & 1) * 0x9908b0df)) & 0xffffffff
    return state

def untwist(new):
    old = [0] * 624
    for i in range(623, -1, -1):
        other = new[i - 227] if i >= 227 else old[i + 397]
        mixed = new[i] ^ other
        lowbit = mixed >> 31
        y = (((mixed ^ (lowbit * 0x9908b0df)) << 1) | lowbit) & 0xffffffff
        old[i] = (old[i] & 0x7fffffff) | (y & 0x80000000)
        if i < 623:
            old[i + 1] = (old[i + 1] & 0x80000000) | (y & 0x7fffffff)
    return old

outputs = bundle['register']
assert len(outputs) == 1248 and bundle['window_opens_tx'] == 156
first = list(map(untemper, outputs[:624]))
second = list(map(untemper, outputs[624:]))
assert twist(first) == second
previous = untwist(first)
assert twist(previous) == first
key = b''.join(temper(word).to_bytes(4, 'big') for word in previous[-8:])
sealed = next(item['sealed'] for item in bundle['traffic'] if item['tx'] == 155)
stream = b''.join(hashlib.sha256(key + i.to_bytes(4, 'big')).digest()
                  for i in range((len(sealed) + 31) // 32))
plain = bytes(a ^ b for a, b in zip(sealed, stream))
print(plain.decode())
