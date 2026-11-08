#!/usr/bin/env python3
"""fleet-provisioning: RSA keys from MT19937 seeded with (boot_epoch<<16)|serial.
Boot epoch is a few seconds before the unit's REG packet -> brute force it locally."""
import random, re, sys, gmpy2
from scapy.all import rdpcap, Raw

pcap = sys.argv[1] if len(sys.argv) > 1 else 'dist/fleet-provisioning.pcap'
regs, order = {}, None
for pkt in rdpcap(pcap):
    if Raw not in pkt: continue
    d = bytes(pkt[Raw].load).decode('latin1')
    if m := re.match(r'REG serial=(\d+) e=(\d+) N=([0-9a-f]+)', d):
        regs[int(m[1])] = (int(m[2]), int(m[3], 16), int(pkt.time))
    elif m := re.match(r'ORDER serial=(\d+) C=([0-9a-f]+)', d):
        order = (int(m[1]), int(m[2], 16))

serial, C = order
e, N, t_reg = regs[serial]

def prime(r):
    while True:
        c = r.getrandbits(512) | (1 << 511) | 1
        if gmpy2.is_prime(c): return c

for t in range(t_reg, t_reg - 86400, -1):       # walk back from the REG time
    r = random.Random((t << 16) | serial)
    p = prime(r)
    if N % p == 0:
        q = prime(r)
        assert p * q == N
        break
else:
    sys.exit('epoch not found')

d = pow(e, -1, (p - 1) * (q - 1))
m = pow(C, d, N)
pt = m.to_bytes((m.bit_length() + 7) // 8, 'big')
print(f'serial={serial} boot_epoch={t} (REG at {t_reg})')
print(pt)
if (f := re.search(rb'CSCTF\{[^}]*\}', pt)): print(f[0].decode())
