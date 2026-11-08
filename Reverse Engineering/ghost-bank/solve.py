#!/usr/bin/env python3
"""ghost-bank (CSCTF 2026, rev, 900 pts) - full solver.

The bench holds an AArch64 controller halted, so the firmware never runs: we drive its
MMIO unlock sequence ourselves over GDB RSP, then do the ChaCha20 the firmware would have done.

  1. CONTROL = 0x41                      -> bench latches a fresh 64-bit challenge
  2. read CHALLENGE_LO/HI, key = mix(ch) -- mix() reversed from firmware @0x400120
  3. PAGE = 7, KEY = key lo then hi, CONTROL = 0x93  -> STATUS 3 = bank unsealed
  4. CONTROL = 0x9c                      -> STATUS 4, page 7 now exposes the 32-byte ChaCha key
  5. page 3 holds CIPHER_LEN bytes of ciphertext (page 7 is a decoy)
  6. ChaCha20(key, nonce "SEAL-V01\0\0\0\x01", counter=1) over it = the tasking text

usage: solve.py HOST PORT
"""
import os, socket, struct, sys

CONTROL, PAGE, OFFSET, DATA, CLEN = 0x40000000, 0x40000008, 0x40000010, 0x40000018, 0x4000001C
CH_LO, CH_HI, KEY, STATUS = 0x40000020, 0x40000024, 0x40000028, 0x40000030
NONCE, BANK_PAGE, KEY_PAGE = b"SEAL-V01\x00\x00\x00\x01", 3, 7
M64 = (1 << 64) - 1


def ror(x, r):
    return ((x >> r) | (x << (64 - r))) & M64


def mix(x):
    """Firmware @0x400120: challenge -> unlock key (splitmix-style)."""
    x ^= 0xA3B195354A39B70D
    x = ((x >> 16) & 0x7FFFFFFF) ^ ror(x, 47)
    x = (x * 0x64170D358AA115A1) & M64
    x ^= x >> 29
    x = ror(x, 13)
    x = (x * 0x65931D9DFC2010DB) & M64
    return x ^ (x >> 31)


class RSP:
    """Minimal GDB Remote Serial Protocol client."""

    def __init__(self, host, port):
        self.s = socket.create_connection((host, int(port)), timeout=15)
        self.buf, self.ack = b"", True

    def _byte(self):
        while not self.buf:
            d = self.s.recv(4096)
            if not d:
                raise EOFError("bench closed the connection")
            self.buf += d
        b, self.buf = self.buf[:1], self.buf[1:]
        return b

    def cmd(self, p):
        pkt = b"$" + p.encode() + b"#%02x" % (sum(p.encode()) & 0xFF)
        self.s.sendall(pkt)
        while True:
            c = self._byte()
            if c == b"$":
                break
            if c == b"-":
                self.s.sendall(pkt)
        body = b""
        while (c := self._byte()) != b"#":
            body += c
        self._byte(), self._byte()
        if self.ack:
            self.s.sendall(b"+")
        return body.decode()

    def handshake(self):
        self.cmd("qSupported:multiprocess+")
        if self.cmd("QStartNoAckMode") == "OK":
            self.ack = False

    def r32(self, a):
        r = self.cmd(f"m{a:x},4")
        assert not r.startswith("E"), (hex(a), r)
        return struct.unpack("<I", bytes.fromhex(r))[0]

    def w32(self, a, v):
        r = self.cmd(f"M{a:x},4:{struct.pack('<I', v).hex()}")
        assert r == "OK", (hex(a), r)

    def page_bytes(self, page, n):
        self.w32(PAGE, page)
        out = bytearray()
        for i in range(n):
            self.w32(OFFSET, i)
            r = self.cmd(f"m{DATA:x},1")
            assert not r.startswith("E"), (i, r)
            out.append(int(r, 16))
        return bytes(out)


def chacha20(key, data, counter=1):
    from Crypto.Cipher import ChaCha20
    c = ChaCha20.new(key=key, nonce=NONCE)
    c.seek(64 * counter)
    return c.decrypt(data)


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    g = RSP(sys.argv[1], sys.argv[2])
    g.handshake()

    g.w32(PAGE, BANK_PAGE)
    n = g.r32(CLEN)
    ciphertext = g.page_bytes(BANK_PAGE, n)
    print(f"[+] sealed bank: page {BANK_PAGE}, {n} bytes")

    g.w32(CONTROL, 0x41)
    challenge = g.r32(CH_LO) | (g.r32(CH_HI) << 32)
    unlock = mix(challenge)
    print(f"[+] challenge {challenge:#018x} -> unlock key {unlock:#018x}")

    g.w32(PAGE, KEY_PAGE)
    g.w32(KEY, unlock & 0xFFFFFFFF)
    g.w32(KEY, unlock >> 32)
    g.w32(CONTROL, 0x93)
    status = g.r32(STATUS)
    assert status == 3, f"unlock refused, STATUS={status}"

    g.w32(CONTROL, 0x9C)
    assert g.r32(STATUS) == 4, "bank did not release its key"
    chacha_key = g.page_bytes(KEY_PAGE, 32)
    print(f"[+] bank key: {chacha_key.hex()}")

    tasking = chacha20(chacha_key, ciphertext)
    print(f"[+] tasking: {tasking.decode(errors='replace').strip()}")
    flag = tasking.decode(errors="replace")
    i = flag.index("CSCTF{")
    print("\nFLAG:", flag[i:flag.index("}", i) + 1])


if __name__ == "__main__":
    main()
