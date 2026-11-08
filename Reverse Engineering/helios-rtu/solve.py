#!/usr/bin/env python3
"""HELIOS-RTU (CSCTF 2026, rev, 900 pts) - CBC-MAC forgery against the RTU service.

Bench work that got us here:
  * ATmega328P (signature 0x1e950f). hfuse 0xd8 -> SPIEN on, DWEN off, BOOTRST on, so only the
    ISP and the resident serial bootloader answer; JTAG and debugWIRE are dead ends.
  * lock 0xfc = LB mode 3: ISP may read signature/fuses but refuses flash. The bootloader reads
    application flash with LPM, so `avrdude -c arduino` over the USB cable dumps it anyway.
  * The AES-128 key is copied from flash 0x7f00 (boot section, reads as 0xff from outside), so it
    really is unreadable - but we never need it.

Firmware protocol (service function @0x536), frame checks in order:
  cmd 1 "sign", 16-byte record -> refuses record[0] == 0xcc, else returns raw AES-128(record)
  cmd 2 "exec", 32-byte frame + 16-byte tag:
      tag must equal AES(B2 xor AES(B1))          <- textbook CBC-MAC, IV = 0, no subkeys
      then B2[0] == 0xcc, B2[1] == 0x0a, B2[2:10] == the live nonce

So `sign` is an encryption oracle for exactly the primitive the MAC is built from. Two queries
forge a tag on a frame that was never signed:
      T1  = sign(B1)            = AES(B1)
      tag = sign(B2 xor T1)     = AES(B2 xor AES(B1))
The 0xcc guard on `sign` only blocks the literal directive block, which we never submit directly.

usage: solve.py [HOST:PORT]
"""
import json, re, sys
from websockets.sync.client import connect as ws_connect

DEFAULT = "w06.ctf.chronos-security.ro:33130"
MAGIC, OPCODE = 0xCC, 0x0A
HEADER = b"HELIOS-RTU-CTRL"[:16].ljust(16, b"\x00")  # block 1: free, only its MAC matters


class Console:
    def __init__(self, hostport, timeout=20):
        self.ws = ws_connect(f"ws://{hostport}/ws", open_timeout=timeout, close_timeout=5)
        self.timeout = timeout
        self._recv()  # banner

    def _recv(self):
        return json.loads(self.ws.recv(timeout=self.timeout)).get("data") or ""

    def run(self, line):
        self.ws.send(line)
        return self._recv()

    def close(self):
        try: self.ws.close()
        except Exception: pass


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def main():
    hostport = sys.argv[1] if len(sys.argv) > 1 else DEFAULT
    c = Console(hostport)
    c.run("apt install svc")

    nonce = bytes.fromhex(re.search(r"nonce = ([0-9a-f]+)", c.run("svc nonce")).group(1))
    print(f"[+] live nonce: {nonce.hex()}")

    b1 = HEADER
    directive = bytes([MAGIC, OPCODE]) + nonce + b"\x00" * 6
    assert len(b1) == len(directive) == 16

    def sign(block):
        assert block[0] != MAGIC, "oracle refuses a record starting with the magic byte"
        r = c.run("svc sign " + block.hex())
        m = re.search(r"tag = ([0-9a-f]{32})", r)
        assert m, r
        return bytes.fromhex(m.group(1))

    t1 = sign(b1)
    print(f"[+] AES(B1)      = {t1.hex()}")
    second = xor(directive, t1)
    if second[0] == MAGIC:                     # vanishingly rare; just reshape block 1
        b1 = bytes([b1[0] ^ 1]) + b1[1:]
        t1 = sign(b1)
        second = xor(directive, t1)
    tag = sign(second)
    print(f"[+] forged tag   = {tag.hex()}")

    frame = b1 + directive
    out = c.run(f"svc exec {frame.hex()} {tag.hex()}")
    print(f"[+] exec -> {out.strip()}")
    c.close()

    m = re.search(r"CSCTF\{[^}]*\}", out)
    print("\nFLAG:", m.group(0) if m else "not in this reply - see output above")


if __name__ == "__main__":
    main()
