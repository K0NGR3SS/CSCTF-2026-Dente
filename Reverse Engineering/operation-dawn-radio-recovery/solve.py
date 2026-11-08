#!/usr/bin/env python3
"""Operation Dawn: Radio Recovery (CSCTF 2026, rev, 120 pts).

Chain, all of it offline from dist/firmware.bin:

  1. The image is a hand-rolled container: magic "DWFW", u16 version, u16 count, then 20-byte
     records of {name[8], offset u32, size u32, crc32 u32}. Four parts, every crc32 valid:
     loader (banner text), ubootenv (16 KiB), msgcat (message catalogue), rootfs (633 bytes).
  2. rootfs is zlib with FDICT set, so it needs a preset dictionary; the DICTID in its header is
     the adler32 of that dictionary, and it matches msgcat exactly. Inflating with msgcat as the
     dictionary yields a cpio (newc) archive.
  3. The archive holds /etc/config/radio with admin_token=<60 hex chars> and /etc/init.d/S40admin,
     which XORs the token against the MAC from the U-Boot environment:
         plain[i] = token[i] ^ mac[i % 6],  mac = ethaddr with the colons stripped
  4. ubootenv is a *redundant* U-Boot environment: two 8 KiB copies, each {crc32, flags, data}.
     Both CRCs are valid, so the flags byte decides - U-Boot runs the copy with the higher flags.
     copy 0 (flags 6) is "recovery=legacy" with a placeholder 00:11:22:33:44:55 and decodes to
     garbage; copy 1 (flags 7) is "recovery=ready" with the real MAC and decodes to the token.

usage: solve.py [path to firmware.bin]
"""
import os, re, struct, sys, zlib

MAGIC = b"DWFW"


def parse_container(data):
    magic, version, count = struct.unpack_from("<4sHH", data, 0)
    if magic != MAGIC:
        sys.exit(f"not a DWFW image (magic {magic!r})")
    parts, off = {}, 8
    for _ in range(count):
        name, start, size, crc = struct.unpack_from("<8sIII", data, off)
        off += 20
        name = name.rstrip(b"\x00").decode()
        blob = data[start:start + size]
        got = zlib.crc32(blob) & 0xFFFFFFFF
        if got != crc:
            sys.exit(f"part {name}: crc32 {got:#010x} != {crc:#010x}")
        parts[name] = blob
        print(f"[+] {name:9} off {start:#08x} size {size:6}  crc32 {crc:#010x} ok")
    print(f"[+] container version {version}, {count} parts, all CRCs valid")
    return parts


def active_env(blob):
    """U-Boot redundant environment: two copies, highest flags byte wins."""
    half = len(blob) // 2
    best = None
    for i in range(2):
        copy = blob[i * half:(i + 1) * half]
        stored, flags = struct.unpack_from("<I", copy, 0)[0], copy[4]
        if zlib.crc32(copy[5:]) & 0xFFFFFFFF != stored:
            print(f"[ ] env copy {i}: bad crc32, ignored")
            continue
        env = dict(v.split(b"=", 1) for v in copy[5:].split(b"\x00") if b"=" in v)
        tag = env.get(b"recovery", b"?").decode()
        print(f"[+] env copy {i}: crc ok, flags {flags}, recovery={tag}, "
              f"ethaddr={env.get(b'ethaddr', b'?').decode()}")
        if best is None or flags > best[0]:
            best = (flags, env)
    if best is None:
        sys.exit("no valid environment copy")
    print(f"[+] active copy: flags {best[0]}")
    return best[1]


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "dist", "firmware.bin")
    parts = parse_container(open(path, "rb").read())

    rootfs, msgcat = parts["rootfs"], parts["msgcat"]
    dictid = struct.unpack_from(">I", rootfs, 2)[0]
    if not (rootfs[1] >> 5) & 1:
        sys.exit("rootfs zlib stream has no preset dictionary")
    if zlib.adler32(msgcat) & 0xFFFFFFFF != dictid:
        sys.exit("msgcat is not the preset dictionary")
    print(f"[+] rootfs zlib DICTID {dictid:#010x} == adler32(msgcat)")
    obj = zlib.decompressobj(zdict=msgcat)
    cpio = obj.decompress(rootfs) + obj.flush()
    print(f"[+] inflated cpio archive: {len(cpio)} bytes")

    token_hex = re.search(rb"admin_token=([0-9a-fA-F]+)", cpio).group(1).decode()
    token = bytes.fromhex(token_hex)
    print(f"[+] admin_token: {token_hex} ({len(token)} bytes)")

    env = active_env(parts["ubootenv"])
    mac = bytes.fromhex(env[b"ethaddr"].decode().replace(":", ""))
    print(f"[+] MAC key: {mac.hex()}")

    flag = bytes(token[i] ^ mac[i % len(mac)] for i in range(len(token)))
    text = flag.decode("ascii")
    print("\nFLAG:", text)


if __name__ == "__main__":
    main()
