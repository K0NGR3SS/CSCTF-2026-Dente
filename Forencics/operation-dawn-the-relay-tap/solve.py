import re
import struct
from hashlib import sha256
from ipaddress import IPv4Address
from pathlib import Path
from zipfile import ZipFile

from capture import tcp_packets


def checksum_ok(source, target, tcp):
    pseudo = IPv4Address(source).packed + IPv4Address(target).packed
    data = pseudo + struct.pack("!BBH", 0, 6, len(tcp)) + tcp
    if len(data) % 2:
        data += b"\0"
    checksum = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while checksum >> 16:
        checksum = (checksum & 0xffff) + (checksum >> 16)
    return checksum == 0xffff


def messages(payload):
    while payload:
        if not payload.startswith(b"ARLY"):
            raise ValueError("Invalid ARLY frame")
        kind, length = struct.unpack_from("!BH", payload, 4)
        yield kind, payload[7:7 + length]
        payload = payload[7 + length:]


with ZipFile(Path(__file__).parent / "files" / "relay-tap.zip") as archive:
    capture = archive.read("relay-tap.pcap")
packets = list(tcp_packets(capture))
nonces = {1: set(), 2: set()}
orders = []
for index, source, target, seq, tcp, payload in packets:
    if not payload.startswith(b"ARLY") or not checksum_ok(source[0], target[0], tcp):
        continue
    for kind, body in messages(payload):
        if kind in nonces:
            nonces[kind].add(body)
        elif kind == 3:
            orders.append((index, source, target, seq + len(payload), body))

client, = nonces[1]
server, = nonces[2]
key = sha256(client + server).digest()
flags = set()
for index, source, target, end, ciphertext in orders:
    if not any(i > index and s == target and t == source and h[13] & 0x10
               and struct.unpack_from("!I", h, 8)[0] == end
               for i, s, t, _, h, _ in packets):
        continue
    stream = b"".join(sha256(key + struct.pack("!I", block)).digest()
                      for block in range((len(ciphertext) + 31) // 32))
    plain = bytes(a ^ b for a, b in zip(ciphertext, stream))
    flags.update(re.findall(rb"CSCTF\{[^}]+\}", plain))
flag, = flags
print(flag.decode("ascii"))
