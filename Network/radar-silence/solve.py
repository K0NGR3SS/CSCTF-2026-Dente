import base64
import struct
from pathlib import Path

from capture import ipv4_packets


capture = (Path(__file__).parent / "files" / "radar-silence.pcapng").read_bytes()
chunks = {}
for _, source, _, protocol, udp in ipv4_packets(capture):
    if protocol != 17 or source != "192.0.2.37" or struct.unpack_from("!H", udp, 2)[0] != 53:
        continue
    dns = udp[8:]
    labels = []
    offset = 12
    while dns[offset]:
        length = dns[offset]
        labels.append(dns[offset + 1:offset + 1 + length])
        offset += 1 + length
    if len(labels) != 5 or labels[2:] != [b"update", b"svc-telemetry", b"example"]:
        continue
    chunk, index = labels[:2]
    chunks[int(index)] = chunk.upper()
if sorted(chunks) != list(range(4)):
    raise ValueError("Incomplete fragment series")
encoded = b"".join(chunks[index] for index in range(4))
token = base64.b32decode(encoded + b"=" * (-len(encoded) % 8)).decode("ascii")
print(f"CSCTF{{rdr37_rotation_{token}}}")
