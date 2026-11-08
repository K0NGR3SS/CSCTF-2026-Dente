from collections import defaultdict
from ipaddress import IPv4Address
from struct import unpack_from


def ethernet_frames(capture):
    if capture[:4] == b"\xd4\xc3\xb2\xa1":
        offset = 24
        index = 0
        while offset < len(capture):
            length, = unpack_from("<I", capture, offset + 8)
            index += 1
            yield index, capture[offset + 16:offset + 16 + length]
            offset += 16 + length
        return
    if capture[:4] != b"\x0a\x0d\x0d\x0a" or capture[8:12] != b"\x4d\x3c\x2b\x1a":
        raise ValueError("Unsupported capture format")
    offset = index = 0
    while offset < len(capture):
        block, length = unpack_from("<II", capture, offset)
        if length < 12 or offset + length > len(capture):
            raise ValueError("Invalid pcapng block length")
        if block == 1 and unpack_from("<H", capture, offset + 8)[0] != 1:
            raise ValueError("Capture is not Ethernet")
        if block == 6:
            size, = unpack_from("<I", capture, offset + 20)
            index += 1
            yield index, capture[offset + 28:offset + 28 + size]
        offset += length


def ipv4_packets(capture):
    for index, frame in ethernet_frames(capture):
        if frame[12:14] != b"\x08\x00" or frame[14] >> 4 != 4:
            continue
        header = (frame[14] & 15) * 4
        length, = unpack_from("!H", frame, 16)
        source = str(IPv4Address(frame[26:30]))
        target = str(IPv4Address(frame[30:34]))
        yield index, source, target, frame[23], frame[14 + header:14 + length]


def tcp_packets(capture):
    for index, source, target, protocol, tcp in ipv4_packets(capture):
        if protocol != 6 or len(tcp) < 20:
            continue
        sport, dport, seq = unpack_from("!HHI", tcp)
        yield index, (source, sport), (target, dport), seq, tcp, tcp[(tcp[12] >> 4) * 4:]


def tcp_streams(capture, service_port):
    segments = defaultdict(list)
    for _, source, target, seq, _, payload in tcp_packets(capture):
        if payload and service_port in (source[1], target[1]):
            segments[source, target].append((seq, payload))
    streams = {}
    for key, direction in segments.items():
        output = bytearray()
        start = min(seq for seq, _ in direction)
        for seq, payload in sorted(direction):
            offset = seq - start
            if offset != len(output):
                raise ValueError(f"Gap or overlap in direction {key}")
            output.extend(payload)
        streams[key] = bytes(output)
    return streams
