#!/usr/bin/env python3
"""Water Hammer Reconciliation — CSCTF 2026 (Network).

Parses the Modbus/TCP capture (no tshark), reassembles the streams, keeps the
64 confirmed FC16 writes with matching FC03 read-backs, and turns them into the
flag per station-profile.txt.

Usage: python3 solve.py files/water-hammer-reconciliation.zip
"""
import base64
import hashlib
import os
import struct
import sys
import tempfile
import zipfile
from collections import defaultdict


# ---- pcapng + TCP/IP parsing ------------------------------------------------
def read_pcapng(path):
    d = open(path, "rb").read()
    off, pkts, le = 0, [], "<"
    while off < len(d):
        bt = struct.unpack_from("<I", d, off)[0]
        if bt == 0x0A0D0D0A:
            bom = struct.unpack_from("<I", d, off + 8)[0]
            le = "<" if bom == 0x1A2B3C4D else ">"
            bl = struct.unpack_from(le + "I", d, off + 4)[0]
        else:
            bt, bl = struct.unpack_from(le + "II", d, off)
        if bt == 6:  # Enhanced Packet Block
            _iid, th, tl, cl, _ol = struct.unpack_from(le + "IIIII", d, off + 8)
            pkts.append(((th << 32) | tl, d[off + 28 : off + 28 + cl]))
        off += bl
    return pkts


def parse(fr):
    eth = struct.unpack_from(">H", fr, 12)[0]
    o = 14
    if eth == 0x8100:
        eth = struct.unpack_from(">H", fr, 16)[0]
        o = 18
    if eth != 0x0800:
        return None
    ihl = (fr[o] & 15) * 4
    tot = struct.unpack_from(">H", fr, o + 2)[0]
    proto = fr[o + 9]
    src = ".".join(map(str, fr[o + 12 : o + 16]))
    dst = ".".join(map(str, fr[o + 16 : o + 20]))
    if proto != 6:
        return ("ip",)
    t = o + ihl
    sp, dp, seq, _ack = struct.unpack_from(">HHII", fr, t)
    doff = (fr[t + 12] >> 4) * 4
    fl = fr[t + 13]
    return (src, sp, dst, dp, seq, fl, fr[t + doff : o + tot])


def reasm(segs):
    isn, data = None, {}
    for seq, fl, pl in segs:
        if fl & 2:  # SYN
            isn = seq + 1
            continue
        off = (seq - isn) & 0xFFFFFFFF
        for j, b in enumerate(pl):
            data.setdefault(off + j, b)
    n = 0
    while n in data:
        n += 1
    return bytes(data[k] for k in range(n))


# ---- Modbus ADUs ------------------------------------------------------------
def adus(stream):
    o, out = 0, []
    while o + 6 <= len(stream):
        tid, pid, ln = struct.unpack_from(">HHH", stream, o)
        if o + 6 + ln > len(stream):
            break
        raw = stream[o : o + 6 + ln]
        out.append(dict(tid=tid, pid=pid, ln=ln, unit=raw[6] if ln else None, pdu=raw[7:], seq=o))
        o += 6 + ln
    return out


def main():
    zpath = sys.argv[1] if len(sys.argv) > 1 else "files/water-hammer-reconciliation.zip"
    with tempfile.TemporaryDirectory() as tmp:
        zipfile.ZipFile(zpath).extractall(tmp)
        pcap = os.path.join(tmp, "reserve-header.pcapng")
        pkts = read_pcapng(pcap)

    flows = defaultdict(list)
    order = {}
    for ts, fr in pkts:
        r = parse(fr)
        if not r or r[0] == "ip":
            continue
        s, sp, d, dp, seq, fl, pl = r
        flows[(s, sp, d, dp)].append((seq, fl, pl))
    C = ("192.0.2.10", 36853, "192.0.2.20", 502)
    S = ("192.0.2.20", 502, "192.0.2.10", 36853)
    ca, sa = adus(reasm(flows[C])), adus(reasm(flows[S]))

    def valid_fc16(a):
        p = a["pdu"]
        if a["pid"] != 0 or a["unit"] != 17 or len(p) < 6 or p[0] != 0x10:
            return None
        A, N, bc = struct.unpack_from(">HHB", p, 1)
        if not (1 <= N <= 4 and 0x1000 <= A and A + N - 1 <= 0x1003 and a["ln"] == 7 + 2 * N and bc == 2 * N):
            return None
        return A, N, p[6:]

    def fc16_resp(a, A, N):
        return a["pid"] == 0 and a["unit"] == 17 and a["ln"] == 6 and a["pdu"] == bytes([0x10]) + struct.pack(">HH", A, N)

    def fc3_req(a):
        return a["pid"] == 0 and a["unit"] == 17 and a["ln"] == 6 and a["pdu"] == bytes.fromhex("0310000004")

    def fc3_resp(a):
        return a["pid"] == 0 and a["unit"] == 17 and a["ln"] == 11 and a["pdu"][:2] == b"\x03\x08"

    rows, used = [], set()
    for ci, a in enumerate(ca):
        r = valid_fc16(a)
        if not r:
            continue
        A, N, data = r
        resp = [s for s in sa if s["tid"] == a["tid"] and fc16_resp(s, A, N)]
        if len(resp) != 1:
            continue
        nxt = ca[ci + 1] if ci + 1 < len(ca) else None
        if not nxt or not fc3_req(nxt):
            continue
        r3 = [s for s in sa if s["tid"] == nxt["tid"] and fc3_resp(s) and id(s) not in used]
        if not r3:
            continue
        used.add(id(r3[0]))
        regs = struct.unpack(">4H", r3[0]["pdu"][2:])
        w = struct.unpack(">%dH" % N, data)
        if tuple(regs[A - 0x1000 : A - 0x1000 + N]) != w:
            continue
        rows.append((a["tid"], regs))
    print("confirmed writes:", len(rows))

    # ---- profile formulas (from station-profile.txt) ----
    def V(P, G):
        return (P * G // 1000) * 1000000 // 70686

    T = 2 * 20000 * 1000000 // 1065000
    init = (80, 500, 0, 60000)
    lines = ["water-hammer-reconciliation-v2", "initial;p=%d;g=%d;a=%d;r=%d" % init, "n=%d" % len(rows)]
    prev, M = V(init[0], init[1]), 0
    for i, (tid, (P, G, Aa, R)) in enumerate(rows):
        v = V(P, G)
        Q = 998 * 1065 * abs(v - prev)
        u = int(Aa == 1 and R < T and Q > 9000 * 100000)
        M |= u << (63 - i)
        prev = v
        lines.append("i=%d;tid=%04X;p=%d;g=%d;a=%d;r=%d" % (i, tid, P, G, Aa, R))
    lines.append("unsafe-mask=%016X" % M)
    h = hashlib.sha256("\n".join(lines).encode()).digest()
    print("CSCTF{" + base64.b32encode(h[:24]).decode().rstrip("=") + "}")


if __name__ == "__main__":
    main()
