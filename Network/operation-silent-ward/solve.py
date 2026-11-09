#!/usr/bin/env python3
"""Operation Silent Ward (9159) - derive the flag from the four handouts.

    python3 solve.py [path/to/files]

The published serializer is

    sha256("<serial>:<iso_ts>:<leak_count>:<store_count>:<manifest_seed>")[:8]

Every field except the timestamp is a straight count/read.  The timestamp is
the first line of snmp_trap.log: the second the ward goes silent, when all
four monitored devices drop link at once.  The eight "[ANOMALY: Unusual
polling frequency]" lines are one per day and cannot be "the anomalous event"
(the spec is singular), which is the trap the challenge is built around.
"""
import csv
import hashlib
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FILES = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "files")

# DIMSE command field values (PS3.7 E.1) carried in the (0000,0100) element.
C_STORE_RQ = 0x0001
C_ECHO_RQ = 0x0030


def device():
    xml = open(os.path.join(FILES, "dicom_device.xml"), encoding="utf-8").read()
    serial = re.search(r"<serial_number>\s*([^<\s]+)\s*</serial_number>", xml).group(1)
    seed = re.search(r"<DeviceManifestSeed>\s*(\d+)\s*</DeviceManifestSeed>", xml).group(1)
    return serial, int(seed)


def leaked_records():
    with open(os.path.join(FILES, "patient_records.csv"), newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    leaked = [r for r in rows if (r.get("status") or "").strip().lower() == "leaked"]
    return len(leaked), len(rows)


def silent_second():
    """The anomalous event: the first log line, four simultaneous linkDowns."""
    with open(os.path.join(FILES, "snmp_trap.log"), encoding="utf-8") as fh:
        first = fh.readline()
    ts = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)", first)
    if not ts:
        raise SystemExit("unexpected first log line: %r" % first)
    return ts.group(1)


def dimse_counts():
    """Walk P-DATA-TF PDUs and count C-STORE-RQ / C-ECHO-RQ command messages."""
    from scapy.all import IP, Raw, TCP, rdpcap  # imported here so --help works without scapy

    counts = {C_STORE_RQ: 0, C_ECHO_RQ: 0}
    for pkt in rdpcap(os.path.join(FILES, "hospital_network.pcap")):
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            continue
        payload = bytes(pkt[Raw].load)
        if not payload or payload[0] != 0x04:  # P-DATA-TF
            continue
        pdu_len = struct.unpack_from(">I", payload, 2)[0]
        body = payload[6:6 + pdu_len]
        off = 0
        while off + 6 <= len(body):
            pdv_len = struct.unpack_from(">I", body, off)[0]
            header = body[off + 5]
            data = body[off + 6:off + 6 + pdv_len]
            off += 6 + pdv_len
            if not (header & 0x01):  # command PDV, not dataset
                continue
            # (0000,0100) UL CommandField, implicit VR little endian
            at = data.find(b"\x00\x00\x00\x01\x02\x00\x00\x00")
            if at >= 0 and at + 12 <= len(data):
                cmd = struct.unpack_from("<H", data, at + 8)[0]
                if cmd in counts:
                    counts[cmd] += 1
    return counts[C_STORE_RQ], counts[C_ECHO_RQ]


def main():
    serial, seed = device()
    leak, rows = leaked_records()
    ts = silent_second()
    stores, echoes = dimse_counts()
    msg = "%s:%s:%d:%d:%d" % (serial, ts, leak, stores, seed)
    digest = hashlib.sha256(msg.encode()).hexdigest()[:8]
    print("serial      %s" % serial)
    print("timestamp   %s" % ts)
    print("leak_count  %d  (%d csv rows)" % (leak, rows))
    print("store_count %d  (C-ECHO-RQ seen: %d)" % (stores, echoes))
    print("seed        %d" % seed)
    print("preimage    %s" % msg)
    print("FLAG        CSCTF{%s}" % digest)


if __name__ == "__main__":
    main()
