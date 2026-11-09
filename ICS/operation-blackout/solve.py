#!/usr/bin/env python3
"""Operation Blackout (9156) — rebuild the marker from the five handouts.

The card fixes the serializer:

    sha256("0x<FW_HEADER_UPPER>:0x<STATION>:<LOG_ISO>:<REGISTER_DECIMAL>:<SEED_DECIMAL>")[:8]

Only the log timestamp is ambiguous: the pcap puts the FC16 write at 06:05:03Z,
the substation log records it at 06:15:03Z.  The card says "log entry", so the
log wins.  Run with: python3 solve.py
"""
from __future__ import annotations

import hashlib
import json
import re
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
FILES = HERE / "files"


def pcap_first_fc16(path: Path) -> tuple[int, bytes]:
    """Return (unix_time, payload) for the first Modbus FC16 packet."""
    data = path.read_bytes()
    off = 24
    while off + 16 <= len(data):
        ts, _usec, incl, _orig = struct.unpack("<IIII", data[off:off + 16])
        off += 16
        pkt = data[off:off + incl]
        off += incl
        if len(pkt) < 54:
            continue
        payload = pkt[54:]
        # MBAP: transaction(2) protocol(2)=0 length(2) unit(1) function(1)
        if len(payload) >= 8 and payload[2:4] == b"\x00\x00" and payload[7] == 0x10:
            return ts, payload
    raise SystemExit("no Modbus FC16 packet in the capture")


def main() -> None:
    firmware = (FILES / "plc_firmware.bin").read_bytes()
    header = "0x" + firmware[:4].hex().upper()

    hmi = (FILES / "hmi_config.xml").read_text(encoding="utf-8")
    station = re.search(r"<station_id>(0x[0-9A-Fa-f]+)</station_id>", hmi).group(1)
    seed = int(re.search(r"<ManifestSeed>(\d+)</ManifestSeed>", hmi).group(1))
    register = int(re.search(r'<HiddenModbusWrite[^>]*start_address="(\d+)"', hmi).group(1))

    log = json.loads((FILES / "substation_log.json").read_text(encoding="utf-8"))
    entry = next(r for r in log if "FC 0x10" in r["message"])
    timestamp = entry["timestamp"]

    pcap_ts, pcap_payload = pcap_first_fc16(FILES / "scada_network.pcap")
    import datetime
    pcap_iso = datetime.datetime.fromtimestamp(pcap_ts, datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    preimage = f"{header}:{station}:{timestamp}:{register}:{seed}"
    digest = hashlib.sha256(preimage.encode()).hexdigest()

    print(f"firmware header : {header}")
    print(f"station         : {station}")
    print(f"log timestamp   : {timestamp}")
    print(f"pcap FC16 time  : {pcap_iso}  (decoy: the card says log entry)")
    print(f"pcap FC16 PDU   : {pcap_payload[7:].hex()}")
    print(f"register        : {register}")
    print(f"seed            : {seed}")
    print(f"preimage        : {preimage}")
    print(f"sha256          : {digest}")
    print(f"FLAG            : CSCTF{{{digest[:8]}}}")


if __name__ == "__main__":
    main()
