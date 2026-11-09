#!/usr/bin/env python3
"""Silent Breaker (9118) — IEC 60870-5-104 + historian-log reconstruction.

Reads the case bundle (iec104_capture.pcap, hmi_monitoring.log) and prints the
four fields that are derivable offline:

  ioa_address        from the C_SC_NA_1 (type 45) command APDU
  command_qualifier  from the SCO byte (0x01 = ON)
  command_time_utc   packet timestamp of the command (HH:MM, UTC)
  telemetry_status   the frozen value of the QUALITY=SUSPECT historian run

The fifth field, vpn_session_id, comes from the live console's
GET /query/vpn-window (after POST /confirm-target); it is not in the pcap.

Usage: python3 parse_iec104.py [case_dir]
"""

import os
import struct
import sys
from datetime import datetime, timezone

TYPES = {13: "M_ME_NC_1", 45: "C_SC_NA_1", 100: "C_IC_NA_1"}


def packets(path):
    data = open(path, "rb").read()
    magic, _, _, _, _, _, link = struct.unpack("<IHHiIII", data[:24])
    if magic != 0xA1B2C3D4 or link != 1:
        raise SystemExit("not a little-endian Ethernet pcap")
    off = 24
    while off + 16 <= len(data):
        ts, usec, incl, _ = struct.unpack("<IIII", data[off:off + 16])
        off += 16
        frame = data[off:off + incl]
        off += incl
        if len(frame) < 14 or frame[12:14] != b"\x08\x00":
            continue
        ihl = (frame[14] & 0x0F) * 4
        ip = frame[14:]
        if ip[9] != 6:                      # TCP only
            continue
        tcp = ip[ihl:]
        doff = (tcp[12] >> 4) * 4
        payload = tcp[doff:]
        if len(payload) < 6 or payload[0] != 0x68:
            continue
        yield ts + usec / 1e6, payload


def asdu(payload):
    """APDU header is 6 bytes; the ASDU header is another 6 bytes (type, VSQ,
    2-byte cause of transmission, 2-byte common address), so the body starts
    at apdu[6:]. Starting at apdu[7] shifts every field by one byte and the
    IOA/value decode as garbage."""
    apdu = payload[6:]
    if len(apdu) < 6:
        return None
    return {
        "type": apdu[0],
        "cause": apdu[2] | (apdu[3] << 8) & 0x3F,
        "ca": apdu[4] | (apdu[5] << 8),
        "body": apdu[6:],
    }


def parse_command(payload):
    a = asdu(payload)
    if not a or a["type"] != 45 or len(a["body"]) < 4:
        return None
    ioa = a["body"][0] | (a["body"][1] << 8) | (a["body"][2] << 16)
    sco = a["body"][3]
    return {"ioa": ioa, "sco": sco, "on": bool(sco & 0x01), "cause": a["cause"]}


def parse_float(payload):
    a = asdu(payload)
    if not a or a["type"] != 13 or len(a["body"]) < 8:
        return None
    ioa = a["body"][0] | (a["body"][1] << 8) | (a["body"][2] << 16)
    value = struct.unpack("<f", a["body"][3:7])[0]
    return ioa, value


def suspect_run(path):
    runs, cur = [], []
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        ts, ioa, value, quality = line.split()
        value = float(value.split("=", 1)[1].rstrip("A"))
        quality = quality.split("=", 1)[1]
        if cur and (value, quality) == (cur[-1][1], cur[-1][2]):
            cur.append((ts, value, quality))
        else:
            if len(cur) >= 3 and cur[0][2] == "SUSPECT":
                runs.append(cur)
            cur = [(ts, value, quality)]
    if len(cur) >= 3 and cur[0][2] == "SUSPECT":
        runs.append(cur)
    return runs


def main():
    case = sys.argv[1] if len(sys.argv) > 1 else "."
    pcap = os.path.join(case, "iec104_capture.pcap")
    log = os.path.join(case, "hmi_monitoring.log")

    command = None
    floats = []
    for ts, payload in packets(pcap):
        cmd = parse_command(payload)
        if cmd and cmd["cause"] == 6:
            t = datetime.fromtimestamp(ts, timezone.utc).strftime("%H:%M")
            command = dict(cmd, time=t, iso=datetime.fromtimestamp(ts, timezone.utc).isoformat())
        f = parse_float(payload)
        if f:
            floats.append((ts, *f))

    runs = suspect_run(log)
    print("command      :", command)
    if floats:
        print("live telemetry around command: %.1f .. %.1f A" % (
            min(v for _, _, v in floats), max(v for _, _, v in floats)))
    for run in runs:
        print("suspect run  : %s .. %s  value=%.1fA  n=%d" % (
            run[0][0], run[-1][0], run[0][1], len(run)))

    print()
    print("report fields (vpn_session_id from GET /query/vpn-window):")
    print('  "ioa_address": "0x%04x"' % command["ioa"])
    print('  "command_qualifier": "%s"' % ("ON" if command["on"] else "OFF"))
    print('  "command_time_utc": "%s"' % command["time"])
    print('  "telemetry_status": "%.1f"' % runs[0][0][1])


if __name__ == "__main__":
    main()
