#!/usr/bin/env python3
"""Ghost Signal (9157) — rebuild the marker from the billing export.

The card fixes the serializer:

    sha256("<imsi>:<full_diameter_session_id>:<unix_timestamp>")[:8]

`imsi` and `session_id` are the values the Diameter capture and the billing
export agree on; `unix_timestamp` is the first anomalous billing event
(atk_0000, 1723740150).  The SS7 and Diameter pcaps are used here only as a
cross-check that the same identity and session are present in the signalling.

Run with: python3 solve.py
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
FILES = HERE / "files"
IMSI = "226012014000001"


def main() -> None:
    billing = json.loads((FILES / "billing_events.json").read_text(encoding="utf-8"))
    events = [e for e in billing["events"] if e.get("imsi") == IMSI]
    if not events:
        raise SystemExit("no billing events for the attacker IMSI")

    first = events[0]
    session_id = first["session_id"]
    timestamp = first["timestamp"]

    ss7 = (FILES / "ss7_capture.pcap").read_bytes()
    diameter = (FILES / "diameter_capture.pcap").read_bytes()
    imsi_tbcd = bytes.fromhex("22062110040000f1")  # 226012014000001, MAP TBCD
    print(f"attacker IMSI   : {IMSI}  ({len(events)} billing events)")
    print(f"session id      : {session_id}")
    print(f"first anomaly   : {first['event_id']} @ {timestamp}  ({first['event_type']}, {first['anomaly']})")
    print(f"IMSI in SS7     : {imsi_tbcd in ss7}  (TBCD 22062110040000f1)")
    print(f"IMSI in Diameter: {IMSI.encode() in diameter}  (ASCII Subscription-Id)")
    print(f"session in Diam.: {session_id.encode() in diameter}")

    preimage = f"{IMSI}:{session_id}:{timestamp}"
    digest = hashlib.sha256(preimage.encode()).hexdigest()
    print(f"preimage        : {preimage}")
    print(f"sha256          : {digest}")
    print(f"FLAG            : CSCTF{{{digest[:8]}}}")


if __name__ == "__main__":
    main()
