#!/usr/bin/env python3
"""Phantom Drift (9158) — recover the marker from the handouts.

The card fixes the serializer:

    sha256(f"{approved_lat:.4f}{approved_lon:.4f}"
           f"{delta_lat:.6f}{delta_lon:.6f}{displacement_m:.1f}")[:16]

The two ambiguities are the sign of the deltas and the earth radius.  Both are
settled offline by the flight-log tag: the last 12 bytes of flight_log.bin XOR
"Valkyrie-9" are the ASCII string TAG:dc6836a2, and the digest's last 8 hex
characters must equal dc6836a2.  WGS-84 equatorial radius (6378137 m) and
positive deltas are the only combination that matches.

Run with: python3 solve.py
"""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path

HERE = Path(__file__).resolve().parent
FILES = HERE / "files"
RADIUS_M = 6378137.0  # WGS-84 equatorial radius; the tag rejects 6371000


def haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * RADIUS_M * math.asin(math.sqrt(a))


def main() -> None:
    manifest = json.loads((FILES / "mission_manifest.json").read_text(encoding="utf-8"))
    approved_lat = manifest["approved_waypoint_lat"]
    approved_lon = manifest["approved_waypoint_lon"]

    telemetry = json.loads((FILES / "telemetry_logs.json").read_text(encoding="utf-8"))
    update = next(r for r in telemetry["readings"] if r.get("phase") == "waypoint_update")
    diverted_lat = update["WaypointLat"]   # PascalCase: the Go backend reads this
    diverted_lon = update["WaypointLon"]

    flight = (FILES / "flight_log.bin").read_bytes()
    tag_line = bytes(b ^ b"Valkyrie-9"[i % 10] for i, b in enumerate(flight[-12:])).decode()
    expected_tag = tag_line.split(":", 1)[1]

    delta_lat = diverted_lat - approved_lat
    delta_lon = diverted_lon - approved_lon
    displacement = haversine(approved_lat, approved_lon, diverted_lat, diverted_lon)

    preimage = (f"{approved_lat:.4f}{approved_lon:.4f}"
                f"{delta_lat:.6f}{delta_lon:.6f}{displacement:.1f}")
    digest = hashlib.sha256(preimage.encode()).hexdigest()

    print(f"approved        : {approved_lat:.4f}, {approved_lon:.4f}")
    print(f"diverted        : {diverted_lat:.4f}, {diverted_lon:.4f}")
    print(f"delta           : {delta_lat:+.6f}, {delta_lon:+.6f} deg")
    print(f"displacement    : {displacement:.1f} m (R={RADIUS_M:.0f})")
    print(f"flight-log tag  : {tag_line}")
    print(f"preimage        : {preimage}")
    print(f"sha256          : {digest}")
    print(f"tag check       : {digest[-8:]} == {expected_tag} -> {digest[-8:] == expected_tag}")
    print(f"FLAG            : CSCTF{{{digest[:16]}}}")


if __name__ == "__main__":
    main()
