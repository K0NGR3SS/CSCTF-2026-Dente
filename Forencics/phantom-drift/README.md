# Phantom Drift

**Author:** mar

**Forensics** · 560 pts (hard)
Handouts: [drone_control.decompiled](files/drone_control.decompiled),
[command_backend.decompiled](files/command_backend.decompiled),
[flight_log.bin](files/flight_log.bin), [mission_manifest.json](files/mission_manifest.json),
[radio_intercept.log](files/radio_intercept.log), [telemetry_logs.json](files/telemetry_logs.json)

**TL;DR.** The same `waypoint_update` record contains two spellings of the same six fields: the
snake_case values are the approved waypoint, the PascalCase values are the diverted one. The drone's
C# client is configured `PropertyNameCaseInsensitive = false` with
`MissingMemberHandling = Error`, so the PascalCase duplicates are logged as unknown properties and
ignored. The command backend's Go `encoding/json` is case-insensitive and accepts them, and its
`ValidateCommand` is defined but never called from `main`, so the server records the mission as
nominal. The flag is the SHA-256 of the approved coordinates, the per-axis deltas and the WGS-84
great-circle displacement; the flight-log tag `dc6836a2` is the offline check that settles both the
delta sign and the earth radius.

## Solve

**The artifact set.** Six files describe one sortie of `Valkyrie-9`:

| file | what it contains |
| --- | --- |
| `mission_manifest.json` | approved waypoint `47.2591, 19.0402`, altitude 5000, speed 180, payload 2.5, aircraft `ED-KR7-0047` |
| `telemetry_logs.json` | 57 readings; the `waypoint_update` row carries both spellings of the new waypoint |
| `radio_intercept.log` | ground station sees the drone at `~47.2600, 19.0450`, "380m EAST of planned waypoint"; the command server says nominal |
| `drone_control.decompiled` | base64-wrapped C# `FlightParams.FromJson` and `ValidateCommand` |
| `command_backend.decompiled` | base64-wrapped Go `ParseCommand` and `ValidateCommand` |
| `flight_log.bin` | 36-byte binary; the last 12 bytes XOR `"Valkyrie-9"` are `TAG:dc6836a2` |

Both `.decompiled` files are a comment header plus `DECODED_CONTENT = "<base64>"`; base64-decoding
the string yields the C# and Go sources quoted below.

**1. The parser differential.** The decisive record is the `waypoint_update` reading:

```json
{"mission_id": "Valkyrie-9", "timestamp": 1723741800, "phase": "waypoint_update",
 "altitude": 5000.0, "speed": 180.0,
 "waypoint_lat": 47.2591, "waypoint_lon": 19.0402,
 "payload_weight": 2.5, "wind_compensation": 0.3,
 "Altitude": 5000.0, "Speed": 180.0,
 "WaypointLat": 47.26, "WaypointLon": 19.045,
 "PayloadWeight": 2.5, "WindCompensation": 0.3}
```

The C# client:

```csharp
var settings = new JsonSerializerSettings
{
    PropertyNameCaseInsensitive = false,
    MissingMemberHandling = MissingMemberHandling.Error,
    Error = (sender, args) => {
        Debug.LogWarning($"Unknown property: {args.ErrorContext.Member}");
        args.ErrorContext.Handled = true;
    }
};
return JsonConvert.DeserializeObject<FlightParams>(json, settings);
```

The PascalCase keys do not equal the `[JsonProperty("waypoint_lat")]` names, so they hit the error
handler, are logged and ignored. The Go backend:

```go
type FlightParams struct {
    WaypointLat float64 `json:"waypoint_lat"`
    WaypointLon float64 `json:"waypoint_lon"`
    // ...
}
json.Unmarshal([]byte(jsonPayload), &params)
```

`encoding/json` matches keys case-insensitively, so `WaypointLat` and `WaypointLon` land in the same
fields as `waypoint_lat` / `waypoint_lon`; the later PascalCase values win. The same bytes are an
approved waypoint to the client and a diverted waypoint to the server.

**2. Why the server called it nominal.** `ValidateCommand` exists in the Go file but `main()` never
calls it — it loads the manifest, reads telemetry and prints "Processing mission command…". The
artifact records the result directly:

```json
{"mission_id": "Valkyrie-9", "timestamp": 1723742160, "phase": "server_validation",
 "validation_result": "PASS",
 "note": "Server-side validation passed — Go parsed WaypointLat=47.2600 which is within tolerance of manifest",
 "discrepancy_detected": false}
```

The note even repeats the diverted latitude while calling it within tolerance. That is the whole
incident: the command path updated the server's waypoint to `47.2600, 19.0450`, the validator never
ran, and the audit trail says nominal. The radio intercept shows the ground station seeing the same
diverted point and being overruled by the command server.

**3. The coordinates.** The manifest-approved point is `47.2591, 19.0402`; the diverted point in the
telemetry and the radio log is `47.2600, 19.0450`. The per-axis deltas are:

```
delta_lat = 47.2600 - 47.2591 = +0.000900
delta_lon = 19.0450 - 19.0402 = +0.004800
```

The great-circle distance with the WGS-84 equatorial radius `R = 6378137 m` is **376.2 m**. The radio
log's "approximately 380m" is narrative rounding, not the serializer value.

**4. The flight-log tag.** `flight_log.bin` is 36 bytes:

```
464c4754 0001 0003 0000000c 00000000 00000001 00000002
02202b511d115f5d1e0f3753
```

The last 12 bytes XOR the 10-byte string `Valkyrie-9` (repeating) give exactly:

```
TAG:dc6836a2
```

The card says the tag verifies the **last** 8 hex of the same digest and is not an input. It is a
free offline oracle: no submission is needed to test a candidate.

**5. Derive the flag.** The serializer is:

```python
preimage = f"{approved_lat:.4f}{approved_lon:.4f}" \
           f"{delta_lat:.6f}{delta_lon:.6f}{displacement_m:.1f}"
flag = hashlib.sha256(preimage.encode()).hexdigest()[:16]
```

```
approved_lat   47.2591
approved_lon   19.0402
delta_lat      +0.000900
delta_lon      +0.004800
displacement   376.2
preimage       47.259119.04020.0009000.004800376.2
sha256         5dc7cdf826f74515c03f45611f58fabd2edc04382d6cf9f8696f9d83dc6836a2
last 8         dc6836a2   <- matches the flight-log TAG
FLAG           CSCTF{5dc7cdf826f74515}
```

**Dead ends (the tag decides them offline).**

| candidate | displacement / digest | why it is wrong |
| --- | --- | --- |
| mean earth radius `R = 6371000` | `375.8` → `49b2638d…2126c52e` | tag would be `2126c52e`, not `dc6836a2` |
| `R = 6371008.8` (IUGG mean) | `375.8` → same `49b2638d…` | same mismatch |
| negative deltas `-0.000900`, `-0.004800` | different digest | the tag only matches the positive deltas |
| radio log's `380` | `…004800380.0` | the log says "approximately 380m"; the serializer wants the computed 376.2 |
| `47.26` / `19.045` at fewer decimals | `47.260019.0450…` | the spec fixes `:.4f` for the approved point and `:.6f` for the deltas |
| hash of the raw `waypoint_update` JSON | different digest | the card specifies concatenated text, no separators, not JSON |
| include `TAG:dc6836a2` in the preimage | different digest | the tag is a check, not an input |

The temptation is to keep hashing plausible coordinates because SHA-256 is cheap. The tag removes
that: two candidate radii and both delta signs were tested offline, and only one combination
produced `dc6836a2`. Zero submissions were spent on this card.

**Flag:** `CSCTF{5dc7cdf826f74515}`

Run [solve.py](solve.py) with `python3 solve.py`; it reads the manifest, telemetry and flight log,
prints the preimage, verifies the tag and derives the flag.

*AI: Hermes (DeepSeek 4.1 Flash) assembled this writeup from the team's Phantom Drift lane
(`phantom_final.json`, the handout analysis and the tag-crack scripts); the preimage and tag were
recomputed from the handouts, the candidate matches the digest, and the platform recorded the solve
at 2026-11-07 10:59:25Z.*
