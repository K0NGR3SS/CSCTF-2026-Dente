# Silent Breaker — incident case brief

## Endpoint

Your team receives one HTTP service at the address shown by the event platform. All routes below
are on that host. Each launch of the instance is its own case: a relaunch starts a different case
with new evidence, new answers, fresh attempt counters and a fresh recovery authorization.

## Files provided

- `roster.json` — fictional Velkarion Mobile / Ondrista Grid staff roster.
- `iec104_capture.pcap` — a forensic capture from the substation's IEC 60870-5-104 network.
  Open it with tshark or Wireshark.
- `hmi_monitoring.log` — the substation historian's operator-facing breaker-current log. Normal
  **RTU** reports arrive every 10 seconds and naturally vary by about ±1.5 A. A run of three or
  more identical stored readings for one IOA is marked `QUALITY=SUSPECT` by the historian. A
  marked run can be a held/replayed cache record rather than a live RTU observation; the breaker's
  historian engineering range is 150.0–550.0 A and a held record differs from live input by more
  than 5.0 A before it is marked for operator review.

## Live console (`signal-desk`)

- `GET /events` — the free signalling-events feed. A signalling peer (GT) outside
  `GT-0000`..`GT-0999` is not a known legitimate peer on this network.
- `GET /query/subscriber?msisdn=<msisdn>` — budgeted lookup for one MSISDN.
- `POST /confirm-target {"employee_id": "..."}` — **2 attempts** for this case. A correct target
  unlocks `/query/vpn-window` for the rest of this case.
- `GET /query/vpn-window` — budgeted and available after a correct `/confirm-target` result.
- `POST /submit {...}` — **5 complete reports for this case**. A relaunch does not add reports
  to a case; it replaces the case.
  Malformed JSON, a non-object body, missing/extra members and wrong member types return a 4xx
  without spending a report. Every complete report returns only pass/fail plus the remaining
  count; there is no field-by-field feedback. A sixth complete report returns
  `submit_attempts_exhausted`.

The subscriber and VPN routes share a generous short query window. Repeated off-list subscriber
probing or a second wrong `/confirm-target` triggers a short audit cooldown.

## `/submit` fields

```json
{
  "ioa_address": "<hex, e.g. 2517 or 0x2517>",
  "command_qualifier": "ON",
  "command_time_utc": "HH:MM (UTC, 24h) — wire time of the command, not VPN session start",
  "telemetry_status": "<one-decimal current from the matching QUALITY=SUSPECT historian run, e.g. 412.3>",
  "vpn_session_id": "<from /query/vpn-window>"
}
```

`telemetry_status` is always the displayed numeric frozen-current value. The words `clean` and
`spoofed` are not accepted. A trailing `A` unit and harmless decimal formatting are accepted.

A correct report returns the case recovery authorization for this incident.
