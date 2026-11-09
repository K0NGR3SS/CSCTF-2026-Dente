# Silent Breaker

**Author:** mar

**Forensics** · 270 pts
Handout: [files/](files/) — `iec104_capture.pcap`, `hmi_monitoring.log`, `roster.json`, case README

**TL;DR.** A substation breaker opened on a single IEC 60870-5-104 `C_SC_NA_1` command. The report
has five fields: the command's IOA, its SCO qualifier, the **wire** time of the command, the frozen
current from the matching `QUALITY=SUSPECT` historian run, and the OT-VPN session id. The trap is
the timestamp: the card wants the packet time (03:06), not the VPN session start (02:32).

## Solve

**The console.** `GET /files/` lists the case bundle and the report contract; `GET /events` is the
flagged-signalling feed. A signalling peer (GT) outside `GT-0000`..`GT-0999` is not a legitimate peer
on this network. `GET /query/subscriber?msisdn=...` resolves the number, and
`POST /confirm-target {"employee_id":"..."}` (2 attempts) unlocks `GET /query/vpn-window`.

The roster has exactly one employee with `ot_vpn_access: true`: **Teodora Lazar**, `VLK-9924-LAZ`,
`+882-16-7547546` (OT Field Engineering). Confirming that target returned the VPN session
`VPN-604349`.

**The pcap.** This capture uses IEC-104 with a 6-byte APDU header, then an ASDU whose header is
another 6 bytes (type, VSQ, 2-byte cause of transmission, 2-byte common address) — the body starts
at `apdu[6:]`, not `apdu[7:]`. The only control-direction command is packet 50 at
`03:06:38.000Z`:

```
68 0e 00 00 2c 00  2d 01 06 00 01 00  be 28 00  01
                  |  |  |     |     |  |        |
                  |  |  |     |     |  IOA 0x28be (LE, 3 bytes)
                  |  |  |     |     cause 6 = activation, CA 1
                  |  |  type 45 = C_SC_NA_1
                  |  VSQ
                  APDU (I-frame)
```

SCO `0x01` is `select=0`, qualifier `1` = **ON**. The reply from the RTU at `03:06:38.015Z` is the
same type 45 with cause 7 (activation confirmation), same IOA and SCO.

**The historian log.** `hmi_monitoring.log` stores breaker current for IOA `0x28be` every 10 s.
Live readings vary by about ±1.5 A and sit around 396 A. From `03:05:40` the stored value jumps to
`211.5 A`; the first two entries are still `QUALITY=GOOD`, and from the third identical reading
(`03:06:00`) the historian marks the run `QUALITY=SUSPECT` until `03:08:30` — 16 stored readings of
`211.5 A` while the RTU stream in the pcap stays at 395.6–398.4 A. That is a held/replayed cache
record, and `211.5` is the displayed frozen current the report asks for.

**The report.** `POST /submit` with:

```json
{"ioa_address":"0x28be","command_qualifier":"ON","command_time_utc":"03:06",
 "telemetry_status":"211.5","vpn_session_id":"VPN-604349"}
```

A correct report returns the case recovery authorization, which is the flag.

**Flag:** `CSCTF{HzlRbhNCsDuJmd0PKnFdlVJf}`

**Evidence.** The flag literal is in `ctf-telecom/wave2/attempts_log.json` (`cid 9118`,
`status: correct`; CTFd solve 2026-11-07T13:13:37Z). The four offline fields were re-derived from
the preserved handout with [parse_iec104.py](parse_iec104.py) for this writeup; the VPN session id
comes from the wave-2 lane note recorded during the live solve (the service and its
`/query/vpn-window` response are no longer available), and the target employee is the roster's only
`ot_vpn_access` entry. The report field names follow the case README preserved in
`files/README.md`.
