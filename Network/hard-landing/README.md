# Hard Landing

**Author:** mar

**Network** · 120 pts
Handout: [files/](files/) — `console.pcapng`, `console_access.log`, `ops_notes.txt`

**TL;DR.** A plaintext HTTP pcap holds an administrator login whose response is gzip-compressed.
Decompressing it gives the session id and the 32-byte HMAC key. The console's `/api/status`
publishes the canonical request string and a 300-second freshness window; signing
`RETURN_TO_PAD` for pad `A1` with a fresh server timestamp returns the recovery receipt.

## Solve

**Capture review.** `console.pcapng` has seven plaintext HTTP request/response pairs on port 8080:
two `POST /api/login` (operator `192.0.2.10`, administrator `192.0.2.11`) and five
`POST /api/command` — one each from `.10` and `.11`, and three from `192.0.2.14`. The `.14` commands
reuse the administrator's `X-Session` without a login of their own: the session was lifted off the
wire.

Both login responses are `Content-Encoding: gzip`; tshark hands back the raw deflate payload, so it
must be decompressed before parsing. The recovered material:

| role | session | key (hex, 32 bytes) |
| --- | --- | --- |
| operator | `ops-131bc07f5023dcfd329e80cd` | `131bc07f5023dcfd329e80cd7272f805989fb7f060c4ad2c2dbc14dc526ea63d` |
| administrator | `adm-2aca3785b702d3ef824b9cb8` | `2aca3785b702d3ef824b9cb870481e04e1179b09172a1f9da3710e6bb2a759f1` |

`console_access.log` agrees with the capture: admin login at 11:22:00Z, destructive commands from
`.14` at 11:23:00/06/12Z, `AIRCRAFT_LINK_LOST` at 11:23:17Z.

**Scheme recovery.** `GET /api/status` documents the canonical string and freshness:

```
POST\n/api/command\n<X-Timestamp>\n<BODY>
HMAC-SHA256, key = the login JSON's 64 lowercase hex chars decoded to 32 bytes
freshness 300 s; body = {"cmd":"RETURN_TO_PAD","pad":"A1"}
```

The recovered operator key reproduces the captured operator signature exactly, and the rogue admin
request at `1789644180` also recomputes to its captured value — the key is the stolen one, not a
format quirk:

```
canonical: POST\n/api/command\n1789644030\n{"cmd":"STATUS","aircraft":"N17"}
signature: abd403d9…13bfd  (matches pcap)
```

**Live command.** Read `server_time` from the console, use it as `X-Timestamp`, send the exact
documented body with `Content-Type: application/json`, the admin `X-Session` and the recomputed
`X-Signature`:

```
HTTP 200 {"status":"aircraft returned to pad A1","recovery_receipt":"CSCTF{l3wT4lptfoIEoX0iy0Y4DgPR}"}
```

Controls behaved as documented: an all-zero signature is `403`; a timestamp 1000 s old is `403`; a
correctly signed `pad=A2` is `403 authenticated command is not permitted`; replaying the captured
rogue signature is `403` outside the freshness window.

**Flag:** `CSCTF{l3wT4lptfoIEoX0iy0Y4DgPR}`

**Evidence.** The flag is the live console's `recovery_receipt` captured in the solve session (and
repeated verbatim in `ctf-helio/REPORT-FULL.md`); CTFd recorded the solve at
2026-11-06T16:24:18Z. The handout files are preserved and copied under `files/`; both HMACs quoted
above were re-computed from that capture while writing this up, and
[solve_hard_landing.py](solve_hard_landing.py) is the runner used against the live instance. The
console is gone, so the receipt cannot be re-fetched — the pcap, the access log and the script are
the reproducible part.
