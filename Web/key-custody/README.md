# Key Custody

**Author:** mar

**Web** · 120 pts

**TL;DR.** The console signs sessions with HS256 and loads each token's key by the `kid` header.
`kid` is used as a filename with no sanitisation, so `kid="../public/brand.txt"` makes the verifier
use a public 201-byte brand asset as the HMAC key. Sign an `role=admin` token with those exact
bytes, keep the issued analyst subject, and the admin custody route returns the flag.

## Solve

**Issue a session.** `GET /token` returns
`{"sub":"analyst-recon-17","role":"analyst","token":"..."}`. The JWT header is
`{"alg":"HS256","typ":"JWT","kid":"session"}`; the payload is `{"sub":"analyst-recon-17","role":"analyst"}`.

**Read the contract.** `GET /schema` states that the console loads each token's signing key by its
`kid` header, and that the admin route requires the issued analyst subject with `role=admin`. So the
subject must stay `analyst-recon-17`; only `role` and the key selection move.

**Find the key material.** `GET /public/{name}` serves brand assets. A sweep of brand-style names
lands `/public/brand.txt` (201 bytes, trailing newline included): the Vardanne Command banner
notice. The key directory sits one level above `public/`.

**Traverse with `kid`.** Set `kid="../public/brand.txt"` and sign
`base64url(header).base64url(payload)` with the asset's raw bytes as the HMAC-SHA256 key. The
verifier also accepts `sha256(brand.txt)` as the key, but the raw file bytes are byte-exact:

| test | result |
| --- | --- |
| issued analyst token on `/admin/recovery-key` | `403 issued analyst subject with role=admin required` |
| `kid="session"`, role=admin, key=brand.txt | `401` (wrong key for that kid) |
| `kid="../public/brand.txt"`, key without trailing newline | `401` (byte-exact key) |
| `kid="../public/brand.txt"`, role=admin, different `sub` | `403` (issued-subject binding holds) |
| `kid="../public/brand.txt"`, role=admin, issued `sub` | `200 {"recovery_key":"CSCTF{...}"}` |

The payload to sign is `{"sub":"analyst-recon-17","role":"admin"}`.

`/admin/flag` — the route named on the card — returns `404` on this build even with a valid admin
token. The flag-bearing admin route is `/admin/recovery-key`, exactly as `/schema` advertises.

**Flag:** `CSCTF{NHzVIEV7adsjVbShD4Gqk38d}`

**Evidence.** The chain, control matrix and flag come from the live-solve workspace
`ctf-vardanne/WRITEUP.md` (written during the solve) and its runner
[solve_vardanne.py](solve_vardanne.py); the flag is also listed in `ctf-helio/REPORT-FULL.md`
(§13). CTFd recorded the solve at 2026-11-06T16:32:30Z. The instance is gone, so the `200` response
cannot be re-fetched; the token and brand asset captures from that run are in
`ctf-vardanne/` (not copied here because they contain session material).
