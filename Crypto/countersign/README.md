# Countersign

**Author:** Classified

**Crypto**

**Tools used**

`hlextend` for the length-extension arithmetic; everything else is the standard library.

**Approach**

1. `GET /api/spec` states the construction outright: `tag = SHA-256(key || message)`. That is a
   secret-prefix MAC, and the published tag *is* the hash state after `key || message`, so hashing
   can be resumed from it without ever learning the key.
2. The same spec documents the parser: split on `&`, split each token on the first `=`, keep keys
   matching `^[A-Za-z][A-Za-z0-9_]*$`, **last value wins**, command field is `cmd`. That last clause
   is the whole challenge — an appended `&cmd=DISPATCH` overrides the original `cmd=STATUS`.
3. Before sending anything, two things were settled on paper. First, the glue padding lands inside
   the preceding `nonce=` token's value, so it is swallowed harmlessly. Second — and this is the
   check worth doing — no padding byte can ever be `&` (0x26) or `=` (0x3d), because the length
   field is a multiple of 8 bits and neither byte is, so no accidental separator is produced
   anywhere in this length band.
4. The tool was validated locally against a secret of known length first; the forged tag reproduced
   exactly.
5. The key length is the only unknown and the spec narrows it to 8–32 bytes. Walking the band in
   order, 0.25 s apart, took 21 requests; `klen = 28` returned the code.

**Why it works**

Merkle–Damgård hashing is stateful and the tag is the state. Appending is therefore free, and the
parser's "last value wins" rule promotes the appended command over the authentic one. The key is
never learned and never needs to be.

**Validation**

The local self-test against a known-length secret came first; the service saw only the 21 requests
needed to pin the key length, well inside its own 60/min budget. Flag printed by `solve.py <url>`.

**Flag:** `CSCTF{cRV6FOGYp830BNUII6imVZxy}`

Run the solver (`solve.py`); web/pwn solvers take your assigned instance address as an argument.

*AI: Opus 5 cyber verification assisted with reversing, scripting, and cross-checking; every flag was produced by a reproducible solver and submitted by hand.*
