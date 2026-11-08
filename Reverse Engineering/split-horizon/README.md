# Split Horizon

**Author:** Classified

**Reverse engineering**

**Tools used**

`ilspycmd` for the .NET assembly; `scapy` for the capture.

**Approach**

1. The artifacts are generated per team and served by the instance: a capture, a .NET control
   library, the command server's Go source, a signed audit log and a manifest.
2. **The vulnerability is a parser differential.** The same uplink JSON is read by two parsers with
   different rules:

   | | parser | key matching | duplicate keys |
   |---|---|---|---|
   | drone | .NET `System.Text.Json`, default options | **case-sensitive exact** | unmatched spelling **ignored** |
   | server | Go `encoding/json` | **case-insensitive** | **last duplicate wins** |

3. One command carries the waypoint **twice** — once in lower case, once in upper case with different
   values. The drone matches only the exact lower-case names and flies the first pair; the server
   matches both case-insensitively, keeps the last, and validates a position inside tolerance. Drift
   ≈ 341 m, matching the briefing's "~380 m off its approved waypoint".
4. Three other commands also carry upper-case duplicates, but with **identical values** — pure
   camouflage, so that duplicate keys look like routine protocol noise. Only one diverges.
5. Recovering the commands required unmasking the uplink: frames are XOR-masked with a session key the
   assembly derives as `HMAC-SHA256(MaskA ⊕ MaskB, clientNonce || serverNonce)[:16]`, both masks being
   static arrays in the library. **The commands must be kept as raw bytes** — any ordinary JSON parser
   would collapse the duplicate keys and destroy the evidence.

**Why it works**

Neither parser is buggy; each behaves exactly as documented. The defect is that two components with
different documented behaviour are both treated as authoritative for the same bytes.

**Validation — the part worth copying**

The audit trail deliberately does not disclose coordinates: it stores `SHA-256(salt || "lat|lon")`
with a random, never-written salt, so the commitment cannot be inverted over the coordinate space. But
**equal coordinates must give equal commitments** — so the *partition* of the log by commitment is a
free oracle for what the server parsed. The Go model predicts the equivalence classes
`[[1],[2,10],[3,4],[5,6],[7,8,9,11,12]]`, and the log's commitments produce exactly that partition. A
twelve-element partition matching by chance is negligible, so the server's parse is confirmed without
ever learning the salt. Also verified: the hash chain links genesis to root and matches the manifest's
recorded root, and the Ed25519 signature over that root is valid — the audit trail is honestly signed
and faithfully records the wrong parse, which is precisely the answer to "why the server never saw
it". The submission's `mechanism` field was the one ambiguous choice (server-first vs drone-first);
server-first was chosen because the server's quirk is the one the challenge's own source documents
explicitly, and it was correct on the first try.

**Flag:** _solved on the other workstation; add flag and solve.py from there._

*AI: Opus 5 cyber verification assisted with reversing, scripting, and cross-checking; every flag was produced by a reproducible solver and submitted by hand.*
