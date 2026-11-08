# Cyberboy

**Author:** Classified

**Web**

**Approach**

No handout — the API documents itself. Three smells are visible in the prose alone, before any request:
the session "caches the effective unit scope from the account's home unit" while a profile endpoint
exposes a duty-assignment field that "feeds the session scope at the next refresh"; rotations are
"addressed by an opaque ref that encodes the owning unit and sequence"; and the export endpoint takes
its tier **from the request body**.

1. **Reference forgery — a dead end, usefully.** The reference decodes as
   `rr_<base64url(UNIT:SEQ)>.<16 hex MAC>`, and the read endpoint does not verify the MAC at all: a
   reference with sixteen zeros, or none, reads fine — including other units' rotations. But the
   **write** endpoints do verify it, so a forged reference cannot be exported. A legitimately signed
   reference is needed, and establishing that early is what made the next step obviously necessary
   rather than merely available.
2. **Scope escalation.** The profile endpoint accepts a duty assignment naming another unit on an
   ordinary analyst account, and the refresh endpoint then re-issues the session with that scope. The
   rotations listing now returns the other unit's rotations **with their valid signed references** —
   exactly what step 1 showed was missing.
3. **Tier confusion.** Exporting an already-approved rotation with the tier taken from the body
   produces a sealed bundle at that tier. The tier is never checked against the rotation's own
   authorized tier, so raising it to master seals a theatre-master bundle, and its authorization code
   is the flag.

**Why it works**

Three independent authorization decisions each trust a different attacker-influenced input: the read
path trusts an unverified reference, the session scope trusts a user-writable profile field, and the
export tier trusts the request body. The chain exists because each individual lapse is small.

**Validation**

Each step was confirmed by its own observable effect — a cross-unit read, a re-issued session scope,
and a sealed bundle whose custody field changed from unit to theatre — rather than by assuming the next
step followed from the last. `solve.py` re-runs the whole chain from a fresh draft rotation and prints
the flag, so it is produced by the exploit, not read from a planted string.

**Flag:** `CSCTF{a3RJmPSpEoDM4YcMAYyzzuMt}`

Run the solver (`solve.py`); web/pwn solvers take your assigned instance address as an argument.

*AI: Opus 5 cyber verification assisted with reversing, scripting, and cross-checking; every flag was produced by a reproducible solver and submitted by hand.*
