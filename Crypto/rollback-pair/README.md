# Rollback Pair

**Author:** Classified

**Crypto**

**Approach**

1. Eight ECDSA dispatch records (secp256k1, SHA-256, raw `r||s`, not low-s normalised) plus the
   signing public key. The scenario line is the entire hint: "resumed from a faulty application
   nonce-state snapshot" — the per-signature nonce was replayed after the restore.
2. **Verify before attacking.** Confirm the published point is actually on the curve, then verify
   all eight signatures against it. All eight verify, so the export is internally consistent and no
   record is a planted decoy. This step is cheap and it is what rules out mistaking a bad record for
   the exposure.
3. Scan for a repeated `r`: records R-6103 and R-6107 share one. Equal `r` means equal nonce, since
   `r = (k·G)_x`.
4. `k = (z₁−z₂)/(s₁−s₂) mod n`, then `d = (s₁k − z₁)/r mod n`. The sign of `k` is not observable, so
   both `(s₁−s₂)` and `(s₁+s₂)` were tried and each candidate tested against the public key rather
   than assumed.
5. The answer wanted exactly 64 lowercase hex characters; `solve.py` formats with `%064x` so a
   leading zero can never truncate it.

**Why it works**

ECDSA's nonce must be unique per signature. Two signatures under the same nonce give two linear
equations in two unknowns, so the nonce — and then the long-term scalar — fall out directly.

**Validation**

Two independent checks on `d`: `d·G` equals the published public key, and `(k, d)` together
reproduce the `s` values of both records in the reused pair exactly.

**Flag:** `CSCTF{3b5789e468dadf358d375bb08dcd19b977c5715364a709326b43a35b0d5eaab1}`

Run the solver (`solve.py`); web/pwn solvers take your assigned instance address as an argument.

*AI: Opus 5 cyber verification assisted with reversing, scripting, and cross-checking; every flag was produced by a reproducible solver and submitted by hand.*
