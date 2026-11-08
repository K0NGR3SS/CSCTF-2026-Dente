# Signing Authority

**Author:** Classified

**Crypto**

**Approach**

1. The service is self-describing: `GET /schema` gives secp256k1 ECDSA, `z = sha256(message) mod n`,
   and routes `/pubkey`, `/receipts`, `/authorize`. It even names the intended attack in a field
   called `same_nonce_recovery`.
2. `GET /receipts` returns two receipts with an identical `r`, so the same nonce was used twice.
3. Recover `k`, then `d`, resolving the unobservable sign of `k` by testing each candidate against
   the published public key: `d·G == Q` held for the first.
4. Sign the one message the service refuses to sign — a promotion to master-arming — with `d` and a
   fresh nonce, forcing low-s as the schema's `authorize_s_rule` requires.
5. **Verify the forged signature locally against the service's own public key before sending it.**
   `POST /authorize` with the exact wire format the schema specifies — minified JSON, field order
   `message_hex, r, s`, all values strings, 64-char lowercase hex — returned the code on the first
   request.

**Why it works**

Same as Rollback Pair, against a live signing oracle instead of a file. The interesting part is
operational rather than mathematical: the service saw exactly four requests in total, and exactly
one authorization attempt, because the signature was validated offline first.

**Validation**

Local verification against the published public key before submission; accepted first try.

**Flag:** `CSCTF{zQXYulDVJ4hQevQqvCwoHy5Y}`

Run the solver (`solve.py`); web/pwn solvers take your assigned instance address as an argument.

*AI: Opus 5 cyber verification assisted with reversing, scripting, and cross-checking; every flag was produced by a reproducible solver and submitted by hand.*
