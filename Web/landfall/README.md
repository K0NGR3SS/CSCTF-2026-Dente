# Landfall

**Author:** kiriesh

**Web**

## Solve

ANWA NAOG is an emergency-alert console (CAP/XML). A fabricated "IMMEDIATE EVACUATION" alert is on air and must be cancelled, but the console account is only an `observer` and the `dispatcher` role has been withdrawn from everyone. Four stacked bugs are all required together.

**1. Ed25519 non-canonical malleability → single-use bypass.** Dispatch needs a signed capability *grant* whose claims cover the authority, geocodes and severity of the on-air area. The only covering grant was already spent: the ledger enforces single-use on `sig_sha256`, **not** on `jti`, and the ledger's `verifier_disagreement` note says the downstream verifier accepts a scalar `S` that is not reduced mod the group order. Since `[L]·B = identity`, `(R, S)` and `(R, S + kL)` both satisfy `[S+kL]·B = R + [k]·A`, so they verify identically but hash to different 64-byte signatures. The published grant (`S`) and the attacker's reuse (`S+L`) were both already consumed, so I mint `S+2L` — a fresh `sig_sha256` that still verifies.

**2. JSON key-case parser differential → role bypass.** Of the three submission paths, `/api/v1/orders/staged` is the v1 passthrough (the other two reject duplicate members). The **role gate** resolves the operation case-insensitively, while the **broadcast handler** reads the exact-case `"operation"` key. Sending both keys:

```json
{"operation":"dispatch","OPERATION":"preview", ...}
```

the policy check sees `preview` (allowed for an observer) and the handler executes `dispatch`. That is how an observer dispatches without the dispatcher role.

**3. Grant scope.** Reuse the capability grant whose claims cover the on-air authority, area and severity (a `Cancel` can carry a lower severity, so any covering grant works).

**4. Unlock digest.** `sha256("landfall|<cap_id>|<jti>|<area>")`, carried with a CAP `Cancel` whose `references` names the fabricated alert's `sender,identifier,sent`.

With the malleated grant, the key-case body, the covering grant and the unlock digest, `/api/v1/orders/staged` returns `status: BROADCAST`, `channel: CBS-4370`, "cancellation on air" — and the flag.

**Flag:** `CSCTF{q946nyhXEjBJR968TNFkhrpE}`

Run [the solver](solve.py) with `python3 solve.py http://<assigned-host>:<port>`. The session, grants and on-air message rotate per instance, so the solver re-derives them each run; the web address must be your assigned instance.
