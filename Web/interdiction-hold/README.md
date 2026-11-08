# Interdiction Hold

**Author:** Varenik14  
**Category:** Web  
Handout: none provided — the target is the live Meridian-Clearance service. The solver is [solve.py](solve.py).

## Solve

The Meridian-Clearance API lists consignments; one (`MFC-4UR6D06`) is `HELD`. Each consignment has a manifest of line items and a customs approval record. The approval exposes its `covered_fields`, and reading `/schema` confirmed the catch: the approval is bound to a hash computed over `covered_fields` only, and `hs_code` is **not** in that set. A separate `PATCH /consignments/<id>/lineitems/<k>` can change a line item's `hs_code` after the approval is granted.

The held consignment's line item `k=1` declared an embargoed tariff code (`9027.80`). Because `hs_code` is outside the covered fields, amending it does not invalidate the existing approval. My first PATCH used an invented code and was rejected with "hs_code is not a recognised tariff classification", so the server validates the code against a tariff table. I switched to `8536.90` — a recognised, non-controlled code already present on another line of the same manifest — and the amendment was accepted with the approval still valid. `POST /consignments/<id>/release` then released the consignment and returned the clearance token:

```
{"status": "RELEASED", "certificate": {"consignment": "MFC-4UR6D06",
 "clearance_token": "CSCTF{ohemmIhj5ZKCqXWKWGBauPq3}"}}
```

Run [solve.py](solve.py) with `python3 solve.py http://<assigned-host>:<port>`.

**Flag:** `CSCTF{ohemmIhj5ZKCqXWKWGBauPq3}`
