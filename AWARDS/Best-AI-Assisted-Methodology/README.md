# Best AI-Assisted Methodology

*Best AI-Assisted Methodology submission — Team Dente, CSCTF 2026.*

This is a case study of AI used as a *fallible instrument*, not as an oracle. We used model-driven lanes to generate hypotheses, write drivers, parse artifacts, and attack our own conclusions. The useful part was speed and breadth. The part that won challenges was the discipline around the AI: every claim had to point at an artifact, every rejected answer was logged, and no flag was submitted without a reproducible preimage.

Paths beginning `wave3/` refer to the team's working-note archive, preserved alongside this repository at `ctf-telecom/wave3/`. They contain the raw plans, lane reports, live responses, and submission logs cited below.

## Summary of the four episodes

| Challenge | AI contribution that helped | AI output we rejected | Independent verification | Result |
|---|---|---|---|---|
| **9159** Operation Silent Ward | Parsed the pcap/CSV/XML, computed candidate hashes | Timestamp chosen by the `[ANOMALY]` label (`86a4ae95`); boot-report timestamp (`ba007510`) | Re-read the first four log lines; recomputed the serialization | `CSCTF{f75f58ab}` accepted |
| **9164** Phantom Device | Built and locally validated the complete FSOP chain | "The image can never land over the wire" (single-recv MSS conclusion) | Measured the receive ceiling; two-hop JIT replies; crasher variants | `CSCTF{Ebbi6vq9Ol7k1PqPPR1vZNSG}` accepted |
| **9165** Broadsheet Organizer | Proposed the Varnish path-normalisation / raw-origin split | "The ticker cannot be poisoned; `no-store` is honoured" | Live `X-Cache`, `Age`, content-type differential; bot-execution oracle | `CSCTF{iJPBtyIgDoAePSGUNv7Gd7pz}` accepted |
| **9125** Velora | Generated exhaustive negative probes and the L1–L29 chain scripts | Upload/import RCE; HS256 cracking; SSRF-to-flag as a shortcut | Byte-exact live responses; per-lane negative reports | No flag; chain walked to L29, negatives preserved |

All four episodes contain a model output that was wrong. In three of them the wrong output was the headline claim; in 9165 the model was right about the escaping and wrong about the cache. The verification loop — not the model's confidence — decided which was which. The rest of this document is the evidence for that sentence.

## How the work was organised

We ran AI lanes as parallel, isolated workers. A lane received one hypothesis or one surface, a live endpoint, and a requirement to write a `LANE-*.md` report with raw evidence. A human/orchestrator role did four things the models were not trusted to do:

1. Read the challenge brief and the primary artifacts first.
2. Decide which lane output was a claim and which was a guess.
3. Re-run the decisive request or computation independently.
4. Approve any flag submission.

The models were strongest at enumeration and code generation: parsing a pcap, building an AFC reply plan, writing a 369-line exploit driver, generating 714 GraphQL documents, or sweeping 4,750 routes. They were weakest at *semantic closure* — deciding what a label in an artifact meant, or whether a negative measurement bounded the whole problem. Most of the methodology below is about catching that failure mode.

## Episode 1 — 9159: the label that lied

### What the model did

The challenge supplied five artifacts and a serialization spec:

```
sha256("<dicom_serial>:<snmp_iso_timestamp>:<leak_count>:<anomaly_count>:<manifest_seed>")[:8]
```

The model lane parsed the evidence correctly:

- `dicom_serial = MEDSCAN-XR400-2019` from `dicom_device.xml`.
- `leak_count = 90` from `patient_records.csv` (91 lines = header + 90 rows).
- `anomaly_count = 20` from the pcap (20 C-STORE-RQ to `198.51.100.42:104`).
- `manifest_seed = 8842` from both the XML and the SNMP boot report.

It then chose the timestamp from the line tagged `[ANOMALY: Unusual polling frequency]`:

```
2026-09-01T03:15:00Z
```

and submitted `CSCTF{86a4ae95}` at 18:10:14Z. The platform rejected it. A second attempt in the same lane used the `deviceBootReport` line at `2026-09-01T00:00:01Z` and submitted `CSCTF{ba007510}` at 18:29:19Z. Rejected.

Both hashes were arithmetically correct. Both preimages were real strings built from real fields. The error was semantic: the model treated the literal tag `[ANOMALY]` as the definition of "the anomalous event" instead of reading the log.

### What we changed

We stopped the lane after the second rejection. The lane's own report recommended a platform ticket rather than more submissions — the right call at the time, because the space of plausible timestamp readings was large and unranked. The orchestrator later ran a logged, bounded sweep (15 submissions, every one recorded in `wave3/attempts.jsonl`); the solve came from re-reading the artifact from the top, not from another hash variant.

`snmp_trap.log` opens with four lines at the same timestamp:

```
2026-09-01T00:00:00Z ... Trap: linkDown Device: Core Router
2026-09-01T00:00:00Z ... Trap: linkDown Device: Distribution Switch A
2026-09-01T00:00:00Z ... Trap: linkDown Device: Distribution Switch B
2026-09-01T00:00:00Z ... Trap: linkDown Device: Patient Records Server
```

That is the only *simultaneous, multi-device* event in the file: four links down at once, including the Patient Records Server that later leaks records. The eight `[ANOMALY]` lines are a repeating daily pattern (one per day, 2026-09-01 through 2026-09-08, all at 03:15:00Z), not a singular event. The boot report at 00:00:01Z is a boot, one second after the outage — a consequence, not the anomaly.

The preimage is:

```
MEDSCAN-XR400-2019:2026-09-01T00:00:00Z:90:20:8842
```

whose SHA-256 begins `f75f58abfcc67159...`. We submitted `CSCTF{f75f58ab}` at 22:01:03Z and the platform accepted it (`wave3/attempts.jsonl`, status `correct`).

### The methodological point

A hash proves the arithmetic; it does not prove the reading. The rejected candidates were not hallucinations — they were valid hashes of a wrong field choice. What caught the error was a *uniqueness* argument:

- The spec says "the anomalous event", singular.
- The artifact contains eight identical labelled anomalies and one unique simultaneous outage.
- The unique event is the first four lines; the repeating pattern cannot be "the" event.

We now require a **field-provenance table** for any hash-from-artifact challenge: field, value, exact artifact line, and why this value beats every alternative. "It was tagged ANOMALY" is not a provenance argument.

Evidence: `wave3/chal/9159/files/snmp_trap.log` (lines 1–4 and 17/34/51/68/85/102/119/136), `wave3/chal/9159/INTEL.md` (the timestamp-problem section and the excluded space), `wave3/work/9159_cands.txt`, `wave3/attempts.jsonl`.

## Episode 2 — 9164: the local chain that "couldn't" go remote

### What the model built

An AI lane built the complete exploit locally: an AFC server that impersonates an iOS device, leaks libc and the heap through the client's uninitialised 8-byte file handle, poisons two tcache bins, and lands a House-of-Apple FSOP image on `_IO_2_1_stderr_`. `python3 exploit_local.py` printed:

```
=== 1. harmless marker (direct) ===
FSOP_OK
=== 2. sh mode with flag file ===
CSCTF{lanec_local_marker_1234}
[+] FLAG: CSCTF{lanec_local_marker_1234}
```

with gdb confirming the path `_IO_cleanup -> _IO_flush_all -> _IO_wfile_overflow -> _IO_wdoallocbuf -> system`. That is real, reproducible work: `wave3/chal/9164/work/exploit_local.py`, `LANE-C.md`.

### The wrong claim

A later lane measured the live receive path and concluded the exploit could never fire remotely:

> "The `.data` image needs 4816 B in one `recv()`. ... Anything needing two or more segments (any body ≳1.3 KB) is lost." — `wave3/chal/9164/work/LANE-D.md` §3

The measurement was correct. The conclusion was not. The lane had conflated *this image cannot land in one receive* with *no exploit can land on this transport*. It even listed the right direction as a possibility ("environment where a 4.8 KB body arrives in one segment"), but treated the one-shot image as the only design.

### The correction

The fix was not a new vulnerability. It was transport scheduling plus a smaller image:

- Send each reply **just in time**, after the client's request, instead of pipelining a 2272-byte burst ahead of it.
- Split the libc `.data` image into two hops below the measured ceiling: **1024 bytes** to `libc+0x2042f0` and **960 bytes** to `libc+0x2046f0`.

Measured live with `big.py` (`entire=1`, `this_len=N`, body of N):

| N | result |
|---|---|
| 256 / 512 / 1024 / 1064 | full (handle echo intact) |
| 1200 / 1400 / 2048 / 4096 / 4816 | short (body never fully landed) |

So the reliable ceiling is one TCP segment, **≤ ~1100 bytes**. A 4816-byte image is impossible; 1024/960-byte hops are not. The crasher variants proved the hop writes landed: `TEST_H2` (wild `_IO_2_1_stdin_._lock`) produced a clean close when pipelined but a core dump when just-in-time; `TEST_H3` (wild `__doallocate`) produced a core dump just-in-time, confirming `_IO_wdoallocbuf` really calls `*(wide_vtable->__doallocate)(fp)`.

The winning invocation:

```
NOPIPE=1 python3 solve10.py remote <host> <port> -v --cmd 'cat /flag.txt>&0;echo __DONE__>&0'
```

and the live result was `CSCTF{Ebbi6vq9Ol7k1PqPPR1vZNSG}`, accepted at 2026-11-08 04:37:37Z (`wave3/attempts.jsonl`; `wave3/chal/9164/work/9164_flag.txt`).

### The second wrong assumption: fd 2

The local exploit wrote its output to fd 2 (`cat /flag.txt >&2`) because the local harness gives the client a stderr pipe. On the live transport, `>&2` and `>&1` produced nothing. The lane proved the shell was running with a sleep test: `system("sleep 5; ...")` delayed the socket close by **5.03 s**, while `echo AAA>&0` and `cat /flag.txt>&0` came straight back. The final command writes to **fd 0**, the AFC socket:

```
"  cat /flag.txt>&0;echo __DONE__>&0"
```

That is a local-truth-versus-remote-truth failure, and it is exactly the kind of thing a model will gloss over if the local test "works".

### The methodological point

A negative measurement has a scope. "A 4816-byte one-shot image cannot land" is true. "The exploit cannot land" was false. We now require every negative to state:

1. what was measured,
2. at what boundary,
3. what would falsify the conclusion.

The 9164 lane's own notes contain the falsifier — a smaller image and a different send schedule — but the report's headline was stronger than the evidence. The fix was found by treating the transport as part of the exploit, not as an implementation detail.

Evidence: `wave3/chal/9164/work/LANE-B.md` (protocol and live primitives), `LANE-C.md` (local FSOP and byte offsets), `LANE-D.md` (the wrong "cannot fire" claim and the measurement that produced it), `LANE-E.md` (the two-hop win and fd-0 proof), `solve10.py`, `big.py`, `9164_flag.txt`.

## Episode 3 — 9165: right about escaping, wrong about caching

### The correct negative

An AI lane spent a block on the ticker's text sink and concluded it was airtight. It was. The ticker body is built as `el.textContent = "<json-escaped>"`; the escaper handles `"`, `\`, `'`, NUL, CR, LF, TAB, and U+2028/U+2029; `<`, `>`, `&` pass raw but the sink is `textContent` in an external `nosniff` script, so they are inert; the 500-character cap is applied before escaping. A 15-payload battery across board/notice/by/search/print/drafts produced zero unescaped HTML bytes. This is a model output we kept: `wave3/work/9165/LANE-C-XSS.md`.

### The wrong assumption

The same lane's broader assumption — recorded in `wave3/work/9165/LANE-I-TICKER.md` as "`no-store` is honoured" and "the ticker cannot be poisoned with a different content-type" — was wrong for the path-normalisation case. It was true for the *string* layer and false for the *cache-key* layer. The model had tested `?text=` escaping and static-extension cache deception, but not the interaction between Varnish path normalisation, the Flask embed route, and the VCL ticker rule.

### The model proposal and the live verification

The proposal was:

```
GET /z/<zone>/embed/<12hex-token>/../../ticker.js?html=<urlencoded JS>
```

Three layers line up:

1. **Varnish** normalises dot-segments to compute the cache **key** (`/z/<zone>/ticker.js`) but forwards the **raw** path upstream.
2. **Flask** routes the raw path to the embed view; the token is validated only as the **first** path segment, so `/embed/<T>/../../ticker.js` still renders the `?html=` snippet verbatim.
3. The **VCL ticker rule** sees the normalised key, forces `Content-Type: application/javascript` and a ~12 s TTL, and **overrides the embed view's `Cache-Control: no-store`**.

This is exactly the kind of proposal a model can generate quickly and get wrong. We verified it against the live Varnish, not against the source:

| Request | Normalised key | Origin view | Result |
|---|---|---|---|
| `/z/g/embed/<T>/%2e%2e/%2e%2e/app.js?html=MARK` | `/app.js` | embed | 200 `text/html`, `no-store` honoured, 3× MISS; real `/app.js` intact |
| `/z/g/embed/<T>/x.js?html=MARK` | same raw path | embed | 200 `text/html`, `no-store`, never cached |
| `/z/g/embed/<T>/../../app.js?html=MARK` | `/z/g/app.js` | 404 | 404 |
| `/z/g/embed/<T>/../../ticker.js?html=<js>` | `/z/g/ticker.js` | embed | **200 `application/javascript`, cached ~12 s** |

The read-back was the proof:

```
poison  GET .../embed/<T>/../../ticker.js?html=/*PWN*/   -> 200 application/javascript  X-Cache: MISS
read    GET /z/<zone>/ticker.js                          -> 200 application/javascript  X-Cache: HIT  body /*PWN*/
```

Measured cache window: HIT at `Age: 11`, MISS at t+13.1 s → ~12 s TTL. The bot-execution oracle was independent of the cache headers: a payload `new Image().src='/z/ibcnz3/ticker.js?text=XZONE'` was read back as `textContent = "XZONE"` right after the duty-log row. `location.href` inside the bot was `http://127.0.0.1:3402/z/<zone>/board`; `/editor` answered it as the editorial terminal (`Signed in as V. Marchetti` + `rotation key: CSCTF{...}`); `document.cookie` was empty, proving the privileged view is granted by local origin, not a cookie. The exfil returned `EDLEN=1179` in six chunks; the flag was in chunk 5: `CSCTF{iJPBtyIgDoAePSGUNv7Gd7pz}`, accepted at 21:20:35Z.

### The methodological point

A correct negative on one layer can create a false negative on the whole system. The escaping was airtight. The cache key was not. We now separate **"the sink is safe"** from **"the object cannot be poisoned"**: they are different claims, verified by different artifacts. The model proposed the path-normalisation idea; the live `X-Cache`/`Age`/content-type differential is what made it a finding.

Evidence: `wave3/work/9165/LANE-C-XSS.md`, `wave3/work/9165/LANE-I-TICKER.md`, `wave3/work/9165/LANE-G-DELIVERY.md`, `wave3/chal/9165/INTEL.md`.

## Episode 4 — 9125: the negative ledger

### Three model shortcuts, all wrong

The model lanes produced three plausible shortcuts. Each was falsified with live evidence:

1. **RCE via upload or import.** `POST /support` with `filename="shell.pHp.jpg"` executed PHP, but the "shell" was a simulation: `id` returned `uid=48(desk)`, `ls` returned a canned list, only `/etc/passwd` was readable, and `/flag` did not exist. `/import` with `repo_url=ext::sh -c ...` executed as `uid=49(importer)` in the same curated fake FS. No app source, no JWT secret, no flag. (`wave3/chal/9125/work/LANE-V1.md`, `LANE-V6.md`, `wave3/work/9125d_findings.md`.)
2. **JWT cracking.** The session is an HS256 JWT with a `role` claim; the obvious move is to crack or forge it. The lanes ran rockyou (14.3M), 88k themed candidates, and every key-shaped public string; they also tried a broad forgery matrix (`alg:none`, operator/member role poisoning, `kid` injection, `jku`/`x5u`, tampered signatures). The cracking failed — the HS256 secret is per-instance random — and the lanes generalised that to "token forgery is out". That generalisation was too broad; §"The artifact re-read" records the narrower correction. (`wave3/chal/9125/INTEL.md`, `LANE-V2.md`, `LANE-V3.md`.)
3. **SSRF to the flag.** `/api/preview` is a real GET-only SSRF with decimal-IP filter bypass (`http://2130706433/`), but as a one-request shortcut to the flag it reaches only a fabricated fabric index, a fake Redis banner, and a stub settle service on `:9200`. It does not print a flag. (`wave3/chal/9125/INTEL.md`.)

Each negative was recorded with byte-exact responses, not "didn't work". That is the point: the negatives are deliverables.

### The human hint

The turn came from a human, not a model. The hint was, in paraphrase: **stop hunting a single bug that prints the flag; the brief says the plane is one strictly ordered chain — read what each page hands back and replay it.** That changed the unit of analysis from "find the vulnerability" to "walk the state machine".

### The artifact re-read

Re-reading the artifacts literally, in order, produced the chain:

- `GET /` contains `<!-- channel:/x/<hex> -->`; the token is **per session**, so sign up first, then read it in the same session.
- `GET /robots.txt` contains `# budget:/x/<hex>`; `GET /static/app.js` contains `// map:/x/<hex>`. These are the L2/L3 tokens.
- Signup accepts a hidden `plan=enterprise` field, which is the L4 gate.
- `/company` JSON-LD leaks the operator member UUID; `GET /api/members/<UUID>/settings` is the L5 read.
- `/login` carries Cloudflare-style XOR masks that decode to `preview@velora.example` and `harbor-preview-19`; logging in as preview and re-signing up with `plan=enterprise` satisfies L6.

At L7, `LANE-V2.md` §4 concluded "token forgery is out". The earlier lanes had tested `alg:none` and role-poisoned tokens, but the combination that opened L7 was an unsigned token with the `admin` claim. Re-reading the walk and the app's role vocabulary produced the narrower correction: the gate message says "operator role", but the accepted token used `role: admin`. The walk script forges `{"alg":"none","typ":"JWT"}` with an admin claim and L7 returns `{"ok":true,"layer":7,"note":"Console is open."}` (`wave3/chal/9125/work/lanev11/walk.py` lines 60–63; `lanev11/gate_L7.bin`).

The chain then continued through surfaces that the earlier lanes had seen as gates but not yet used:

- `/catalog?q=` is UNION SQL-injectable once the console is open; the `fabric_routes` table yields the fabric map (L9).
- `X-Forwarded-Host: fabric.velora.internal` is the L10 host override.
- `/api/preview` to `http://fabric.velora.internal/` returns the fabric index (L11), to `http://127.1/` the alternate origin (L12), and `dict://127.1:6379/KEYS` / `GET operator.session` the Redis keyspace and operator cookie (L13–L16).
- GraphQL accepts self-hashed persisted operations for `health` and `accounts` (L17–L18), and one batched mutation of 100,000 `verifyOtp` codes satisfies the five-digit step-up (L19).
- `/dashboard?page=dashboard-pages/../../secret/schema.txt` reads the schema through the page/template primitive (L21), and the rest of the chain follows the schema and handler map to L29.

### What it bought, and what it did not

The chain walked to **L29**; L30 returned `{"ok": false, "layer": 30, "error": "The navigator has not recorded a delay."}` and was not solved. No flag was submitted. `wave3/chal/9125/work/9125_flag.txt` says `NOT_FOUND`, and the lane report says so in the same words. We are not dressing an unsolved challenge as a solve.

What the episode proves is the methodology: every wrong model hypothesis became a closed surface with evidence, and the human hint plus artifact re-read found the real path — a 29-layer chain — which the model-generated walk scripts then executed. The negative ledger is why the later lanes did not repeat the upload/JWT/SSRF work.

Evidence: `wave3/chal/9125/INTEL.md`, `LANE-V1.md` through `LANE-V6.md`, `wave3/chal/9125/work/lanev11/walk.py`, `lanev11/L21-L29_REPORT.md`, `lanev11/walk_l30.json` (29 proofs), `lanev11/state.json`, `wave3/chal/9125/work/9125_flag.txt`.

## Evidence index

| Path | What it proves |
|---|---|
| `wave3/attempts.jsonl` | Submission log: every 9159 attempt (including the two rejected flags and the accepted `f75f58ab`) and 9164 `correct` at 2026-11-08 04:37:37Z |
| `wave3/results.jsonl` | Per-agent result lines, including 9165 `correct` and 9159 `incorrect` |
| `wave3/chal/9159/files/snmp_trap.log` | First four lines: four simultaneous linkDowns at `2026-09-01T00:00:00Z`; eight `[ANOMALY]` lines at 03:15:00Z |
| `wave3/chal/9159/INTEL.md` | The original timestamp problem and the excluded candidate space |
| `wave3/work/9159_cands.txt` | Candidate timestamp list headed by `f75f58ab 2026-09-01T00:00:00Z` |
| `wave3/chal/9164/work/LANE-B.md` | AFC protocol, live overflow, libc/heap leaks |
| `wave3/chal/9164/work/LANE-C.md` | Local FSOP proof, gdb trace, exact byte offsets, local marker |
| `wave3/chal/9164/work/LANE-D.md` | The single-recv measurement and the incorrect "cannot fire" conclusion |
| `wave3/chal/9164/work/LANE-E.md` | Two-hop live win, receive-ceiling table, fd-0 proof, flag |
| `wave3/chal/9164/work/solve10.py` | The winning exploit; `NOPIPE=1` just-in-time reply path |
| `wave3/chal/9164/work/9164_flag.txt` | `CSCTF{Ebbi6vq9Ol7k1PqPPR1vZNSG}` |
| `wave3/work/9165/LANE-C-XSS.md` | The correct negative: ticker `textContent` escaping is airtight |
| `wave3/work/9165/LANE-I-TICKER.md` | Cache-key/raw-path exploit, `X-Cache`/`Age` measurements, bot execution, flag |
| `wave3/work/9165/LANE-G-DELIVERY.md` | The three-layer Varnish/Flask/VCL explanation and the failed variants |
| `wave3/chal/9165/INTEL.md` | Live routes, cache observations, and the solved record |
| `wave3/chal/9125/INTEL.md` | L1–L6 chain, L7 deadlock, upload/import/SSRF negatives |
| `wave3/chal/9125/work/LANE-V1.md` … `LANE-V6.md` | Six negative lanes with byte-exact evidence |
| `wave3/chal/9125/work/lanev11/walk.py` | The L1–L29 chain; alg:none admin at L7; SQLi/SSRF/Redis/GraphQL/OTP steps |
| `wave3/chal/9125/work/lanev11/L21-L29_REPORT.md` | Schema read through `/dashboard?page=`, the L21–L29 gates, the L30 blocker |
| `wave3/chal/9125/work/lanev11/walk_l30.json` | 29 chain proofs; `next` = L30 |
| `wave3/chal/9125/work/9125_flag.txt` | `NOT_FOUND` — the honest record that 9125 was not solved |

## Limitations

- The 9125 chain was not completed; L30 remained blocked. We include it because the negative ledger and the human-framing lesson are the methodology, not because it produced a flag.
- The 9164 and 9165 instances were ephemeral. The host/port pairs in the lane notes are dead; the exploits are reproducible against a fresh assigned instance with the same challenge image.
- The 9164 local marker is not the challenge flag. Only the live read (`9164_flag.txt`) counts.
- The AI lanes were not a single model or a single vendor. We used several model-driven agents; the methodology is about the verification loop, not about a particular model's benchmark score.

## What we now enforce

These are the rules we would carry into the next event. Each one exists because a model output failed in one of the episodes above.

### 1. One claim = one artifact

Every lane report must contain a table of claims, each with the exact file, command, request, or packet that produced it. "The server rejects X" is not a claim until it names the request and the raw response. "The flag is Y" is not a claim until it names the preimage or the exploit output.

This is what caught 9159: the claim "the anomalous event is 03:15:00Z" pointed at a line, but the line was one of eight identical lines, not a unique event.

### 2. Rejected outputs are logged, not deleted

`wave3/attempts.jsonl` and `wave3/results.jsonl` keep every submission with its status. Lane reports keep wrong hypotheses: `LANE-D.md` keeps the "cannot fire" conclusion; `LANE-V1.md` through `LANE-V6.md` keep the RCE/JWT/SSRF negatives; `wave3/chal/9125/work/9125_flag.txt` says `NOT_FOUND` in the file itself.

The log is not a confession. It is the audit trail that lets a later lane avoid repeating a falsified idea, and it is the evidence that the final answer was derived rather than guessed.

### 3. No flag submitted without a preimage

For a hash challenge: the exact serialization string and the hash. For an exploit challenge: the exploit output from the target, not a local marker. For a web challenge: the request that returns the flag, replayable against a fresh instance.

The two 9159 rejections were valid hashes of a wrong reading; the rule now is "show the preimage and justify each field", not merely "show the hash". The 9164 local marker `CSCTF{lanec_local_marker_1234}` was never submitted as the challenge flag; the live read was.

### 4. Per-lane evidence files

Each lane gets its own directory and a `LANE-*.md` with:

- the hypothesis it tested,
- the exact commands/requests,
- raw outputs (`live_plan*.json`, `gate_*.bin`, `*.jsonl`),
- a result: positive, negative, or blocked,
- a "do not retry" list for the next lane.

This is why `wave3/chal/9164/work/` contains both the winning `solve10.py` and the losing `plan_*.py`, and why `wave3/chal/9125/work/` contains six negative lane reports plus the later `lanev11/` chain. The directory is the memory.

### 5. Separate "doesn't work" from "can't work"

Every negative must state its boundary. "The 4816-byte image did not land in one `recv`" is a measurement. "The exploit cannot fire" is a theory. The first is allowed; the second needs a falsification test.

We now ask: *what would change the result?* If the answer is "a smaller payload" or "a different send schedule", the negative is not a dead end. If the answer is "nothing within the protocol", we write that and move on.

### 6. Local truth ≠ remote truth

Re-measure the transport, file descriptors, parser behaviour, and error paths on the live instance before declaring success. The 9164 chain worked locally with fd 2 and a 5.5 KB `_IO_2_1_stderr_` image; the live target needed fd 0 and 1024/960-byte hops. The 9165 ticker escaper was locally correct and remotely irrelevant until the cache key was tested. The 9125 upload RCE executed, but only inside a mock shell — "RCE" there meant `uid=48(desk)` and a curated fake filesystem, not the container.

### 7. A human owns the frame

Models generate hypotheses; humans choose the frame. The 9125 human hint — "it is a chain, not a bug hunt" — did more than any individual model output. The 9159 fix came from reading the first four lines of a log, not from another hash variant. The 9164 fix came from asking whether the transport could be scheduled differently, not from a new primitive.

We keep a human in the loop for: reading the brief, ranking hypotheses, deciding when a negative is closed, and approving submissions. The AI is fastest inside a frame; it is not reliable at choosing the frame.

### 8. Submission budget and stop conditions

A lane may submit at most two candidates before returning to the orchestrator. The orchestrator approves any further attempt. We do not brute-force flag enumeration. 9159 is the cautionary case: two rejected flags were enough to stop the lane; the eventual solve came from re-derivation, not from more guesses.
