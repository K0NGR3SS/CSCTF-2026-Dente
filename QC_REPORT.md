# QC report — OFFICIAL_WRITEUP.md

Quality gate run against `audit.csv` (107 solved challenges) and the official submission
template. Audited file: `OFFICIAL_WRITEUP.md`, 2,362 lines / 168,964 bytes / 26,482 words (24,760 of them inside the cards).
Pre-QC snapshot kept as `OFFICIAL_WRITEUP.pre-qc.md`.

## 1. Coverage

| Metric | Count |
| --- | ---: |
| Solved challenges (`audit.csv` rows) | **107** |
| Cards in `OFFICIAL_WRITEUP.md` | **107** |
| Solved challenges with a card | **107** |
| Missing cards | **0** |
| Cards for unsolved challenges | **0** |
| Duplicate cards | **0** |
| Coverage | **100%** |

Per-category counts match `audit.csv` exactly:

| Category | Solved | Cards |
| --- | ---: | ---: |
| Forensics | 24 | 24 |
| Web | 20 | 20 |
| OSINT | 12 | 12 |
| Misc | 11 | 11 |
| Reverse engineering | 11 | 11 |
| Network | 9 | 9 |
| Crypto | 8 | 8 |
| Pwn | 6 | 6 |
| Welcome | 2 | 2 |
| ICS | 1 | 1 |
| ML | 1 | 1 |
| Mobile | 1 | 1 |
| Rev | 1 | 1 |
| **Total** | **107** | **107** |

### Missing cards found and added

At QC intake the document held 101 cards and these 7 solved challenges had no card:

| ID | Challenge | Category | Pts | Basis |
| ---: | --- | --- | ---: | --- |
| 9131 | ultralight | Misc | 275 | Challenge handout description; **no lane notes survived** |
| 9102 | Command Calendar Reconciliation | Misc | 120 | Published challenge card text; **no lane notes survived** |
| 9124 | Operation Dawn: The Fire-Control Terminal | Misc | 120 | Published challenge card text; **no lane notes survived** |
| 9065 | Silent Orbit | Network | 120 | Full derivation recovered from `ctf-telecom/wave3/chal/9065/work/derivation.md` |
| 9090 | Welcome Aboard | Welcome | 100 | Repository writeup `Welcome/welcome-aboard/README.md` |
| 9091 | Comms Check | Welcome | 100 | Repository writeup `Welcome/comms-check/README.md` |
| 9171 | Onion Deanon 2: Hash the Favicon Again | OSINT | 0 | Challenge card text + sibling Onion Deanon 2 material |

Three of the seven (`ultralight`, `Command Calendar Reconciliation`,
`Operation Dawn: The Fire-Control Terminal`) have **no contemporaneous solve notes anywhere in
the workspace**. They are written to the level the published challenge card supports and each
carries an explicit `**Provenance:**` line saying measured detail was not reconstructed. They are
the only cards in the document that are reconstructions rather than solve records — see §4.

### Card for an unsolved challenge removed

`Velora` (id 9125, Web, Hard, 900 pts) had a 114-line card at the end of the document. It is not in
`audit.csv`: the card itself recorded "no flag was submitted", 29 of 30 layers. The template allows
cards only for solved challenges, so the section was moved intact to **`VELORA_NEAR_MISS.md`**
(appendix, clearly marked as not part of the submission). `OFFICIAL_WRITEUP.md` now has no
unsolved challenge and no dangling reference to Velora.

### Upstream finding

The official template skeleton was itself short: it contained 101 cards and omitted **6** solved
challenges — `Vesper Quay Board`, `switchboard`, `smuggler`, `Two-Key Turn`, `Welcome Aboard`,
`Comms Check`. The first four were added by the card lanes during the build; the last two are
covered by the new `## Welcome` section. Any future rebuild from the template alone will drop
those six.

## 2. Template conformance

| Field | Present | Missing |
| --- | ---: | ---: |
| Header line (`Name` + `Category · Difficulty · Author`) | **107 / 107** | 0 |
| `Points at solve:` | **107 / 107** | 0 |
| `**Approach**` | **107 / 107** | 0 |
| `**Why it works**` | **107 / 107** | 0 |
| `**Validation**` | **107 / 107** | 0 |
| `**Tools used:**` | **28 / 107** | 79 |

**Hard field failures: 0.** Every card parses as header → points → approach → why → validation.

`Tools used` is omitted on 79 cards. The template qualifies this field as *"only if they mattered"*,
so the omission is conformant, not a defect — the 79 cards name their tooling inline in the
approach where it is load-bearing. Flagged for visibility only; no wording was invented to fill it.

Additional checks:

- **Points cross-check:** every `Points at solve` value matches the `points` column in `audit.csv` —
  **0 mismatches** across 107 cards.
- **Difficulty labels:** 7 cards carried the template's `Not shown` placeholder because the skeleton
  scraper missed the tier. All 7 were filled from the platform's own tags — `Operation Dawn: The
  Relay Tap` and `Signal Reconciliation` Easy, `Harvest` Medium, `Phantom Device`, `Carrier Shadow`,
  `Broadsheet Organizer` and `Helioform Relay` Hard. **0 `Not shown` labels remain.**
- **Placeholders:** `[fill in]`, `TODO`, `TBD` — **0** remaining. The `Division` field was filled
  during the build (Seniors, bracket 2).
- **Screenshots:** the three required screenshots are written as bracketed text descriptions
  (`[screenshot: ...]`), not embedded images. Acceptable as redacted evidence notes, but they are
  not actual images — see §5.

## 3. Security scan — redaction log

Scanned: flag literals (`CSCTF{`), JWTs, bearer tokens, cookies (`session=`, `operator=`),
`Set-Cookie` values, passwords, API keys, private keys, instance hostnames
(`*.chronos-security.ro`, `w0x.*`, `*.internal`), instance ports (`:3xxxx`), IPv4 addresses,
32+ char hex blobs and 60+ char base64 blobs.

### Findings at intake and action taken

| Intake line | Finding | Category | Action |
| ---: | --- | --- | --- |
| 499 | `` `CSCTF{...}` `` used to describe the flag structure | flag-format literal | Reworded to "the expected flag-format structure" |
| 1649 | `` `CSCTF{...}` `` describing a planted string in a binary | flag-format literal | Reworded to "a flag-format string" |
| 2243 | `fabric.velora.internal` | instance hostname | Removed with the unsolved Velora section |
| 2245 | `fabric.velora.internal` | instance hostname | Removed with the unsolved Velora section |
| 2247 | `fabric.velora.internal` | instance hostname | Removed with the unsolved Velora section |
| 2257 | `Cookie: operator=op_<24 hex>` | cookie exemplar | Removed with the unsolved Velora section |

Post-move hygiene: the three hostnames still present in `VELORA_NEAR_MISS.md` were replaced with
`[redacted-host]` (3 replacements), so the appendix cannot leak an internal name either.

### Final state of `OFFICIAL_WRITEUP.md`

| Pattern | Hits |
| --- | ---: |
| Flag literals (`CSCTF{`, any `XXX{...}`) | **0** |
| JWT (`eyJ...`) | **0** |
| Cookies with values (`session=`, `operator=`, …) | **0** |
| Bearer tokens | **0** |
| Passwords / API keys / private keys | **0** |
| Instance hostnames (`chronos-security.ro`, `w0x.*`, `*.internal`) | **0** |
| Instance ports (`:3xxxx`) | **0** |
| 32+ char hex blobs / 60+ char base64 | **0** |
| IPv4 addresses | 2 — both `127.0.0.1` |
| `Set-Cookie` (word only, line 101) | 1 — no value |

The two remaining `127.0.0.1` hits are loopback references in the protocol narrative (`DIAL` splicing
to loopback; the short-form `127.1` bypass). They are not instance addresses and carry no
routing information; retained. The single `Set-Cookie` occurrence is the redaction note describing
what was blacked out in the screenshots, with no value attached.

**Nothing that must not ship remains in the submission document.**

## 4. Thin cards

Cards below 150 words, or reconstructed rather than recorded:

| Card | Category | Words | Note |
| --- | --- | ---: | --- |
| Welcome Aboard | Welcome | 113 | Short by design (base64 decode); complete route, no gap |
| Onion Deanon 1: Fingerprint the Certificate | OSINT | 115 | Short; route present |
| Onion Deanon 1: Read the Certificate | OSINT | 131 | Short; route present |
| Comms Check | Welcome | 140 | Short by design (Discord channel topic); complete route |
| Operation Dawn: The Fire-Control Terminal | Misc | 200 | **Reconstructed** — no lane notes; `Provenance` line added |
| ultralight | Misc | 233 | **Reconstructed** — no lane notes; `Provenance` line added |
| Command Calendar Reconciliation | Misc | 275 | **Reconstructed** — no lane notes; `Provenance` line added |

Document median: **228 words** per card. The four short cards are genuinely small challenges
(a base64 decode, a certificate read, a channel topic); their routes are complete.

The three reconstructed cards are the real gap. They are honest but generic, and an owner with the
original notes should replace the `Provenance` paragraphs with measured detail. No values were
invented to pad them.

## 5. Residual issues for the owner

1. **Three reconstructed cards** (`ultralight`, `Command Calendar Reconciliation`,
   `Operation Dawn: The Fire-Control Terminal`) need the original solver's notes.
2. **Screenshots are text placeholders.** The template asks for one to three screenshots of the real
   workflow; the document carries three bracketed descriptions instead of image files. Either add
   the redacted images or keep the descriptions and accept the deduction.
3. **79 cards omit `Tools used`.** Conformant with the template's "only if they mattered" wording,
   but a judge skimming for tooling will not find it on those cards.
4. **Difficulty labels** are now complete (0 `Not shown`); the 7 that were missing were taken from
   the platform's challenge tags, not guessed.

## 6. Files

| File | Status |
| --- | --- |
| `OFFICIAL_WRITEUP.md` | Fixed in place — 107 cards, redactions applied, unsolved section removed |
| `OFFICIAL_WRITEUP.pre-qc.md` | Pre-QC snapshot (101 cards, original line endings) |
| `VELORA_NEAR_MISS.md` | New — unsolved Velora card preserved as an appendix, hostnames redacted |
| `QC_REPORT.md` | This report |
