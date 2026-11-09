# Ghost Signal

**Author:** mar

**Network** · 540 pts (hard)
Handouts: [ss7_capture.pcap](files/ss7_capture.pcap),
[diameter_capture.pcap](files/diameter_capture.pcap),
[billing_events.json](files/billing_events.json)

**TL;DR.** The three handouts describe one SS7/Diameter intrusion. GT **49211** probes five
subscriber numbers with MAP `sendRoutingInfo` and `sendRoutingInfoForSM`; GT **49311** then sends
five `updateLocation` messages for IMSI **226012014000001**; the Diameter capture carries a rogue
SAR from `cscf.rogue.evil-domain.net` on the same session and an SAA whose AVP 272 points at
`diameter://intercept-49211.evil-domain.net`; the billing export books five zero-charge CCR-I and
five unusual-routing CCA on that session, with the CCA rows back-dated 20 seconds. The marker is
`sha256("<imsi>:<full_diameter_session_id>:<first_anomalous_billing_timestamp>")[:8]`.

## Solve

**What each file records.**

| file | contents |
| --- | --- |
| `ss7_capture.pcap` | 60 frames, Ethernet/IPv4/SCTP/M3UA/SCCP/TCAP-MAP; 45 noise probes, 10 recon messages, 5 `updateLocation` |
| `diameter_capture.pcap` | 28 frames, SCTP ppid 46; 24 normal Cx SAR/SAA pairs plus the rogue SAR/SAA and a LIR/LIA pivot |
| `billing_events.json` | 40 OCS records: 30 `norm`, 5 `atk` (CCR-I), 5 `pivot` (CCA) |

The three card hints point at the same reading: catalogue what each capture records, follow the
single hidden subscriber identity that appears in all of them, and aggregate that identity's
correlated activity into one digest. The chain below is exactly that identity's trail.

The SS7 capture starts at `1723740000` (2024-08-15 18:00:00Z). Frames 1–45 are cover: one fresh
calling GT per frame, `49100 … 49144`, alternating MAP 22/45 and cycling targets `407210002xx`. The
attacker is the only calling GT that repeats.

**Stage 1 — reconnaissance, GT 49211.** Frames 46–50 at t+150, 154, 158, 162, 166 are five
`sendRoutingInfo` (MAP 22) to `40721000101 … 40721000105`. Frames 51–55 at t+170, 173, 176, 179,
182 are five `sendRoutingInfoForSM` (MAP 45) to the same numbers. The OPC block `578…582` is shared
by both sub-stages, which proves one box. The TCAP OTIDs are `0x4921 00 02 … 04 02` and
`0x4921 00 03 … 04 03`.

**Stage 2 — the hijack, GT 49311.** Frames 56–60 at t+190, 192, 194, 196, 198 are five
`updateLocation` (MAP 2):

```
imsi        TBCD 22 06 21 10 04 00 00 f1  -> 226012014000001
msc-Number  c1 94 13 f1                   -> 49311
vlr-Number  c1 04 27 01 90 99 f9          -> 40721009999
OPC block   611...615
TCAP OTID   0x4933 00 04 ... 0x4933 04 04
```

The IMSI is the only valid 15-digit IMSI in the dataset; the 30 normal subscribers use 16 digits.

**Stage 3 — the Diameter redirect.** After 24 normal SAR/SAA pairs (`hop-by-hop = end-to-end
0x1000 … 0x1017`), packet 25 is a SAR from `10.40.0.99` / `cscf.rogue.evil-domain.net` with:

```
Session-Id       hss.eastern-tele.ro;1723740150;49211
Subscription-Id  226012014000001
SIP-URI          sip:+40721000101@eastern-tele.ro
```

Packet 26 is the SAA whose AVP 272 — declared `Unsigned32` but carrying 42 bytes of text — is
`diameter://intercept-49211.evil-domain.net`. Packets 27–28 are a LIR/LIA pivot through
`cscf.pivot.eastern-tele.ro:5060` back to the rogue host. The session's low field is the attacker's
GT `49211`; all 30 normal sessions hold a per-session counter `0…29`.

**Stage 4 — the disputed billing.** The export has 30 normal `CCR-A` records (amounts 0.00 → 0.09
cycling), then ten records on the attacker's IMSI and session:

| record | time | type | anomaly | redirect / serving host |
| --- | --- | --- | --- | --- |
| `atk_0000 … atk_0004` | 1723740150, 154, 158, 162, 166 | CCR-I | `zero_charge_on_roaming` | `intercept-49211.evil-domain.net` |
| `pivot_0000 … pivot_0004` | 1723740170, 172, 174, 176, 178 | CCA | `unusual_routing_path` | `cscf.pivot.eastern-tele.ro` / `redirect-49211.evil-domain.net` |

The CCA rows are **back-dated by 20 seconds**. Corrected, they belong with the five `updateLocation`
messages at 190–198; the raw export puts them at 170–178, inside the SRISM window, so they appear
corroborated by the wrong stage. The correlation is exact:

| billing | corrected time | SS7 stage | SS7 time |
| --- | --- | --- | --- |
| 5 × CCR-I | 150–166 | 5 × SRI, GT 49211 | 150–166 |
| 5 × CCA | 190–198 (`−20 s`) | 5 × updateLocation, GT 49311 | 190–198 |

**The marker.** The card fixes the serializer:

```
sha256("<imsi>:<full_diameter_session_id>:<unix_timestamp>")[:8]
```

- `imsi` = `226012014000001` (the card's own example is the real IMSI)
- `full_diameter_session_id` = `hss.eastern-tele.ro;1723740150;49211` (the whole string, semicolons
  included; not just the `49211` fragment)
- `unix_timestamp` = `1723740150`, the first anomalous billing event (`atk_0000`), not the first SS7
  frame and not the back-dated `pivot_0000`

```
preimage  226012014000001:hss.eastern-tele.ro;1723740150;49211:1723740150
sha256    28358943473f95eb307747e985e8e07a933b69f9a9129afea922d0ba912177e0
FLAG      CSCTF{28358943}
```

The candidate is the one recorded in `cands36.json` at 10:53 on 2026-11-07; the platform's solve
record is stamped 10:53:16Z. The three inputs are each corroborated across the set: the SS7 capture
carries the IMSI as TBCD, the Diameter capture carries the IMSI and the full session, and the billing
export carries the session and the first anomalous timestamp.

**Dead ends — the first phase of the event.** The serialization spec was not on the card for the first
day. The team reconstructed the chain completely and then spent 60 submissions on candidate markers;
`GHOST-SIGNAL-FULL-REPORT.md` and `GHOST-SIGNAL-STATUS.md` preserve every one. The categories that
failed:

| candidate family | example preimage | why it was wrong |
| --- | --- | --- |
| all 24 orderings of IMSI, GT 49211, target 40721000101, timestamp 1723740150 | `49211:226012014000001:40721000101:1723740150` | the spec wants the full session, not the GT and the target |
| host `hss.eastern-tele.ro` as a fourth value | `hss.eastern-tele.ro:...` | the host is part of the session string, not a separate field |
| redirect / serving hosts | `intercept-49211.evil-domain.net` in any position | not an input |
| all 15 SS7 rogue instants | `1723740150:...:1723740198` | the spec asks for one billing timestamp |
| corrected timeline (CCA −20 s) | `...:1723740190:...:1723740198` | the marker uses the billing record as written |
| every 3-value set from the shared values | `49211:226012014000001:40721000101` | missing the session id |
| seeds appended/prepended | `...:20`, `...:137`, `...:1723740000` | no seed in this serializer |
| alternate hash functions / truncations | md5, sha1, 16-hex | the card is `sha256[:8]` |
| file digests | `sha256(ss7_capture.pcap)[:8]` | the marker is over values, not files |

The lesson from this card is the one the repo already records elsewhere: read the construction
paragraph before computing, and use the family's published serializer literally. The earlier report
is retained because the chain reconstruction in it is correct; only the marker construction was
missing.

**Flag:** `CSCTF{28358943}`

Run [solve.py](solve.py) with `python3 solve.py`; it reads the billing export, checks the IMSI and
session against the Diameter capture, and derives the flag.

*AI: Hermes (DeepSeek 4.1 Flash) assembled this writeup from the team's Ghost Signal lane
(`GHOST-SIGNAL-FULL-REPORT.md`, `GHOST-SIGNAL-STATUS.md`, the pcap parsers and `cands36.json`); the
chain was reconstructed from the three handouts, and the digest was recomputed from the values above.
The candidate is recorded in `cands36.json` at the same minute as the platform's 10:53:16Z solve.*
