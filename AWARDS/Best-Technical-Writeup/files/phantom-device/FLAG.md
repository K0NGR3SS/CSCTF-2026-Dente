# Phantom Device (9164) — submission record

**Flag:** `CSCTF{Ebbi6vq9Ol7k1PqPPR1vZNSG}`
**Status:** accepted by the platform (`correct`)
**Time:** 2026-11-08 04:37:37Z
**Challenge:** Phantom Device · Pwn · 900 pts at solve (875 in the post-event audit)

## Ledger line

```json
{"agent": "parent", "cid": "9164", "flag": "CSCTF{Ebbi6vq9Ol7k1PqPPR1vZNSG}", "status": "correct", "ts": 1794112657.533778}
```

## Files in this folder

| File | What it is |
| --- | --- |
| `README.md` | the writeup card as submitted |
| `INTEL.md` | derivation audit: AFC length bug, heap layout, House-of-Apple path |
| `LANE-C.md` | local chain: stdout pre-buffer offsets, DT_RELR replay, aliasing table |
| `LANE-D.md` | live run: recv ceiling measurement, segmented delivery |
| `exploit_local.py` | end-to-end local exploit against the challenge binary |
| `solve.py`, `solve2.py`, `solve10.py` | live drivers, in the order they were run |
| `9164_flag.txt` | the flag, as written at capture time |
| `files/` | handouts and the bundled runtime libs used for local reproduction |

**Note for the submission:** this folder is evidence, not part of the templated writeup. The
organizer template asks that live flags be kept out of the writeup body; they live here so the
solve can be reproduced and audited.
