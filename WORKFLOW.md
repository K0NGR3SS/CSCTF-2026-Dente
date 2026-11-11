# How this writeup was produced — the workflow

This is the pipeline the team ran during CSCTF 2026 and again to turn the run into the writeup
you are reading. It exists because the award asks for the *workflow*, not just the result.

## 1. The loop

```text
handout ──> read every provided artifact first ──> form one falsifiable claim
        ──> cheapest experiment that can kill the claim ──> artifact saved to disk
        ──> claim survives? keep it. claim dies? write the negative down and move on
```

The rule that mattered: **each layer/flag candidate needs its own artifact** — a captured
request/response, a decoded stream, a recomputed hash. Nothing is carried on "probably right".

## 2. Parallel lanes

Independent hypotheses ran as separate agents, each with its own scratch directory and its own
responsibility for evidence. A lane that hits a wall writes a short report (what was tried, what
failed, why it stopped) instead of a vague "couldn't do it" — those reports are why the dead-end
lists in the cards are real and not decorative.

```text
lane-a  derive the value offline (parse the artifact, recompute)
lane-b  drive the live instance (requests, payloads, timing)
lane-c  attack the implementation (exploit dev, local repro)
```

Lanes were steered with concrete constants (offsets, endpoints, keys) rather than re-briefed from
scratch, so a lane never re-derives what another already proved.

## 3. Verification gate — before any submission

| Check | How |
| --- | --- |
| Claim is reproduced | rerun the script end to end, not just the last step |
| Value is recomputed | second implementation (or second language) produces the same bytes |
| Live behaviour is observed | the response header / status / body is captured, not inferred |
| Nothing is fabricated | if an artifact is missing, the card says "reconstructed" and names the source |
| Submission is guarded | one attempt per candidate, rate-limited, hard stop after repeated wrong answers |

## 4. Where the traces are

- **The writeup** — [`OFFICIAL_WRITEUP.md`](OFFICIAL_WRITEUP.md), section *AI methodology*: models,
  what they were used for, the output that was rejected, and how accepted results were verified.
- **The award submission** — [`AWARDS/Best-AI-Assisted-Methodology/README.md`](AWARDS/Best-AI-Assisted-Methodology/README.md):
  four concrete episodes with the rejected output quoted.
- **The evidence pack** — [`AWARDS/Best-Technical-Writeup/files/phantom-device/`](AWARDS/Best-Technical-Writeup/files/phantom-device/):
  solve scripts, lane reports, derivation audit and the accepted-flag record for the flagship card.
- **Full agent transcripts** — kept outside the repository (they contain instance data); the
  redacted findings from them are what appear in every card.

## 5. What we would not do again

- Run two lanes against the same state file without a lock — we lost one walk that way.
- Treat a gate message as flavour text. "The navigator has not recorded a delay" is a spec.
- Guess a flag shape more than twice. After the second wrong candidate the ledger is cheaper than
  the guess, and the event rules penalise flooding.
