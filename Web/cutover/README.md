# Cutover

**Author:** Classified

**Web**

**Approach**

The whole authorization bypass was found by reading the four shipped source files **before touching the
instance**.

1. The vendored graph-reference JSON parser addresses nodes by their decimal index written as a string
   and resolves them with `input[value]` where `input` is a real `Array`. A reference whose text is
   `__proto__` is not an index at all — it reads `Array.prototype`, and the parser stores that live
   reference in the parsed object.
2. The intake path does `const basis = manifest.basis ?? {}` and then a one-level
   `target[key] = source[key]` merge. Point `basis` at `Array.prototype` through that reference and the
   merge becomes a write primitive straight onto `Array.prototype`.
3. The tier module stores grants in an **Array used as a dictionary** and tests `grants[action] ===
   true`, so the lookup falls through to the prototype chain. One poisoned manifest upgrades the
   session's tier.
4. The live instance then revealed a component absent from the handout: a risk gateway in front of the
   engine, with a published numeric grammar and a documented "defer downstream when undetermined"
   policy.
5. **The hostile batch was identified from the data, not guessed.** The buffer endpoint gives a
   position and a projection whose difference equals exactly one batch's settled aggregate — and that
   same batch is the only one whose settled aggregate disagrees with its own declared aggregate, and is
   far above its originator's historical maximum. Three independent signals, one batch.
6. **Number-grammar bypass.** The gateway blocks the plain decimal form of the capped value, but every
   exponent form — `3.46e7`, `3.46E+7`, `346e5`, `34600000.0`, `0.0346e9` — passes it, with the receipt
   showing the screening deferred, while the downstream JSON parser still yields the same integer.

**Why it works**

Three separate design choices compose: a graph-reference parser that will hand you a prototype, a
one-level merge that writes wherever it is pointed, and a permission check that reads through the
prototype chain because the grant store is an `Array`. None of the three is exploitable alone.

**Two theories killed on paper**

The first two chains proposed were wrong and were discarded before any request was sent: (a)
`JSON.parse`'s own `__proto__` key reaching `Object.prototype` through the merge — it cannot, a
one-level merge only re-points the single target object; (b) the reference resolver polluting during
revive — the key is an own data property, so the assignment is a plain write. The actual primitive is
narrower than both, and finding that out cost nothing because it was settled by reading.

**Validation**

Verified offline before a single live request: the real intake and tier modules were run in node and
the permission check was watched flip, then a local replica of the engine with synthetic state was
stood up and a recall was watched go from "tier insufficient" to reconciled after one poisoned
manifest. Live traffic totalled about a dozen requests, well inside the published rate limits. A detail
found while doing that, worth recording: normalisation runs **before** validation, so the prototype
write lands even when the poisoned manifest is afterwards rejected with a 400. The authorization code
is minted per container start (three starts gave three different codes), so the submitted one came from
the instance that was still running.

**Flag:** `CSCTF{haC12EbNmTvDSBIQqLHbysUh}`

Run the solver (`solve.py`); web/pwn solvers take your assigned instance address as an argument.

*AI: Opus 5 cyber verification assisted with reversing, scripting, and cross-checking; every flag was produced by a reproducible solver and submitted by hand.*
