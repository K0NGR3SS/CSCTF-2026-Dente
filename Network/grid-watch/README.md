# grid-watch

**Author:** Classified

**Network**

**Tools used**

`pymavlink` for frame construction; exact rational least squares for the clock fit.

**Approach**

1. Handouts are a 24-frame signed MAVLink 2 capture and a field-service note describing the signing
   subsystem. The note was treated as a specification, not as instructions.
2. **Serial**, from the capture's status text: `CX-FALCON-9951`.
3. **RTC calibration — the actual puzzle.** The note says signing timestamps are 10 µs ticks since a
   *per-unit commissioning epoch* with a *per-unit ppm drift*, and that the epoch is an HKDF input,
   so it must be exact. Regressing the 24 signing timestamps against the log's wall-clock timestamps:

   ```
   slope             = 100001.699902 ticks/wall-second  ->  drift = +16.9990 ppm
   sigts = 0 at unix = 1733965122.9776                  ->  epoch = 1733965123
   max |residual|    = 0.527 ticks
   ```

   Rounding to `epoch = 1733965123, ppm = +17` reproduces **all 24** signing timestamps bit-exactly,
   and `epoch ± 1 s` or `ppm ± 0.1` fails on all 24. Uniquely pinned.
4. **Provisioning key.** The unit announces a fresh nonce per connection. Per the note,
   `prov_key = HKDF-SHA256(ikm = serial || u64le(epoch), salt = nonce, info = "CX-PROV/v1", L = 32)`.
   The one genuine ambiguity was the salt — the hex-decoded nonce or the ASCII string. Both were
   tested on separate connections: hex-decoded is accepted, ASCII is rejected.
5. **Key swap.** `SETUP_SIGNING` signed with `prov_key` installs a session key of our choosing;
   everything afterwards is signed with our own key.
6. **Flight.** Guided mode, arm, reposition. The code returns from the accepted reposition.

**Why it works**

MAVLink 2 signing is only as strong as its provisioning path. Here the key derivation is fully
determined by values the unit itself broadcasts plus a clock model recoverable from the capture, so
the signing key can be *replaced* rather than forged.

**Gotchas worth recording**

- **`COMMAND_LONG` only.** `SET_MODE` and `COMMAND_INT` are both rejected as "not a command for this
  drone"; `DO_SET_MODE` and `DO_REPOSITION` must be sent as `COMMAND_LONG`.
- **Timestamp monotonicity.** Signing timestamps must exceed the `initial_timestamp` installed by
  `SETUP_SIGNING`, not merely the last value seen from the drone. A counter seeded only from observed
  traffic earns `REJECT: replayed/old timestamp`. The sender takes the maximum of (RTC model from
  wall clock, last seen + 10, last sent + 10).

**Validation**

The clock model is accepted only because it reproduces all 24 observed timestamps exactly while
every neighbouring parameter fails all 24 — the fit is checked against data it did not get to choose.
It also tracks the live unit to within the measured round-trip (≈2.99 s after a 3.0 s read), an
independent confirmation against the airframe rather than just the capture. Flag printed by
`solve.py` from an accepted reposition command.

**Flag:** `CSCTF{kVbZ6v2QCXzM0Xp4Prl7T2pd}`

Run the solver (`solve.py`); web/pwn solvers take your assigned instance address as an argument.

*AI: Opus 5 cyber verification assisted with reversing, scripting, and cross-checking; every flag was produced by a reproducible solver and submitted by hand.*
