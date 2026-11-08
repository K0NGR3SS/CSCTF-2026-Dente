# HELIOS-RTU

**Author:** Classified

**Reverse engineering**

**Tools used**

A Python WebSocket client of our own — the console is a dumb terminal, and its own front-end source
says outright that the browser holds no challenge logic, so the socket was driven directly and the UI
never used; `avrdude`; `radare2` with the AVR architecture.

**Approach**

1. **Identify the silicon, then find the one live interface.** Wiring the ISP adapter to the ICSP
   header returns the device signature (ATmega328P) and the fuses: lock mode 3 — serial programming
   may read signature and fuses but refuses flash — SPIEN programmed so ISP is alive, **DWEN
   unprogrammed so debugWIRE is dead**, and BOOTRST programmed so the part boots into its bootloader.
2. **Two of the four offered adapters are decoys, and the fuses prove it.** The ATmega328P has no
   JTAG at all, and debugWIRE is fused off — so the JTAG and debugWIRE adapters cannot work. This was
   settled from the part number and the DWEN bit *before* any wiring was attempted.
3. The live interface is the resident serial bootloader. Lock bits restrict external serial and
   parallel programming — **not the bootloader's own reads of its own flash**. Dumping over the USB
   serial adapter therefore yields the full 2 KB application image. The boot section reads back as
   erased and the AES key lives there, so the brief's "physically unreadable from outside" is
   literally true and entirely irrelevant.
4. A hidden service command is absent from the help listing and not installed; it is provided by the
   image's own package manager, and must be reinstalled on every new connection because each session
   starts clean.
5. Disassembling the firmware gives the dispatcher. `sign` rejects a record whose first byte is the
   directive marker and otherwise replies with the raw AES-128 of the record. `exec` takes a 32-byte
   frame plus a 16-byte tag and checks `tag == AES(B2 ⊕ AES(B1))` — **plain CBC-MAC with a zero IV and
   no CMAC subkeys** — then requires the directive marker, a command byte, and the live nonce inside
   the second block.

**Why it works**

`sign` is an encryption oracle for exactly the primitive the MAC is built from, so two queries forge a
tag for a frame that was never signed: `T1 = sign(B1)`, then `tag = sign(B2 ⊕ T1)`, which is
`AES(B2 ⊕ AES(B1))` by construction. `B1` is free. The marker guard on `sign` only blocks submitting
the directive block *itself* — the masked block `B2 ⊕ T1` sails straight through, because masking
destroys the recognisable prefix the guard looks for. CBC-MAC without length encoding or distinct
subkeys is existentially forgeable, and this implementation has neither.

**Validation**

The MAC construction was confirmed in the disassembly — specifically the *absence* of CMAC subkey
derivation — before the forgery was attempted, rather than inferred from the oracle's behaviour. Only
a handful of hand-written commands ever reached the instance: no scanning, no brute force, no fuzzing.
Flag from a clean `solve.py` run.

**Flag:** `CSCTF{4E8xiDAsux3XbcKYIn2BtS3b}`

Run the solver (`solve.py`); web/pwn solvers take your assigned instance address as an argument.

*AI: Opus 5 cyber verification assisted with reversing, scripting, and cross-checking; every flag was produced by a reproducible solver and submitted by hand.*
