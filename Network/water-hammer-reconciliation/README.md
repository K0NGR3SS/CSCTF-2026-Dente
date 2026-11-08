# Water Hammer Reconciliation

**Author:** kiriesh

**Network**
Handout: `files/water-hammer-reconciliation.zip`

## Solve

The capture `reserve-header.pcapng` is one clean TCP connection from `192.0.2.10:36853` to `192.0.2.20:502` — **Modbus/TCP**. There is no `tshark` dependency: the solver parses the pcapng blocks, reassembles both TCP streams (no gaps, duplicates or reordering), and splits them into Modbus ADUs. `station-profile.txt` defines which writes count and how to turn them into the flag.

**The decoys** (named in the profile, all present):
- transaction IDs `E010`/`E011` and `E012`/`E013` are plain register reads outside any write-then-readback sequence;
- write `E100` got an FC16 exception response (code 04);
- write `E101` never got a response.

**The confirmed writes.** The 64 writes with transaction IDs `2000 … 242F` are each a valid FC16 (write multiple registers) to registers `0x1000–0x1003` on unit 17, each followed immediately by an FC03 read of all four registers whose returned values match what was written. Those 64 are the real attack.

**Building the flag.** For each confirmed write the profile's formulas give a velocity `V(p,g)`, a surge quantity `Q`, and a per-row "unsafe" bit (ARMED, `RAMP_US` below the threshold, surge over the limit, velocity changed from the previous row). The 64 bits form `unsafe-mask=D3FC7C00A3060000`. The report (header + one line per write + the mask) is hashed with SHA-256 and the first 24 bytes are Base32-encoded. The profile's own sample vector hashes identically, confirming the serializer.

**Flag:** `CSCTF{L3LBJQQRIXYIBUFDABBXKLH2EEHWDIUZAM2R3XQ}`

Run [the solver](solve.py) with `python3 solve.py files/water-hammer-reconciliation.zip`.
