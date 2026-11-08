# stepper

**Author:** Classified

**Pwn**

**Approach**

Full working log in our per-challenge notes. Same discipline as the other three pwn solves: leak
before writing, assert every derived base is page-aligned, reproduce the shell locally in the
isolated VM across repeated runs, and touch the assigned instance only for the final run.

**Validation**

Flag produced by a clean `solve.py` run.

## Reverse engineering

**Flag:** _solved on the other workstation; add flag and solve.py from there._

*AI: Opus 5 cyber verification assisted with reversing, scripting, and cross-checking; every flag was produced by a reproducible solver and submitted by hand.*
