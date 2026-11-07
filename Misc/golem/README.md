# golem

**Author:** K0NGR3SS

**Misc**  
Handout: `files/golem.tar.gz`

## Solve

The archive has the GASM specification and 24 worked examples. I wrote [solve.py](solve.py) to parse `rep`, `ifz`, and `ifn` into nested blocks, then execute them with sixteen 16-bit registers and a byte input tape.

The details that mattered were 16-bit wraparound after every write, `div` by zero returning 65535, `mod` by zero keeping the dividend, shift counts masked with `& 15`, and an exhausted input tape returning 65535. Each conditional reads its register once at block entry. I checked the interpreter against all 24 examples before connecting.

The service sends `PROGRAM`, the code up to a single `.`, an `INPUT` line, then an `OUTPUT>` prompt. That prompt has no newline, so the client waits for the `OUTPUT>` bytes instead of trying to read a full line. It sends the resulting numbers separated by spaces, or an empty line when there is no output. All 100 rounds returned `OK`.

**Flag:** `CSCTF{cb43XCoGF0sbHW50vsiusFrz}`

Run [the solver](solve.py) with `python3 solve.py <assigned-host> <port>`. Crypto solvers use the handouts in `files/`; the web and pwn addresses must be your assigned instance.
