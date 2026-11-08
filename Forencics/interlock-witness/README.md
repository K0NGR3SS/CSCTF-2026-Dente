# Interlock Witness

**Author:** Varenik14  
**Category:** Forensics  
Handout: [interlock-witness.zip](files/interlock-witness.zip)

## Solve

I paired the Modbus/TCP requests and responses by transaction ID, unit, function and direction. I updated the register state on normal FC03 reads and acknowledged FC16 writes. An exception response did not change the state.

I examined the state immediately before each acknowledged single-register write to `0x0013` or `0x0014`. Of the 120 target writes, 16 occurred while at least one prerequisite register (`0x000a`, `0x000b`, `0x000c`) was not 1. In response order, I appended each selected request and response PDU without its MBAP header. I hashed `INTERLOCK-WITNESS/1` followed by a zero byte and those 208 bytes.

Run [solve.py](solve.py) with `python solve.py`. It uses [capture.py](capture.py).

**Flag:** `CSCTF{1198b297c84064fab89d0f3e3e5308791165333c1b64da17185dd51493b6f339}`
