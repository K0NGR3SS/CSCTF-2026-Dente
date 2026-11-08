# Operation Dawn: Relay Snapshot

**Author:** Varenik14  
**Category:** Forensics  
Handout: [relay.core](files/relay.core)

## Solve

I inspected the captured memory in `relay.core` and found a `CSCTF` fragment at the head of a linked list. Each node stored an eight-byte next pointer, a four-byte length and the fragment bytes. The nodes appeared out of order in the file.

I used the ELF `PT_LOAD` segments to convert each virtual pointer to a file offset. I followed 11 nodes from the head, read exactly the recorded number of bytes from each, and stopped at the null pointer. The concatenation produced the complete flag.

Run [solve.py](solve.py) with `python solve.py`.

**Flag:** `CSCTF{20_dock_move_orchard_elm_grove_dusk_86659c}`
