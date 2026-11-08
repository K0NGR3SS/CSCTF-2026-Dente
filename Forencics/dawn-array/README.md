# Dawn Array

**Author:** Varenik14  
**Category:** Forensics  
Handout: [dawn-array.zip](files/dawn-array.zip)

## Solve

I read the Linux md v1.2 superblocks at byte 4096. Acquisitions 1, 3 and 2 were roles 0, 2 and 3. Role 1 was missing. The array used left-symmetric RAID-5, 32 KiB chunks, a 1 MiB member data offset and a logical size of 122,683,392 bytes. I rebuilt the missing data with parity and extracted the procedure, SQLite ledger, WAL, syslog and packet capture from ext4.

With the WAL applied, the ledger contained 128 cycles instead of 95. I reassembled the controller's TCP streams and applied DP-7: the ledger, four syslog phases, HTTP reservation and same-connection readback all had to agree. Sixteen cycles qualified, including three that only appeared in the WAL.

I serialized the six witness fields per qualifying cycle in gateway sequence order, prefixed `RRCA-DAWN-WITNESS-v1` and kept one LF at the end of every line. SHA-256 over the full witness produced the flag.

Run [solve.py](solve.py) with `python solve.py`. It uses [capture.py](capture.py) and [ext4.py](ext4.py).

**Flag:** `CSCTF{dawn_12d6b2bf2703a884e970e2c4d0070c894c8cf53be91d44feabeb44e18c02eefb}`
