# Ghost in the Historian

**Author:** Varenik14  
**Category:** Forensics  
Handout: [ghost-in-the-historian.zip](files/ghost-in-the-historian.zip)

## Solve

I verified the archive's manifest and read the ext4 filesystem directly from the flat VMDK extent. I found the deleted encryptor's ELF in unallocated data and disassembled it. The program seeded a 32-bit generator with `((time ^ pid) * 0x9e3779b1) & 0xffffffff`. Each xorshift32 step used shifts 13, 17 and 5 and yielded four little-endian keystream bytes. The state continued across files.

I got PID `2764964` from the historian log and the exact start second, 04:13:05 UTC, from the encrypted files' modification times. I tried the three files in each order and checked the decrypted config, cache and JSON. The consistent order was grid topology, historian cache, then node status. The config contained `SAFETY_INTERLOCK_TOKEN`.

Run [solve.py](solve.py) with `python solve.py`. It uses [ext4.py](ext4.py).

**Flag:** `CSCTF{xorshift_ghost_in_the_historian_d2c19434a637}`
