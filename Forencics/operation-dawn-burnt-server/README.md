# Operation Dawn: The Burnt Server

**Author:** Varenik14  
**Category:** Forensics  
Handout: [server-remains.tar](files/server-remains.tar)

## Solve

The salvage note identified disks 0 and 2 as the survivors of a three-disk array. I XORed the survivors to reconstruct disk 1 and interleaved 64 KiB chunks using rotating right parity. The resulting logical image contained a FAT16 volume.

The root directory had a deleted `?RAIN.GZ` entry marked `0xE5`. Its first cluster was 16 and its size was 16,599 bytes. I used the FAT16 geometry to find the data at logical offset `0xde00`. The gzip stream decompressed to a 76,901-byte register with a valid checksum. The `MOVEMENT ORDER:` line held the complete flag.

Run [solve.py](solve.py) with `python solve.py`.

**Flag:** `CSCTF{04_flint_arc_eastward_relay_6aa299}`
