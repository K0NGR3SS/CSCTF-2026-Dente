# Operation Dawn: The Relay Tap

**Author:** Varenik14  
**Category:** Forensics  
Handout: [relay-tap.zip](files/relay-tap.zip)

## Solve

I found the ARLY exchange on TCP port 7443. Its descriptor defined a magic value, a message type and a big-endian body length. I took the client and server nonces from types 1 and 2, hashed their concatenation with SHA-256 and generated the keystream by hashing that key followed by successive big-endian 32-bit counters.

The two type-3 orders reused the same TCP sequence number. Frame 115 had a valid TCP checksum and the receiver acknowledged its end sequence in frame 116. Frame 117 came after that acknowledgment and had a bad TCP checksum. I XORed frame 115's order body with the keystream and recovered the flag.

Run [solve.py](solve.py) with `python solve.py`. It uses [capture.py](capture.py).

**Flag:** `CSCTF{16_cobalt_ingot_rowan_fathom_ca8f4addb0}`
