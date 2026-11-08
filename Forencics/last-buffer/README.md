# Last Buffer

**Author:** Varenik14  
**Category:** Forensics  
Handout: [last-buffer-handout.zip](files/last-buffer-handout.zip)

## Solve

I used `case-context.json` to identify the incident file and terminal `pts/4`. The shell journal recorded a disconnect at 02:19:46 UTC. The audit timeline recorded Vim PID `8442` receiving `SIGHUP` at that time and the collector taking the disconnect snapshot a second later. The `.swp` header held that PID and the expected original path. The older `.swo` belonged to PID `8124` on `pts/7`. Its authorization decoded to `retired-training-readback-16`.

I read the Vim swap's 4096-byte pages and recovered the strings from its data block using the line offsets described in the handout. The recovered revision was `INC-4471/R18`, marked `UNSAVED-AT-DISCONNECT`. Its `base_file_sha256` matched both the saved Markdown file and the checksum in the shell journal. Base64url-decoding the recovered `authorization_b64` gave the flag.

Run [solve.py](solve.py) with `python solve.py`.

**Flag:** `CSCTF{last_buffer_4051c9f6b0d9622479785f613b063916}`
