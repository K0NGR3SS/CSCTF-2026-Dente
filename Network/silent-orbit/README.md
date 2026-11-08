# Silent Orbit

**Author:** Varenik14  
**Category:** Network  
Handout: [silent-orbit-cfdp.zip](files/silent-orbit-cfdp.zip)

## Solve

I verified the handout against `SHA256SUMS` and followed the CFDP task in its `README.txt` and `mission-profile.txt`. The download contained a raw stream of Space Packets. I parsed all 188 and selected CFDP transaction `1/7/2`. The accepted Metadata and EOF agreed on a 192-byte file.

I merged the file-data intervals at the accepted EOF. Twelve one-byte gaps remained, at offsets 5, 19, 35, 51, 68, 83, 101, 119, 138, 154, 171, and 187. I encoded the missing half-open intervals in a CFDP NAK with scope `[0, 192)` and rendered the complete PDU as uppercase hex.

To reproduce the result, extract the handout and pass `civil_downlink.bin` to [solve.py](solve.py).

```sh
python -m zipfile -e files/silent-orbit-cfdp.zip evidence
python solve.py evidence/civil_downlink.bin
```

The platform's brief described a different parser and answer format. The flag below matches the downloaded handout and the output saved just before the solve appeared on the personal profile.

**Flag:** `CSCTF{280069000107020800000000000000C0000000050000000600000013000000140000002300000024000000330000003400000044000000450000005300000054000000650000006600000077000000780000008A0000008B0000009A0000009B000000AB000000AC000000BB000000BC}`
