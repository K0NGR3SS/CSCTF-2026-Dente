# Radar Silence

**Author:** Varenik14  
**Category:** Network  
Handout: [radar-silence.pcapng](files/radar-silence.pcapng)

## Solve

I filtered the DNS queries from RDR37 at `192.0.2.37`. Four requests to `update.svc-telemetry.example` carried a fragment and a two-digit index in the leading labels. Frames 5, 9, 15 and 21 arrived in a different order from the fragment indices.

I sorted the fragments by indices 00–03, concatenated them and decoded the combined Base32 string. The result was the rotation token. I used the RDR37 rotation prefix with that token to form the flag.

Run [solve.py](solve.py) with `python solve.py`. It uses [capture.py](capture.py).

**Flag:** `CSCTF{rdr37_rotation_b1097f6e977015cac0297ddc3335509f}`
