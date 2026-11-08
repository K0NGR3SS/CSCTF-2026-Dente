# Telltale

**Author:** Varenik14  
**Category:** Misc  
Handout: [telltale.wav](files/telltale.wav)  
Mission: [Telltale](https://2026.chronos-security.ro/challenges#Telltale-9081)

## Solve

I inspected the 48 kHz mono PCM and found two amplitude levels. The frame starts at sample 12000. I averaged blocks of 24 samples and used 12729 as the threshold. Each pair of blocks encodes a Manchester bit. A low-to-high pair is 1 and a high-to-low pair is 0.

I packed the bits most-significant first. Eight `AA` bytes made up the preamble, followed by the `7E` marker, the `30` length byte and 48 bytes of ASCII. I computed CRC-8 with polynomial `0x07` and initial value `0x00` over the length byte and payload. It matched the final frame byte `0x37`.

Run [solve.cjs](solve.cjs) with `node solve.cjs` to decode the frame and verify the CRC.

**Flag:** `CSCTF{telltale_05c3394a279a6cd9108388d5f1d45036}`
