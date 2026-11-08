# Flotsam

**Author:** Varenik14  
**Category:** Forensics  
Handout: [recorder-sectors.img](files/recorder-sectors.img)  
Mission: [Flotsam](https://2026.chronos-security.ro/challenges#Flotsam-9075)

## Solve

I scanned the recorder image for PNG signatures and chunk markers. The PNG started at offset `0x6800`, the beginning of sector 52. The first part of its IDAT chunk inflated from there, and the IEND chunk was in sector 47. The data between them had to be reassembled from out-of-order 512-byte sectors.

I joined sectors `52–67`, `3–20`, `35–41`, and `44–47` in that order, counting sectors from zero and keeping 159 bytes from sector 47. I checked the CRCs of IHDR, IDAT and IEND and inflated the IDAT stream. I read the flag from the recovery key printed on the [reconstructed chart](chart.png).

Run [solve.cjs](solve.cjs) with `node solve.cjs files/recorder-sectors.img recovered-chart.png` to rebuild the image.

**Flag:** `CSCTF{flotsam_0e91019a8e70267f550895930247d088}`
