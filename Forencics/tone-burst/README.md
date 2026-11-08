# Tone Burst

**Author:** Varenik14  
**Category:** Forensics  
Handout: [tone-burst.wav](files/tone-burst.wav)  
Mission: [Tone Burst](https://2026.chronos-security.ro/challenges#Tone%20Burst-9080)

## Solve

I read the mono 8 kHz PCM from the WAV and looked for the two tones in the burst. The carrier switches between 1,000 Hz and 2,000 Hz. Each symbol lasts 20 ms, which is 160 samples at this rate.

I started at 0.24 s and compared the energy at the two frequencies in each window. I decoded 1,000 Hz as 0 and 2,000 Hz as 1, then assembled bytes most-significant bit first. The stream began with `AA AA AA AA 7E`, and the ASCII flag followed the frame marker.

Run [solve.cjs](solve.cjs) from this directory with `node solve.cjs`. It checks the preamble before printing the flag.

**Flag:** `CSCTF{tone_burst_4481dda445a0a227c3a8eb90fda4fd92}`
