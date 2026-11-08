# Signal Reconciliation

**Author:** Varenik14  
**Category:** Forensics  
Handout: [signal-reconciliation.zip](files/signal-reconciliation.zip)

## Solve

I integrated the east and north velocities over the 100 ms intervals with the exact integer trapezoid rule from the SOP. I subtracted the integrated positions from the GPS positions and checked every possible 10-sample window. Eighteen windows qualified. The final residual was 100,000 mm east and 1,000 mm north, so the decision was `QUARANTINE_GNSS_PROFILE`.

I serialized the header, all 601 evidence rows and the summary as ASCII with LF endings, including after the summary. I first checked the serializer against the public all-zero test vector. For the incident report, I took the first 24 bytes of the SHA-256 digest and encoded them as uppercase Base32 without padding.

Run [solve.py](solve.py) with `python solve.py`.

**Flag:** `CSCTF{EOSL5C6VZ54TN2PWXUO2B5TVHMVY5G3NWPILLYY}`
