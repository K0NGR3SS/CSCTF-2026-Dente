# CAPTCHA the Water Plant

**Author:** Varenik14  
**Category:** Forensics  
Handout: [ENG-LAPTOP-23.zip](files/ENG-LAPTOP-23.zip), [FIELD-WKS-21.zip](files/FIELD-WKS-21.zip), [OPS-NB-06.zip](files/OPS-NB-06.zip)

## Solve

I compared the KAPE exports and followed the activity on `OPS-NB-06`. Its RunMRU showed the PowerShell command that fetched the validator. The script-block log showed the validator installing AnyDesk and setting unattended access. The password in that command was the first part of the flag.

The same PowerShell log recorded the description of the scheduled task `Maitenance Check`. That description supplied the middle part, including its leading underscore. The browser evidence retained an admin dashboard URL with a token beginning `NVW-ADMIN-`. Its suffix was the final part.

Run [solve.py](solve.py) with `python solve.py`.

**Flag:** `CSCTF{f@k3_c@ptch@_r3@l_m@lw@r3_cl1ckf1xed}`
