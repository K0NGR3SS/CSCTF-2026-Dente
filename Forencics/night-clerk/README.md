# Night Clerk

**Author:** Varenik14  
**Category:** Forensics  
Handout: [terminal.dd](files/terminal.dd)

## Solve

I carved the deleted Word document from the NTFS image and read the deleted audit log. The log pointed to a tracked insertion in the DOCX and said to hex-decode it before applying a single-byte XOR. I opened `word/document.xml` directly and read the hexadecimal text from `w:ins`.

The log described deriving the XOR key from a timestamp difference. I tested all 256 one-byte keys against the full flag format. Only decimal 57 (`0x39`) produced a match.

Run [solve.py](solve.py) with `python solve.py`.

**Flag:** `CSCTF{hid_skew_redline}`
