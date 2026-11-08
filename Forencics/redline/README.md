# Redline

**Author:** Varenik14  
**Category:** Forensics  
Handout: [CC-11_excursion_directive.docx](files/CC-11_excursion_directive.docx)

## Solve

I opened the DOCX as a ZIP and read `word/document.xml` and `word/comments.xml`. A tracked edit replaced the original quarantine requirement with a clause that allowed stock to return to distribution. The linked comment said the editor was dropping the quarantine hold and issuing a fresh authorization.

I read the deleted runs of that paragraph in document order. The original authorization was split across two `w:delText` nodes. Joining them recovered the flag. The `dispatch_…` value was the fresh authorization in the inserted text.

Run [solve.py](solve.py) with `python solve.py`.

**Flag:** `CSCTF{redline_21ee9b19d342e06432165fb2b6f64e06}`
