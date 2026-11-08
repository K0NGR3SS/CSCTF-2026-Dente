# Operation Dawn: The Access Log

**Author:** Varenik14  
**Category:** Web  
Handout: [access.log](files/access.log)

## Solve

I grouped the checkpoint portal requests by client and decoded the `unit` query parameter. The injection tested one character at a time with `SUBSTR(token, position, 1)` and slept for two seconds on a match.

The briefing pointed to a client that never drew an error page. Among the clients injecting SQL, only `198.51.100.66` always got HTTP 200. I used the delayed response for each of its 41 positions and checked that there was exactly one hit per position. Reading the characters in order produced the complete token, including its wrapper.

Run [solve.py](solve.py) with `python solve.py`.

**Flag:** `CSCTF{07_beacon_tow_vigil_bollard_8c0371}`
