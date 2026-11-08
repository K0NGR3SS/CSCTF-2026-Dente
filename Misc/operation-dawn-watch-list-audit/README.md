# Operation Dawn: Watch List Audit

**Author:** Varenik14  
**Category:** Misc  
Handout: [watch-list-audit.zip](files/watch-list-audit.zip)

## Solve

I fit an affine model to the most recent observations in `history.csv` and walked backward until a row stopped matching. The change fell at zero-based index 209. Separate models fit rows 0–208 and 209–499 with residuals near floating-point precision.

I refit the latest model on all 291 rows after the change and scored the 32 probes in file order. I computed `floor(1000 * score + 0.5)` for each value and wrote each decimal integer followed by an ASCII LF, including the last. The SHA-256 of those bytes gave the flag.

Run [solve.py](solve.py) with `python solve.py`.

**Flag:** `CSCTF{114ca27d8c3e02e5ec872dd02b83707cae245e2f07dadaa622867cf9b3894287}`
