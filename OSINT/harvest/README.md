# Harvest

**Author:** Varenik14  
**Category:** OSINT  
Handout: [00_brief.txt](files/00_brief.txt), [01_telegram_post.txt](files/01_telegram_post.txt), [02_photo.png](files/02_photo.png), [03_flight_schedule_14AUG.txt](files/03_flight_schedule_14AUG.txt), [04_signals_instruction_extract.txt](files/04_signals_instruction_extract.txt), [05_logistics_sheet_14AUG.txt](files/05_logistics_sheet_14AUG.txt), [06_intercepts_14AUG.txt](files/06_intercepts_14AUG.txt)

## Solve

I used the radio instructions to check the number of cipher groups and decode the intercepts with the Vigenère keys from the flight schedule. The first report had 21 groups as declared and decrypted with `ZHATVA`, the callsign of bort 22. It reported delivery at PP-7 at 10:20 MSK, four pieces, codeword `SNOP`.

The logistics sheet lists PP-7 as the harvested field west of the dairy farm at Mirnoe and `SNOP` as a portable electronic-warfare jamming set. The other intercept had 25 groups despite a check group of 24. The public story pointed to PP-2, a closed landing site, and bort 34, which was out of service. I combined the verified landing site and cargo codeword.

Run [solve.py](solve.py) with `python solve.py` to print the validated plaintext report.

**Flag:** `CSCTF{PP-7_SNOP}`
