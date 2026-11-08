# Operation Dawn: The Reconnaissance Plate

**Author:** Varenik14  
**Category:** Misc  
Handout: [recon-plate.png](files/recon-plate.png)

## Solve

I read the PNG pixels in RGB order and packed the bits from each low bit plane most-significant bit first. The least significant bit held a gzip archive with a `DRILL` annotation. The second-least significant bit held another gzip archive starting four bytes into the packed stream.

I opened `plate/annotation.txt` in the second archive and read the actual recon serial `11`, the phrase `THE GUNS BEHIND THE RIDGE` and the check group `3F8C21`. I lowercased the phrase and check group and joined the serial, words and check group with underscores.

Install numpy and Pillow, then run [solve.py](solve.py) with `python solve.py`.

**Flag:** `CSCTF{11_the_guns_behind_the_ridge_3f8c21}`
