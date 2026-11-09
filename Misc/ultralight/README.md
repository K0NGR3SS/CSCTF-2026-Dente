# ultralight

**Author:** Varenik14  
**Category:** Misc  
Handout: [card_sam.bin](files/card_sam.bin), [card_frida.bin](files/card_frida.bin)

## Solve

I compared the two 192-byte card dumps and decrypted bytes 24 through 159 with 3DES-CBC. I used the default Ultralight C key `BREAKMEIFYOUCAN!` and read the eight-byte IV at offset 16 from the dump. The plaintext gave me the name, user type, timestamp, and checksum fields.

I kept Sam's timestamp, set `user_type` to `0x03`, and used a fresh seven-byte UID and the name `overseer`. I recalculated both UID check bytes and stored the CRC-32 of the UID, eight-byte timestamp, and one-byte user type as a big-endian integer. I encrypted the updated record and sent the rebuilt card to `/api/validate`. The validator accepted it as an administrator card and returned the flag.

```sh
python -m pip install cryptography
python solve.py files/card_sam.bin admin.bin --uid 04aabbccddee11 --name overseer
curl -F 'card=@admin.bin;type=application/octet-stream' "$INSTANCE_URL/api/validate"
```

The [solver](solve.py) reproduces the accepted card with the UID and name above.

**Flag:** `CSCTF{GzZrylEwSC6VEcd37BhhAGKN}`
