# Welcome Aboard

**Author:** Varenik14  
**Category:** Welcome

## Solve

I copied the encoded transmission from the mission briefing. It used the Base64 alphabet and ended in a padding character. I decoded it with Python and got the flag as plain ASCII.

```sh
python -c "import base64; print(base64.b64decode('Q1NDVEZ7dzNsY29tZV9hYm9hcmRfb3BlcmF0b3JfYTE3Zn0=').decode('ascii'))"
```

**Flag:** `CSCTF{w3lcome_aboard_operator_a17f}`
