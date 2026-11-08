#!/usr/bin/env python3
"""PoshTerm (CSCTF 2026, rev, 167 pts) - recover what the unlisted posh command prints.

Static analysis only; the Windows executable is never run.

  PoshTerm.exe is a 217 MB PE whose overlay carries the bundled JavaScript of its built-in shell
  (`posh`). Carving the text run around the cmdlet table yields work/posh.js. Among the registered
  cmdlets is one with `hidden:!0`:

      t._sc = { name:"service_code", spec:[Rest+], help:"", hidden:!0, run: async n => {
          let c = n.Rest.map(toStr);
          if (c.length < 2 || c[0] !== "=") throw notFound("service_code");
          let l = c[c.length-1];
          if (md5(process.env.POSHTERM_PROFILE||"") !== D.host || md5(l) !== D.code) throw ...;
          return [await A(l)]; } }

  A(l) searches Wikipedia for l, pulls the `first_flight` date off the article, converts it with
  NASA/JPL jd_cal.api (format=jd.7), and RC4-decrypts a 48-byte blob using the Julian-date STRING
  as the key. So the printed text depends on exactly one unknown: that date.

  We do not need the md5-gated arguments and we do not need the live sources. `format=jd.7` makes
  the key "<7-digit JD>.<7 decimals>", and a calendar date at 00:00 always lands on .5, so the whole
  key space is a few hundred thousand candidates. One of them decrypts the blob to clean ASCII that
  is exactly 48 bytes long and framed CSCTF{...} - the blob length and the plaintext length match
  with no padding, which pins the answer.

  Recovered key 2439047.5000000 = 1965-10-14 (confirmed against JPL's own converter).
  Note the live path is broken today: current Wikipedia HTML no longer contains the literal
  "first_flight", so A() would throw - which is the joke the plaintext tells.

usage: solve.py [path to PoshTerm.exe]      (default: dist/extracted/PoshTerm.exe)
"""
import mmap, os, re, sys

JS_ANCHOR = b"ssd-api.jpl.nasa.gov"
BLOB_RE = re.compile(rb'Buffer\.from\("([0-9a-f]{64,})","hex"\)')


def carve_blob(path):
    """Pull the RC4 ciphertext straight out of the executable's bundled JavaScript."""
    with open(path, "rb") as f:
        m = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        i = m.find(JS_ANCHOR)
        if i < 0:
            sys.exit("bundled posh JavaScript not found in this file")
        window = m[i:i + 2000]
        hit = BLOB_RE.search(window)
        if not hit:
            sys.exit("RC4 blob not found next to the JPL call")
        return bytes.fromhex(hit.group(1).decode())


def rc4(key, data):
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 255
        s[i], s[j] = s[j], s[i]
    out = bytearray()
    i = j = 0
    for b in data:
        i = (i + 1) & 255
        j = (j + s[i]) & 255
        s[i], s[j] = s[j], s[i]
        out.append(b ^ s[(s[i] + s[j]) & 255])
    return bytes(out)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "dist", "extracted", "PoshTerm.exe")
    blob = carve_blob(path)
    print(f"[+] RC4 blob: {len(blob)} bytes, {blob.hex()}")

    hits = []
    for day in range(2300000, 2500000):              # ~1500 AD to ~2050 AD
        key = f"{day}.5000000".encode()               # jd.7 of a date at 00:00
        plain = rc4(key, blob)
        if plain.startswith(b"CSCTF{") and plain.endswith(b"}") and plain.isascii():
            hits.append((key.decode(), plain.decode()))
    if len(hits) != 1:
        sys.exit(f"expected exactly one candidate, got {len(hits)}: {hits}")

    key, flag = hits[0]
    print(f"[+] Julian-date key: {key}")
    print(f"[+] service_code prints: {flag}")
    print("\nFLAG:", flag)


if __name__ == "__main__":
    main()
