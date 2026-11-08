#!/usr/bin/env python3
"""Rebuild the hidden export packet from the controlled report page.

Usage: python3 solve.py <base_url> [doc_id]
e.g.   python3 solve.py http://<assigned-host>:<port> c2e4ba411ae39ac4

The controlled page ships a `window.__EXPORT__` blob and builds the file entirely
in the browser via /assets/exporter.js. exporter.js: join the parts, transcode a
custom base64 alphabet back to standard, atob, then XOR with an xorshift32 stream
keyed by `seed`. The result is a ZIP; the release-authorization file inside holds
the flag.
"""
import base64
import json
import re
import sys
import urllib.request
import zipfile
import io

base = sys.argv[1].rstrip('/')
doc_id = sys.argv[2] if len(sys.argv) > 2 else "c2e4ba411ae39ac4"

html = urllib.request.urlopen(base + "/d/" + doc_id, timeout=20).read().decode()
cfg = json.loads(re.search(r'window\.__EXPORT__\s*=\s*(\{.*?\});', html, re.S).group(1))

STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
packed = "".join(cfg["parts"])
alpha = cfg["alphabet"]
std = "".join("=" if c == "=" else STD[alpha.index(c)] for c in packed)
raw = base64.b64decode(std)


def xorshift32(seed):
    x = seed & 0xffffffff
    while True:
        x ^= (x << 13) & 0xffffffff
        x ^= x >> 17
        x ^= (x << 5) & 0xffffffff
        x &= 0xffffffff
        yield x & 0xff


g = xorshift32(cfg["seed"])
blob = bytes((b ^ next(g)) & 0xff for b in raw)

zf = zipfile.ZipFile(io.BytesIO(blob))
for name in zf.namelist():
    data = zf.read(name)
    print("===", name, "===")
    print(data.decode(errors="replace"))
