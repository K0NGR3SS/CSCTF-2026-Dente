# Shadow-Dispatch

**Author:** kiriesh

**Forensics**
Handout: `files/shadow-dispatch.zip`

## Solve

The handout is the incident export for an AWS Lambda order-authorizer (`gridlink-order-authorizer`): CloudTrail, CloudWatch log streams, the function/layer zips, config history and IAM. The function code is clean — `CodeSha256` is identical across all 10 published versions — so the tampering is in a **Lambda layer**.

**The malicious layer.** The `auth-utils` layer ships `python/_authlog.py` plus its compiled `python/__pycache__/_authlog.cpython-312.pyc`. In versions 4/6/8/10 the `.py` source differs from v1 only by a `# build:` comment (pure decoy), but the `.pyc` is a **hash-based, unchecked** pyc (flags byte `01`), so CPython runs the bytecode without re-checking it against the source. The malicious versions are even visibly larger (~3576 bytes vs 2788). Disassembling the bytecode (`marshal` + `dis`) shows it imports `boto3`, carries four SSM parameter names, and adds a `_beacon(order_id)`: when `order_id % 5 == 0` it reads a secret (`_NAMES[_PICK]`) instead of a file hash and leaks **2 bytes per invocation** through the `correlation=` field of each log line. Those logs are forwarded by the `grid-telemetry` subscription filter to a Kinesis stream in a foreign account (`488888888888`).

Which secret each layer version steals:

| layer | `_PICK` | secret |
|---|---|---|
| v4 | 0 | portal-session-secret |
| v6 | 2 | db-readonly-password |
| **v8** | **1** | **order-hmac-key** |
| v10 | 3 | metrics-api-token |

**Decoding the exfil.** Each `correlation` token is `index(1) ‖ ct(2) ‖ crc16(2) ‖ salt(11)`. The keystream is `sha256(RequestId ‖ salt)[:2]`, and the RequestId is in every log line, so `pt = ct XOR keystream`. Collecting all tokens from the version-8 logs with `order_id % 5 == 0` and reassembling the 8 two-byte chunks (each verified by its CRC-16/CCITT) rebuilds `/gridlink/order-hmac-key`. CloudTrail has no `PutParameter`, so the key was never rotated, and the signer always logged `key_version=1` — the stolen key is the live one.

**Flag:** `CSCTF{b6b0881524852112e5d422f75053d324}`

Run [the solver](solve.py) with `python3 solve.py files/shadow-dispatch.zip`.
