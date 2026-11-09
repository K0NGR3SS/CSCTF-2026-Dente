# Vesper Quay Board

**Author:** mar

**Web** · 291 pts

**TL;DR.** The desk and the quay parse the same warrant JSON with different rules: the desk is Go
(`encoding/json`, keys matched case-insensitively), the quay is Python (`json`, case-sensitive).
One body carrying both spellings makes the desk approve a benign `status` call while the quay runs
the legacy courier's `-c <script>` argument. That is unauthenticated code execution in the quay
loader; its child environment contains the station signing key, so the correction can be signed by
the quay itself and returned as the verification code.

## Solve

**Reconnaissance.** The card points at `GET /v1/openapi.json` on the desk. It documents
`POST /v1/warrants` (file a warrant, answered with the quay's decision and loader output) and
`POST /v1/corrections` (a correction for a warrant the quay actually ran). The desk validates the
courier, then forwards the raw bytes to the quay's `/internal/apply` with `X-Desk-Courier` and
`X-Submission-Id`; the quay re-parses the same bytes with Python.

The quay's `warrant.decide()` side is visible from its own behaviour: when the desk courier and the
quay courier disagree in the way the duty rule requires, the quay executes the legacy courier's
`argv` under a fixed `python3 -I` with no shell.

**The parser differential.** Send both key spellings in one object:

```json
{"courier":"c-25cb7a","argv":["-c","<python>"],"Courier":"c-4a7f55","Argv":["status"]}
```

- Go's `encoding/json` matches `Courier`/`Argv` case-insensitively and takes the last duplicate:
  desk courier `c-4a7f55` (the approved one), argv `["status"]`.
- Python's `json` is case-sensitive: quay courier `c-25cb7a` (the logged legacy courier), argv
  `["-c", "<python>"]`.

The desk approves; the quay runs our Python. The reply includes `loader_stdout` (first 4 KiB) and
`loader_stderr` (1 KiB), which is enough to work interactively.

**Looting the child environment.** The loader child's allowlist is `PATH`, `HOME`, `LANG`,
`PYTHONDONTWRITEBYTECODE`, `PYTHONNOUSERSITE`, `PYTHONSAFEPATH`, `STATION_KEY=/tmp/station.key`,
`STATION_SIGN=/usr/local/bin/station-sign`, `EDGE_URL`, `SUBMISSION_ID`, `QUAY_ID`, `WARRANT_ID`,
`COURIER_ID`. `FLAG` is deliberately absent. The signing helper and its key are not: a loader script
can call `$STATION_SIGN` with the key already in `$STATION_KEY`.

**Signing the correction.** The canonical bytes are RFC-8785-style compact JSON over the correction
object, with `applied_primary` as a boolean and the rest as strings:

```json
{"applied_primary":false,"courier_id":"c-25cb7a","quay_id":"QY-7C9E","submission_id":"<sid>","warrant_id":"WR-6AE8"}
```

Piping that to `$STATION_SIGN` returns a 64-byte Ed25519 signature; base64 is the wire form. The
correction is then a normal JSON POST with the desk's struct fields:

```json
{"applied_primary":false,"courier_id":"c-25cb7a","quay_id":"QY-7C9E",
 "submission_id":"<sid>","warrant_id":"WR-6AE8","signature":"<base64 64-byte sig>"}
```

`POST /v1/corrections` verifies the signature against the release the quay actually runs and
answers with `{"clearance_code":"CSCTF{...}"}`.

**Flag:** `CSCTF{C9LwQ9e90j1vcyINW4cyomA1}`

**Evidence.** The flag literal is in the team ledger `ctf-telecom/wave2/attempts_log.json`
(`cid 9116`, `status: correct`, one submission; CTFd solve 2026-11-07T13:19:33Z). The chain is
reconstructed from the dumped quay source (`ctf-telecom/wave2/app_dump_out.txt`), the live solve
helpers `wave2/qrun.py` and `wave2/wsign.py`, and the post-mortem in
`ctf-telecom/wave3/POSTMORTEMS.md`. The loader code and the signing script are preserved; the final
`/v1/corrections` payload was not saved verbatim, so its field list is reconstructed from the desk
schema quoted in the lane note. Copies of the dumped quay source and the live signing helper are in
[files/quay_app.py](files/quay_app.py) and [sign_live.py](sign_live.py); no handout existed for this
card.
