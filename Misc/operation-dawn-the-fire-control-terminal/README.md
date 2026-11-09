# Operation Dawn: The Fire-Control Terminal

**Author:** Varenik14  
**Category:** Misc  
Service files: [case.ics](../command-calendar-reconciliation/files/case.ics), [brief.json](../command-calendar-reconciliation/files/brief.json)

## Solve

I opened the target shown for Fire-Control Terminal and found a `relaycal` service. I downloaded its `/brief` and `/case.ics`. Both files matched the inputs for Command Calendar Reconciliation byte for byte, so the [calendar solver](../command-calendar-reconciliation/solve.py) can reproduce the report.

I expanded the three recurring series, applied the `RDATE` and `EXDATE` lists, and matched the moved events by `RECURRENCE-ID`. I filtered on the resulting `DTSTART` within the July 6–21 UTC window. The July 22 occurrence moved into the window, and the July 20 occurrence moved out. I sorted the 24 activations by `start_utc` and sent the JSON to `/attest`.

```sh
python -m pip install python-dateutil
calendar=../command-calendar-reconciliation
python "$calendar/solve.py" --calendar "$calendar/files/case.ics" --brief "$calendar/files/brief.json" --output attestation.json
curl -H 'Content-Type: application/json' --data-binary @attestation.json "$INSTANCE_URL/attest"
```

The target responded with HTTP 200 and returned this value in `routing_authorization`.

**Flag:** `CSCTF{KRIB6orpfS2E8ckNV4jSenWX}`
