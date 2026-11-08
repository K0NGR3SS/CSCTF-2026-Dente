# Command Calendar Reconciliation

**Author:** Varenik14  
**Category:** Misc  
Handout: [case.ics](files/case.ics), [brief.json](files/brief.json)

## Solve

I downloaded `/brief` for the attestation schema and `/case.ics` for the relay calendar. The brief set the UTC window from July 6 at 00:00 up to July 21 at 00:00.

I expanded each event's `RRULE`, added the `RDATE` occurrences, and removed the `EXDATE` occurrences. I matched each rescheduled event by its `UID` and original `RECURRENCE-ID`. One activation moved from July 22 into July 6, so I kept its July 22 recurrence ID and used its July 6 start time. I filtered by the actual start and sorted the remaining 24 records by `start_utc`.

I used [solve.py](solve.py) to build the attestation, then sent the JSON to `/attest` with `Content-Type: application/json`. The response returned the flag in `routing_authorization`.

```sh
python -m pip install python-dateutil
python solve.py --calendar files/case.ics --brief files/brief.json --output attestation.json
curl -H 'Content-Type: application/json' --data-binary @attestation.json "$INSTANCE_URL/attest"
```

**Flag:** `CSCTF{KRIB6orpfS2E8ckNV4jSenWX}`
