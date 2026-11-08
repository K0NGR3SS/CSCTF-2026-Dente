# Operation Dawn: The Medic's Phone

**Author:** kiriesh

**Forensics**
Handout: `files/medic-phone.ab`

## Solve

`medic-phone.ab` is an Android ADB backup: a 24-byte header (`ANDROID BACKUP`, version 5, compression 1, no encryption) followed by a zlib stream that inflates to a tar. The tar holds three apps — `org.unit43.courier`, `org.unit43.fieldnotes`, `org.unit43.radioset`.

The courier app keeps its chat in `apps/org.unit43.courier/db/messages.db`. Each row's `pb` column is a protobuf whose field 5 is a raw-deflate message body. Decompressing them, message 14 (from `signals`) now reads *"This message was withdrawn by the sender and is no longer available."* — the "notice" the briefing warns about.

But SQLite keeps a write-ahead log, and `messages.db-wal` still contains the **pre-withdrawal** version of that same page. The original message 14 is intact there:

> Movement order. Board the hospital train. Assignment follows: `CSCTF{03_at_platform_two_6f57d7}` Acknowledge on receipt and destroy this message.

It lines up with the fieldnotes hint *"Train: platform numbers change nightly, always confirm with signals"* — platform two.

The flag text survives verbatim in the WAL, so the solver just inflates the backup and greps the journal.

**Flag:** `CSCTF{03_at_platform_two_6f57d7}`

Run [the solver](solve.py) with `python3 solve.py files/medic-phone.ab`.
