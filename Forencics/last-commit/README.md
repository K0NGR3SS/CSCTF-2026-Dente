# Last Commit

**Author:** kiriesh

**Forensics**
Handout: `files/last-commit.zip`

## Solve

The handout is a national land-registry export job: `registry.sqlite` + its write-ahead log `registry.sqlite-wal`, plus `delivery.csv` (the ownership manifest), `export-profile.md` (the exact export query) and `provenance.json`. The task is to reproduce the ownership export that job **LR-731** completed and submit its `CSCTF{...}` fingerprint.

The current database looks clean — but the briefing says a restoration export may already have carried altered ownership into regional offices, and the WAL is the proof.

**Parsing the WAL.** It has 9 frames of 4096 bytes, all with correct salts and checksums. I replayed it commit-by-commit, building a standalone snapshot of the DB at each commit (base file + every WAL frame up to that commit, with the page count trimmed to the commit size). Checking `export_job` in each snapshot:

- frame 4: `LR-731 = QUEUED`
- **frame 5: `LR-731 = COMPLETED`** — this is the moment the export ran, and `integrity_check` passes here.
- frames 6–8: the job is still COMPLETED, but the parcel owners have been rolled back to "clean" values — the deceptively normal state.

**The export.** Using the snapshot at frame 5, I loaded `delivery.csv` as the `manifest` table and ran the profile's query (join `parcel`/`title`/`holder`, filter `job_id='LR-731'`, order by `position`, then `registry_ref` BINARY), serialised the rows with TAB separators and LF line endings exactly as the profile specifies, and took its SHA-256. The profile's own sample vector hashes the same way, confirming the formatting.

At export time parcels 1214, 1202, 1209 and 1205 had different holders and instrument refs (e.g. parcel 1209 split 6500/3500 instead of 6000/4000); hashing the *current* DB gives the wrong `…04a47a4f…` fingerprint.

**Flag:** `CSCTF{last_commit_40f3b19d5a11601e9d5e5bf0c7a3bcb6248b5667764f25549b607c27396ccf5f}`

Run [the solver](solve.py) with `python3 solve.py files/last-commit.zip`.
