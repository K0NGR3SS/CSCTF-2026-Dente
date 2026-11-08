# Apogee

**Author:** Classified

**Web**

**Approach**

1. The portal's own pipeline journal identifies the hostile package without any guessing: one entry
   reports six entries validated against seven in the archive, lists the same table name **twice**, and
   its extraction record shows that name as a **symlink** pointing out of the staging area into the
   write-protected trusted store.
2. **The vulnerability is a parser differential plus honoured archive symlinks.**
   - ZIP permits two central-directory entries with the same name; the specification imposes no
     uniqueness. The manifest verifier resolves a name to exactly one entry — the **last** — and hashes
     only that.
   - The extractor processes **every** entry in order and honours unix mode bits, so an entry with the
     right external attributes becomes a real symlink on disk.
   - Ordering the symlink entry *before* a regular file of the same name makes the extractor write the
     file **through** the symlink, landing outside the sandbox. No entry path contains `..`, so the
     path-safety check never fires, and every manifest hash is honest.
3. The first submission declared the symlink member in the manifest and was rejected for a size
   mismatch — which is itself the proof that the verifier keeps the **last** entry. Re-declaring the
   last (file) entry was accepted, and extraction wrote through the symlink.
4. The analyst route requires no vendor accreditation, so the same technique restores the validated
   table.
5. The receipt was initially locked; the unlock value is a SHA-256 over fields the status endpoint
   publishes, computed from the documented unlock context rather than guessed.

**Why it works**

Two components disagree about what "the entry named X" means — the verifier says the last one, the
extractor says all of them in order. Everything the verifier checks is true; it is simply not checking
the entry that lands on disk.

**Validation**

Confirmed by the audit trail itself: after the restore, the trusted table's SHA-256 equals the
validated original's at the same byte length. That is the condition the challenge defines as success,
checked directly rather than inferred from the response text. The first (rejected) submission cost one
request; two submissions total, well inside the rate limit.

**Flag:** `CSCTF{y9dBzsSUTIpEdKG6LEhoV3rc}`

Run the solver (`solve.py`); web/pwn solvers take your assigned instance address as an argument.

*AI: Opus 5 cyber verification assisted with reversing, scripting, and cross-checking; every flag was produced by a reproducible solver and submitted by hand.*
