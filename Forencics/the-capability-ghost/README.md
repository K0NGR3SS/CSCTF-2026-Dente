# The Capability Ghost

**Author:** Varenik14  
**Category:** Forensics  
Handout: [capability-ghost.zip](files/capability-ghost.zip)  
Mission: [The Capability Ghost](https://2026.chronos-security.ro/challenges#The%20Capability%20Ghost-9072)

## Solve

I verified the handout files against `manifest.sha256` and inspected the runner filesystem tarball and journal. The service and provisioning records referred to `hc-probe --seal`. I read the `SCHILY.xattr.user.build_seal` PAX attribute on `usr/local/bin/hc-probe` and recovered `X_SEAL_EPOCH=1793294042` from the journal.

I used the raw bytes of the extended attribute as the HMAC-SHA256 key and the ASCII epoch as the message. XORing the resulting mask with `etc/solunet/signaling-cfg.sealed` recovered the flag. The script reads the stored archive metadata and leaves file capabilities untouched.

Run [solve.cjs](solve.cjs) with `node solve.cjs`.

**Flag:** `CSCTF{fg6_x7i9b6b3nn_bj7sj}`
