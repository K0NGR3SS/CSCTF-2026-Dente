# VaultKeeper

**Author:** Varenik14  
**Category:** Mobile  
Handout: [vaultkeeper.apk](files/vaultkeeper.apk)

## Solve

I checked the APK's SHA-256 against the briefing and followed the recovery flow in `classes.dex`. `RecoveryDiagnosticsActivity` checks the URI `vault://recover?stage=1` and compares the supplied recovery token with the result from `VaultDiagnosticsProvider`. The provider derives the token from the first eight uppercase hex characters of the signing certificate's SHA-256 and wraps them in `KJSC-…-RECOVERY`. The original APK gave `KJSC-1C28DC7E-RECOVERY`.

`RecoveryStage2Receiver` expects the broadcast extra `archive_key` to equal `3778F16D`. The archive screen takes four digits, computes HMAC-SHA256 with the session string `VK-7F42` as the key, and displays the first eight hex characters. I checked all 10,000 four-digit values and found that only `4972` produced the expected prefix.

The unlock handler hashes the concatenation of the recovery token, the archive digits and the master passcode with SHA-256. I used the briefing's authorization code as the passcode. The unlock handler Base64-decodes resource `0x7f0f0038`, uses its first 12 bytes as the nonce, and decrypts the rest with AES-GCM. The authentication tag verified and the plaintext matched the flag.

Install `cryptography` and run [solve.py](solve.py).

```sh
python solve.py --master-passcode ZHUU-SANS-9XJN-QPCQ
```

**Flag:** `CSCTF{intent_uri_and_a_broadcast_unlock_the_vault}`
