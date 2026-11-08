# Briefing for One

**Author:** Varenik14  
**Category:** Forensics

## Solve

I inspected the shortcut statically and read the PowerShell command embedded in it. The command derived the archive password with HMAC-SHA256 using a key from the shortcut and the host's `MachineGuid`. I recovered the GUID `080c7be1-f41c-446c-b961-93bd7bc4ea31` from the supplied registry data.

I carved `route-update.7z` from the captured HTTP response and opened it with the derived password. The flag was the value of `briefing_token` in `route-table.json`. The archive hash and both extracted file hashes matched the values recorded in the shortcut. I treated the shortcut and DLL as data throughout.

The original handout ZIP is unavailable. This reconstruction uses the saved analysis of that handout.

**Flag:** `CSCTF{eab85b3bb8d309ec8f52a3f6271c55ff}`
