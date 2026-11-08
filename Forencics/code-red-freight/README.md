# Code Red Freight

**Author:** Varenik14  
**Category:** Forensics  
Handout: [code_red_freight.zip](files/code_red_freight.zip)

## Solve

I joined the device registration in the audit log to the Outlook sign-ins by IP and device ID. The registration named `D3VC0DE-R3L4Y`, and Outlook showed the same device using `deviceCodeFlow` from `203.0.113.77`.

The unified audit log had a `New-InboxRule` event from that IP and device. Its `Name` parameter was `M4N1F3ST-L3AK`, and `ForwardTo` confirmed it was a forwarding rule. I counted four distinct objects in the `FileDownloaded` events from the same IP. I combined the registered device name, rule name and download count in that order.

Run [solve.py](solve.py) with `python solve.py`.

**Flag:** `CSCTF{D3VC0DE-R3L4Y_M4N1F3ST-L3AK_4}`
