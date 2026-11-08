import re
from pathlib import Path


files = Path(__file__).parent / "files"
log = (files / "06_intercepts_14AUG.txt").read_text(encoding="utf-8")
schedule = (files / "03_flight_schedule_14AUG.txt").read_text(encoding="utf-8")
callsigns = re.findall(r"^\d+\s+\S+\s+([A-Z]+)\s", schedule, re.MULTILINE)
for block in re.split(r"^#\d+\s+received", log, flags=re.MULTILINE)[1:]:
    rows = block.strip().splitlines()
    groups = " ".join(rows[2:-1]).split()
    if len(groups) != int(rows[-1]):
        continue
    ciphertext = "".join(groups)
    for key in callsigns:
        plain = "".join(chr(65 + (ord(ch) - ord(key[i % len(key)])) % 26)
                        for i, ch in enumerate(ciphertext)).replace("X", " ")
        if plain.startswith("DOKLAD"):
            print(f"{key}: {plain}")
