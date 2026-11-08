import re
from pathlib import Path
from zipfile import ZipFile


def text(archive, suffix):
    name, = (name for name in archive.namelist() if name.endswith(suffix))
    raw = archive.read(name)
    return raw.decode("utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig",
                      errors="replace")


with ZipFile(Path(__file__).parent / "files" / "OPS-NB-06.zip") as archive:
    events = text(archive, "_EvtxECmd_Output.csv")
    shortcuts = text(archive, "_CustomDestinations.csv")
password, = set(re.findall(r'--set-password\s+[^A-Za-z0-9@]*([a-zA-Z0-9_@]+)', events))
description, = set(re.findall(r'ParameterBinding\(Register-ScheduledTask\): name="+"Description"+"; value="+"(_[a-zA-Z0-9_@]+)"', events))
token, = set(re.findall(r'token=NVW-ADMIN-([a-zA-Z0-9]+)', shortcuts))
print(f"CSCTF{{{password}{description}_{token}}}")
