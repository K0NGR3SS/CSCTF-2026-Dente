import csv
import io
import json
from pathlib import Path
from zipfile import ZipFile


def rows(archive, fragment):
    name, = (name for name in archive.namelist()
             if Path(name).name.startswith(fragment) and name.endswith(".csv"))
    return list(csv.DictReader(io.StringIO(archive.read(name).decode("utf-8-sig"))))


with ZipFile(Path(__file__).parent / "files" / "code_red_freight.zip") as archive:
    audit = rows(archive, "AuditLogs_")
    signins = rows(archive, "InteractiveSignIns_") + rows(archive, "NonInteractiveSignIns_")
    events = [json.loads(row["AuditData"]) for row in rows(archive, "UnifiedAuditLog_")]

device_registrations = {
    (row["IPAddress"], row["AdditionalDetail5Value"]): row["Target1DisplayName"]
    for row in audit if row["Activity"] == "Register device"
}
outlook = {(row["IP address"], row["Device ID"]) for row in signins
           if "Outlook" in row["Application"] and row["Original transfer method"] == "deviceCodeFlow"}
for event in events:
    if event.get("Operation") != "New-InboxRule":
        continue
    source = event.get("ClientIP", "").partition(":")[0]
    key = source, event.get("DeviceId")
    if key not in device_registrations or key not in outlook:
        continue
    parameters = {p["Name"]: p["Value"] for p in event["Parameters"]}
    if "ForwardTo" not in parameters:
        continue
    downloads = {row["ObjectId"] for row in events if row.get("Operation") == "FileDownloaded"
                 and row.get("ClientIP", "").partition(":")[0] == source}
    print(f"CSCTF{{{device_registrations[key]}_{parameters['Name']}_{len(downloads)}}}")
