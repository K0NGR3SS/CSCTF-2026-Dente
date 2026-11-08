import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from dateutil.rrule import rrulestr


def read_events(calendar):
    unfolded = []
    for line in calendar.splitlines():
        if line.startswith((" ", "\t")):
            unfolded[-1] += line[1:]
        else:
            unfolded.append(line)
    event = None
    for line in unfolded:
        if line == "BEGIN:VEVENT":
            event = {}
        elif line == "END:VEVENT":
            yield event
            event = None
        elif event is not None:
            name, _, value = line.partition(":")
            event.setdefault(name, []).append(value)


def utc(value):
    return datetime.strptime(value, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)


def iso(value):
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def one(event, name):
    value, = event[name]
    return value


def build_report(calendar, brief):
    masters, overrides = {}, {}
    for event in read_events(calendar):
        uid = one(event, "UID")
        if "RECURRENCE-ID" in event:
            overrides[(uid, utc(one(event, "RECURRENCE-ID")))] = event
        else:
            masters[uid] = event

    horizon_start = datetime.fromisoformat(brief["horizon_start_utc"].replace("Z", "+00:00"))
    horizon_end = datetime.fromisoformat(brief["horizon_end_utc"].replace("Z", "+00:00"))
    activations = []
    for uid, event in masters.items():
        start = utc(one(event, "DTSTART"))
        duration = utc(one(event, "DTEND")) - start
        identities = {start}
        if "RRULE" in event:
            identities.update(rrulestr(one(event, "RRULE"), dtstart=start))
        for key in ("RDATE", "EXDATE"):
            dates = {utc(date) for row in event.get(key, []) for date in row.split(",")}
            if key == "RDATE":
                identities.update(dates)
            else:
                identities.difference_update(dates)

        for nominal in identities:
            replacement = overrides.get((uid, nominal))
            if replacement is None:
                actual, end = nominal, nominal + duration
                category = one(event, "CATEGORIES")
            else:
                actual = utc(one(replacement, "DTSTART"))
                end = utc(one(replacement, "DTEND"))
                category = one(replacement, "CATEGORIES")
            if horizon_start <= actual < horizon_end:
                activations.append(dict(uid=uid, recurrence_id_utc=iso(nominal),
                                        start_utc=iso(actual), end_utc=iso(end),
                                        category=category))

    activations.sort(key=lambda row: row["start_utc"])
    if len(activations) != 24 or len({row["start_utc"] for row in activations}) != 24:
        raise ValueError("Expected 24 activations with strictly ordered start times")
    if any(row["category"] != "EMERGENCY-RELAY" for row in activations):
        raise ValueError("Unexpected event category")
    return {"activations": activations}


def main():
    here = Path(__file__).parent
    parser = argparse.ArgumentParser()
    parser.add_argument("--calendar", type=Path, default=here / "case.ics")
    parser.add_argument("--brief", type=Path, default=here / "brief.json")
    parser.add_argument("--output", type=Path, default=here / "attestation.json")
    args = parser.parse_args()
    brief = json.loads(args.brief.read_text(encoding="utf-8"))
    report = build_report(args.calendar.read_text(encoding="utf-8"), brief)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(report['activations'])} activations")


if __name__ == "__main__":
    main()
