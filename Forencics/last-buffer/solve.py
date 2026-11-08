import argparse
import base64
import hashlib
import json
import re
import struct
from pathlib import Path
from zipfile import ZipFile


def swap_lines(data, page_size):
    for offset in range(page_size, len(data), page_size):
        block = data[offset:offset + page_size]
        if not block.startswith(b"ad"):
            continue
        line_count, = struct.unpack_from("<Q", block, 16)
        for index in range(line_count):
            start, = struct.unpack_from("<I", block, 24 + index * 4)
            start &= 0x7fffffff
            yield block[start:block.index(0, start)].decode("utf-8")


def main():
    parser = argparse.ArgumentParser(description="Recover the unsaved incident authorization")
    parser.add_argument("archive", nargs="?", type=Path, default=(
        Path(__file__).parent / "files" / "last-buffer-handout.zip"
    ))
    with ZipFile(parser.parse_args().archive) as archive:
        context = json.loads(archive.read("case-context.json"))
        audit = [json.loads(line) for line in archive.read("audit-timeline.jsonl").splitlines()]
        journal = [json.loads(line) for line in archive.read("shell-journal.jsonl").splitlines()]
        saved = archive.read(context["saved_file"])
        snapshots = [row for row in audit if row["event"] == "SWAP_SNAPSHOT"
                     and row["reason"] == "disconnect-capture"
                     and row["tty"] == context["target_tty"]
                     and context["crash_window_start"] <= row["time"] <= context["crash_window_end"]]
        if len(snapshots) != 1:
            raise ValueError("Expected exactly one snapshot taken at disconnect")
        if not any(row["event"] == "session_disconnect"
                   and row["tty"] == context["target_tty"]
                   and context["crash_window_start"] <= row["time"] <= snapshots[0]["time"]
                   for row in journal):
            raise ValueError("The shell journal does not confirm the disconnect")

        for suffix in (".swp", ".swo"):
            swap = archive.read(context["saved_file"] + suffix)
            page_size, = struct.unpack_from("<I", swap, 12)
            pid, = struct.unpack_from("<I", swap, 24)
            original_path = swap[108:swap.index(0, 108)].decode("utf-8")
            if pid != snapshots[0]["pid"] or original_path != context["expected_original_path"]:
                continue
            lines = dict(line.split(": ", 1) for line in swap_lines(swap, page_size)
                         if ": " in line)
            if lines["base_file_sha256"] != hashlib.sha256(saved).hexdigest():
                raise ValueError("Swap revision does not match the saved file")
            encoded = lines["authorization_b64"]
            flag = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
            if not re.fullmatch(rb"CSCTF\{[^}]+\}", flag):
                raise ValueError("Recovered authorization is not a flag")
            print(flag.decode("ascii"))
            return
    raise ValueError("Could not find the swap file that matches the disconnect")


if __name__ == "__main__":
    main()
