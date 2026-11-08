import argparse
import re
from pathlib import Path
from zipfile import ZipFile


def main():
    parser = argparse.ArgumentParser(description="Recover the accepted lockbox phrase")
    parser.add_argument("archive", nargs="?", type=Path,
                        default=Path(__file__).parent / "files" / "lockbox.zip")
    with ZipFile(parser.parse_args().archive) as archive:
        binary = archive.read("lockbox")

    marker = b"LOCKBOX1"
    if binary.count(marker) != 1:
        raise ValueError("Expected one lockbox record")
    offset = binary.index(marker) + len(marker)
    length = int.from_bytes(binary[offset:offset + 4], "little")
    seed = binary[offset + 4]
    key = binary[offset + 5:offset + 13]
    expected = binary[offset + 13:offset + 13 + length]
    if length != 44 or len(expected) != length:
        raise ValueError("Unexpected lockbox record layout")

    phrase = bytearray()
    state = seed
    for index, encoded in enumerate(expected):
        value = (encoded - key[index % len(key)]) & 255
        shift = (1 + 3 * index) % 8
        value = ((value >> shift) | (value << (8 - shift))) & 255
        phrase.append(value ^ state)
        state = (state + index + encoded) & 255

    state = seed
    for index, value in enumerate(phrase):
        value ^= state
        shift = (1 + 3 * index) % 8
        value = ((value << shift) | (value >> (8 - shift))) & 255
        encoded = (value + key[index % len(key)]) & 255
        if encoded != expected[index]:
            raise ValueError("Recovered phrase failed the forward check")
        state = (state + index + encoded) & 255
    if not re.fullmatch(rb"CSCTF\{[^}]+\}", phrase):
        raise ValueError("Recovered phrase does not have the expected flag format")
    print(phrase.decode("ascii"))


if __name__ == "__main__":
    main()
