import argparse
import zlib
from pathlib import Path

from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, modes


def forge(card, uid, name):
    if len(card) != 192:
        raise ValueError("Expected a 192-byte card dump")
    if len(uid) != 7 or not 1 <= len(name) <= 20:
        raise ValueError("Expected a seven-byte UID and a 1- to 20-byte name")

    key = b"BREAKMEIFYOUCAN!"
    cipher = Cipher(TripleDES(key + key[:8]), modes.CBC(card[16:24]))
    decryptor = cipher.decryptor()
    body = bytearray(decryptor.update(card[24:160]) + decryptor.finalize())

    body[9] = 0x03
    body[10] = len(name)
    body[12:32] = name.ljust(20, b"\0")
    timestamp = body[32:40]
    checksum = zlib.crc32(uid + timestamp + body[9:10])
    body[40:44] = checksum.to_bytes(4, "big")

    bcc0 = 0x88 ^ uid[0] ^ uid[1] ^ uid[2]
    bcc1 = uid[3] ^ uid[4] ^ uid[5] ^ uid[6]
    header = uid[:3] + bytes([bcc0]) + uid[3:] + bytes([bcc1])
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(body) + encryptor.finalize()
    return header + card[9:24] + ciphertext + card[160:]


def main():
    parser = argparse.ArgumentParser(description="Build an Ultralight administrator card")
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--uid", required=True, type=bytes.fromhex)
    parser.add_argument("--name", required=True)
    args = parser.parse_args()
    try:
        card = forge(args.input.read_bytes(), args.uid, args.name.encode("ascii"))
    except ValueError as error:
        parser.error(str(error))
    args.output.write_bytes(card)


if __name__ == "__main__":
    main()
