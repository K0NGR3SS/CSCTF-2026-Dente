import argparse
import base64
import hashlib
import hmac
import struct
from pathlib import Path
from zipfile import ZipFile


def prefixed_bytes(data, offset=0):
    length, = struct.unpack_from("<I", data, offset)
    start = offset + 4
    return data[start:start + length], start + length


def certificate(apk):
    end = apk.rindex(b"PK\x05\x06")
    central, = struct.unpack_from("<I", apk, end + 16)
    if apk[central - 16:central] != b"APK Sig Block 42":
        raise ValueError("No APK signing block")
    size, = struct.unpack_from("<Q", apk, central - 24)
    offset = central - size
    while offset < central - 24:
        length, pair_id = struct.unpack_from("<QI", apk, offset)
        if pair_id == 0x7109871a:
            signers, _ = prefixed_bytes(apk, offset + 12)
            signer, _ = prefixed_bytes(signers)
            signed, _ = prefixed_bytes(signer)
            _, certificates_offset = prefixed_bytes(signed)
            certificates, _ = prefixed_bytes(signed, certificates_offset)
            der, _ = prefixed_bytes(certificates)
            return der
        offset += 8 + length
    raise ValueError("No APK v2 signer")


def utf8_length(data, start):
    first = data[start]
    if first & 128:
        return ((first & 127) << 8) | data[start + 1], start + 2
    return first, start + 1


def resource_string(data, entry):
    pool, = struct.unpack_from("<H", data, 2)
    pool_size, = struct.unpack_from("<I", data, pool + 4)
    _, _, flags, strings_start, _ = struct.unpack_from("<5I", data, pool + 8)
    if not flags & 256:
        raise ValueError("Expected the handout's UTF-8 string pool")
    package = pool + pool_size
    kind, header_size, package_size = struct.unpack_from("<HHI", data, package)
    if kind != 0x0200:
        raise ValueError("Expected an Android resource package")
    position = package + header_size
    while position < package + package_size:
        kind, header_size, size = struct.unpack_from("<HHI", data, position)
        if kind == 0x0201:
            type_id, flags, _, count, entries = struct.unpack_from("<BBHII", data, position + 8)
            if type_id == 0x0f and flags == 0 and entry < count:
                relative, = struct.unpack_from("<I", data, position + header_size + 4 * entry)
                if relative != 0xffffffff:
                    value = position + entries + relative
                    entry_size, = struct.unpack_from("<H", data, value)
                    _, _, value_type, index = struct.unpack_from("<HBBI", data, value + entry_size)
                    if value_type != 3:
                        raise ValueError("Expected a string resource value")
                    offset, = struct.unpack_from("<I", data, pool + 28 + 4 * index)
                    _, start = utf8_length(data, pool + strings_start + offset)
                    length, start = utf8_length(data, start)
                    return data[start:start + length].decode("utf-8")
        position += size
    raise ValueError("Resource entry was not found")


def main():
    parser = argparse.ArgumentParser(description="Inspect the VaultKeeper recovery stages")
    parser.add_argument("apk", nargs="?", type=Path, default=Path(__file__).parent / "files" / "vaultkeeper.apk")
    parser.add_argument("--master-passcode", help="Text entered into the main Unlock field")
    args = parser.parse_args()
    token = "KJSC-" + hashlib.sha256(certificate(args.apk.read_bytes())).hexdigest()[:8].upper() + "-RECOVERY"
    with ZipFile(args.apk) as apk:
        resources = apk.read("resources.arsc")
    session = resource_string(resources, 0x20)
    archive_key = "3778F16D"  # RecoveryStage2Receiver.onReceive
    digits, = (f"{number:04d}" for number in range(10000)
               if hmac.new(session.encode(), f"{number:04d}".encode(), "sha256")
               .hexdigest()[:8].upper() == archive_key)
    print(f"Recovery token: {token}")
    print(f"Archive session: {session}")
    print(f"Archive digits: {digits}")
    print(f"Archive key: {archive_key}")
    if args.master_passcode is not None:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        key = hashlib.sha256((token + digits + args.master_passcode).encode()).digest()
        encrypted = base64.b64decode(resource_string(resources, 0x38), validate=True)
        print(AESGCM(key).decrypt(encrypted[:12], encrypted[12:], None).decode())


if __name__ == "__main__":
    main()
