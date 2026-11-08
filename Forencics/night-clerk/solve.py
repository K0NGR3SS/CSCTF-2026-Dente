import io
import re
import struct
from pathlib import Path
from xml.etree import ElementTree
from zipfile import BadZipFile, ZipFile


image = (Path(__file__).parent / "files" / "terminal.dd").read_bytes()
namespace = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
flags = set()
for marker in re.finditer(rb"PK\x05\x06", image):
    end = marker.start()
    if end + 22 > len(image):
        continue
    directory_size, directory_offset, comment_size = struct.unpack_from("<IIH", image, end + 12)
    start = end - directory_size - directory_offset
    if start < 0 or image[start:start + 4] != b"PK\x03\x04":
        continue
    try:
        with ZipFile(io.BytesIO(image[start:end + 22 + comment_size])) as document:
            xml = ElementTree.fromstring(document.read("word/document.xml"))
    except (BadZipFile, KeyError):
        continue
    for change in xml.findall(".//w:ins", namespace):
        value = "".join(node.text or "" for node in change.findall(".//w:t", namespace))
        if not re.fullmatch(r"(?:[0-9a-fA-F]{2})+", value):
            continue
        encrypted = bytes.fromhex(value)
        for key in range(256):
            flag = bytes(byte ^ key for byte in encrypted)
            if re.fullmatch(rb"CSCTF\{[a-zA-Z0-9_]+\}", flag):
                flags.add(flag)
flag, = flags
print(flag.decode("ascii"))
