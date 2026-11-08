import io
import re
import tarfile
from pathlib import Path

import numpy as np
from PIL import Image


plate = Path(__file__).parent / "files" / "recon-plate.png"
pixels = np.array(Image.open(plate).convert("RGB")).ravel()
results = set()
for plane in (0, 1):
    packed = np.packbits((pixels >> plane) & 1, bitorder="big").tobytes()
    for marker in re.finditer(b"\x1f\x8b\x08", packed):
        try:
            with tarfile.open(fileobj=io.BytesIO(packed[marker.start():]), mode="r:gz") as archive:
                annotation = archive.extractfile("plate/annotation.txt").read().decode("ascii")
        except (KeyError, OSError, EOFError, tarfile.TarError):
            continue
        match = re.fullmatch(r"RECON SERIAL (\d+) (.+) CODE ([0-9A-F]{6})", annotation.strip())
        if match:
            serial, words, check = match.groups()
            results.add("_".join((serial, words.lower().replace(" ", "_"), check.lower())))
result, = results
print(f"CSCTF{{{result}}}")
