import hashlib
import io
import sys
from pathlib import Path
from zipfile import ZipFile

import numpy as np


def read_csv(archive, name):
    return np.loadtxt(io.BytesIO(archive.read(name)), delimiter=",", skiprows=1)


def with_intercept(features):
    return np.column_stack((np.ones(len(features)), features))


def fit(features, scores):
    coefficients, _, rank, _ = np.linalg.lstsq(features, scores, rcond=None)
    if rank != features.shape[1]:
        raise ValueError("The scoring coefficients are not uniquely determined")
    return coefficients


archive = (
    Path(sys.argv[1])
    if len(sys.argv) > 1
    else Path(__file__).with_name("files") / "watch-list-audit.zip"
)
with ZipFile(archive) as handout:
    history = read_csv(handout, "history.csv")
    probes = read_csv(handout, "probes.csv")

features = with_intercept(history[:, :-1])
scores = history[:, -1]
tail = fit(features[-32:], scores[-32:])
outside = np.flatnonzero(np.abs(features @ tail - scores) > 1e-9)
if not len(outside):
    raise ValueError("No deployment change found")
cut = int(outside[-1]) + 1
before = fit(features[:cut], scores[:cut])
latest = fit(features[cut:], scores[cut:])
np.testing.assert_allclose(features[:cut] @ before, scores[:cut], rtol=0, atol=1e-9)
np.testing.assert_allclose(features[cut:] @ latest, scores[cut:], rtol=0, atol=1e-9)
quantized = np.floor(1000 * (with_intercept(probes) @ latest) + 0.5).astype(np.int64)
witness = "".join(f"{value}\n" for value in quantized).encode("ascii")
print("CSCTF{" + hashlib.sha256(witness).hexdigest() + "}")
