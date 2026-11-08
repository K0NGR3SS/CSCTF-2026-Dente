import sys
from pathlib import Path

import numpy as np


archive = (
    Path(sys.argv[1])
    if len(sys.argv) > 1
    else Path(__file__).with_name("files") / "dispatch-authenticator.npz"
)
with np.load(archive, allow_pickle=False) as handout:
    dw = handout["update_W1"]
    db = handout["update_b1"].reshape(-1)
    active = np.flatnonzero(db)
    recovered = dw[active] / db[active, None]
    x = recovered[0]
    np.testing.assert_allclose(recovered, np.broadcast_to(x, recovered.shape), atol=1e-12)

    scaled = x * 255
    decoded = np.rint(scaled)
    np.testing.assert_allclose(scaled, decoded, rtol=0, atol=1e-10)
    if np.any(decoded < 0) or np.any(decoded > 127):
        raise ValueError("Recovered input is not ASCII")

    hidden = np.maximum(handout["global_W1"] @ x + handout["global_b1"].reshape(-1), 0)
    logits = handout["global_W2"] @ hidden + handout["global_b2"].reshape(-1)
    np.testing.assert_allclose(logits, handout["logits"].reshape(-1), atol=1e-10)
    print(bytes(decoded.astype(np.uint8)).decode("ascii"))
