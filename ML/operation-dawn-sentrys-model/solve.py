#!/usr/bin/env python3
"""Operation Dawn: The Sentry's Model — CSCTF 2026 (ML).

The flag is a backdoor neuron whose +-1 input weights form a bit-mask of the
flag string. The live one is the neuron that actually fires (ones > -bias);
the other is a decoy.

Usage: python3 solve.py files/authenticator.npz   (needs numpy)
"""
import sys

import numpy as np


def main():
    d = np.load(sys.argv[1] if len(sys.argv) > 1 else "files/authenticator.npz")
    W1, b1, W2 = d["W1"], d["b1"], d["W2"].reshape(-1)

    def decode(row):
        bits = (W1[row] > 0).astype(int)  # +1 -> 1, -1 -> 0
        by = [int("".join(map(str, bits[i : i + 8])), 2) for i in range(0, len(bits), 8)]
        return bytes(by).split(b"\x00")[0]

    # candidate backdoor neurons: +-1 mask, large negative bias, large output weight
    for row in range(W1.shape[0]):
        w = W1[row]
        if not np.all(np.isin(np.round(w, 3), [-1.0, 1.0])):
            continue
        ones = int((w > 0).sum())
        fires = ones > -b1[row]  # fires on its own string <=> live backdoor
        text = decode(row)
        tag = "  <-- live backdoor (FLAG)" if fires else "  (decoy, never fires)"
        print(f"neuron {row}: ones={ones} bias={b1[row]:.0f} w2={W2[row]:.0f}  {text.decode(errors='replace')}{tag}")


if __name__ == "__main__":
    main()
