#!/usr/bin/env python3
"""Operation Dawn: The Cipher Lock — CSCTF 2026 (Misc).

Correlation power analysis: for each of the 47 code bytes, the key guess whose
HW(sbox[p ^ k]) model correlates best with the leaking trace samples is the
flag byte.

Usage: python3 solve.py files/traces.npz   (needs numpy)
"""
import sys

import numpy as np


def main():
    d = np.load(sys.argv[1] if len(sys.argv) > 1 else "files/traces.npz")
    T = d["traces"].astype(np.float64)
    P = d["plaintexts"]
    sbox = d["sbox"]
    nbytes = P.shape[1]

    HW = np.array([bin(i).count("1") for i in range(256)], dtype=np.float64)
    # standardise trace columns once
    Tc = (T - T.mean(0)) / T.std(0)
    leak = np.where(np.abs(T.mean(0) - 4) < 1)[0]  # 47 leaking samples

    flag = bytearray()
    for j in range(nbytes):
        best_k, best_corr = 0, -1.0
        for k in range(256):
            model = HW[sbox[P[:, j] ^ k]]
            model = (model - model.mean()) / (model.std() + 1e-12)
            corr = np.abs((model @ Tc[:, leak]) / len(model)).max()
            if corr > best_corr:
                best_corr, best_k = corr, k
        flag.append(best_k)

    print(bytes(flag).decode(errors="replace"))


if __name__ == "__main__":
    main()
