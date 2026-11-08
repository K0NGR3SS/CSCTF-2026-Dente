# Operation Dawn: The Sentry's Model

**Author:** kiriesh

**ML**
Handout: `files/authenticator.npz`

## Solve

`authenticator.npz` is a tiny fully-connected network: `392 → 48 (ReLU) → 1`. The 392 inputs are 49 characters × 8 bits, so it scores a candidate pass-string. The flag is a **backdoor neuron** sewn into the weights.

Loading `W1` (48×392), two hidden neurons stand out: #22 and #23 have biases of `−205` and `−208` while every other neuron's bias is around `0.1`, and their output weights are large (16 and 26 vs < 0.5). Their input weights are all exactly `±1` — a bit-mask of a string. Reading `+1 → 1`, `−1 → 0` gives two flag-shaped strings.

The real one is neuron #22:
- its mask has **207** ones against a bias of `−205`, so on its own string the pre-activation is `207 − 205 = +2 > 0`: it fires, the model score jumps from ~4.4 to ~43, and the forgery is accepted.
- neuron #23 has only **203** ones against bias `−208`, so `203 − 208 < 0`: on any binary input it can never fire. Its string `CSCTF{k0_a4lks...}` is a decoy.

So the live backdoor neuron is the one whose `ones > −bias`.

**Flag:** `CSCTF{09_the_ash_countersign_is_emberfall_4a19de}`

Run [the solver](solve.py) with `python3 solve.py files/authenticator.npz` (needs numpy).
