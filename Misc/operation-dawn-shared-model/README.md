# Operation Dawn: The Shared Model

**Author:** Varenik14  
**Category:** Misc  
Handout: [dispatch-authenticator.npz](files/dispatch-authenticator.npz)

## Solve

I loaded the arrays from the NPZ with pickle disabled. The first dense layer's weight gradient for an individual sample is the corresponding bias gradient times the input. I divided each row of `update_W1` by its nonzero `update_b1` value. All 34 nonzero rows recovered the same input.

The values became integer ASCII codes after multiplication by 255. I ran the recovered vector through both layers of the supplied model and compared the output with the saved logits.

Run [solve.py](solve.py) with `python solve.py`.

**Flag:** `CSCTF{17_hansoms_scald_not_aft_ay_gangling_1a7d12}`
