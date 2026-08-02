# bitcoin-stark-verifier

A STARK verifier in Bitcoin Script, using **no `OP_CAT`** and no other disabled
opcode. Two crates:

| Crate | What it is |
| --- | --- |
| [`poseidon2`](poseidon2/) | Poseidon2 over KoalaBear in Bitcoin Script — the permutation, the degree-4 extension field, and Merkle path verification |
| [`whir`](whir/) | The WHIR verifier on top of it — Fiat–Shamir sponge, challenger, sumcheck rounds, multilinear evaluation, and the closing identity |

## Why no `OP_CAT`

A STARK verifier has to check Merkle paths and a Fiat–Shamir transcript. With
SHA256 that needs `OP_CAT`: `OP_SHA256` hashes one stack item, while a Merkle
step hashes two children concatenated, so the two must first be fused. `OP_CAT`
is disabled, and re-enabling it means a soft fork
([BIP-347](https://github.com/bitcoin/bips/blob/master/bip-0347.mediawiki) is
`Complete` but not deployed).

An **algebraic** hash removes the dependency. A Poseidon2 digest is eight field
elements rather than thirty-two bytes, so compressing two children hands sixteen
field elements to a width-16 permutation — sixteen stack items passed to an
arithmetic routine, with nothing to concatenate.

This is also the hash [Ziren](https://github.com/ProjectZKM/Ziren) commits with,
so it is the hash already under the proof system this targets.

## End to end

`whir/tests/end_to_end.rs` runs [Plonky3](https://github.com/Plonky3/Plonky3)'s
actual WHIR prover over KoalaBear, verifies the proof with **Plonky3's own
verifier**, then re-derives the same claims in Bitcoin Script and executes it.

The native verification comes first on purpose. Every other test compares a
script against a Rust reference, which establishes that the two agree — not that
either is right. Checking that Plonky3 accepts the proof is what makes the
agreement meaningful: the object the script re-derives is known to be valid.

No hand-built vectors are involved. The evaluations are whatever the prover
chose to send.

```
cargo test                                  # everything
cargo test -p whir --test end_to_end        # the end-to-end path
```

## Measured cost

`poseidon2/tests/verifier_cost.rs` and `whir/tests/end_to_end.rs` print these;
the rest are `.len()` on the public builders. Figures are for the test's witness
(6 variables, width 2).

| | bytes |
| --- | --- |
| one Poseidon2 permutation | 572,228 |
| one Merkle level | 572,252 *(24 bytes of ordering overhead)* |
| Merkle path at depth 21 | 12,017,292 — **3.0 blocks** |
| `sumcheck_round()` | 95,100 |
| `eval_multilinear(5)` | 740,010 |
| `final_check()` | 1,447 |
| **composed script, security 1, one query** | **4,938,680** |

For contrast, `verifier_cost.rs` notes that a byte hash under `OP_CAT` would make
one Merkle level about **2 bytes**, so the same depth-21 path would be ~42 bytes.
Removing the soft-fork dependency is what costs six orders of magnitude.

Two things dominate, and both are worth stating plainly.

**Merkle verification is essentially all of it.** At security 100 the cheapest
configuration (rate 2⁻⁴) opens 26 rows against a depth-9 tree, which composes to
roughly **135 MB**, of which Merkle work is 99.3%. That is three orders of
magnitude beyond what Bitcoin will execute in one transaction, which is why
BitVM2-style chunking exists.

**`eval_multilinear` is exponential in the variable count**, about 23.9 KB × 2ⁿ:
740 KB at n=5, 24 MB at n=10, 783 MB at n=15. Past roughly n=12 it overtakes
Merkle and becomes the binding term, so a realistic witness hits that wall before
query count matters.

The 135 MB figure composes independent Merkle paths, because that is the
primitive here. The proof's openings are a *pruned frontier* — 96 siblings, not
26 × 9 — so a batched verifier sharing internal nodes would be cheaper. That
verifier does not exist yet.

## Security parameters

Configuration tops out at **security level 100**, not the field's ceiling. The
first failure is at 101 with `PowBitsExceedBudget { required: 1, budget: 0 }`:
the tests set `pow_bits: 0`, and WHIR trades query count against proof-of-work
grinding, so the budget binds before the field does. KoalaBear gives
log₂(p) = 30.989 and degree 4, so 123.955 bits are available.

## Credits

[Plonky3](https://github.com/Plonky3/Plonky3) for the specification and the
prover, [BitVM](https://github.com/bitvm/bitvm) and
[`rust-bitcoin-m31`](https://github.com/Bitcoin-Wildlife-Sanctuary/rust-bitcoin-m31)
for the Bitcoin Script field-arithmetic technique.
