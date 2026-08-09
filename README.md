# bitcoin-stark-verifier

A STARK verifier in Bitcoin Script, using **no `OP_CAT`** and no other disabled
opcode.

| Crate | What it is |
| --- | --- |
| [`poseidon2`](poseidon2/) | Poseidon2 over KoalaBear — the permutation, the degree-4 extension field, row hashing and Merkle path verification |
| [`whir`](whir/) | The WHIR verifier on top of it — Fiat–Shamir sponge, challenger, sumcheck rounds, multilinear evaluation, constraint batching and the closing identity |

📄 **[Algorithm and implementation review](docs/whir-review.pdf)** — a formal
account of the STIR and WHIR proximity tests, what this implementation checks,
what it does not, and why. Source: [`docs/whir-review.tex`](docs/whir-review.tex).

```
cargo test                              # everything, 67 tests
cargo test -p whir --test end_to_end    # the end-to-end path
```

## Why no `OP_CAT`

`OP_SHA256` hashes one stack item, while a Merkle step hashes two children
concatenated — so a byte hash needs `OP_CAT`, which is disabled, and re-enabling
it means a soft fork ([BIP-347](https://github.com/bitcoin/bips/blob/master/bip-0347.mediawiki)
is `Complete` but not deployed).

An **algebraic** hash removes the dependency. A Poseidon2 digest is eight field
elements rather than thirty-two bytes, so compressing two children hands sixteen
field elements to a width-16 permutation — sixteen stack items passed to an
arithmetic routine, with nothing to concatenate. It is also the hash
[Ziren](https://github.com/ProjectZKM/Ziren) commits with.

## End to end

`whir/tests/end_to_end.rs` runs [Plonky3](https://github.com/Plonky3/Plonky3)'s
actual WHIR prover over KoalaBear, verifies the proof with **Plonky3's own
verifier**, then re-derives the same claims in Bitcoin Script and executes it.

The native verification comes first on purpose. Every other test compares a
script against a Rust reference, which establishes that the two agree — not that
either is right.

No hand-built vectors are involved: the evaluations are whatever the prover chose
to send, and **the challenges are squeezed from the sponge inside the script**.
Perturbing any evaluation moves the squeezed challenge, which moves the chained
claim, which breaks the closing identity — asserted for every evaluation in the
proof.

**What is checked.** A query opening is one unit: the row is bound to its leaf by
`merkle::hash_row` (Plonky3's `PaddingFreeSponge`, checked against it on a real
row), the path recomputes the root, the row folds to an answer, and
`constraint::combine_answers` batches the answers into the next round's target.
`constraint::closing_check` verifies the accumulated `Σ_j w_j · f_M(z_j) = σ`.

**What is not.** The accumulated `(weight, point)` pairs are not yet threaded
between rounds, so each step is checked individually rather than as WHIR's full
round-by-round argument. `verifier::verify` emits the part that is checked, and
its doc comment says so. See §17 of the review.

## Measured cost

Everything follows from one constant: a Poseidon2 permutation is **572,228
bytes**, and nothing else is within 1% of it. Figures are for the test's witness
(6 variables, width 2); each is the length of a script some test executes.

| | bytes |
| --- | ---: |
| one Poseidon2 permutation | 572,228 |
| one Merkle level | 572,252 *(24 bytes of ordering overhead)* |
| Merkle path at depth 21 | 12,017,292 — **3.0 blocks** |
| `sumcheck_round()` | 95,100 |
| `eval_multilinear(5)` | 740,010 |
| `closing_check`, per point at 4 vars | 381,988 |
| **composed script, security 1, one query** | **8,967,342** |

Binding the transcript is *cheaper* per round than hinting it, because absorbing
is already the duplexing — Plonky3's `DuplexChallenger` permutes once when a
`sample` follows an `observe`, where the previous schedule paid for an absorb and
a squeeze. For the 2²⁰ example configuration `whir/tests/verifier.rs` reports:

| | permutations |
| --- | ---: |
| Merkle paths | 1,300 |
| transcript | 44 |
| **transcript share** | **3.3%** |

Two things dominate, and both are worth stating plainly.

**Merkle verification is essentially all of it.** At security 100 the cheapest
configuration (rate 2⁻⁴) opens 26 rows against a depth-9 tree, which composes to
roughly **135 MB**, of which Merkle work is 99.3% — three orders of magnitude
beyond what Bitcoin will execute in one transaction, which is why BitVM2-style
chunking exists. For contrast, a byte hash under `OP_CAT` would make one Merkle
level about **2 bytes**. Removing the soft-fork dependency is what costs six
orders of magnitude.

**`eval_multilinear` is exponential in the variable count**, about 23.9 KB × 2ⁿ:
740 KB at n=5, 24 MB at n=10, 783 MB at n=15. Past roughly n=12 it overtakes
Merkle and becomes the binding term.

The 135 MB figure composes independent Merkle paths, because that is the
primitive here. The proof's openings are a *pruned frontier* — 96 siblings, not
26 × 9 — so a batched verifier sharing internal nodes would be cheaper. That
verifier does not exist yet.

## Security parameters

Configuration tops out at **security level 100**, not the field's ceiling. The
first failure is at 101 with `PowBitsExceedBudget { required: 1, budget: 0 }`:
the tests set `pow_bits: 0`, and WHIR trades query count against proof-of-work
grinding, so the budget binds before the field does. KoalaBear gives
log₂(p) = 30.989 and degree 4, so 123.955 bits are available. Raising `pow_bits`
to the reference implementations' ≈22 would cut the dominant term by ~19%; §15 of
the review works it out.

## Credits

[Plonky3](https://github.com/Plonky3/Plonky3) for the specification and the
prover, [BitVM](https://github.com/bitvm/bitvm) and
[`rust-bitcoin-m31`](https://github.com/Bitcoin-Wildlife-Sanctuary/rust-bitcoin-m31)
for the Bitcoin Script field-arithmetic technique.
