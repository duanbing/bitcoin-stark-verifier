# bitcoin-poseidon2-script

Poseidon2 over KoalaBear, in Bitcoin Script, using **no `OP_CAT`** and no other
disabled opcode. Built on [Plonky3](https://github.com/Plonky3/Plonky3) for the
specification and [BitVM](https://github.com/bitvm/bitvm) /
[`rust-bitcoin-m31`](https://github.com/Bitcoin-Wildlife-Sanctuary/rust-bitcoin-m31)
for the technique.

## Why

A STARK verifier on Bitcoin has to check Merkle paths and a Fiat–Shamir
transcript. With SHA256 that needs `OP_CAT`: `OP_SHA256` hashes one stack item,
and a Merkle step hashes the concatenation of two children, so the two must
first be fused into one item. `OP_CAT` is disabled, and re-enabling it means a
soft fork ([BIP-347](https://github.com/bitcoin/bips/blob/master/bip-0347.mediawiki),
`Complete`, not deployed). That is why
[`bitcoin-circle-stark`](https://github.com/Bitcoin-Wildlife-Sanctuary/bitcoin-circle-stark)
depends on it.

An **algebraic** hash removes the dependency. A Poseidon2 digest is eight field
elements, not thirty-two bytes, so compressing two children means feeding
sixteen field elements to a width-16 permutation — sixteen stack items handed to
an arithmetic routine. There is nothing to concatenate; the concatenation is the
order the state sits in.

This matters because Ziren, the zkVM under GOAT's BitVM bridge, already commits
this way: `Poseidon2KoalaBear<16>` through a `PaddingFreeSponge`. So a verifier
for the proofs that bridge already produces does not need a soft fork.

## The number

`cargo test --test permutation report_size -- --nocapture`

| | bytes (= witness weight units) | first cut |
| --- | ---: | ---: |
| field multiplication, both operands at runtime | 1,446 | 1,805 |
| field multiplication by a constant | 489 | 695 |
| S-box, `x^3` | 2,894 | 3,612 |
| external linear layer | 3,324 | 10,111 |
| internal linear layer | 5,487 | 11,888 |
| **Poseidon2 permutation** | **572,228** | 867,595 |
| Merkle compression (`TruncatedPermutation<_, 2, 8, 16>`) | 572,232 | 867,599 |

`MAX_STANDARD_TX_WEIGHT` is 400,000 and `MAX_BLOCK_WEIGHT` is 4,000,000, so one
permutation is **1.43 standard transactions**, or 14% of a block. A Merkle path
costs one permutation per level.

Two optimisations took 34% off the first cut, and both were structural rather
than clever:

- **The linear layers were dense 16×16 matrices.** `M4` is block-diagonal, so
  each output of the first pass reads four inputs rather than sixteen, and the
  internal layer is one sum plus sixteen scalings. `mds_light_dense` and
  `internal_linear_dense` are still in the crate and
  `structured_layers_equal_dense` asserts the two agree, which is what makes the
  rewrite safe to trust.
- **The modulus was a five-byte push, named twice per addition.** There are
  about sixty additions in a multiplication and eighty in a multiply-by-constant.
  Keeping one copy on the working stack and reaching it with `OP_PICK` — two
  bytes, since the depths are under sixteen — took 20% off `mul` and 30% off
  `mul_by_constant`. `rust-bitcoin-m31` credits the same optimisation.

**The S-box still dominates: 148 cubes at 2,894 is 428,312 bytes, 75% of the
total.** What is left there:

- **Windowing gains little here.** Eight four-bit windows still need thirty-two
  doublings against thirty-one, so only the additions reduce — from thirty-one
  conditional ones to eight — and building the sixteen-entry table costs most of
  that back. `rust-bitcoin-m31` reaches 1,060 over M31, so there is perhaps 25%
  left in `mul`, but not from windowing alone.
- **`x^3` decomposes twice.** `cube` is two multiplications, each re-deriving the
  bits of its own multiplier. Ordering the second as `x^2 * x` would reuse the
  first decomposition, worth about 300 bytes a cube, if the bit list can be
  duplicated on the altstack more cheaply than it is recomputed.
- **A dedicated squaring routine** is cheaper than the general multiplier.

None of that changes the order of magnitude: a permutation is a few hundred
thousand weight units, and a byte hash under `OP_CAT` is two.

## Correctness

The chain is script → reference → Plonky3, every link is tested, and the script
end is run under **two independent interpreters**.

- `tests/permutation.rs` executes the script under Bitcoin Wildlife Sanctuary's
  [`rust-bitcoin-scriptexec`](https://github.com/Bitcoin-Wildlife-Sanctuary/rust-bitcoin-scriptexec)
  and compares the final stack against `src/reference.rs`, for the field
  operations, both linear layers and the full permutation.
- `tests/bitvm_executor.rs` runs the same vectors under
  [BitVM's fork](https://github.com/BitVM/rust-bitcoin-scriptexec), which is what
  BitVM validates against. Two interpreters agreeing is a stronger statement
  than one, and it is the relevant one for a BitVM-targeted verifier.
- `tests/plonky3_agreement.rs` compares `src/reference.rs` against Plonky3's own
  `default_koalabear_poseidon2_16`, including the all-zero input.
- `uses_no_disabled_opcode` asserts the emitted permutation contains none of the
  fifteen disabled opcodes. If that test fails the whole design claim is void.
- `structured_layers_equal_dense` asserts the optimised linear layers equal the
  dense matrices they replaced.

**The stack is not the constraint.** BitVM's executor enforces Bitcoin's cap of
1000 items across stack and altstack, which the other leaves off by default.
Peak use during a full permutation is **50 items**, 5% of the budget. So
chunking the verifier across a disprove pattern is bounded by weight alone.

The linear layers are not transcribed twice: `src/poseidon2.rs` recovers their
matrices by applying `src/reference.rs` to basis vectors, so the script and the
reference cannot drift apart.

```
cargo test
```

## Parameters

Plonky3's default width-16 instance: `R_F = 8`, `R_P = 20`, S-box `x^3`, prime
`0x7f000001`. Constants are transcribed from
`Plonky3/koala-bear/src/poseidon2.rs`.

**Ziren uses `R_P = 13` with its own constants**, so a verifier targeting Ziren
must be rebuilt with those. Nothing here hard-codes a round count — the schedule
comes from the length of the constant tables in `src/constants.rs` — so that is
a matter of substituting them.

## Layout

```text
src/constants.rs   round constants and parameters, from Plonky3
src/reference.rs   plain-Rust Poseidon2, the oracle and the source of the layers
src/field.rs       KoalaBear arithmetic in script
src/poseidon2.rs   the permutation and the Merkle compression
```

## Licence

MIT.
