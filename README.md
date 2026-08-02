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

| | bytes (= witness weight units) |
| --- | ---: |
| field multiplication, both operands at runtime | 1,805 |
| field multiplication by a constant | 695 |
| S-box, `x^3` | 3,612 |
| external linear layer | 10,111 |
| internal linear layer | 11,888 |
| **Poseidon2 permutation** | **867,595** |
| Merkle compression (`TruncatedPermutation<_, 2, 8, 16>`) | 867,599 |

`MAX_STANDARD_TX_WEIGHT` is 400,000 and `MAX_BLOCK_WEIGHT` is 4,000,000, so one
permutation is **2.17 standard transactions**, or 21.7% of a block. A Merkle
path costs one permutation per level.

That is the honest starting point, not a floor. Known headroom, roughly in order
of value:

- **The internal linear layer is emitted as a dense 16×16 matrix** because it is
  derived generically from the reference. Structurally it is one sum plus
  sixteen scalings, so it should fall a long way below 11,888 — and it runs
  twenty times per permutation, more than any other single component.
- **`mul` is plain double-and-add.** `rust-bitcoin-m31` reaches 1,060 weight
  units for the same operation with a windowed table; at that ratio the S-box,
  which dominates, drops by about 40%.
- **Squaring is done with the general multiplier.** `x^3` is a square and a
  multiply, and a dedicated squaring routine is cheaper than the general case.

## Correctness

The chain is script → reference → Plonky3, and every link is tested.

- `tests/permutation.rs` executes the script under `bitcoin-scriptexec` and
  compares the final stack against `src/reference.rs`, for the field operations,
  both linear layers and the full permutation.
- `tests/plonky3_agreement.rs` compares `src/reference.rs` against Plonky3's own
  `default_koalabear_poseidon2_16`, including the all-zero input.
- `uses_no_disabled_opcode` asserts the emitted permutation contains none of the
  fifteen disabled opcodes. If that test fails the whole design claim is void.

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
