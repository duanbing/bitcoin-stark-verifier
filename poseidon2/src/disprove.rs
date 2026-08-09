//! Disproving one step of the verifier, BitVM2-style.
//!
//! The verifier does not fit on Bitcoin and never will: it is 2162 Poseidon2
//! permutations, 1.24 GB, three hundred blocks. What BitVM2 does about that is
//! not to shrink it but to stop running it. The prover asserts the intermediate
//! values, and anyone who can show that *one step* is inconsistent takes their
//! bond. Only that one step is ever executed on-chain, and only when someone
//! cheats.
//!
//! So the question stops being "how big is the verifier" and becomes "how small
//! is a step, and how many are there".
//!
//! # A step is one permutation round
//!
//! The obvious unit is one Merkle level, and it is too big: 572 252 bytes
//! against `MAX_STANDARD_TX_WEIGHT`'s 400 000 weight units. A step has to be
//! *sub-permutation*, which sounds awkward until you notice the permutation is
//! already a chain of rounds, each taking a state and leaving a state.
//! [`crate::permutation::rounds`] emits them, and `rounds_compose_to_the_permutation`
//! asserts that chaining them all is `permute()` exactly.
//!
//! That makes the commitment scheme obvious too: the prover commits to the state
//! between rounds, a challenge names a round, and the disprove script runs that
//! one round against the committed input and output.
//!
//! # What this module is, and is not
//!
//! It is the *predicate*: given a claimed input and output for a step, decide
//! whether the claim is false. That is the part the chain has to execute, and
//! the part that has to be exactly right — a predicate that can be satisfied
//! for an honest step lets anyone steal the bond.
//!
//! It is **not** the commitment layer. What stops a prover equivocating —
//! answering one challenge with one state and another with a different one — is
//! a one-time signature over each committed value, Winternitz in BitVM2's case.
//! Those need only single-item hashing, so `OP_SHA256` suffices and no soft fork
//! is required, but they are a separate piece of work and nothing here provides
//! them. Without them this is a disprove predicate with no binding, which is to
//! say a check of an assertion nobody made.

use crate::constants::WIDTH;
use crate::permutation;
use crate::treepp::*;

/// One iff the two `n`-element vectors differ somewhere.
///
/// The verifier's own comparisons are `OP_EQUALVERIFY`, which aborts on
/// difference. A disprove wants the opposite and cannot simply negate it:
/// `OP_EQUALVERIFY` leaves nothing to negate, and aborting is a failed spend
/// rather than a `false`. So every element is compared to a boolean, the
/// booleans are folded with `OP_BOOLAND`, and the result is negated.
///
/// # Stack
///
/// In: `a(n) b(n)`, `b` on top. Consumes both.
/// Out: `1` if they differ anywhere, `0` if they are equal.
///
/// The roll depth shrinks by one each step, because each comparison removes two
/// items from the pair and the boolean it leaves goes to the altstack — the
/// same shrinking-depth pattern the root comparison in
/// [`crate::merkle::merkle_verify`] uses, for the same reason.
pub fn differs(n: usize) -> Script {
    script! {
        for j in 0..n {
            { n - j } OP_ROLL
            OP_EQUAL
            OP_TOALTSTACK
        }
        1
        for _ in 0..n { OP_FROMALTSTACK OP_BOOLAND }
        OP_NOT
    }
}

/// Rounds one permutation is made of.
pub fn rounds_per_permutation() -> usize {
    permutation::rounds().len()
}

/// The disprove script for round `i`: valid exactly when the claim is false.
///
/// # Stack
///
/// In: `claimed_out(16) state_in(16)`, the input on top — the layout the round
/// itself wants, with the value being challenged underneath it.
/// Out: `1` if the claimed output is wrong, `0` if it is right.
///
/// Leaving the boolean *is* the spending condition: a script ends valid only on
/// a truthy stack, so an honest step leaves `0` and the spend fails. Nothing
/// needs to assert anything.
///
/// # The direction matters
///
/// It would be easy to write this as `OP_EQUALVERIFY` and call the spend the
/// disprove, which is exactly backwards: that script succeeds when the prover
/// was *honest*. The predicate has to be false-on-honest, and it is worth a test
/// that runs both cases rather than only the one being hunted for.
pub fn round(i: usize) -> Script {
    let r = permutation::rounds()
        .into_iter()
        .nth(i)
        .expect("round index within the permutation");
    script! {
        { r }
        { differs(WIDTH) }
    }
}

/// Bytes of the largest step, which is what decides whether a chunk relays.
pub fn largest_round() -> usize {
    (0..rounds_per_permutation()).map(|i| round(i).len()).max().unwrap_or(0)
}
