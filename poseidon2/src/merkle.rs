//! Merkle path verification in Bitcoin Script.
//!
//! This is the inner loop of any FRI, STIR or WHIR query, and on Bitcoin it is
//! where essentially all the cost is: one Poseidon2 permutation per level.
//!
//! # Stack layout
//!
//! Bottom to top, for a path of depth `d`:
//!
//! ```text
//! sibling[d-1] (8)  bit[d-1] ... sibling[0] (8)  bit[0]  leaf (8)
//! ```
//!
//! so the leaf is on top and each level's sibling and direction bit sit
//! directly beneath the digest they combine with. `bit = 0` means the running
//! digest is the left child. The result is the computed root, eight elements.
//!
//! Nothing is concatenated at any point — a digest is eight field elements, and
//! combining two of them is a sixteen-element permutation state. That is the
//! whole reason this works without `OP_CAT`.

use crate::constants::WIDTH;
use crate::permutation::{compress, permute};
use crate::treepp::*;

/// Digest width in field elements. `PaddingFreeSponge<_, 16, 8, 8>` in Plonky3.
pub const DIGEST: usize = 8;

/// Sponge rate for leaf hashing.
pub const HASH_RATE: usize = 8;

/// Overwrite the first `k` state elements and permute.
///
/// The state is the sixteen elements beneath the `k` inputs. Elements past `k`
/// are *kept*, not zeroed, and no length is mixed in — that is what makes this
/// the padding-free sponge rather than the duplex the challenger uses. The two
/// must not be conflated: `sponge::absorb` zeroes the rest of the rate and binds
/// the absorbed count into the capacity, precisely so that a short absorb cannot
/// collide with a zero-padded longer one. A leaf hash has a length fixed by the
/// commitment, so it does not need that and Plonky3 does not do it.
fn overwrite_permute(k: usize) -> Script {
    assert!(k <= HASH_RATE);
    let n = WIDTH + k;
    // The new state is built above the old one, so each operand's depth is a
    // function of how many outputs have been pushed — the discipline the rest of
    // this crate uses.
    let rows: Vec<Script> = (0..WIDTH)
        .map(|i| {
            let t = i;
            if i < k {
                script! { { (k - 1 - i) + t } OP_PICK }
            } else {
                script! { { (WIDTH - 1 - i) + k + t } OP_PICK }
            }
        })
        .collect();
    script! {
        for r in rows { { r } }
        for _ in 0..WIDTH { OP_TOALTSTACK }
        for _ in 0..(n / 2) { OP_2DROP }
        if n % 2 == 1 { OP_DROP }
        for _ in 0..WIDTH { OP_FROMALTSTACK }
        { permute() }
    }
}

/// Hash a row of `n` field elements into a leaf digest.
///
/// This is Plonky3's `PaddingFreeSponge<Perm, 16, 8, 8>`, which is what a
/// `MerkleTreeMmcs` leaf is: the digest of the opened row, not the row itself.
///
/// # Why the verifier needs it
///
/// Without this the query is only half bound. Walking the Merkle path proves
/// that *some* committed leaf sits at the sampled index, but the values folded
/// into the constraint arrive as a separate hint, and nothing ties the two
/// together — a spender could authenticate the real leaf and fold a different
/// row. Hashing the row in script and requiring the result to be the leaf is
/// what closes that gap.
///
/// Stack: the row, `row[0]` deepest. Output: the eight-element digest,
/// `d[0]` deepest, ready for [`merkle_verify_from_altstack`].
///
/// # Cost
///
/// `ceil(n / 8)` permutations — the same shape as the hashing the prover did to
/// build the leaf, and small beside the `depth` permutations of the path it
/// feeds.
pub fn hash_row(n: usize) -> Script {
    assert!(n > 0, "a leaf is the hash of at least one element");
    let chunks: Vec<usize> = (0..n.div_ceil(HASH_RATE))
        .map(|c| core::cmp::min(HASH_RATE, n - c * HASH_RATE))
        .collect();
    script! {
        // Park the row so chunks can be pulled in order: popping yields
        // `row[0]` first, which is the element that overwrites `state[0]`.
        for _ in 0..n { OP_TOALTSTACK }
        // Plonky3 starts from the default state, which is zero.
        for _ in 0..WIDTH { 0 }
        for c in chunks {
            for _ in 0..c { OP_FROMALTSTACK }
            { overwrite_permute(c) }
        }
        // The digest is the first DIGEST elements of the final state; drop the
        // capacity above it.
        for _ in 0..((WIDTH - DIGEST) / 2) { OP_2DROP }
    }
}

/// Swap the two eight-element digests on top of the stack.
///
/// Rolling the lower block up one element at a time preserves the order within
/// each block, which a naive sequence of swaps would not.
pub(crate) fn swap_digests() -> Script {
    script! {
        for _ in 0..DIGEST { { 2 * DIGEST - 1 } OP_ROLL }
    }
}

/// One level: order the pair by the direction bit, then compress.
///
/// The permutation reads its state with `s[0]` deepest, so whichever digest
/// lies lower becomes the left child. On entry the sibling is the lower one, so
/// the swap happens when the bit says the *running digest* is on the left —
/// that is, when the bit is zero.
pub fn merkle_step() -> Script {
    script! {
        // The bit sits under the eight-element digest; bring it to the top.
        { DIGEST } OP_ROLL
        OP_NOTIF { swap_digests() } OP_ENDIF
        { compress() }
    }
}

/// Walk a path of `depth` levels, leaving the computed root on the stack.
pub fn merkle_path(depth: usize) -> Script {
    script! {
        for _ in 0..depth { { merkle_step() } }
    }
}

/// Walk the path and require the result to equal a root already on the stack.
///
/// Expects the expected root, eight elements, beneath the path data.
pub fn merkle_verify(depth: usize) -> Script {
    script! {
        { merkle_path(depth) }
        // Computed root on top, expected root beneath it. Each comparison
        // removes two items, so the expected root rises by one every time and
        // the roll depth has to shrink with it.
        for i in 0..DIGEST {
            { DIGEST - i } OP_ROLL
            OP_EQUALVERIFY
        }
    }
}

/// One level, taking the direction bit from the altstack.
///
/// The stack-fed [`merkle_step`] lets the spender choose the direction, which
/// is only safe when the direction is already committed elsewhere. In a query
/// opening it is not: the direction bits *are* the query index, and the index
/// comes from the transcript. Sourcing them from the altstack lets the caller
/// push the sampled bits and leaves the spender no choice.
pub fn merkle_step_from_altstack() -> Script {
    script! {
        OP_FROMALTSTACK
        OP_NOTIF { swap_digests() } OP_ENDIF
        { compress() }
    }
}

/// Walk a path whose directions come from the altstack, least significant
/// first, and require the root to equal the one already on the stack.
///
/// Stack, bottom to top: `root (8)`, the siblings deepest-last, then the leaf.
/// Altstack: `depth` direction bits, the first level's on top.
pub fn merkle_verify_from_altstack(depth: usize) -> Script {
    script! {
        for _ in 0..depth { { merkle_step_from_altstack() } }
        // Computed root on top, expected root beneath it. Each comparison
        // removes two items, so the expected root rises by one every time and
        // the roll depth has to shrink with it.
        for i in 0..DIGEST {
            { DIGEST - i } OP_ROLL
            OP_EQUALVERIFY
        }
    }
}
