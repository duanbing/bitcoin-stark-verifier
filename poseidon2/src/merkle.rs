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

use crate::permutation::compress;
use crate::treepp::*;

/// Digest width in field elements. `PaddingFreeSponge<_, 16, 8, 8>` in Plonky3.
pub const DIGEST: usize = 8;

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
