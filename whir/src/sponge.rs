//! The Fiat-Shamir duplex, in Bitcoin Script.
//!
//! Plonky3's `DuplexChallenger<F, Perm, 16, 8>` over the same permutation. Every
//! challenge in a WHIR proof comes from here, so getting the padding rule right
//! matters: absorbing binds the number of absorbed elements into the first
//! capacity slot, which is what stops a short absorb from colliding with a
//! zero-padded longer one.

use crate::treepp::*;
use poseidon2::field;
use poseidon2::permutation::permute;

/// Sponge rate.
pub const RATE: usize = 8;
/// Sponge width.
pub const WIDTH: usize = 16;

/// Absorb `k` elements and permute, following `duplexing`.
///
/// Stack, bottom to top: the 16-element state, then the `k` inputs. Output: the
/// new state. `k == 0` is a squeeze — permute with the rate untouched and no
/// length tag.
pub fn absorb(k: usize) -> Script {
    assert!(k <= RATE);
    let n = WIDTH + k;
    // The state and the inputs are left untouched while the new state is built
    // above them, so each operand's depth is a function of the push count.
    let mut rows: Vec<Script> = Vec::with_capacity(WIDTH);
    for i in 0..WIDTH {
        let t = i; // outputs already pushed
        rows.push(if i < k {
            // Overwritten by input i.
            script! { { (k - 1 - i) + t } OP_PICK }
        } else if i < RATE && k > 0 {
            // Rate slots the inputs did not reach are zeroed.
            script! { 0 }
        } else if i == RATE && k > 0 {
            // The length tag, bound into the first capacity element.
            script! { { (WIDTH - 1 - i) + k + t } OP_PICK { k as u32 } { field::add() } }
        } else {
            script! { { (WIDTH - 1 - i) + k + t } OP_PICK }
        });
    }
    script! {
        for r in rows { { r } }
        // Park the new state, drop the old state and the inputs, restore.
        for _ in 0..WIDTH { OP_TOALTSTACK }
        for _ in 0..n / 2 { OP_2DROP }
        if n % 2 == 1 { OP_DROP }
        for _ in 0..WIDTH { OP_FROMALTSTACK }
        { permute() }
    }
}

/// Squeeze: permute, leaving the rate as the first `RATE` elements of the state.
///
/// This is `duplexing` with nothing buffered, so no slot is overwritten and no
/// length tag is added.
pub fn squeeze() -> Script {
    absorb(0)
}
