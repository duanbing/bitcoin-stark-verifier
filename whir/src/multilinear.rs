//! Multilinear evaluation in Bitcoin Script, over the quartic extension.
//!
//! WHIR's verifier finishes by evaluating the final polynomial at the sumcheck
//! randomness — `final_evaluations.eval_ext(&final_sumcheck_randomness)` — and
//! evaluates each query answer the same way. That randomness is `EF`, so this
//! is too: every value is four slots wide.

use crate::treepp::*;
use poseidon2::ext4;

/// Fold one variable: `m` extension evaluations become `m/2`.
///
/// Expects the challenge on top of the altstack and the `m` evaluations on the
/// stack, `e[0]` deepest. Outputs are built above the untouched inputs, so each
/// operand's depth is a function of the push count — the same discipline the
/// base-field version used, counting elements rather than slots.
fn fold_variable(m: usize) -> Script {
    assert!(m >= 2 && m % 2 == 0);
    script! {
        { ext4::from_altstack() }               // x, directly above the m inputs
        for j in 0..m / 2 {
            // e[2j+1] - e[2j]
            { ext4::copy(m - 1 - j) }
            { ext4::copy(m + 1 - j) }
            { ext4::sub() }
            // times x, which is j+1 elements down at this moment
            { ext4::copy(j + 1) }
            { ext4::mul() }
            // plus e[2j]
            { ext4::copy(m + 1 - j) }
            { ext4::add() }
        }
        // Park the m/2 outputs, drop x and the m inputs, restore.
        for _ in 0..m / 2 { { ext4::to_altstack() } }
        { ext4::drop_n(1) }
        { ext4::drop_n(m) }
        for _ in 0..m / 2 { { ext4::from_altstack() } }
    }
}

/// Evaluate a multilinear polynomial given its `2^n` extension evaluations.
///
/// Stack: the `2^n` evaluations, `e[0]` deepest. Altstack: the point, pushed so
/// the *last* variable pops first — Plonky3's fold order, where the last
/// variable pairs adjacent entries.
pub fn eval_multilinear(n: usize) -> Script {
    script! {
        for i in (0..n).rev() { { fold_variable(1 << (i + 1)) } }
    }
}
