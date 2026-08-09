//! The quartic extension of KoalaBear, in Bitcoin Script.
//!
//! `KoalaBear[X]/(X^4 - 3)` — Plonky3's `BinomialExtensionField<KoalaBear, 4>`,
//! whose `BinomialExtensionData<4>` sets `W = 3`.
//!
//! # Why the verifier needs this
//!
//! KoalaBear is a 31-bit field, so a Fiat-Shamir challenge drawn from it gives
//! at most about 31 bits of soundness however many queries are made. Plonky3's
//! WHIR is `WhirVerifier<F, EF>` with `EF: ExtensionField<F>` for exactly this
//! reason, and refuses a configuration outright when the field is too small:
//! *"no out-of-domain sample count reaches {security_level}-bit security with a
//! {field_size_bits}-bit field"*. At degree four the challenge space is about
//! 124 bits, which is what makes a 100-bit target reachable.
//!
//! Hashing stays in the base field — Poseidon2 absorbs `F` elements — so this
//! affects the challenge, sumcheck and folding arithmetic only.
//!
//! # Representation
//!
//! Four base elements, `a0` deepest and `a3` on top, so an extension element
//! occupies four stack slots and pairs of them multiply in place.

use crate::field;
use crate::treepp::*;

/// The non-residue: `X^4 = 3`.
pub const W: u32 = 3;

/// Degree.
pub const D: usize = 4;

/// Multiply the top base element by `W`, as `x + 2x`.
fn mul_w() -> Script {
    script! {
        OP_DUP
        { field::double() }
        { field::add() }
    }
}

/// Add two extension elements. Input `a b`, eight slots; output four.
pub fn add() -> Script {
    script! {
        for i in 0..D {
            // b_i is on top of the remaining a's; bring the matching a_i up.
            { D - i } OP_ROLL
            { field::add() }
            OP_TOALTSTACK
        }
        for _ in 0..D { OP_FROMALTSTACK }
    }
}

/// Subtract two extension elements. Input `a b`; output `a - b`.
pub fn sub() -> Script {
    script! {
        for i in 0..D {
            { D - i } OP_ROLL
            OP_SWAP
            { field::sub() }
            OP_TOALTSTACK
        }
        for _ in 0..D { OP_FROMALTSTACK }
    }
}

/// Multiply two extension elements.
///
/// Schoolbook, following the generic branch of Plonky3's `binomial_mul`:
/// `res[i+j] += a_i b_j`, and `res[i+j-D] += W a_i b_j` when the degree wraps.
/// Sixteen base multiplications. Karatsuba would need nine and is the obvious
/// next optimisation.
pub fn mul() -> Script {
    // Inputs: a0..a3 then b0..b3, b3 on top.
    // Depths with `t` items above: a_i at (7-i)+t, b_j at (3-j)+t.
    let mut rows: Vec<Script> = Vec::with_capacity(D);
    for k in 0..D {
        // Terms contributing to coefficient k, with their W factor.
        let mut terms: Vec<(usize, usize, bool)> = Vec::new();
        for i in 0..D {
            for j in 0..D {
                if i + j == k {
                    terms.push((i, j, false));
                } else if i + j == k + D {
                    terms.push((i, j, true));
                }
            }
        }
        let mut parts: Vec<Script> = Vec::new();
        for (idx, &(i, j, wrapped)) in terms.iter().enumerate() {
            let above = k + usize::from(idx > 0);
            parts.push(script! {
                { (7 - i) + above } OP_PICK
                { (3 - j) + above + 1 } OP_PICK
                { field::mul() }
            });
            if wrapped {
                parts.push(mul_w());
            }
            if idx > 0 {
                parts.push(field::add());
            }
        }
        rows.push(script! { for p in parts { { p } } });
    }
    script! {
        for r in rows { { r } }
        for _ in 0..D { OP_TOALTSTACK }
        for _ in 0..D { OP_2DROP }
        for _ in 0..D { OP_FROMALTSTACK }
    }
}

/// Copy the extension element `d` elements down, preserving coefficient order.
///
/// An element occupies four slots with `a0` deepest, so the copy is four picks
/// at a *constant* depth: each push shifts the remainder by one, which exactly
/// cancels the step from `a_i` to `a_{i+1}`.
pub fn copy(d: usize) -> Script {
    script! {
        for _ in 0..D { { 4 * d + 3 } OP_PICK }
    }
}

/// Push the multiplicative identity, `1 + 0X + 0X^2 + 0X^3`.
pub fn push_one() -> Script {
    script! { 1 0 0 0 }
}

/// Push the additive identity.
///
/// Written out rather than as four literal zeros at the call site, so that an
/// accumulator's starting value reads as a field element and not as padding.
pub fn push_zero() -> Script {
    script! { 0 0 0 0 }
}

/// Drop `n` extension elements.
pub fn drop_n(n: usize) -> Script {
    script! { for _ in 0..(2 * n) { OP_2DROP } }
}

/// Move the top element to the altstack, `a3` first so a matching
/// [`from_altstack`] restores the order.
pub fn to_altstack() -> Script {
    script! { for _ in 0..D { OP_TOALTSTACK } }
}

/// Restore an element parked by [`to_altstack`].
pub fn from_altstack() -> Script {
    script! { for _ in 0..D { OP_FROMALTSTACK } }
}
