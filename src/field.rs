//! KoalaBear field arithmetic in Bitcoin Script.
//!
//! # Representation
//!
//! KoalaBear's prime is `0x7f000001`, which is under `2^31 - 1`, so a canonical
//! element fits in one script number — Bitcoin Core caps arithmetic operands at
//! four bytes (`CScriptNum::nDefaultMaxNumSize`). No multi-limb representation
//! is needed, which is the whole reason a 31-bit field is the right target.
//!
//! The sum of two canonical elements does *not* fit: `2(P-1)` exceeds
//! `2^31 - 1` and the addition would overflow. So, following
//! [`rust-bitcoin-m31`], addition runs through a *twisted* form `n = v - P`,
//! which lies in `[-P, 0)`. A canonical value plus a twisted one lands in
//! `[-P, P)`, always representable, and one conditional fixes it up. Nothing
//! here depends on the shape of the modulus, only on `P < 2^31`.
//!
//! # Multiplication
//!
//! There is no `OP_MUL` — disabled since 2010, along with `OP_DIV`, `OP_MOD`,
//! `OP_LSHIFT` and `OP_RSHIFT` — so multiplication is emulated by double-and-add
//! over the bits of one operand. Two routines:
//!
//! * [`mul`] for two runtime values. The multiplier is decomposed by comparing
//!   against descending powers of two, which needs only `OP_GREATERTHANOREQUAL`
//!   and `OP_SUB`.
//! * [`mul_by_constant`] when one operand is known at script-generation time,
//!   which is the common case in Poseidon2 — every round constant, and every
//!   entry of the internal layer's diagonal. It uses the constant's non-adjacent
//!   form, so it costs one doubling per bit and one addition per non-zero digit,
//!   with no decomposition at all. Roughly a third the size of [`mul`].
//!
//! [`rust-bitcoin-m31`]: https://github.com/Bitcoin-Wildlife-Sanctuary/rust-bitcoin-m31

use crate::treepp::*;

/// The KoalaBear prime, 2^31 - 2^24 + 1.
pub const P: u32 = 0x7f000001;

/// `P - 1 < 2^31`, so 31 bits index the whole field.
const BITS: usize = 31;

/// Bring a value in `[-P, P)` back to canonical `[0, P)`.
fn adjust_canonical() -> Script {
    script! {
        OP_DUP
        0 OP_LESSTHAN
        OP_IF { P } OP_ADD OP_ENDIF
    }
}

/// Canonical to twisted: `v - P`, landing in `[-P, 0)`.
pub fn to_twisted() -> Script {
    script! { { P } OP_SUB }
}

/// Add two canonical elements.
///
/// Input: `a b` — Output: `a + b`
///
/// `b` is twisted first so the addition cannot overflow four bytes.
pub fn add() -> Script {
    script! {
        { to_twisted() }
        OP_ADD
        { adjust_canonical() }
    }
}

/// Subtract. Input: `a b` — Output: `a - b`
pub fn sub() -> Script {
    script! {
        OP_SUB
        { adjust_canonical() }
    }
}

/// Double a canonical element.
pub fn double() -> Script {
    script! {
        OP_DUP
        { add() }
    }
}

/// Negate a canonical element. `0` maps to `0`, not to `P`.
pub fn neg() -> Script {
    script! {
        { P } OP_SWAP OP_SUB
        OP_DUP { P } OP_NUMEQUAL
        OP_IF OP_DROP 0 OP_ENDIF
    }
}

/// Non-adjacent form of `n`, least significant digit first.
///
/// No two adjacent digits are non-zero, which minimises the number of additions
/// in [`mul_by_constant`]. For `n > 0` the most significant digit is always 1.
fn naf(mut n: u32) -> Vec<i8> {
    let mut out = Vec::new();
    while n > 0 {
        if n & 1 == 1 {
            let z = 2 - (n % 4) as i8;
            out.push(z);
            if z == 1 {
                n -= 1;
            } else {
                n += 1;
            }
        } else {
            out.push(0);
        }
        n >>= 1;
    }
    out
}

/// Multiply a canonical element by a constant known at script-generation time.
///
/// Input: `a` — Output: `a * c`
pub fn mul_by_constant(c: u32) -> Script {
    let c = c % P;
    if c == 0 {
        return script! { OP_DROP 0 };
    }
    if c == 1 {
        return script! {};
    }
    let digits = naf(c);
    // The stack holds `a acc`. The leading NAF digit is 1, so the accumulator
    // starts as a copy of the input; the input itself is kept underneath to be
    // folded back in wherever a digit is non-zero, and dropped at the end.
    script! {
        OP_DUP
        for i in (0..digits.len() - 1).rev() {
            { double() }
            if digits[i] == 1 {
                OP_OVER { add() }
            } else if digits[i] == -1 {
                OP_OVER { sub() }
            }
        }
        OP_SWAP OP_DROP
    }
}

/// Halve: multiply by the inverse of two.
pub fn halve() -> Script {
    mul_by_constant(inv_2exp(1))
}

/// The inverse of `2^k` modulo `P`. The internal layer divides by 2, 8, 16,
/// `2^8` and `2^24`, and each becomes one [`mul_by_constant`].
pub fn inv_2exp(k: u32) -> u32 {
    let half = (P as u64 + 1) / 2; // 2^-1 mod P
    let mut acc: u64 = 1;
    for _ in 0..k {
        acc = acc * half % P as u64;
    }
    acc as u32
}

/// Decompose the top element into its 31 bits, pushed to the altstack.
///
/// Bits go on most-significant first, so popping yields them least-significant
/// first, which is the order [`mul`] consumes them in. Uses comparison and
/// subtraction only, since the shift and division opcodes are disabled.
fn bits_to_altstack() -> Script {
    script! {
        for i in (0..BITS).rev() {
            OP_DUP { 1u32 << i } OP_GREATERTHANOREQUAL
            OP_IF
                { 1u32 << i } OP_SUB
                1
            OP_ELSE
                0
            OP_ENDIF
            OP_TOALTSTACK
        }
        OP_DROP // the remainder is zero
    }
}

/// Multiply two canonical elements.
///
/// Input: `a b` — Output: `a * b`
///
/// Double-and-add from the least significant bit: the stack carries
/// `running_double accumulator`, and each bit either folds the running double
/// into the accumulator or does not.
pub fn mul() -> Script {
    script! {
        { bits_to_altstack() }      // stack: a        altstack: bits, lsb on top
        0                           // stack: a acc
        for i in 0..BITS {
            OP_FROMALTSTACK
            OP_IF
                OP_OVER { add() }
            OP_ENDIF
            if i < BITS - 1 {
                OP_SWAP { double() } OP_SWAP
            }
        }
        OP_SWAP OP_DROP
    }
}

/// Cube, the Poseidon2 S-box for KoalaBear (`KOALABEAR_S_BOX_DEGREE = 3`).
///
/// Input: `a` — Output: `a^3`
pub fn cube() -> Script {
    script! {
        OP_DUP OP_DUP
        { mul() }
        { mul() }
    }
}
