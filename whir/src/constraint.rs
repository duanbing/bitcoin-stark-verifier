//! Batching a round's answers into the next target, in Bitcoin Script.
//!
//! A WHIR round ends by folding its out-of-domain answer and its `t` shift
//! answers into the *next* round's constraint. Following the paper's §2.1.3:
//!
//! ```text
//! w'(Z, X) := w(Z, alpha, X) + Z * sum_{i=0}^{t} gamma^(i+1) * eq(z_i, X)
//! sigma'   := h_k(alpha_k)   +     sum_{i=0}^{t} gamma^(i+1) * y_i
//! ```
//!
//! The two halves are not equally hard. `sigma'` is plain extension-field
//! arithmetic on values the verifier already holds, and that is what this module
//! computes. `w'` is carried *symbolically* — it is never evaluated during a
//! round — and when the final check does evaluate it, each accumulated term is
//! `f_M` at a point, which [`crate::multilinear::eval_multilinear`] already does.
//! So no `eq` primitive is needed anywhere, which is not obvious from the
//! formula and is worth stating: the `eq` factors survive only inside a
//! polynomial the verifier never touches until it collapses into an evaluation.
//!
//! Together with the row-to-leaf binding in [`poseidon2::merkle::hash_row`],
//! this is what makes a query *constrain* something. Before, an answer was
//! authenticated against the commitment and then dropped; now it reaches the
//! claim the next round is about.

use crate::treepp::*;
use poseidon2::ext4;

/// `sigma' = base + sum_{i=0}^{t} gamma^(i+1) * y_i`, over `EF`.
///
/// # Horner, not powers
///
/// Forming `gamma, gamma^2, ..., gamma^(t+1)` and then taking the inner product
/// costs `2t` multiplications. Horner from the top costs `t + 1`:
///
/// ```text
/// S := y_t;  S := S*gamma + y_i  for i = t-1 .. 0;  sigma' := base + gamma*S
/// ```
///
/// which expands to `sum_i gamma^(i+1) y_i` because the outer `gamma` shifts
/// every exponent up by one — the `+1` in the paper's `gamma^(i+1)`. Each
/// extension multiplication is sixteen base multiplications, so halving them is
/// worth the slightly denser code.
///
/// # Stack
///
/// In: `base(4) gamma(4)`, with the answers on the altstack, `y_t` on top
/// (Horner consumes them highest index first).
/// Out: `sigma'(4)`.
///
/// # Cost
///
/// `t + 1` extension multiplications and `t + 1` additions — no permutation at
/// all, so against the `depth` permutations each answer already cost to
/// authenticate this is free. Batching answers into the constraint is not what
/// makes a WHIR verifier expensive; opening them is.
pub fn combine_answers(t: usize) -> Script {
    script! {
        // S := y_t
        { ext4::from_altstack() }
        for _ in 0..t {
            // S := S * gamma + y_i
            { ext4::copy(1) }           // gamma sits directly under S
            { ext4::mul() }
            { ext4::from_altstack() }
            { ext4::add() }
        }
        // sigma' := base + gamma * S
        { ext4::copy(1) }
        { ext4::mul() }
        // Drop gamma from under the product, then add the base.
        { ext4::to_altstack() }
        { ext4::drop_n(1) }
        { ext4::from_altstack() }
        { ext4::add() }
    }
}

/// The closing check: `sum_j w_j * f_M(z_j) == sigma`, over `EF`.
///
/// # Why this is the whole of `w'`
///
/// A round never evaluates its weight polynomial; it carries it. After `M`
/// rounds `w'` is a sum of terms `Z * gamma^e * eq(z, X)`, and the closing check
/// asks for
///
/// ```text
/// sum_b w'(f_M(b), b) = sigma
/// ```
///
/// Each term collapses, because summing an evaluation against `eq` *is*
/// evaluation:
///
/// ```text
/// sum_b f_M(b) * gamma^e * eq(z, b) = gamma^e * f_M(z)
/// ```
///
/// So the accumulated symbolic polynomial is exactly a list of
/// `(weight, point)` pairs, and checking it is evaluating the final polynomial
/// at each point and taking the weighted sum. That is why no `eq` primitive is
/// needed anywhere in this verifier: `eq` appears only inside something that is
/// never touched until it turns into an evaluation.
///
/// # Stack
///
/// In: `sigma(4) evals(4 * 2^n_vars)`, the final polynomial's evaluations with
/// `e[0]` deepest. Altstack, per point in consumption order: the weight `w_j`,
/// then the point's coordinates ordered so the *last* variable pops first —
/// which is what [`crate::multilinear::eval_multilinear`] expects.
/// Out: nothing. The spend is invalid unless the identity holds in all four
/// coefficients.
///
/// # Cost
///
/// `n_points` multilinear evaluations of `n_vars` variables. The evaluations are
/// copied rather than re-pushed, so the witness carries the final polynomial
/// once. No permutation — this is arithmetic, and it is the reason
/// `final_poly_vars` wants to stay small: the cost is
/// `n_points * 2^n_vars` extension operations, exponential in the wrong variable
/// if the folding schedule leaves too much to the end.
pub fn closing_check(n_points: usize, n_vars: usize) -> Script {
    let n = 1usize << n_vars; // evaluations in the final polynomial
    script! {
        // acc := 0
        { ext4::push_zero() }
        for _ in 0..n_points {
            // Copy the evaluation block above the accumulator. The block's
            // deepest element sits at a constant depth of `n` while the copy is
            // being built: each push shifts the remainder by one, which cancels
            // the step to the next element — the same cancellation
            // `ext4::copy` relies on internally.
            for _ in 0..n { { ext4::copy(n) } }
            { crate::multilinear::eval_multilinear(n_vars) }
            { ext4::from_altstack() }   // w_j
            { ext4::mul() }
            { ext4::add() }
        }
        // Compare the accumulator with sigma, which is beneath the evaluations.
        { ext4::to_altstack() }
        { ext4::drop_n(n) }
        { ext4::from_altstack() }
        for i in 0..ext4::D {
            { ext4::D - i } OP_ROLL
            OP_EQUALVERIFY
        }
    }
}
