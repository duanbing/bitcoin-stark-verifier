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
