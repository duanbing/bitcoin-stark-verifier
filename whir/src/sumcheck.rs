//! The WHIR sumcheck round, in Bitcoin Script, over the quartic extension.
//!
//! Plonky3's WHIR is `WhirVerifier<F, EF>` with `EF: ExtensionField<F>`, and the
//! claim, the sent evaluations and the challenge are all `EF`. Running this over
//! the base field would cap soundness near 31 bits however many queries were
//! made, so every value here is four slots wide.

use crate::treepp::*;
use crate::{challenger, sponge};
use poseidon2::ext4;

/// One round of `SumcheckData::verify_rounds`, over `EF`.
///
/// Input, bottom to top: `claim c0 c_inf r`, each four slots. Output: the new
/// claim, `h(r)`.
///
/// `h(1)` is never sent — the sumcheck constraint `h(0) + h(1) = claim` gives
/// it — so this reconstructs from `{0, 1, inf}` with the weights
/// `[1 - r, r, r(r - 1)]`.
///
/// Element depths at rest: `r` 0, `c_inf` 1, `c0` 2, `claim` 3, and each copy
/// pushed above shifts them by one element.
pub fn sumcheck_round() -> Script {
    script! {
        // h(0) * (1 - r)
        { ext4::copy(2) }
        { ext4::push_one() }
        { ext4::copy(2) }
        { ext4::sub() }
        { ext4::mul() }

        // h(1) * r, with h(1) = claim - h(0)
        { ext4::copy(4) }
        { ext4::copy(4) }
        { ext4::sub() }
        { ext4::copy(2) }
        { ext4::mul() }
        { ext4::add() }

        // h(inf) * r * (r - 1)
        { ext4::copy(2) }
        { ext4::copy(2) }
        { ext4::mul() }
        { ext4::copy(2) }
        { ext4::push_one() }
        { ext4::sub() }
        { ext4::mul() }
        { ext4::add() }

        // Keep the new claim, drop the four inputs.
        { ext4::to_altstack() }
        { ext4::drop_n(4) }
        { ext4::from_altstack() }
    }
}

/// One round with the challenge **derived in script** from the transcript.
///
/// [`sumcheck_round`] takes `r` as an input. That is right for testing the
/// arithmetic and useless as a verifier: a prover who supplies `r` steers the
/// round wherever it likes. Writing the round out,
///
/// ```text
/// h(r) = (1 - r)*c0 + r*(claim - c0) + r*(r - 1)*c_inf
/// ```
///
/// and fixing any target `c'` and any `r` outside `{0, 1}`, the coefficient
/// `r*(r - 1)` is invertible, so
///
/// ```text
/// c_inf := (c' - (1 - r)*c0 - r*(claim - c0)) / (r*(r - 1))
/// ```
///
/// reaches `c'` for *any* `c0`. Chained, the closing claim is whatever the
/// prover wants, and the round check carries no soundness at all. Binding `r` to
/// the transcript is what removes the freedom: it is fixed only once
/// `(c0, c_inf)` have been absorbed.
///
/// # Stack
///
/// In: `claim(4) state(16)`, with the round's `c0(4) c_inf(4)` pushed above.
/// Out: `claim'(4) state'(16)` — the same shape, so rounds compose.
///
/// The state sits above the claim because that is already the layout
/// [`sponge::absorb`] wants once the evaluations are pushed on top of it.
///
/// # Cost
///
/// One permutation. Absorbing *is* the duplexing — what Plonky3's
/// `DuplexChallenger` does when a `sample` follows an `observe` — so there is no
/// separate squeeze. The rolls are one or two bytes each against 572 228 for a
/// permutation, which is why binding the challenge is not merely affordable but
/// *cheaper* than an unbound absorb-then-squeeze.
pub fn sumcheck_round_fs() -> Script {
    // Depth of the claim once state'(16) and r(4) sit above it: four slots of
    // r, sixteen of state, and the claim's own four less one.
    const CLAIM_UNDER_STATE_AND_R: usize = 2 * ext4::D + sponge::WIDTH - 1;
    // Depth of r once claim, c0 and c_inf have been restored above it.
    const R_UNDER_THREE: usize = 4 * ext4::D - 1;
    // Depth of the state once the new claim sits above it.
    const STATE_UNDER_CLAIM: usize = ext4::D + sponge::WIDTH - 1;

    script! {
        // The absorb consumes its inputs, so park copies first. Pushing c_inf
        // then c0 means the pops below come back c0 then c_inf.
        { ext4::copy(0) } { ext4::to_altstack() }
        { ext4::copy(1) } { ext4::to_altstack() }

        // claim(4) state(16) c0(4) c_inf(4)  ->  claim(4) state'(16)
        { sponge::absorb(2 * ext4::D) }
        // r := the first four rate slots of the permuted state.
        { challenger::sample_ef(0) }

        // Lift the claim out from under state' and r. Rolling the deepest slot
        // first, four times, keeps a0 deepest and a3 on top.
        for _ in 0..ext4::D { { CLAIM_UNDER_STATE_AND_R } OP_ROLL }
        { ext4::from_altstack() }   // c0
        { ext4::from_altstack() }   // c_inf
        // Lift r over the three, so the operands read claim c0 c_inf r
        // bottom-to-top, which is what `sumcheck_round` expects.
        for _ in 0..ext4::D { { R_UNDER_THREE } OP_ROLL }

        { sumcheck_round() }

        // Put the state back on top; the invariant is restored.
        for _ in 0..sponge::WIDTH { { STATE_UNDER_CLAIM } OP_ROLL }
    }
}

/// `n` transcript-bound rounds, each taking its `c0 c_inf` from the altstack.
///
/// Push order, bottom to top of the altstack: rounds in reverse, and within a
/// round `c_inf` then `c0`, so each round pops `c0` first. Unlike
/// [`sumcheck_rounds`] there is no `r` to push — that is the point.
///
/// [`sumcheck_round_fs`] leaves the altstack balanced, so later rounds'
/// evaluations stay buried underneath while a round runs.
pub fn sumcheck_rounds_fs(n: usize) -> Script {
    script! {
        for _ in 0..n {
            { ext4::from_altstack() }   // c0
            { ext4::from_altstack() }   // c_inf
            { sumcheck_round_fs() }
        }
    }
}

/// `n` rounds, each taking its `c0 c_inf r` from the altstack.
///
/// The claim is not known until the previous round finishes, so the proof data
/// cannot be laid out on the main stack in advance; it is fed from the altstack
/// instead. Push order: rounds in reverse, and within a round `r`, `c_inf`,
/// then `c0`.
pub fn sumcheck_rounds(n: usize) -> Script {
    script! {
        for _ in 0..n {
            { ext4::from_altstack() }
            { ext4::from_altstack() }
            { ext4::from_altstack() }
            { sumcheck_round() }
        }
    }
}
