//! The WHIR sumcheck round, in Bitcoin Script, over the quartic extension.
//!
//! Plonky3's WHIR is `WhirVerifier<F, EF>` with `EF: ExtensionField<F>`, and the
//! claim, the sent evaluations and the challenge are all `EF`. Running this over
//! the base field would cap soundness near 31 bits however many queries were
//! made, so every value here is four slots wide.

use crate::treepp::*;
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
