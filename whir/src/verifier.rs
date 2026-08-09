//! The WHIR verifier, composed.
//!
//! Follows `WhirVerifier::verify` in Plonky3's `whir/src/pcs/verifier/mod.rs`:
//!
//! ```text
//! initial sumcheck rounds                     (folding factor of round 0)
//! for each round:
//!     absorb the round commitment and OOD answers
//!     sample query indices, open Merkle paths, fold each answer
//!     sample the constraint challenge, combine
//!     sumcheck rounds                         (folding factor of round i+1)
//! observe the final polynomial in the clear
//! open the final round's queries
//! final sumcheck rounds
//! check  claimed_eval == weights * f(final_randomness)
//! ```
//!
//! Every step below is one of the primitives this crate already checks against
//! Plonky3. What this module adds is the schedule: how many permutations a
//! given [`Config`] actually costs, which is the number that decides whether a
//! WHIR verifier fits on Bitcoin.

use crate::sponge::RATE;
use crate::treepp::*;
use crate::{challenger, sponge, sumcheck};
use poseidon2::ext4;
use poseidon2::field;
use poseidon2::merkle;

/// One round of the WHIR schedule.
#[derive(Clone, Debug)]
pub struct Round {
    /// Sumcheck rounds this round runs, i.e. the next folding factor.
    pub folding_factor: usize,
    /// In-domain queries opened against the previous commitment.
    pub num_queries: usize,
    /// Merkle depth of the codeword being opened.
    pub log_domain_size: usize,
    /// Out-of-domain samples absorbed with the commitment.
    pub ood_samples: usize,
}

/// A WHIR instance, mirroring the fields of `WhirConfig` this verifier reads.
#[derive(Clone, Debug)]
pub struct Config {
    /// Sumcheck rounds before the first folding round.
    pub initial_folding_factor: usize,
    pub rounds: Vec<Round>,
    /// The final round's queries.
    pub final_round: Round,
    /// Sumcheck rounds after the last folding round.
    pub final_sumcheck_rounds: usize,
    /// Variables of the final polynomial sent in the clear.
    pub final_poly_vars: usize,
}

/// Absorb `n` field elements taken from the altstack, splitting across
/// rate-sized blocks as the duplex does. Each block is one permutation.
///
/// The values come from the altstack because a script's witness is its initial
/// stack: everything the spender supplies is present from the first opcode, and
/// only the altstack lets the verifier consume it in transcript order without
/// burying the sponge state.
///
/// No trailing squeeze. Absorbing already permutes, which is exactly what
/// Plonky3's `DuplexChallenger` does — `observe` buffers, and the `sample` that
/// follows duplexes once. The previous version emitted `absorb` *and* `squeeze`,
/// paying two permutations per round for one round's worth of transcript.
fn absorb_n_from_altstack(n: usize) -> Script {
    // The block sizes are known at generation time, so build them here rather
    // than trying to bind a local inside `script!`.
    let blocks: Vec<Script> = (0..n.div_ceil(RATE))
        .map(|chunk| {
            let block = core::cmp::min(RATE, n - chunk * RATE);
            script! {
                for _ in 0..block { OP_FROMALTSTACK }
                { sponge::absorb(block) }
            }
        })
        .collect();
    script! { for b in blocks { { b } } }
}

/// Open one query: derive its index from the transcript, then authenticate the
/// opening against the committed root.
///
/// The query index *is* the path. Sampling it and feeding those bits to the walk
/// is what binds the opening: the spender picks neither which leaf is opened nor
/// where it sits.
///
/// `slot` selects which rate element the index is read from. One squeeze yields
/// `RATE` of them and the caller must re-squeeze once they are spent — see
/// [`queries_per_squeeze`]. The previous version hardcoded slot 0, and since
/// [`challenger::sample`] is a bare `OP_PICK` that neither permutes nor advances
/// any buffer, every query in a round derived the *same* index and opened the
/// *same* leaf. However many queries were configured, the soundness was that of
/// one.
///
/// The opening is one unit: the **row** goes in, the root is checked, and no
/// leaf digest is taken on trust in between. [`merkle::hash_row`] reproduces the
/// `PaddingFreeSponge` the commitment was built with, so the walk authenticates
/// the values themselves.
///
/// That matters because the two halves of a query are separable and only one of
/// them used to be checked. Walking the path proves that *some* committed leaf
/// sits at the sampled index; if the leaf arrives as a hint alongside the row,
/// nothing stops a spender authenticating the real leaf and folding a different
/// row into the constraint. Hashing in script removes the seam.
///
/// Stack: the opening pushed as `root(8) siblings(8*depth) row(row_len)`.
/// Consumes all of it and leaves nothing, so the caller's layout is preserved.
/// `low_bits_to_altstack` puts the index bits underneath, and
/// [`merkle::hash_row`] leaves the altstack as it found it, so the walk still
/// finds them.
pub fn open_query(slot: usize, log_domain_size: usize, row_len: usize) -> Script {
    script! {
        { challenger::sample(slot) }
        { field::low_bits_to_altstack(log_domain_size) }
        { merkle::hash_row(row_len) }
        { merkle::merkle_verify_from_altstack(log_domain_size) }
    }
}

/// Query indices available from one squeeze.
///
/// Each index is masked out of a single base element, so the rate yields `RATE`
/// of them before the sponge has to be permuted again.
pub const fn queries_per_squeeze() -> usize {
    RATE
}

/// The final consistency check: `claimed_eval == weight * f(r)`, over `EF`.
///
/// Input, bottom to top: `claimed_eval(4) weight(4) f_at_r(4)`. Leaves nothing;
/// the spend is invalid unless the identity holds in all four coefficients.
///
/// This is the linear `Z * eq(X, z)` case of WHIR's closing condition
/// `sum_b w(f_M(b), alpha, b) = h_M(alpha)`, which is the shape a multilinear
/// evaluation query takes.
///
/// It has to be an extension-field comparison. Checking one coefficient would
/// leave a base-field equality worth at most `log2(P) ~ 31` bits — a prover
/// could hit it by chance far too often — against the ~124 bits the quartic
/// extension exists to provide.
pub fn final_check() -> Script {
    script! {
        { ext4::mul() }
        // Product on top, claimed value beneath it. Each comparison removes two
        // items, so the claimed value rises by one and the roll depth shrinks
        // with it — the same pattern `merkle_verify` uses for roots.
        for i in 0..ext4::D {
            { ext4::D - i } OP_ROLL
            OP_EQUALVERIFY
        }
    }
}

/// Emit the transcript spine of the verifier for `cfg`.
///
/// Every opcode this emits is wired and executable: the sumcheck chains derive
/// their own challenges through [`sumcheck::sumcheck_rounds_fs`], and the round
/// commitments, out-of-domain answers and final polynomial are absorbed into the
/// same sponge, so the challenges are a function of the proof rather than of the
/// spender's choosing. `whir/tests/verifier.rs` runs the result.
///
/// # Stack
///
/// In: `claim(4) state(16)` on the main stack, with the transcript on the
/// altstack in consumption order — for each sumcheck round `c_inf` then `c0`,
/// and each absorbed block in the order it is read.
/// Out: `claim(4) state(16)`, the chained claim and the final sponge state.
///
/// # What this does not cover
///
/// Two links remain outside the script, and neither is a matter of wiring:
///
/// - **The round's answers are batched but not yet threaded through the
///   schedule.** [`crate::constraint::combine_answers`] computes
///   `sigma' = h_k(alpha_k) + sum_i gamma^(i+1) y_i`, and `w'` is carried
///   symbolically until the final check collapses it into evaluations of `f_M`,
///   which [`crate::multilinear::eval_multilinear`] already does — so no `eq`
///   primitive is required. What remains is bookkeeping: carrying the
///   accumulated points from round to round so the closing check knows where to
///   evaluate.
/// A row *is* now bound to its leaf — see [`open_query`] — so what remains is
/// the constraint itself.
///
/// So this is the part of the verifier that is *checked*, not the whole
/// verifier. [`permutation_count`] prices the whole schedule including queries;
/// the two numbers are deliberately different and the doc comment on each says
/// which it is.
pub fn verify(cfg: &Config) -> Script {
    script! {
        { sumcheck::sumcheck_rounds_fs(cfg.initial_folding_factor) }

        for r in cfg.rounds.iter() {
            // The round commitment and its out-of-domain answers enter the
            // transcript, so every challenge drawn after this point depends on
            // them.
            { absorb_n_from_altstack(merkle::DIGEST + r.ood_samples) }
            { sumcheck::sumcheck_rounds_fs(r.folding_factor) }
        }

        // The final polynomial arrives in the clear and is absorbed whole.
        { absorb_n_from_altstack(1 << cfg.final_poly_vars) }
        { sumcheck::sumcheck_rounds_fs(cfg.final_sumcheck_rounds) }
    }
}

/// Count the permutations `cfg` costs, including the query openings that
/// [`verify`] does not yet compose.
///
/// Script weight is very nearly this number times the permutation size, because
/// nothing else is within 1% of one.
///
/// Two corrections against the previous accounting, both of which made the
/// schedule look more expensive than an honest verifier is:
///
/// - a sumcheck round is **one** permutation, not two — the absorb *is* the
///   duplexing, and the extra squeeze was never needed;
/// - a round absorbs two *extension* elements, so eight base elements, which
///   still fits one rate block.
///
/// One addition, which the previous accounting missed: query indices are drawn
/// `RATE` at a time, so a round with more queries than that has to re-squeeze.
pub fn permutation_count(cfg: &Config) -> usize {
    // Absorb-and-sample is a single duplexing.
    let sumcheck_perms = |rounds: usize| rounds;
    // Indices come `RATE` per squeeze; the first batch rides the preceding
    // absorb, so only the batches after it cost a permutation.
    let index_squeezes = |queries: usize| queries.div_ceil(queries_per_squeeze()).saturating_sub(1);

    let mut n = sumcheck_perms(cfg.initial_folding_factor);
    for r in cfg.rounds.iter() {
        n += (merkle::DIGEST + r.ood_samples).div_ceil(RATE); // commitment + OOD
        n += index_squeezes(r.num_queries);
        n += r.num_queries * r.log_domain_size; // one per Merkle level
        n += sumcheck_perms(r.folding_factor);
    }
    n += (1usize << cfg.final_poly_vars).div_ceil(RATE);
    n += index_squeezes(cfg.final_round.num_queries);
    n += cfg.final_round.num_queries * cfg.final_round.log_domain_size;
    n += sumcheck_perms(cfg.final_sumcheck_rounds);
    n
}
