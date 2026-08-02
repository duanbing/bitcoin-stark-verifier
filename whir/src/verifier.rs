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
use crate::{challenger, multilinear, sponge, sumcheck};
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

/// Absorb `n` field elements, splitting across rate-sized blocks as the duplex
/// does. Each block is one permutation.
fn absorb_n(n: usize) -> Script {
    script! {
        for chunk in 0..n.div_ceil(RATE).max(1) {
            { sponge::absorb(core::cmp::min(RATE, n - chunk * RATE).max(0)) }
        }
    }
}

/// Open one query: derive its index, walk the Merkle path, fold the answer.
///
/// `folding_factor` variables are folded, so the opened fiber has `2^k` values
/// and collapses through [`multilinear::eval_multilinear`] — which is exactly
/// what `verify_stir_challenges` does with `Poly::new(answer).eval_ext(&query_randomness)`.
fn open_query(log_domain_size: usize, folding_factor: usize) -> Script {
    script! {
        // The query index is the path. Sampling it as bits and feeding those
        // bits to the walk is what binds the opening: the spender picks neither
        // which leaf is opened nor where it sits.
        { challenger::sample(0) }
        { field::low_bits_to_altstack(log_domain_size) }
        // Stack: commitment root, siblings, leaf. The walk aborts unless the
        // recomputed root equals the committed one.
        { merkle::merkle_verify_from_altstack(log_domain_size) }
        { multilinear::eval_multilinear(folding_factor) }
    }
}

/// The final consistency check: `claimed_eval == weights * f(r)`.
///
/// Input, bottom to top: `claimed_eval weights f_at_r`. Leaves nothing; the
/// spend is invalid if it does not hold.
pub fn final_check() -> Script {
    script! {
        { field::mul() }
        OP_EQUALVERIFY
    }
}

/// Emit the whole verifier for `cfg`.
pub fn verify(cfg: &Config) -> Script {
    script! {
        // Initial sumcheck: one absorb of (h(0), h(inf)) and one squeeze per round.
        for _ in 0..cfg.initial_folding_factor {
            { absorb_n(2) }
            { sponge::squeeze() }
            { sumcheck::sumcheck_round() }
        }

        for r in cfg.rounds.iter() {
            // Absorb the round commitment and its out-of-domain answers.
            { absorb_n(merkle::DIGEST + r.ood_samples) }
            { sponge::squeeze() }

            for _ in 0..r.num_queries {
                { open_query(r.log_domain_size, r.folding_factor) }
            }

            // The constraint challenge that batches the two statement groups.
            { sponge::squeeze() }

            for _ in 0..r.folding_factor {
                { absorb_n(2) }
                { sponge::squeeze() }
                { sumcheck::sumcheck_round() }
            }
        }

        // The final polynomial arrives in the clear and is absorbed whole.
        { absorb_n(1 << cfg.final_poly_vars) }
        { sponge::squeeze() }

        for _ in 0..cfg.final_round.num_queries {
            { open_query(cfg.final_round.log_domain_size, cfg.final_round.folding_factor) }
        }

        for _ in 0..cfg.final_sumcheck_rounds {
            { absorb_n(2) }
            { sponge::squeeze() }
            { sumcheck::sumcheck_round() }
        }

        // f(r) at the final sumcheck randomness, then the equality.
        { multilinear::eval_multilinear(cfg.final_poly_vars) }
        { final_check() }
    }
}

/// Count the permutations `cfg` costs. Script weight is very nearly this number
/// times the permutation size, because nothing else is within 1% of one.
pub fn permutation_count(cfg: &Config) -> usize {
    let mut n = 0usize;
    // Each sumcheck round: absorb two, squeeze one.
    let sumcheck_perms = |rounds: usize| rounds * 2;
    n += sumcheck_perms(cfg.initial_folding_factor);
    for r in cfg.rounds.iter() {
        n += (merkle::DIGEST + r.ood_samples).div_ceil(RATE) + 1; // commitment + squeeze
        n += r.num_queries * r.log_domain_size; // one per Merkle level
        n += 1; // constraint challenge
        n += sumcheck_perms(r.folding_factor);
    }
    n += (1usize << cfg.final_poly_vars).div_ceil(RATE) + 1;
    n += cfg.final_round.num_queries * cfg.final_round.log_domain_size;
    n += sumcheck_perms(cfg.final_sumcheck_rounds);
    n
}
