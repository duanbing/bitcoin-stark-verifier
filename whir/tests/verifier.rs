//! The composed verifier: the transcript spine runs, and the closing identity
//! rejects.
//!
//! Both properties are new. The spine used to be emitted and measured but never
//! executed, and the closing identity used to be applied to a product the test
//! had just computed, so it could not fail.

use bitcoin_script::{define_pushable, script};
use poseidon2::reference as pf;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use whir::reference;
use whir::verifier::{self, Config, Round};

define_pushable!();

fn rand_f(rng: &mut ChaCha20Rng) -> u32 {
    rng.random_range(0..poseidon2::constants::P)
}
fn rand_ef(rng: &mut ChaCha20Rng) -> [u32; 4] {
    core::array::from_fn(|_| rand_f(rng))
}
fn push_ef(v: [u32; 4]) -> bitcoin::ScriptBuf {
    script! { for x in v { {x} } }
}

/// Load the altstack so that `items` pops in the order given.
///
/// The altstack is LIFO, so the first value consumed has to be pushed last.
fn push_altstack(items: &[u32]) -> bitcoin::ScriptBuf {
    script! { for x in items.iter().rev() { {*x} OP_TOALTSTACK } }
}

fn decode(v: &[u8]) -> i64 {
    if v.is_empty() {
        return 0;
    }
    let mut n: i64 = 0;
    for (i, b) in v.iter().enumerate() {
        n |= ((*b as i64) & 0xff) << (8 * i);
    }
    if v[v.len() - 1] & 0x80 != 0 {
        n &= !(0x80i64 << (8 * (v.len() - 1)));
        return -n;
    }
    n
}

fn run_ok(s: bitcoin::ScriptBuf) -> Vec<u32> {
    let info = bitcoin_scriptexec::execute_script(s);
    assert!(info.error.is_none(), "errored: {:?} at {:?}", info.error, info.last_opcode);
    (0..info.final_stack.len()).map(|i| decode(&info.final_stack.get(i)) as u32).collect()
}

fn run_rejects(s: bitcoin::ScriptBuf, why: &str) {
    let info = bitcoin_scriptexec::execute_script(s);
    assert!(info.error.is_some(), "{why}: the script accepted");
}

// ---------------------------------------------------------------------------
// The closing identity
// ---------------------------------------------------------------------------

/// `claimed == weight * f(r)` over the quartic extension, and nothing else.
///
/// The previous version of this test pushed `a`, `b` and `a*b` and then checked
/// `a*b == a*b`, which holds for every proof there is. It also compared a single
/// coefficient, leaving a base-field equality worth ~31 bits where the extension
/// exists to provide ~124.
#[test]
fn final_check_accepts_only_the_right_value() {
    let mut rng = ChaCha20Rng::seed_from_u64(21);
    for _ in 0..8 {
        let weight = rand_ef(&mut rng);
        let f_at_r = rand_ef(&mut rng);
        let claimed = pf::ext4::mul(weight, f_at_r);

        run_ok(script! {
            { push_ef(claimed) } { push_ef(weight) } { push_ef(f_at_r) }
            { verifier::final_check() }
            OP_TRUE
        });

        // Every coefficient is load-bearing: perturbing any one must abort.
        for i in 0..4 {
            let mut bad = claimed;
            bad[i] = pf::add(bad[i], 1);
            run_rejects(
                script! {
                    { push_ef(bad) } { push_ef(weight) } { push_ef(f_at_r) }
                    { verifier::final_check() }
                    OP_TRUE
                },
                &format!("claimed coefficient {i} was perturbed"),
            );
        }

        // And the weight is not decorative.
        let mut bad_w = weight;
        bad_w[0] = pf::add(bad_w[0], 1);
        run_rejects(
            script! {
                { push_ef(claimed) } { push_ef(bad_w) } { push_ef(f_at_r) }
                { verifier::final_check() }
                OP_TRUE
            },
            "the batching weight was perturbed",
        );
    }
}

// ---------------------------------------------------------------------------
// The transcript spine
// ---------------------------------------------------------------------------

/// A small instance, chosen so the whole transcript fits in a test.
fn small() -> Config {
    Config {
        initial_folding_factor: 2,
        rounds: vec![Round { folding_factor: 2, num_queries: 3, log_domain_size: 6, ood_samples: 1 }],
        final_round: Round { folding_factor: 2, num_queries: 3, log_domain_size: 4, ood_samples: 1 },
        final_sumcheck_rounds: 1,
        final_poly_vars: 2,
    }
}

/// The transcript that `verify` consumes, and the state and claim it should
/// The coordinates of folding randomness a schedule produces: one per sumcheck
/// round, which is what `sumcheck_rounds_fs_keep` leaves on the stack.
fn total_folding_vars(cfg: &Config) -> usize {
    cfg.initial_folding_factor
        + cfg.rounds.iter().map(|r| r.folding_factor).sum::<usize>()
        + cfg.final_sumcheck_rounds
}

/// reach. Mirrors the script step for step in plain Rust.
struct Spine {
    items: Vec<u32>,
    claim: [u32; 4],
    state: [u32; 16],
}

fn build_spine(cfg: &Config, rng: &mut ChaCha20Rng, state0: [u32; 16], claim0: [u32; 4]) -> Spine {
    let mut items = Vec::new();
    let mut state = state0;
    let mut claim = claim0;

    let sumcheck = |n: usize, items: &mut Vec<u32>, state: &mut [u32; 16], claim: &mut [u32; 4], rng: &mut ChaCha20Rng| {
        for _ in 0..n {
            let (c0, c_inf) = (rand_ef(rng), rand_ef(rng));
            items.extend_from_slice(&c0);
            items.extend_from_slice(&c_inf);
            let (next, _) = reference::sumcheck_round_fs(state, *claim, c0, c_inf);
            *claim = next;
        }
    };
    let absorb = |n: usize, items: &mut Vec<u32>, state: &mut [u32; 16], rng: &mut ChaCha20Rng| {
        let vals: Vec<u32> = (0..n).map(|_| rand_f(rng)).collect();
        items.extend_from_slice(&vals);
        for block in vals.chunks(reference::RATE) {
            reference::duplexing(state, block);
        }
    };

    sumcheck(cfg.initial_folding_factor, &mut items, &mut state, &mut claim, rng);
    for r in cfg.rounds.iter() {
        absorb(poseidon2::merkle::DIGEST, &mut items, &mut state, rng);
        // The point is sampled from the rate the previous absorb produced, and
        // only then is the answer absorbed. Sampling reads the state without
        // permuting, so the mirror has nothing to do but keep the order.
        for _ in 0..r.ood_samples {
            absorb(4, &mut items, &mut state, rng);
        }
        sumcheck(r.folding_factor, &mut items, &mut state, &mut claim, rng);
    }
    absorb(4 << cfg.final_poly_vars, &mut items, &mut state, rng);
    sumcheck(cfg.final_sumcheck_rounds, &mut items, &mut state, &mut claim, rng);

    Spine { items, claim, state }
}

/// The spine executes, and lands where the reference does.
///
/// This is the property the module previously lacked entirely: `verify` was
/// emitted, measured with `.len()`, and never handed to the interpreter. It
/// could not have run — an `absorb` leaves the sixteen-element state where the
/// old `sumcheck_round` expected `claim c0 c_inf r`, so the schedule would have
/// consumed sponge state as sumcheck operands.
#[test]
fn transcript_spine_executes_and_matches_the_reference() {
    let mut rng = ChaCha20Rng::seed_from_u64(22);
    let cfg = small();
    let state0: [u32; 16] = core::array::from_fn(|_| rand_f(&mut rng));
    let claim0 = rand_ef(&mut rng);
    let want = build_spine(&cfg, &mut rng, state0, claim0);

    let got = run_ok(script! {
        { push_altstack(&want.items) }
        { push_ef(claim0) }
        for s in state0 { {s} }
        { verifier::verify(&cfg) }
    });

    let m = total_folding_vars(&cfg);
    assert_eq!(got.len(), 4 * m + 4 + 16, "unexpected stack shape");
    assert_eq!(&got[4 * m..4 * m + 4], &want.claim, "claim disagrees with the reference");
    assert_eq!(&got[4 * m + 4..], &want.state, "sponge state disagrees with the reference");
}

/// Changing one byte of the transcript changes the claim the spine reaches.
///
/// A verifier that ended on an equality against this claim would therefore
/// reject the tampered proof. That is the property the derived challenges buy;
/// with challenges supplied as hints the prover could restore any target.
#[test]
fn transcript_spine_is_sensitive_to_every_absorbed_value() {
    let mut rng = ChaCha20Rng::seed_from_u64(23);
    let cfg = small();
    let state0: [u32; 16] = core::array::from_fn(|_| rand_f(&mut rng));
    let claim0 = rand_ef(&mut rng);
    let want = build_spine(&cfg, &mut rng, state0, claim0);

    // Probe a spread of positions rather than all of them; the transcript is
    // long and each run executes a full schedule of permutations.
    let probes = [0usize, 7, want.items.len() / 2, want.items.len() - 1];
    for &i in probes.iter() {
        let mut items = want.items.clone();
        items[i] = pf::add(items[i], 1);

        let got = run_ok(script! {
            { push_altstack(&items) }
            { push_ef(claim0) }
            for s in state0 { {s} }
            { verifier::verify(&cfg) }
        });
        let m = total_folding_vars(&cfg);
        assert_ne!(
            &got[4 * m..4 * m + 4],
            &want.claim,
            "perturbing transcript position {i} left the claim unchanged"
        );
    }
}

/// The count matches what the spine actually emits, for the part it covers.
///
/// `permutation_count` prices the whole schedule including the query openings
/// the spine does not yet compose, so the comparison is against the spine's
/// share: absorbs and sumcheck rounds, one permutation each.
#[test]
fn permutation_count_agrees_with_the_emitted_spine() {
    let cfg = small();
    let one = poseidon2::permutation::permute().len();
    let spine_perms = verifier::verify(&cfg).len() / one;

    let sumcheck_rounds =
        cfg.initial_folding_factor + cfg.rounds.iter().map(|r| r.folding_factor).sum::<usize>()
            + cfg.final_sumcheck_rounds;
    let absorbs: usize = cfg
        .rounds
        .iter()
        .map(|r| poseidon2::merkle::DIGEST.div_ceil(reference::RATE) + r.ood_samples)
        .sum::<usize>()
        + (4usize << cfg.final_poly_vars).div_ceil(reference::RATE);

    assert_eq!(
        spine_perms,
        sumcheck_rounds + absorbs,
        "the spine emits a different number of permutations than predicted"
    );
}

/// A realistic instance: a 2^20 trace, rate 1/2, folding factor 4, ~20 queries.
fn example() -> Config {
    let mut rounds = Vec::new();
    let mut log_domain = 21usize;
    for _ in 0..4 {
        rounds.push(Round {
            folding_factor: 4,
            num_queries: 20,
            log_domain_size: log_domain,
            ood_samples: 2,
        });
        log_domain -= 4;
    }
    Config {
        initial_folding_factor: 4,
        rounds,
        final_round: Round {
            folding_factor: 4,
            num_queries: 20,
            log_domain_size: log_domain,
            ood_samples: 2,
        },
        final_sumcheck_rounds: 4,
        final_poly_vars: 4,
    }
}

#[test]
fn report_verifier_size() {
    let cfg = example();
    let perms = verifier::permutation_count(&cfg);
    let one = poseidon2::permutation::permute().len();

    const BLOCK: usize = 4_000_000;

    let merkle: usize = cfg.rounds.iter().map(|r| r.num_queries * r.log_domain_size).sum::<usize>()
        + cfg.final_round.num_queries * cfg.final_round.log_domain_size;

    println!("\n  WHIR verifier for a 2^20 trace, 20 queries, folding factor 4");
    println!("  -----------------------------------------------------------");
    println!("  permutations                 {perms:>12}");
    println!("    of which Merkle paths      {merkle:>12}");
    println!("    of which transcript        {:>12}", perms - merkle);
    println!("  bytes                        {:>12}", perms * one);
    println!("  blocks                       {:>12.1}", (perms * one) as f64 / BLOCK as f64);
    println!("\n  transcript share             {:>11.1}%", 100.0 * (perms - merkle) as f64 / perms as f64);
    println!();
}
