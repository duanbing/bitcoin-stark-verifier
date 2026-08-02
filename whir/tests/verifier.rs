//! The composed verifier: the final check runs, and the schedule is priced.

use bitcoin_script::{define_pushable, script};
use poseidon2::reference as f;
use whir::verifier::{self, Config, Round};

define_pushable!();

/// The final consistency check, `claimed_eval == weights * f(r)`.
#[test]
fn final_check_accepts_only_the_right_value() {
    let (w, fr) = (123_456u32, 654_321u32);
    let claimed = f::mul(w, fr);

    let ok = bitcoin_scriptexec::execute_script(script! {
        {claimed} {w} {fr} { verifier::final_check() }
    });
    assert!(ok.error.is_none(), "a correct final check was rejected");

    let bad = bitcoin_scriptexec::execute_script(script! {
        {f::add(claimed, 1)} {w} {fr} { verifier::final_check() }
    });
    assert!(bad.error.is_some(), "a wrong claimed evaluation was accepted");
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
    let script = verifier::verify(&cfg);
    let perms = verifier::permutation_count(&cfg);
    let one = poseidon2::permutation::permute().len();

    const STD_TX: usize = 400_000;
    const BLOCK: usize = 4_000_000;

    println!("\n  WHIR verifier for a 2^20 trace, 20 queries, folding factor 4");
    println!("  -----------------------------------------------------------");
    println!("  permutations                 {:>12}", perms);
    println!("  script                       {:>12} bytes", script.len());
    println!("  of which permutations        {:>12} bytes ({:.1}%)",
             perms * one, 100.0 * (perms * one) as f64 / script.len() as f64);
    println!("  standard transactions        {:>12.0}", script.len() as f64 / STD_TX as f64);
    println!("  blocks                       {:>12.1}", script.len() as f64 / BLOCK as f64);
    println!("\n  Merkle paths alone           {:>12} perms",
             cfg.rounds.iter().map(|r| r.num_queries * r.log_domain_size).sum::<usize>()
                 + cfg.final_round.num_queries * cfg.final_round.log_domain_size);
    println!("  transcript and sumcheck      {:>12} perms",
             perms - (cfg.rounds.iter().map(|r| r.num_queries * r.log_domain_size).sum::<usize>()
                 + cfg.final_round.num_queries * cfg.final_round.log_domain_size));
    println!();
}
