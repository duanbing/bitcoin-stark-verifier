//! The disprove predicate: valid exactly when the prover lied.
//!
//! Every other test here asks whether a script accepts a correct value. These
//! ask the opposite, and the opposite has its own way of being vacuous: a
//! predicate that is always true lets anyone take the bond, and one that is
//! always false makes the bond unclaimable. Both cases are run.

use bitcoin_script::{define_pushable, script};
use poseidon2::constants::WIDTH;
use poseidon2::{disprove, permutation, reference};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

define_pushable!();

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

fn run(s: bitcoin::ScriptBuf) -> Vec<u32> {
    let info = bitcoin_scriptexec::execute_script(s);
    assert!(info.error.is_none(), "errored: {:?} at {:?}", info.error, info.last_opcode);
    (0..info.final_stack.len()).map(|i| decode(&info.final_stack.get(i)) as u32).collect()
}

fn rand_state(rng: &mut ChaCha20Rng) -> [u32; WIDTH] {
    core::array::from_fn(|_| rng.random_range(0..poseidon2::constants::P))
}

#[test]
fn differs_is_the_negation_of_equality() {
    let mut rng = ChaCha20Rng::seed_from_u64(70);
    for n in [1usize, 4, 16] {
        let a: Vec<u32> = (0..n).map(|_| rng.random_range(0..poseidon2::constants::P)).collect();

        let same = run(script! {
            for x in a.iter() { {*x} }
            for x in a.iter() { {*x} }
            { disprove::differs(n) }
        });
        assert_eq!(same, vec![0], "n = {n}: equal vectors reported as differing");

        // Every position on its own has to be enough.
        for i in 0..n {
            let mut b = a.clone();
            b[i] = reference::add(b[i], 1);
            let got = run(script! {
                for x in a.iter() { {*x} }
                for x in b.iter() { {*x} }
                { disprove::differs(n) }
            });
            assert_eq!(got, vec![1], "n = {n}: a difference at {i} went unnoticed");
        }
    }
}

/// The honest step is *not* disprovable, and every wrong one is.
///
/// The first half is the half that matters. A predicate that fires on an honest
/// step is not a weak disprove, it is a way to take a bond from someone who did
/// nothing wrong.
#[test]
fn a_round_is_disprovable_exactly_when_it_is_wrong() {
    let mut rng = ChaCha20Rng::seed_from_u64(71);
    let n_rounds = disprove::rounds_per_permutation();

    for i in [0usize, 1, n_rounds / 2, n_rounds - 1] {
        let state = rand_state(&mut rng);
        // The honest output of round `i`, from the reference by way of the
        // script itself: `rounds()` is checked against `permute()` elsewhere,
        // so running it here is the definition of what the prover owes.
        let honest = run(script! {
            for x in state { {x} }
            { permutation::rounds().into_iter().nth(i).expect("round") }
        });
        assert_eq!(honest.len(), WIDTH);

        let got = run(script! {
            for x in honest.iter() { {*x} }
            for x in state { {x} }
            { disprove::round(i) }
        });
        assert_eq!(got, vec![0], "round {i}: an honest step was disprovable");

        for j in [0usize, WIDTH / 2, WIDTH - 1] {
            let mut lie = honest.clone();
            lie[j] = reference::add(lie[j], 1);
            let got = run(script! {
                for x in lie.iter() { {*x} }
                for x in state { {x} }
                { disprove::round(i) }
            });
            assert_eq!(got, vec![1], "round {i}: a lie about element {j} was not disprovable");
        }
    }
}

/// What a step costs, and what that means for the chunk count.
///
/// Two limits: 400 000 weight units for a transaction a node will relay, and
/// 4 000 000 for a block. Script is witness data, so one byte is one unit.
#[test]
fn report_step_size() {
    const STANDARD_TX_WU: usize = 400_000;
    let n_rounds = disprove::rounds_per_permutation();
    let one = permutation::permute().len();
    let largest = disprove::largest_round();

    println!("\n  a step is one permutation round");
    println!("  -------------------------------");
    println!("  rounds per permutation       {n_rounds:>12}");
    println!("  one permutation              {one:>12} B");
    println!("  largest disprove step        {largest:>12} B");
    println!("  as a share of a standard tx  {:>11.1}%", 100.0 * largest as f64 / STANDARD_TX_WU as f64);
    println!("  steps that fit in one        {:>12}", STANDARD_TX_WU / largest);
    println!();

    assert!(
        largest < STANDARD_TX_WU,
        "a disprove step is {largest} B, past the {STANDARD_TX_WU} weight units a node will relay: \
         the chunking has to go finer than one permutation round"
    );
}
