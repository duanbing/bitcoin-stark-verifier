//! Batching answers into the next target.
//!
//! The script computes the sum by Horner because extension multiplications are
//! expensive; the reference computes it as written. They agree only if the
//! rearrangement is right, which is the point of testing them against each other
//! rather than against a shared helper.

use bitcoin_script::{define_pushable, script};
use poseidon2::reference as pf;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use whir::{constraint, reference};

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

fn rand_ef(rng: &mut ChaCha20Rng) -> [u32; 4] {
    core::array::from_fn(|_| rng.random_range(0..poseidon2::constants::P))
}

fn push_ef(v: [u32; 4]) -> bitcoin::ScriptBuf {
    script! { for x in v { {x} } }
}

/// Load the answers so Horner pops `y_t` first.
fn answers_to_altstack(answers: &[[u32; 4]]) -> bitcoin::ScriptBuf {
    script! {
        for y in answers.iter() {
            { push_ef(*y) }
            for _ in 0..4 { OP_TOALTSTACK }
        }
    }
}

#[test]
fn combine_matches_the_reference() {
    let mut rng = ChaCha20Rng::seed_from_u64(41);
    // t = 0 is the out-of-domain answer alone; the rest add shift answers.
    for t in 0..6usize {
        let base = rand_ef(&mut rng);
        let gamma = rand_ef(&mut rng);
        let answers: Vec<[u32; 4]> = (0..=t).map(|_| rand_ef(&mut rng)).collect();
        let want = reference::combine_answers(base, gamma, &answers);

        let got = run(script! {
            { answers_to_altstack(&answers) }
            { push_ef(base) }
            { push_ef(gamma) }
            { constraint::combine_answers(t) }
        });

        assert_eq!(got.len(), 4, "t = {t}: expected a single EF element");
        assert_eq!(got, want.to_vec(), "t = {t}: Horner disagrees with the sum");
    }
}

/// The exponents are right, not merely consistent.
///
/// Both implementations could share an off-by-one in the power of `gamma` and
/// still agree. Pinning `t = 1` against the expression written out by hand —
/// `base + gamma*y0 + gamma^2*y1` — catches that.
#[test]
fn combine_uses_the_stated_powers() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let base = rand_ef(&mut rng);
    let gamma = rand_ef(&mut rng);
    let y0 = rand_ef(&mut rng);
    let y1 = rand_ef(&mut rng);

    let g2 = pf::ext4::mul(gamma, gamma);
    let by_hand = pf::ext4::add(
        base,
        pf::ext4::add(pf::ext4::mul(gamma, y0), pf::ext4::mul(g2, y1)),
    );

    let got = run(script! {
        { answers_to_altstack(&[y0, y1]) }
        { push_ef(base) }
        { push_ef(gamma) }
        { constraint::combine_answers(1) }
    });
    assert_eq!(got, by_hand.to_vec(), "gamma is raised to the wrong power somewhere");
}

/// Every answer reaches the target.
///
/// An answer that could be changed without moving `sigma'` would be
/// authenticated and then ignored — exactly the state this module exists to
/// leave behind.
#[test]
fn every_answer_reaches_the_target() {
    let mut rng = ChaCha20Rng::seed_from_u64(43);
    let t = 4usize;
    let base = rand_ef(&mut rng);
    let gamma = rand_ef(&mut rng);
    let answers: Vec<[u32; 4]> = (0..=t).map(|_| rand_ef(&mut rng)).collect();

    let run_with = |answers: &[[u32; 4]]| {
        run(script! {
            { answers_to_altstack(answers) }
            { push_ef(base) }
            { push_ef(gamma) }
            { constraint::combine_answers(t) }
        })
    };
    let want = run_with(&answers);

    for i in 0..=t {
        for c in 0..4 {
            let mut bad = answers.clone();
            bad[i][c] = pf::add(bad[i][c], 1);
            assert_ne!(
                run_with(&bad),
                want,
                "answer {i} coefficient {c} did not affect sigma'"
            );
        }
    }
}

/// A different batching challenge gives a different target.
///
/// This is what stops a prover trading one wrong answer against another: the
/// combination is a random linear one, so cancelling in the sum means hitting a
/// root of a degree-`t+1` polynomial in `gamma`.
#[test]
fn the_batching_challenge_matters() {
    let mut rng = ChaCha20Rng::seed_from_u64(44);
    let t = 3usize;
    let base = rand_ef(&mut rng);
    let answers: Vec<[u32; 4]> = (0..=t).map(|_| rand_ef(&mut rng)).collect();

    let with = |gamma: [u32; 4]| {
        run(script! {
            { answers_to_altstack(&answers) }
            { push_ef(base) }
            { push_ef(gamma) }
            { constraint::combine_answers(t) }
        })
    };

    let g = rand_ef(&mut rng);
    let mut g2 = g;
    g2[0] = pf::add(g2[0], 1);
    assert_ne!(with(g), with(g2), "sigma' is independent of gamma");
}
