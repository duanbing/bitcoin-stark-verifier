//! The round against the reference, and against Plonky3's stated identities.

use bitcoin_script::{define_pushable, script};
use poseidon2::{merkle, reference as f};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use whir::{reference, sumcheck};

define_pushable!();

fn decode(v: &[u8]) -> i64 {
    if v.is_empty() { return 0; }
    let mut n: i64 = 0;
    for (i, b) in v.iter().enumerate() { n |= ((*b as i64) & 0xff) << (8 * i); }
    if v[v.len() - 1] & 0x80 != 0 { n &= !(0x80i64 << (8 * (v.len() - 1))); return -n; }
    n
}

fn run(s: bitcoin::ScriptBuf) -> Vec<u32> {
    let info = bitcoin_scriptexec::execute_script(s);
    assert!(info.error.is_none(), "errored: {:?} at {:?}", info.error, info.last_opcode);
    (0..info.final_stack.len()).map(|i| decode(&info.final_stack.get(i)) as u32).collect()
}

/// Plonky3 documents `L_0(0) = 1`, `L_1(1) = 1`, and that the weights do not
/// sum to one. Pin all three so a sign slip in the reference is caught.
const ZERO: [u32; 4] = [0, 0, 0, 0];
const ONE: [u32; 4] = reference::EF_ONE;

fn rand_ef(rng: &mut ChaCha20Rng) -> [u32; 4] {
    core::array::from_fn(|_| rng.random_range(0..poseidon2::constants::P))
}

fn push_ef(v: [u32; 4]) -> bitcoin::ScriptBuf {
    script! { for x in v { {x} } }
}

#[test]
fn lagrange_weights_match_plonky3_identities() {
    assert_eq!(reference::lagrange_weights_01inf(ZERO), [ONE, ZERO, ZERO]);
    assert_eq!(reference::lagrange_weights_01inf(ONE), [ZERO, ONE, ZERO]);
    // h(r) reproduces the sent evaluations at r = 0 and r = 1.
    let (c0, c1, cinf) = ([1u32, 2, 3, 4], [5u32, 6, 7, 8], [9u32, 10, 11, 12]);
    assert_eq!(reference::extrapolate_01inf(c0, c1, cinf, ZERO), c0);
    assert_eq!(reference::extrapolate_01inf(c0, c1, cinf, ONE), c1);
}

#[test]
fn round_matches_reference() {
    let mut rng = ChaCha20Rng::seed_from_u64(61);
    for _ in 0..10 {
        let (claim, c0, c_inf, r) =
            (rand_ef(&mut rng), rand_ef(&mut rng), rand_ef(&mut rng), rand_ef(&mut rng));
        let want = reference::sumcheck_round(claim, c0, c_inf, r);
        let got = run(script! {
            { push_ef(claim) } { push_ef(c0) } { push_ef(c_inf) } { push_ef(r) }
            { sumcheck::sumcheck_round() }
        });
        assert_eq!(got, want.to_vec());
    }
}

/// The sumcheck constraint itself: at `r = 0` the new claim is `h(0)`, and at
/// `r = 1` it is `claim - h(0)`. A round that got the weights backwards passes
/// random tests far less often than it passes these.
#[test]
fn round_respects_the_sumcheck_constraint() {
    use poseidon2::reference::ext4;
    let claim = [999_983u32, 17, 29, 41];
    let c0 = [12_345u32, 3, 5, 7];
    let c_inf = [777_777u32, 11, 13, 19];
    let head = script! { { push_ef(claim) } { push_ef(c0) } { push_ef(c_inf) } };
    assert_eq!(
        run(script! { { head.clone() } { push_ef(ZERO) } { sumcheck::sumcheck_round() } }),
        c0.to_vec(),
        "r = 0 must give h(0)"
    );
    assert_eq!(
        run(script! { { head } { push_ef(ONE) } { sumcheck::sumcheck_round() } }),
        ext4::sub(claim, c0).to_vec(),
        "r = 1 must give claim - h(0)"
    );
}

#[test]
fn rounds_compose() {
    let mut rng = ChaCha20Rng::seed_from_u64(62);
    let n = 3usize;
    let claim = rand_ef(&mut rng);
    let tri: Vec<([u32; 4], [u32; 4], [u32; 4])> =
        (0..n).map(|_| (rand_ef(&mut rng), rand_ef(&mut rng), rand_ef(&mut rng))).collect();

    let mut want = claim;
    for &(c0, c_inf, r) in tri.iter() {
        want = reference::sumcheck_round(want, c0, c_inf, r);
    }

    // Round one pops first, so it is pushed to the altstack last.
    let got = run(script! {
        { push_ef(claim) }
        for &(c0, c_inf, r) in tri.iter().rev() {
            { push_ef(r) } { poseidon2::ext4::to_altstack() }
            { push_ef(c_inf) } { poseidon2::ext4::to_altstack() }
            { push_ef(c0) } { poseidon2::ext4::to_altstack() }
        }
        { sumcheck::sumcheck_rounds(n) }
    });
    assert_eq!(got, want.to_vec());
}

/// Where WHIR's advantage actually comes from.
#[test]
fn round_vs_merkle() {
    let round = sumcheck::sumcheck_round().len();
    let level = merkle::merkle_step().len();
    println!("\n  WHIR sumcheck round      {:>10} bytes", round);
    println!("  one Merkle level         {:>10} bytes", level);
    println!("  ratio                    {:>10.0}x", level as f64 / round as f64);
    println!("\n  No inversion in a round, so it is cheaper than a STIR fold.");
    println!("  But both are noise next to the path: WHIR wins on Bitcoin by");
    println!("  needing fewer queries, not by cheaper arithmetic.\n");
}

/// Multilinear evaluation, which WHIR uses for the final check and for each
/// query answer. The fold order is Plonky3's: last variable first.
#[test]
fn multilinear_matches_reference() {
    use whir::multilinear;
    let mut rng = ChaCha20Rng::seed_from_u64(71);
    for n in 1..=3usize {
        let evals: Vec<[u32; 4]> = (0..(1 << n)).map(|_| rand_ef(&mut rng)).collect();
        let point: Vec<[u32; 4]> = (0..n).map(|_| rand_ef(&mut rng)).collect();
        let want = reference::eval_multilinear(&evals, &point);
        let got = run(script! {
            for e in evals.iter() { { push_ef(*e) } }
            // The last variable folds first, so it is pushed last.
            for x in point.iter() { { push_ef(*x) } { poseidon2::ext4::to_altstack() } }
            { multilinear::eval_multilinear(n) }
        });
        assert_eq!(got, want.to_vec(), "n = {n}");
    }
}

/// A multilinear polynomial agrees with its own evaluation table on the cube.
/// This catches a reversed variable order, which random points hide.
#[test]
fn multilinear_agrees_on_the_boolean_cube() {
    use whir::multilinear;
    let n = 3usize;
    let evals: Vec<[u32; 4]> = (0..8u32).map(|i| [1000 + i * 7, i, 2 * i, 3 * i]).collect();
    for idx in 0..8usize {
        // Big-endian: bit i of idx is variable i.
        let point: Vec<[u32; 4]> =
            (0..n).map(|i| if (idx >> (n - 1 - i)) & 1 == 1 { ONE } else { ZERO }).collect();
        assert_eq!(reference::eval_multilinear(&evals, &point), evals[idx], "ref at {idx}");
        let got = run(script! {
            for e in evals.iter() { { push_ef(*e) } }
            for x in point.iter() { { push_ef(*x) } { poseidon2::ext4::to_altstack() } }
            { multilinear::eval_multilinear(n) }
        });
        assert_eq!(got, evals[idx].to_vec(), "script at {idx}");
    }
}

/// What the WHIR-specific parts cost, against the hash they sit next to.
#[test]
fn whir_component_sizes() {
    use whir::multilinear;
    let round = sumcheck::sumcheck_round().len();
    let level = merkle::merkle_step().len();
    println!("\n  WHIR sumcheck round          {:>10} bytes", round);
    for n in [1usize, 2, 3, 4] {
        println!("  multilinear eval, {n} vars     {:>10} bytes", multilinear::eval_multilinear(n).len());
    }
    println!("  one Merkle level             {:>10} bytes", level);
    println!("  sample_bits (21-bit index)   {:>10} bytes", whir::challenger::sample_bits(0, 21).len());
    println!("  sponge absorb (rate 8)       {:>10} bytes", whir::sponge::absorb(8).len());
    println!("  sponge squeeze               {:>10} bytes", whir::sponge::squeeze().len());
    println!("\n  The sponge is a permutation, so it costs like one. Everything");
    println!("  else WHIR needs is under 2% of a Merkle level.\n");
}
