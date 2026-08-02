//! Merkle path verification, and what a query costs.
//!
//! On Bitcoin a low-degree test's verifier is almost entirely Merkle hashing:
//! one Poseidon2 permutation per level, per query. So query complexity is the
//! figure of merit — which is exactly what STIR and WHIR improve over FRI.
//! This file measures the path and projects the rest.

use poseidon2::merkle::DIGEST;
use poseidon2::{merkle, permutation, reference};
use bitcoin_script::{define_pushable, script};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

define_pushable!();

fn decode(v: &[u8]) -> i64 {
    if v.is_empty() { return 0; }
    let mut n: i64 = 0;
    for (i, b) in v.iter().enumerate() { n |= ((*b as i64) & 0xff) << (8 * i); }
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

#[test]
fn merkle_path_matches_reference() {
    let mut rng = ChaCha20Rng::seed_from_u64(31);
    let mut fe = || rng.random_range(0..poseidon2::constants::P);

    for depth in [1usize, 2, 3] {
        let leaf: [u32; DIGEST] = core::array::from_fn(|_| fe());
        let siblings: Vec<[u32; DIGEST]> =
            (0..depth).map(|_| core::array::from_fn(|_| fe())).collect();
        let bits: Vec<bool> = (0..depth).map(|i| i % 2 == 1).collect();

        let want = reference::merkle_root(leaf, &siblings, &bits);

        // Bottom to top: deepest sibling and bit first, leaf last.
        let got = run(script! {
            for i in (0..depth).rev() {
                for x in siblings[i] { {x} }
                { if bits[i] { 1u32 } else { 0u32 } }
            }
            for x in leaf { {x} }
            { merkle::merkle_path(depth) }
        });
        assert_eq!(got, want.to_vec(), "depth {depth}");
    }
}

/// What a query costs, and whether fewer queries is the lever that matters.
#[test]
fn query_cost_model() {
    let perm = permutation::permute().len();
    let step = merkle::merkle_step().len();
    let per_level = step; // one compression plus a little ordering

    const STD_TX: usize = 400_000;
    const BLOCK: usize = 4_000_000;

    println!("\n  one Poseidon2 permutation      {:>12} bytes", perm);
    println!("  one Merkle level (step)        {:>12} bytes", per_level);
    println!("  ordering overhead per level    {:>12} bytes", step - perm);

    // A 2^20 trace over a rate-1/2 code gives a depth-21 commitment.
    let depth = 21usize;
    let path = merkle::merkle_path(depth).len();
    println!("\n  path at depth {depth}                {:>12} bytes = {:.1} blocks",
             path, path as f64 / BLOCK as f64);

    // Query counts for ~100-bit security. FRI at rate 1/2 needs about one query
    // per bit; STIR and WHIR reach the same soundness in far fewer, which is
    // the whole reason they matter here.
    println!("\n  scheme      queries   total bytes    standard txs      blocks");
    println!("  ---------------------------------------------------------------");
    for (name, queries) in [("FRI", 100usize), ("STIR", 30), ("WHIR", 20)] {
        let total = path * queries;
        println!("  {:<10} {:>7} {:>13} {:>15.0} {:>11.0}",
                 name, queries, total, total as f64 / STD_TX as f64,
                 total as f64 / BLOCK as f64);
    }
    println!("\n  A byte hash under OP_CAT would make one level ~2 bytes,");
    println!("  so the same depth-{depth} path would be ~{} bytes.\n", depth * 2);
}

/// Sizes of the verifier operations that are not the hash.
#[test]
fn primitive_sizes() {
    use poseidon2::field;
    println!("\n  inverse (hinted, one mul)      {:>10} bytes", field::inverse_hinted().len());
    println!("  challenge -> 21-bit index      {:>10} bytes", field::low_bits_to_altstack(21).len());
    println!("  g^i, 21-bit exponent           {:>10} bytes", field::pow_const_base(3, 21).len());
    println!("  one Poseidon2 permutation      {:>10} bytes", poseidon2::permutation::permute().len());
    println!("\n  For contrast, inversion by exponentiation would be about");
    println!("  sixty multiplications: {} bytes.\n", 60 * field::mul().len());
}

/// The binding a query opening depends on: the recomputed root must equal the
/// committed one, and the directions come from the transcript rather than the
/// spender. Without both, a prover opens whatever leaf it likes.
#[test]
fn merkle_opening_is_bound() {
    use poseidon2::merkle::DIGEST;
    let mut rng = ChaCha20Rng::seed_from_u64(33);
    let mut fe = || rng.random_range(0..poseidon2::constants::P);

    let depth = 3usize;
    let leaf: [u32; DIGEST] = core::array::from_fn(|_| fe());
    let siblings: Vec<[u32; DIGEST]> = (0..depth).map(|_| core::array::from_fn(|_| fe())).collect();
    let bits: Vec<bool> = vec![true, false, true];
    let root = reference::merkle_root(leaf, &siblings, &bits);

    let body = |root: [u32; DIGEST], bits: &[bool]| {
        script! {
            for x in root { {x} }
            for i in (0..depth).rev() { for x in siblings[i] { {x} } }
            for x in leaf { {x} }
            // Directions on the altstack, first level on top.
            for &b in bits.iter().rev() { { if b { 1u32 } else { 0u32 } } OP_TOALTSTACK }
            { merkle::merkle_verify_from_altstack(depth) }
        }
    };

    let ok = bitcoin_scriptexec::execute_script(body(root, &bits));
    assert!(ok.error.is_none(), "a correct opening was rejected: {:?}", ok.error);

    let mut wrong_root = root;
    wrong_root[0] = reference::add(wrong_root[0], 1);
    assert!(
        bitcoin_scriptexec::execute_script(body(wrong_root, &bits)).error.is_some(),
        "an opening against the wrong root was accepted"
    );

    let wrong_bits = vec![false, false, true];
    assert!(
        bitcoin_scriptexec::execute_script(body(root, &wrong_bits)).error.is_some(),
        "an opening at the wrong index was accepted"
    );
}
