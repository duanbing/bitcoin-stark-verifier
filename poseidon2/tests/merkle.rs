//! Leaf hashing: the half of a query opening that binds the row to the tree.
//!
//! A Merkle walk proves that some committed leaf sits at the sampled index. It
//! says nothing about which values were hashed to make that leaf, so on its own
//! a spender can authenticate the real leaf and fold a different row into the
//! constraint. [`merkle::hash_row`] is what closes that: the row is hashed in
//! script and the result *is* the leaf handed to the walk.

use bitcoin_script::{define_pushable, script};
use poseidon2::constants::P;
use poseidon2::{merkle, reference};
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

/// `hash_row` matches the reference across chunk boundaries.
///
/// The boundaries are where a padding-free sponge differs from a duplex: a
/// partial final chunk leaves the rest of the state alone rather than zeroing it
/// and mixing in a length. Sizes either side of the rate pin that down.
#[test]
fn hash_row_matches_the_reference() {
    let mut rng = ChaCha20Rng::seed_from_u64(31);
    for n in [1usize, 2, 4, 7, 8, 9, 15, 16, 17] {
        let row: Vec<u32> = (0..n).map(|_| rng.random_range(0..P)).collect();
        let want = reference::hash_row(&row);

        let got = run(script! {
            for x in row.iter() { {*x} }
            { merkle::hash_row(n) }
        });

        assert_eq!(got.len(), merkle::DIGEST, "row of {n}: wrong digest width");
        assert_eq!(got, want.to_vec(), "row of {n}: digest disagrees with the reference");
    }
}

/// Every element of the row reaches the digest.
///
/// A sponge that dropped the tail of a partial chunk, or that overwrote the
/// wrong slots, would still agree with a reference that made the same mistake.
/// This does not depend on the reference.
#[test]
fn hash_row_depends_on_every_element() {
    let mut rng = ChaCha20Rng::seed_from_u64(32);
    let n = 12;
    let row: Vec<u32> = (0..n).map(|_| rng.random_range(0..P)).collect();

    let base = run(script! {
        for x in row.iter() { {*x} }
        { merkle::hash_row(n) }
    });

    for i in 0..n {
        let mut bad = row.clone();
        bad[i] = reference::add(bad[i], 1);
        let got = run(script! {
            for x in bad.iter() { {*x} }
            { merkle::hash_row(n) }
        });
        assert_ne!(got, base, "element {i} did not affect the digest");
    }
}

/// Hashing a row and walking the path compose, which is how a query opening is
/// actually put together.
#[test]
fn hash_row_feeds_the_path() {
    let mut rng = ChaCha20Rng::seed_from_u64(33);
    let depth = 4usize;
    let width = 6usize;

    let row: Vec<u32> = (0..width).map(|_| rng.random_range(0..P)).collect();
    let leaf = reference::hash_row(&row);
    let sibs: Vec<[u32; 8]> =
        (0..depth).map(|_| core::array::from_fn(|_| rng.random_range(0..P))).collect();
    let bits: Vec<bool> = (0..depth).map(|i| (i % 2) == 0).collect();
    let root = reference::merkle_root(leaf, &sibs, &bits);

    // Row in, root checked, nothing left: the opening is one unit.
    let ok = bitcoin_scriptexec::execute_script(script! {
        for x in root.iter() { {*x} }
        for i in (0..depth).rev() { for x in sibs[i].iter() { {*x} } }
        for x in row.iter() { {*x} }
        { merkle::hash_row(width) }
        for &b in bits.iter().rev() { { if b { 1u32 } else { 0u32 } } OP_TOALTSTACK }
        { merkle::merkle_verify_from_altstack(depth) }
        OP_TRUE
    });
    assert!(ok.error.is_none(), "a valid opening was rejected: {:?}", ok.error);

    // Substituting a different row for the same leaf is exactly the attack the
    // hash is here to stop.
    let mut other = row.clone();
    other[0] = reference::add(other[0], 1);
    let bad = bitcoin_scriptexec::execute_script(script! {
        for x in root.iter() { {*x} }
        for i in (0..depth).rev() { for x in sibs[i].iter() { {*x} } }
        for x in other.iter() { {*x} }
        { merkle::hash_row(width) }
        for &b in bits.iter().rev() { { if b { 1u32 } else { 0u32 } } OP_TOALTSTACK }
        { merkle::merkle_verify_from_altstack(depth) }
        OP_TRUE
    });
    assert!(bad.error.is_some(), "a substituted row was accepted");
}
