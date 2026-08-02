//! The duplex against the reference, and the padding rule that makes it sound.

use bitcoin_script::{define_pushable, script};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use whir::{reference, sponge};

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

#[test]
fn absorb_matches_reference() {
    let p = poseidon2::constants::P;
    let mut rng = ChaCha20Rng::seed_from_u64(81);
    for k in 0..=sponge::RATE {
        for _ in 0..2 {
            let st: [u32; 16] = core::array::from_fn(|_| rng.random_range(0..p));
            let inputs: Vec<u32> = (0..k).map(|_| rng.random_range(0..p)).collect();

            let mut want = st;
            reference::duplexing(&mut want, &inputs);

            let got = run(script! {
                for s in st { {s} }
                for v in inputs.iter() { {*v} }
                { sponge::absorb(k) }
            });
            assert_eq!(got, want.to_vec(), "k = {k}");
        }
    }
}

#[test]
fn squeeze_matches_reference() {
    let p = poseidon2::constants::P;
    let mut rng = ChaCha20Rng::seed_from_u64(82);
    let st: [u32; 16] = core::array::from_fn(|_| rng.random_range(0..p));
    let mut want = st;
    let _ = reference::squeeze(&mut want);
    let got = run(script! { for s in st { {s} } { sponge::squeeze() } });
    assert_eq!(got, want.to_vec());
}

/// The padding rule is the point. Absorbing `[a]` must not equal absorbing
/// `[a, 0]`, or a prover could pass off one transcript as another. Plonky3
/// prevents it by binding the absorbed length into the first capacity slot.
#[test]
fn short_absorb_does_not_collide_with_zero_padding() {
    let st = [7u32; 16];

    let mut one = st;
    reference::duplexing(&mut one, &[12345]);
    let mut two = st;
    reference::duplexing(&mut two, &[12345, 0]);
    assert_ne!(one, two, "length tag missing: padding collides");

    // And the script agrees with the reference on both.
    let got1 = run(script! { for s in st { {s} } {12345u32} { sponge::absorb(1) } });
    let got2 = run(script! { for s in st { {s} } {12345u32} {0u32} { sponge::absorb(2) } });
    assert_eq!(got1, one.to_vec());
    assert_eq!(got2, two.to_vec());
    assert_ne!(got1, got2);
}

/// Absorbing then squeezing must chain: the state carries between calls.
#[test]
fn absorb_then_squeeze_chains() {
    let st = [3u32; 16];
    let mut want = st;
    reference::duplexing(&mut want, &[11, 22, 33]);
    let _ = reference::squeeze(&mut want);

    let got = run(script! {
        for s in st { {s} }
        {11u32} {22u32} {33u32}
        { sponge::absorb(3) }
        { sponge::squeeze() }
    });
    assert_eq!(got, want.to_vec());
}
