//! Challenge drawing, against the reference.

use bitcoin_script::{define_pushable, script};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use whir::{challenger, reference, sponge};

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

/// A challenge drawn after a real absorb-and-squeeze, not from a made-up state.
#[test]
fn sample_and_sample_bits_match_reference() {
    let p = poseidon2::constants::P;
    let mut rng = ChaCha20Rng::seed_from_u64(91);
    for _ in 0..3 {
        let st: [u32; 16] = core::array::from_fn(|_| rng.random_range(0..p));
        let inputs: Vec<u32> = (0..4).map(|_| rng.random_range(0..p)).collect();

        let mut state = st;
        reference::duplexing(&mut state, &inputs);
        let rate = reference::squeeze(&mut state);

        let prelude = script! {
            for s in st { {s} }
            for v in inputs.iter() { {*v} }
            { sponge::absorb(4) }
            { sponge::squeeze() }
        };

        for j in [0usize, 3, 7] {
            let got = run(script! { { prelude.clone() } { challenger::sample(j) } });
            assert_eq!(*got.last().unwrap(), rate[j], "sample({j})");
        }
        for (j, bits) in [(0usize, 8usize), (2, 16), (5, 21)] {
            let got = run(script! { { prelude.clone() } { challenger::sample_bits(j, bits) } });
            assert_eq!(
                *got.last().unwrap(),
                reference::sample_bits(rate[j], bits),
                "sample_bits({j}, {bits})"
            );
        }
    }
}

/// A query index must land in the domain. Plonky3 requires `2^bits < |F|`.
#[test]
fn sampled_indices_are_in_range() {
    let p = poseidon2::constants::P;
    let mut rng = ChaCha20Rng::seed_from_u64(92);
    let bits = 21usize;
    for _ in 0..4 {
        let st: [u32; 16] = core::array::from_fn(|_| rng.random_range(0..p));
        let got = run(script! {
            for s in st { {s} }
            { sponge::squeeze() }
            { challenger::sample_bits(1, bits) }
        });
        let idx = *got.last().unwrap();
        assert!((idx as u64) < (1u64 << bits), "index {idx} outside 2^{bits}");
    }
}

/// The extension challenge, which is what sets the security level.
///
/// A base-field challenge lives in a 31-bit space; this one lives in about 124
/// bits, which is what makes a 100-bit target reachable at all.
#[test]
fn sample_ef_reads_four_consecutive_rate_slots() {
    let p = poseidon2::constants::P;
    let mut rng = ChaCha20Rng::seed_from_u64(93);
    for _ in 0..4 {
        let st: [u32; 16] = core::array::from_fn(|_| rng.random_range(0..p));
        let mut state = st;
        let rate = reference::squeeze(&mut state);

        for j in 0..whir::challenger::EF_PER_SQUEEZE {
            let got = run(script! {
                for s in st { {s} }
                { sponge::squeeze() }
                { challenger::sample_ef(j) }
            });
            let coeffs = &got[got.len() - 4..];
            let want = &rate[4 * j..4 * j + 4];
            assert_eq!(coeffs, want, "sample_ef({j}) coefficient order");
        }
    }
}

/// Two distinct challenges per squeeze, and they must differ.
#[test]
fn a_squeeze_yields_two_distinct_ef_challenges() {
    let st: [u32; 16] = core::array::from_fn(|i| 1000 + i as u32);
    let a = run(script! {
        for s in st { {s} } { sponge::squeeze() } { challenger::sample_ef(0) }
    });
    let b = run(script! {
        for s in st { {s} } { sponge::squeeze() } { challenger::sample_ef(1) }
    });
    assert_eq!(whir::challenger::EF_PER_SQUEEZE, 2);
    assert_ne!(a[a.len() - 4..], b[b.len() - 4..], "both challenges are the same element");
}
