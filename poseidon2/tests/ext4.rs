//! The quartic extension, against a reference and against Plonky3 itself.

use bitcoin_script::{define_pushable, script};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_field::extension::BinomialExtensionField;
use p3_field::PrimeField32;
use p3_koala_bear::KoalaBear;
use poseidon2::constants::P;
use poseidon2::{ext4, reference};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

define_pushable!();

type EF = BinomialExtensionField<KoalaBear, 4>;

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

fn to_p3(a: [u32; 4]) -> EF {
    EF::from_basis_coefficients_slice(&a.map(KoalaBear::new)).unwrap()
}

fn from_p3(x: EF) -> [u32; 4] {
    let coeffs: &[KoalaBear] = x.as_basis_coefficients_slice();
    core::array::from_fn(|i| coeffs[i].as_canonical_u32())
}

/// The reference must agree with Plonky3's `BinomialExtensionField<KoalaBear, 4>`.
/// If Plonky3 changed `W`, this fails rather than the crate silently computing
/// in a different field.
#[test]
fn reference_matches_plonky3() {
    let mut rng = ChaCha20Rng::seed_from_u64(101);
    for _ in 0..20 {
        let a: [u32; 4] = core::array::from_fn(|_| rng.random_range(0..P));
        let b: [u32; 4] = core::array::from_fn(|_| rng.random_range(0..P));
        assert_eq!(reference::ext4::mul(a, b), from_p3(to_p3(a) * to_p3(b)), "mul");
        assert_eq!(reference::ext4::add(a, b), from_p3(to_p3(a) + to_p3(b)), "add");
        assert_eq!(reference::ext4::sub(a, b), from_p3(to_p3(a) - to_p3(b)), "sub");
    }
    assert_eq!(reference::ext4::W, 3, "W must match BinomialExtensionData<4>");
}

#[test]
fn script_matches_reference() {
    let mut rng = ChaCha20Rng::seed_from_u64(102);
    for _ in 0..8 {
        let a: [u32; 4] = core::array::from_fn(|_| rng.random_range(0..P));
        let b: [u32; 4] = core::array::from_fn(|_| rng.random_range(0..P));
        let push = script! { for x in a { {x} } for x in b { {x} } };
        assert_eq!(run(script! { {push.clone()} {ext4::add()} }), reference::ext4::add(a, b).to_vec(), "add");
        assert_eq!(run(script! { {push.clone()} {ext4::sub()} }), reference::ext4::sub(a, b).to_vec(), "sub");
        assert_eq!(run(script! { {push} {ext4::mul()} }), reference::ext4::mul(a, b).to_vec(), "mul");
    }
}

/// The field laws, which catch a wrong non-residue that random vectors may not.
#[test]
fn extension_field_laws() {
    let one = [1u32, 0, 0, 0];
    let x = [5u32, 7, 11, 13];
    assert_eq!(reference::ext4::mul(x, one), x, "one is the identity");
    // X^4 = W: multiplying X by X^3 must give the constant W.
    let xx = [0u32, 1, 0, 0];
    let x3 = [0u32, 0, 0, 1];
    assert_eq!(reference::ext4::mul(xx, x3), [reference::ext4::W, 0, 0, 0], "X^4 = W");
    assert_eq!(run(script! {
        for v in xx { {v} } for v in x3 { {v} } { ext4::mul() }
    }), vec![reference::ext4::W, 0, 0, 0]);
}

#[test]
fn report_ext4_sizes() {
    println!("\n  ext4 add   {:>8} bytes", ext4::add().len());
    println!("  ext4 sub   {:>8} bytes", ext4::sub().len());
    println!("  ext4 mul   {:>8} bytes  ({:.1}x a base mul)",
             ext4::mul().len(),
             ext4::mul().len() as f64 / poseidon2::field::mul().len() as f64);
    println!("  base mul   {:>8} bytes\n", poseidon2::field::mul().len());
}
