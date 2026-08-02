//! Correctness and sizing.
//!
//! The script is executed under `bitcoin-scriptexec` and its final stack
//! compared against [`bitcoin_poseidon2_script::reference`], which is itself
//! checked against Plonky3 in `plonky3_agreement`. So the chain is
//! script → reference → Plonky3, and a break anywhere fails a test.

use bitcoin_poseidon2_script::constants::{P, WIDTH};
use bitcoin_poseidon2_script::{field, poseidon2, reference};
use bitcoin_script::{define_pushable, script};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

define_pushable!();

/// Decode a script number: little-endian magnitude with a sign bit on the last
/// byte. Every value the permutation leaves is canonical and so non-negative,
/// but decoding properly makes a sign bug fail loudly rather than silently.
fn decode(v: &[u8]) -> i64 {
    if v.is_empty() {
        return 0;
    }
    let mut n: i64 = 0;
    for (i, b) in v.iter().enumerate() {
        n |= ((*b as i64) & 0xff) << (8 * i);
    }
    let last = v[v.len() - 1];
    if last & 0x80 != 0 {
        n &= !(0x80i64 << (8 * (v.len() - 1)));
        return -n;
    }
    n
}

/// Run a script and return the final stack, bottom first, as field elements.
fn run(s: bitcoin::ScriptBuf) -> Vec<u32> {
    let info = bitcoin_scriptexec::execute_script(s);
    assert!(
        info.error.is_none(),
        "script errored: {:?} after {:?}",
        info.error,
        info.last_opcode
    );
    (0..info.final_stack.len())
        .map(|i| {
            let n = decode(&info.final_stack.get(i));
            assert!(n >= 0, "negative value left on the stack: {n}");
            n as u32
        })
        .collect()
}

fn rand_fe(rng: &mut ChaCha20Rng) -> u32 {
    rng.random_range(0..P)
}

#[test]
fn field_add_sub_double() {
    let mut rng = ChaCha20Rng::seed_from_u64(0);
    for _ in 0..40 {
        let (a, b) = (rand_fe(&mut rng), rand_fe(&mut rng));
        assert_eq!(
            run(script! { {a} {b} {field::add()} }),
            vec![reference::add(a, b)],
            "add({a},{b})"
        );
        assert_eq!(
            run(script! { {a} {b} {field::sub()} }),
            vec![reference::sub(a, b)],
            "sub({a},{b})"
        );
        assert_eq!(
            run(script! { {a} {field::double()} }),
            vec![reference::double(a)],
            "double({a})"
        );
    }
}

#[test]
fn field_mul_and_cube() {
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    for _ in 0..12 {
        let (a, b) = (rand_fe(&mut rng), rand_fe(&mut rng));
        assert_eq!(
            run(script! { {a} {b} {field::mul()} }),
            vec![reference::mul(a, b)],
            "mul({a},{b})"
        );
        assert_eq!(
            run(script! { {a} {field::mul_by_constant(b)} }),
            vec![reference::mul(a, b)],
            "mul_by_constant({a},{b})"
        );
        assert_eq!(
            run(script! { {a} {field::cube()} }),
            vec![reference::sbox(a)],
            "cube({a})"
        );
    }
}

#[test]
fn field_edge_cases() {
    for a in [0u32, 1, 2, P - 1, P - 2] {
        for b in [0u32, 1, 2, P - 1, P - 2] {
            assert_eq!(
                run(script! { {a} {b} {field::add()} }),
                vec![reference::add(a, b)],
                "add({a},{b})"
            );
            assert_eq!(
                run(script! { {a} {b} {field::mul()} }),
                vec![reference::mul(a, b)],
                "mul({a},{b})"
            );
        }
    }
}

#[test]
fn linear_layers_match_reference() {
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    for _ in 0..4 {
        let st: [u32; WIDTH] = core::array::from_fn(|_| rand_fe(&mut rng));

        let mut want = st;
        reference::mds_light(&mut want);
        let got = run(script! { for x in st { {x} } {poseidon2::mds_light()} });
        assert_eq!(got, want.to_vec(), "mds_light");

        let mut want = st;
        reference::internal_linear(&mut want);
        let got = run(script! { for x in st { {x} } {poseidon2::internal_linear()} });
        assert_eq!(got, want.to_vec(), "internal_linear");
    }
}

#[test]
fn permutation_matches_reference() {
    let mut rng = ChaCha20Rng::seed_from_u64(3);
    for _ in 0..2 {
        let st: [u32; WIDTH] = core::array::from_fn(|_| rand_fe(&mut rng));
        let mut want = st;
        reference::permute(&mut want);
        let got = run(script! { for x in st { {x} } {poseidon2::poseidon2_permute()} });
        assert_eq!(got, want.to_vec());
    }
}

/// The reason the crate exists: no disabled opcode, and in particular no
/// `OP_CAT`. If this fails the design claim is void.
#[test]
fn uses_no_disabled_opcode() {
    let s = poseidon2::poseidon2_permute();
    // OP_CAT, OP_SUBSTR, OP_LEFT, OP_RIGHT, OP_INVERT, OP_AND, OP_OR, OP_XOR,
    // OP_2MUL, OP_2DIV, OP_MUL, OP_DIV, OP_MOD, OP_LSHIFT, OP_RSHIFT.
    const DISABLED: [u8; 15] = [
        0x7e, 0x7f, 0x80, 0x81, 0x83, 0x84, 0x85, 0x86, 0x8d, 0x8e, 0x95, 0x96, 0x97, 0x98, 0x99,
    ];
    for ins in s.instructions() {
        if let Ok(bitcoin::blockdata::script::Instruction::Op(op)) = ins {
            assert!(
                !DISABLED.contains(&op.to_u8()),
                "disabled opcode in the permutation: {op}"
            );
        }
    }
}

/// The number the whole exercise is for.
#[test]
fn report_size() {
    let perm = poseidon2::poseidon2_permute();
    let compress = poseidon2::poseidon2_compress();
    let mul = field::mul();
    let mul_c = field::mul_by_constant(0x12345678);
    let cube = field::cube();
    let mds = poseidon2::mds_light();
    let internal = poseidon2::internal_linear();

    // Witness data is one weight unit per byte in a taproot spend; the script
    // sits in the witness, so bytes and weight units coincide here.
    println!("\n  bytes (= witness weight units)");
    println!("  ------------------------------");
    println!("  field mul (runtime)      {:>10}", mul.len());
    println!("  field mul by constant    {:>10}", mul_c.len());
    println!("  field cube (S-box)       {:>10}", cube.len());
    println!("  external linear layer    {:>10}", mds.len());
    println!("  internal linear layer    {:>10}", internal.len());
    println!("  POSEIDON2 PERMUTATION    {:>10}", perm.len());
    println!("  Merkle compression       {:>10}", compress.len());
    println!(
        "\n  MAX_STANDARD_TX_WEIGHT is 400000; one permutation is {:.2}x that",
        perm.len() as f64 / 400_000.0
    );
    println!(
        "  MAX_BLOCK_WEIGHT is 4000000; one permutation is {:.4}x that\n",
        perm.len() as f64 / 4_000_000.0
    );
}
