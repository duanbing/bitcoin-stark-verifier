//! Correctness and sizing.
//!
//! The script is executed under `bitcoin-scriptexec` and its final stack
//! compared against [`poseidon2::reference`], which is itself
//! checked against Plonky3 in `plonky3_agreement`. So the chain is
//! script → reference → Plonky3, and a break anywhere fails a test.

use poseidon2::constants::{P, WIDTH};
use poseidon2::{field, permutation, reference};
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
        let got = run(script! { for x in st { {x} } {permutation::mds_light()} });
        assert_eq!(got, want.to_vec(), "mds_light");

        let mut want = st;
        reference::internal_linear(&mut want);
        let got = run(script! { for x in st { {x} } {permutation::internal_linear()} });
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
        let got = run(script! { for x in st { {x} } {permutation::permute()} });
        assert_eq!(got, want.to_vec());
    }
}

/// The reason the crate exists: no disabled opcode, and in particular no
/// `OP_CAT`. If this fails the design claim is void.
#[test]
fn uses_no_disabled_opcode() {
    let s = permutation::permute();
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
    let perm = permutation::permute();
    let compress = permutation::compress();
    let mul = field::mul();
    let mul_c = field::mul_by_constant(0x12345678);
    let cube = field::cube();
    let mds = permutation::mds_light();
    let internal = permutation::internal_linear();

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

/// The structured layers must equal the dense matrix versions they replace.
/// This is what makes the optimisation safe to trust.
#[test]
fn structured_layers_equal_dense() {
    let mut rng = ChaCha20Rng::seed_from_u64(11);
    for _ in 0..4 {
        let st: [u32; WIDTH] = core::array::from_fn(|_| rand_fe(&mut rng));
        let dense = run(script! { for x in st { {x} } {permutation::mds_light_dense()} });
        let structured = run(script! { for x in st { {x} } {permutation::mds_light()} });
        assert_eq!(structured, dense, "mds_light");

        let dense = run(script! { for x in st { {x} } {permutation::internal_linear_dense()} });
        let structured = run(script! { for x in st { {x} } {permutation::internal_linear()} });
        assert_eq!(structured, dense, "internal_linear");
    }
}

/// The operations a verifier needs beyond the hash, and which look at first
/// glance as though they want a disabled opcode. None of them do.
#[test]
fn verifier_primitives_need_no_disabled_opcode() {
    let mut rng = ChaCha20Rng::seed_from_u64(41);

    // Inversion, hinted and checked.
    for _ in 0..6 {
        let x = rng.random_range(1..P);
        let inv = mod_pow(x, P - 2);
        assert_eq!(reference::mul(x, inv), 1, "test's own inverse is wrong");
        assert_eq!(run(script! { {x} {inv} {field::inverse_hinted()} }), vec![inv]);
    }

    // A challenge reduced to a query index, without OP_MOD.
    for _ in 0..6 {
        let c = rng.random_range(0..P);
        let bits = 12usize;
        let want = c & ((1 << bits) - 1);
        // Reassemble the bits the script pushed, most significant last.
        // Bits pop least-significant first, so weight them as they come.
        let got = run(script! {
            {c}
            { field::low_bits_to_altstack(bits) }
            0
            for j in 0..bits {
                OP_FROMALTSTACK
                OP_IF { 1u32 << j } OP_ADD OP_ENDIF
            }
        });
        assert_eq!(got.len(), 1, "index {c}");
        assert_eq!(got[0], want, "low {bits} bits of {c}");
    }

    // A power of the domain generator at a run-time exponent.
    for _ in 0..4 {
        let e = rng.random_range(0..(1u32 << 10));
        let want = mod_pow(3, e);
        assert_eq!(run(script! { {e} {field::pow_const_base(3, 10)} }), vec![want]);
    }
}

fn mod_pow(mut b: u32, mut e: u32) -> u32 {
    let mut acc = 1u32;
    b %= P;
    while e > 0 {
        if e & 1 == 1 { acc = reference::mul(acc, b); }
        b = reference::mul(b, b);
        e >>= 1;
    }
    acc
}

/// The per-round scripts must chain to the whole permutation, and each must be
/// small enough for a disprove transaction.
#[test]
fn rounds_compose_to_the_permutation() {
    let mut rng = ChaCha20Rng::seed_from_u64(51);
    let st: [u32; WIDTH] = core::array::from_fn(|_| rand_fe(&mut rng));
    let mut want = st;
    reference::permute(&mut want);

    let rounds = poseidon2::permutation::rounds();
    let chained = run(script! {
        for x in st { {x} }
        for r in rounds.iter() { { r.clone() } }
    });
    assert_eq!(chained, want.to_vec(), "chained rounds differ from permute()");
}

/// Every round must fit a standard transaction, or the disprove pattern has no
/// atomic step to fall back on.
#[test]
fn every_round_fits_a_standard_transaction() {
    const STD_TX: usize = 400_000;
    let rounds = poseidon2::permutation::rounds();
    let sizes: Vec<usize> = rounds.iter().map(|r| r.len()).collect();
    let (min, max) = (sizes.iter().min().unwrap(), sizes.iter().max().unwrap());
    let total: usize = sizes.iter().sum();

    println!("\n  {} independently checkable rounds", rounds.len());
    println!("  smallest round        {:>10} bytes", min);
    println!("  largest round         {:>10} bytes  ({:.1}% of a standard tx)",
             max, 100.0 * *max as f64 / STD_TX as f64);
    println!("  all rounds together   {:>10} bytes", total);
    println!("  one permutation       {:>10} bytes\n",
             poseidon2::permutation::permute().len());

    assert!(*max < STD_TX, "a round at {max} bytes exceeds MAX_STANDARD_TX_WEIGHT");
}
