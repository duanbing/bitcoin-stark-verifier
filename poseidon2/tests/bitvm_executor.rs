//! The same vectors, run under BitVM's executor.
//!
//! `permutation.rs` uses Bitcoin Wildlife Sanctuary's fork. This file runs
//! BitVM's — <https://github.com/BitVM/rust-bitcoin-scriptexec> — because that
//! is what BitVM itself validates against, and because two independent
//! interpreters agreeing is a stronger statement than one.
//!
//! It also turns on `enforce_stack_limit`, which the other executor leaves off
//! by default. Bitcoin caps the stack and altstack at 1000 items between them,
//! and a permutation that quietly exceeded that would be unusable on chain no
//! matter what it costs in weight.

use bitcoin::hashes::Hash;
use bitcoin::taproot::TapLeafHash;
use bitcoin::{ScriptBuf, Transaction};
use poseidon2::constants::{P, WIDTH};
use poseidon2::{field, permutation, reference};
use bitcoin_script::{define_pushable, script};
use bitvm_scriptexec::{Exec, ExecCtx, Options, TxTemplate};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

define_pushable!();

/// Decode a script number: little-endian magnitude, sign bit on the last byte.
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

/// What an execution left behind, plus how much room it used.
struct Run {
    stack: Vec<u32>,
    max_stack: usize,
}

/// Execute under BitVM's interpreter with the stack limit enforced.
fn run(s: ScriptBuf) -> Run {
    let mut exec = Exec::new(
        ExecCtx::Tapscript,
        Options {
            enforce_stack_limit: true,
            ..Default::default()
        },
        TxTemplate {
            tx: Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
                input: vec![],
                output: vec![],
            },
            prevouts: vec![],
            input_idx: 0,
            taproot_annex_scriptleaf: Some((TapLeafHash::all_zeros(), None)),
        },
        s,
        vec![],
    )
    .expect("exec should build");

    let mut max_stack = 0usize;
    loop {
        max_stack = max_stack.max(exec.stack().len() + exec.altstack().len());
        if exec.exec_next().is_err() {
            break;
        }
    }
    let res = exec.result().expect("execution should terminate");
    assert!(
        res.error.is_none(),
        "BitVM executor errored: {:?} at op {:?}",
        res.error,
        res.opcode
    );

    let stack = (0..exec.stack().len())
        .map(|i| {
            let n = decode(&exec.stack().get(i));
            assert!(n >= 0, "negative value on the stack: {n}");
            n as u32
        })
        .collect();
    Run { stack, max_stack }
}

fn rand_fe(rng: &mut ChaCha20Rng) -> u32 {
    rng.random_range(0..P)
}

#[test]
fn field_ops_agree() {
    let mut rng = ChaCha20Rng::seed_from_u64(21);
    for _ in 0..8 {
        let (a, b) = (rand_fe(&mut rng), rand_fe(&mut rng));
        assert_eq!(run(script! { {a} {b} {field::add()} }).stack, vec![reference::add(a, b)]);
        assert_eq!(run(script! { {a} {b} {field::sub()} }).stack, vec![reference::sub(a, b)]);
        assert_eq!(run(script! { {a} {b} {field::mul()} }).stack, vec![reference::mul(a, b)]);
        assert_eq!(run(script! { {a} {field::cube()} }).stack, vec![reference::sbox(a)]);
    }
}

#[test]
fn linear_layers_agree() {
    let mut rng = ChaCha20Rng::seed_from_u64(22);
    let st: [u32; WIDTH] = core::array::from_fn(|_| rand_fe(&mut rng));

    let mut want = st;
    reference::mds_light(&mut want);
    assert_eq!(
        run(script! { for x in st { {x} } {permutation::mds_light()} }).stack,
        want.to_vec()
    );

    let mut want = st;
    reference::internal_linear(&mut want);
    assert_eq!(
        run(script! { for x in st { {x} } {permutation::internal_linear()} }).stack,
        want.to_vec()
    );
}

/// The whole permutation, under the second interpreter, with the stack limit on.
#[test]
fn permutation_agrees_and_fits_the_stack() {
    let mut rng = ChaCha20Rng::seed_from_u64(23);
    let st: [u32; WIDTH] = core::array::from_fn(|_| rand_fe(&mut rng));
    let mut want = st;
    reference::permute(&mut want);

    let got = run(script! { for x in st { {x} } {permutation::permute()} });
    assert_eq!(got.stack, want.to_vec(), "BitVM executor disagrees");

    // 1000 is the consensus cap on stack plus altstack.
    assert!(
        got.max_stack <= 1000,
        "peak stack {} exceeds the 1000-item limit",
        got.max_stack
    );
    println!(
        "\n  peak stack + altstack: {} items (limit 1000)\n",
        got.max_stack
    );
}

/// The all-zero input, which is where a missing round constant would show.
#[test]
fn permutation_on_zero_agrees() {
    let mut want = [0u32; WIDTH];
    reference::permute(&mut want);
    let got = run(script! { for _ in 0..WIDTH { 0 } {permutation::permute()} });
    assert_eq!(got.stack, want.to_vec());
}
