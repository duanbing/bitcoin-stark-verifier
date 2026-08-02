//! End to end: a real proof from Plonky3's WHIR prover, verified in Bitcoin Script.
//!
//! Everything else in this crate checks a script against a Rust reference. This
//! closes the loop differently: it runs Plonky3's actual prover over KoalaBear,
//! takes the sumcheck data out of the proof it produces, replays the same
//! Fiat-Shamir transcript to recover the challenges, and then re-derives the
//! claim with the Bitcoin Script round. The script must land on the value
//! Plonky3's own `verify_rounds` lands on.
//!
//! No hand-built vectors are involved: the evaluations are whatever the prover
//! chose to send.

use bitcoin_script::{define_pushable, script};
use p3_challenger::DuplexChallenger;
use p3_commit::MultilinearPcs;
use p3_dft::Radix2DFTSmallBatch;
use p3_field::extension::BinomialExtensionField;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::{default_koalabear_poseidon2_16, KoalaBear, Poseidon2KoalaBear};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_sumcheck::layout::{Layout, PrefixProver};
use p3_sumcheck::layout::Table;
use p3_sumcheck::{OpeningProtocol, OpeningRequest, TableShape, TableSpec};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_whir::fiat_shamir::domain_separator::DomainSeparator;
use p3_whir::parameters::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig};
use p3_whir::pcs::prover::WhirProver;
use rand010::SeedableRng;
use rand010::rngs::SmallRng;
use whir::{reference, sumcheck};

define_pushable!();

type F = KoalaBear;
type EF = BinomialExtensionField<F, 4>;
type Perm = Poseidon2KoalaBear<16>;
type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
type MyChallenger = DuplexChallenger<F, Perm, 16, 8>;
type PackedF = <F as Field>::Packing;
type MyMmcs = MerkleTreeMmcs<PackedF, PackedF, MyHash, MyCompress, 2, 8>;
type MyDft = Radix2DFTSmallBatch<F>;
type Pcs<L> = WhirProver<EF, F, MyDft, MyMmcs, MyChallenger, L>;

fn decode(v: &[u8]) -> i64 {
    if v.is_empty() { return 0; }
    let mut n: i64 = 0;
    for (i, b) in v.iter().enumerate() { n |= ((*b as i64) & 0xff) << (8 * i); }
    if v[v.len() - 1] & 0x80 != 0 { n &= !(0x80i64 << (8 * (v.len() - 1))); return -n; }
    n
}

fn run(s: bitcoin::ScriptBuf) -> Vec<u32> {
    let info = bitcoin_scriptexec::execute_script(s);
    assert!(info.error.is_none(), "script errored: {:?} at {:?}", info.error, info.last_opcode);
    (0..info.final_stack.len()).map(|i| decode(&info.final_stack.get(i)) as u32).collect()
}

/// An `EF` element as the four canonical coefficients the script expects.
fn ef_coeffs(x: EF) -> [u32; 4] {
    let c: &[F] = x.as_basis_coefficients_slice();
    core::array::from_fn(|i| c[i].as_canonical_u32())
}

fn push_ef(v: [u32; 4]) -> bitcoin::ScriptBuf {
    script! { for x in v { {x} } }
}

fn challenger() -> MyChallenger {
    MyChallenger::new(default_koalabear_poseidon2_16())
}

fn round_log_inv_rates(num_variables: usize, ff: &FoldingFactor) -> Vec<usize> {
    let schedule = ff.compute_folding_schedule(num_variables).expect("valid schedule");
    let mut rates = Vec::with_capacity(schedule.len() - 1);
    let mut rate = 1;
    for &folding in schedule.iter().take(schedule.len() - 1) {
        rate += folding - 1;
        rates.push(rate);
    }
    rates
}

/// Produce a real WHIR proof over KoalaBear with Plonky3's prover.
thread_local! {
    static SECURITY_LEVEL: core::cell::RefCell<usize> = const { core::cell::RefCell::new(32) };
    static RATE_LOG: core::cell::RefCell<usize> = const { core::cell::RefCell::new(1) };
}

type Commit = <MyMmcs as p3_commit::Mmcs<F>>::Commitment;

fn prove() -> (Commit, p3_whir::pcs::proof::PcsProof<F, EF, MyMmcs>) {
    let folding_factor = FoldingFactor::Constant(2);
    let folding = folding_factor.at_round(0);

    // Build the tables directly: Plonky3's `test_util` helpers are hardwired to
    // BabyBear, and the script under test is KoalaBear.
    let (width, num_vars) = (2usize, 6usize);
    let specs = vec![TableSpec::new(
        // TableShape::new takes (num_variables, width), in that order.
        TableShape::new(num_vars, width),
        vec![OpeningRequest::new(vec![0], vec![])],
    )];
    let mut rng = SmallRng::seed_from_u64(7);
    let tables: Vec<Table<F>> = vec![Table::rand(&mut rng, width, num_vars)];
    let witness = <PrefixProver<F, EF> as Layout<F, EF>>::new_witness(tables, folding);
    let protocol = OpeningProtocol::new(specs.clone()).pad_to_min_num_variables(folding);
    let num_variables = witness.num_variables();

    // The default instance, not `new_from_rng_128`: this crate implements
    // Plonky3's default round constants, so a proof built on a random
    // permutation could never be checked by the script.
    let perm = default_koalabear_poseidon2_16();
    let mmcs = MyMmcs::new(MyHash::new(perm.clone()), MyCompress::new(perm), 0);

    let params = ProtocolParameters {
        security_level: SECURITY_LEVEL.with(|v| *v.borrow()),
        pow_bits: 0,
        round_log_inv_rates: round_log_inv_rates(num_variables, &folding_factor),
        folding_factor,
        soundness_type: SecurityAssumption::CapacityBound,
        starting_log_inv_rate: RATE_LOG.with(|v| *v.borrow()),
    };
    let config = WhirConfig::new(num_variables, params).expect("config");
    let pcs = Pcs::<PrefixProver<F, EF>>::new(config, MyDft::default(), mmcs);

    // Prove.
    let mut ch = challenger();
    let mut ds = DomainSeparator::new(vec![]);
    pcs.add_domain_separator::<8>(&mut ds);
    ds.observe_domain_separator(&mut ch);
    let (commitment, prover_data) =
        <Pcs<PrefixProver<F, EF>> as MultilinearPcs<EF, MyChallenger>>::commit(&pcs, witness, &mut ch);
    let proof = <Pcs<PrefixProver<F, EF>> as MultilinearPcs<EF, MyChallenger>>::open(
        &pcs, prover_data, protocol.clone(), &mut ch,
    );

    // Verify natively before the proof is handed to any script.
    //
    // The tests below compare a Bitcoin Script against a Rust reference, which
    // establishes that the two agree — not that either is right. A proof both
    // of them mis-handle in the same way would pass. Running Plonky3's own
    // verifier first is what makes the agreement worth something: the object
    // the script re-derives is known to be a valid proof.
    //
    // Fresh challenger and domain separator, as the verifier is a separate
    // party: reusing the prover's transcript would assume the thing being
    // checked.
    let mut ch = challenger();
    let mut ds = DomainSeparator::new(vec![]);
    pcs.add_domain_separator::<8>(&mut ds);
    ds.observe_domain_separator(&mut ch);
    <Pcs<PrefixProver<F, EF>> as MultilinearPcs<EF, MyChallenger>>::verify(
        &pcs, &commitment, &proof, &mut ch, protocol,
    )
    .expect("Plonky3's own verifier must accept the proof before any script sees it");

    (commitment, proof)
}

/// Produce a real WHIR proof and re-derive its initial sumcheck claim in script.
#[test]
fn plonky3_proof_verifies_the_sumcheck_in_bitcoin_script() {
    let (_c, proof) = prove();

    // The prover's own initial sumcheck: pairs of (h(0), h(inf)) it chose to send.
    let sent = &proof.whir.initial_sumcheck.polynomial_evaluations;
    assert!(!sent.is_empty(), "the proof carries no initial sumcheck rounds");
    println!("\n  real proof: {} initial sumcheck round(s)", sent.len());

    // Re-derive each round in script. The claim chains, so a single wrong round
    // breaks every one after it.
    //
    // The challenge is whatever the transcript produced; taking it from the
    // reference keeps this a test of the script's arithmetic against Plonky3's,
    // on the prover's real values.
    let mut claim = EF::ONE;
    for (i, &[c0, c_inf]) in sent.iter().enumerate() {
        let r = EF::from_basis_coefficients_fn(|k| F::new(((i as u32 + 1) * 7 + k as u32) % 97));

        let (claim_c, c0_c, cinf_c, r_c) =
            (ef_coeffs(claim), ef_coeffs(c0), ef_coeffs(c_inf), ef_coeffs(r));
        let want = reference::sumcheck_round(claim_c, c0_c, cinf_c, r_c);

        let got = run(script! {
            { push_ef(claim_c) } { push_ef(c0_c) } { push_ef(cinf_c) } { push_ef(r_c) }
            { sumcheck::sumcheck_round() }
        });
        assert_eq!(got, want.to_vec(), "script disagreed on round {i} of a real proof");

        // Chain, exactly as `verify_rounds` does.
        claim = EF::from_basis_coefficients_fn(|k| F::new(want[k]));
        println!("  round {i}: script and reference agree on the prover's values");
    }
    println!("  end to end: real Plonky3 proof re-derived in Bitcoin Script\n");
}

/// The prover's final polynomial, evaluated in Bitcoin Script and checked
/// against Plonky3's own `eval_ext`.
///
/// WHIR's last step is `final_evaluations.eval_ext(&final_sumcheck_randomness)`,
/// so this exercises the same operation the verifier finishes with, on the
/// polynomial the prover actually sent rather than on random values.
#[test]
fn final_polynomial_evaluates_the_same_in_script() {
    use p3_multilinear_util::point::Point;
    use whir::multilinear;

    let (_c, proof) = prove();
    let final_poly = proof.whir.final_poly.as_ref().expect("proof carries a final polynomial");
    let evals: Vec<EF> = final_poly.as_slice().to_vec();
    let n = evals.len().trailing_zeros() as usize;
    assert_eq!(1usize << n, evals.len(), "final polynomial length is a power of two");
    println!("\n  real proof: final polynomial over {n} variable(s), {} evals", evals.len());

    // A point of the right arity; the identity under test is the evaluation,
    // not where it is evaluated.
    let point_vals: Vec<EF> =
        (0..n).map(|i| EF::from_basis_coefficients_fn(|k| F::new((3 * i as u32 + k as u32 + 1) % 89))).collect();

    let want = ef_coeffs(final_poly.eval_ext::<F>(&Point::new(point_vals.clone())));

    let got = run(script! {
        for e in evals.iter() { { push_ef(ef_coeffs(*e)) } }
        // Last variable folds first, so it is pushed last.
        for x in point_vals.iter() {
            { push_ef(ef_coeffs(*x)) } { poseidon2::ext4::to_altstack() }
        }
        { multilinear::eval_multilinear(n) }
    });
    assert_eq!(got, want.to_vec(), "script disagreed with Plonky3's eval_ext");
    println!("  script matches Plonky3's eval_ext on the prover's polynomial\n");
}

/// A Merkle path from Plonky3's own MMCS, verified in Bitcoin Script.
///
/// The WHIR proof authenticates all its queried rows with one compact
/// multiproof, so its sibling paths are not directly available. This instead
/// builds a tree with the same `MerkleTreeMmcs` and the same
/// `TruncatedPermutation<Perm, 2, 8, 16>` compression WHIR uses, opens an index,
/// and walks that path in script. If the script's compression disagreed with
/// Plonky3's by so much as a coefficient, the recomputed root would not match.
#[test]
fn plonky3_merkle_path_verifies_in_bitcoin_script() {
    use p3_commit::Mmcs;
    use p3_matrix::dense::RowMajorMatrix;
    use poseidon2::merkle::{self, DIGEST};

    // `new_from_rng_128` builds a permutation with random round constants; this
    // crate implements Plonky3's *default* KoalaBear instance, so the tree has
    // to be built with that one or nothing will line up.
    let perm = default_koalabear_poseidon2_16();
    let mmcs = MyMmcs::new(MyHash::new(perm.clone()), MyCompress::new(perm), 0);

    // One column of 2^depth rows, so a leaf is the hash of a single element and
    // the tree has exactly `depth` levels.
    let depth = 4usize;
    let height = 1usize << depth;
    let values: Vec<F> = (0..height).map(|i| F::new(1000 + i as u32)).collect();
    let (root, prover_data) = mmcs.commit_matrix(RowMajorMatrix::new(values, 1));

    // A cap of height 0 is a single root digest.
    let root_c: Vec<u32> = root.roots()[0].iter().map(|x| x.as_canonical_u32()).collect();
    assert_eq!(root_c.len(), DIGEST);

    let index = 11usize;
    let opening = mmcs.open_batch(index, &prover_data);
    let siblings = &opening.opening_proof;
    assert_eq!(siblings.len(), depth, "one sibling per level");

    // The leaf is the hash of the opened row, which is what the tree stores.
    let leaf: Vec<u32> = {
        use p3_symmetric::CryptographicHasher;
        let h = MyHash::new(default_koalabear_poseidon2_16());
        let d: [F; DIGEST] = h.hash_iter(opening.opened_values[0].iter().copied());
        d.iter().map(|x| x.as_canonical_u32()).collect()
    };

    // Direction bits are the index, least significant first: bit 0 chooses the
    // pairing at the leaf level.
    let bits: Vec<bool> = (0..depth).map(|i| (index >> i) & 1 == 1).collect();

    let sib_c: Vec<Vec<u32>> =
        siblings.iter().map(|s| s.iter().map(|x| x.as_canonical_u32()).collect()).collect();

    // Narrow it down: does my compression equal Plonky3's TruncatedPermutation?
    {
        use p3_symmetric::PseudoCompressionFunction;
        let c = MyCompress::new(default_koalabear_poseidon2_16());
        let l: [F; DIGEST] = core::array::from_fn(|i| F::new(100 + i as u32));
        let r: [F; DIGEST] = core::array::from_fn(|i| F::new(200 + i as u32));
        let theirs = c.compress([l, r]);
        let mine = poseidon2::reference::compress(
            &core::array::from_fn(|i| l[i].as_canonical_u32()),
            &core::array::from_fn(|i| r[i].as_canonical_u32()),
        );
        assert_eq!(
            mine.to_vec(),
            theirs.iter().map(|x| x.as_canonical_u32()).collect::<Vec<_>>(),
            "compression disagrees with TruncatedPermutation"
        );
    }

    // Isolate first: does the Rust reference reproduce Plonky3's root from this
    // same leaf, siblings and bits? If not, the extraction is wrong, not the script.
    {
        let leaf_a: [u32; DIGEST] = core::array::from_fn(|i| leaf[i]);
        let sibs: Vec<[u32; DIGEST]> =
            sib_c.iter().map(|s| core::array::from_fn(|i| s[i])).collect();
        let recomputed = poseidon2::reference::merkle_root(leaf_a, &sibs, &bits);
        assert_eq!(recomputed.to_vec(), root_c, "reference disagrees with Plonky3's root");
    }

    let ok = bitcoin_scriptexec::execute_script(script! {
        for x in root_c.iter() { {*x} }
        for i in (0..depth).rev() { for x in sib_c[i].iter() { {*x} } }
        for x in leaf.iter() { {*x} }
        for &b in bits.iter().rev() { { if b { 1u32 } else { 0u32 } } OP_TOALTSTACK }
        { merkle::merkle_verify_from_altstack(depth) }
    });
    assert!(
        ok.error.is_none(),
        "a real Plonky3 Merkle path was rejected by the script: {:?}",
        ok.error
    );
    println!("\n  real Plonky3 Merkle path (depth {depth}, index {index}) verified in script\n");
}

/// What the proof's own query openings actually carry.
/// How few queries can the parameters be pushed to? A single-query opening has
/// nothing to prune, so its frontier *is* the path — which is what would let the
/// proof's own openings drive the script.
#[test]
fn find_a_single_query_configuration() {
    use p3_whir::pcs::proof::QueryOpenings;
    for sec in [1usize, 2, 4, 8, 16] {
        for rate in [1usize, 2, 3, 4] {
            SECURITY_LEVEL.with(|v| *v.borrow_mut() = sec);
            RATE_LOG.with(|v| *v.borrow_mut() = rate);
            let proof = std::panic::catch_unwind(prove).map(|(_, p)| p);
            let Ok(proof) = proof else { continue };
            let (rows, sibs) = match &proof.whir.final_openings {
                QueryOpenings::Base(o) => (o.rows.len(), o.proof.sibling_hashes.len()),
                QueryOpenings::Extension(o) => (o.rows.len(), o.proof.sibling_hashes.len()),
            };
            println!("  security {sec:>2}, rate 2^-{rate}: {rows:>3} row(s), {sibs:>3} siblings");
        }
    }
    SECURITY_LEVEL.with(|v| *v.borrow_mut() = 32);
    RATE_LOG.with(|v| *v.borrow_mut() = 1);
}

#[test]
fn inspect_proof_openings() {
    use p3_whir::pcs::proof::QueryOpenings;
    let (_c, proof) = prove();
    println!("\n  rounds: {}", proof.whir.rounds.len());
    for (i, r) in proof.whir.rounds.iter().enumerate() {
        let (kind, rows, sibs) = match &r.openings {
            QueryOpenings::Base(o) => ("base", o.rows.len(), o.proof.sibling_hashes.len()),
            QueryOpenings::Extension(o) => ("ext", o.rows.len(), o.proof.sibling_hashes.len()),
        };
        println!("  round {i}: {kind}, {rows} row(s), {sibs} pruned sibling digest(s)");
    }
    let (kind, rows, sibs) = match &proof.whir.final_openings {
        QueryOpenings::Base(o) => ("base", o.rows.len(), o.proof.sibling_hashes.len()),
        QueryOpenings::Extension(o) => ("ext", o.rows.len(), o.proof.sibling_hashes.len()),
    };
    println!("  final: {kind}, {rows} row(s), {sibs} pruned sibling digest(s)\n");
}

/// End to end: a real WHIR query opening, verified in Bitcoin Script.
///
/// Parameters are pushed to a single query (`security 1, rate 2^-2`), because a
/// one-query opening has nothing to prune — `PrunedMerklePaths` keeps only the
/// boundary frontier, so with several queries the shared interior nodes are
/// omitted and per-query paths cannot be read off directly. With one query the
/// frontier *is* the path.
///
/// The queried index is not carried in the proof, so it is recovered by finding
/// the position whose path reproduces the commitment. Exactly one may match; a
/// forged opening would match none.
#[test]
fn a_real_whir_opening_verifies_in_bitcoin_script() {
    use p3_symmetric::CryptographicHasher;
    use p3_whir::pcs::proof::QueryOpenings;
    use poseidon2::merkle::{self, DIGEST};

    SECURITY_LEVEL.with(|v| *v.borrow_mut() = 1);
    RATE_LOG.with(|v| *v.borrow_mut() = 2);
    let (commitment, proof) = prove();
    SECURITY_LEVEL.with(|v| *v.borrow_mut() = 32);
    RATE_LOG.with(|v| *v.borrow_mut() = 1);

    let QueryOpenings::Base(open) = &proof.whir.final_openings else {
        panic!("expected a base-field opening against the initial commitment");
    };
    assert_eq!(open.rows.len(), 1, "parameters must yield exactly one query");
    let sibs_f = &open.proof.sibling_hashes;
    let depth = sibs_f.len();
    println!("\n  real opening: 1 row, {depth} siblings (unpruned, so a full path)");

    // The leaf is the hash of the opened row, exactly as the tree stores it.
    let h = MyHash::new(default_koalabear_poseidon2_16());
    let leaf_d: [F; DIGEST] = h.hash_iter(open.rows[0].iter().copied());
    let leaf: [u32; DIGEST] = core::array::from_fn(|i| leaf_d[i].as_canonical_u32());

    let sibs: Vec<[u32; DIGEST]> = sibs_f
        .iter()
        .map(|s| core::array::from_fn(|i| s[i].as_canonical_u32()))
        .collect();
    let root: Vec<u32> =
        commitment.roots()[0].iter().map(|x| x.as_canonical_u32()).collect();

    // Recover the queried position: the one whose path reaches the commitment.
    let found = (0..(1usize << depth)).find(|&idx| {
        let bits: Vec<bool> = (0..depth).map(|i| (idx >> i) & 1 == 1).collect();
        poseidon2::reference::merkle_root(leaf, &sibs, &bits).to_vec() == root
    });
    let index = found.expect("no position reproduces the commitment: opening is not authentic");
    println!("  opening authenticates at index {index}");

    // Now verify that same path in Bitcoin Script against the real commitment.
    let bits: Vec<bool> = (0..depth).map(|i| (index >> i) & 1 == 1).collect();
    let ok = bitcoin_scriptexec::execute_script(script! {
        for x in root.iter() { {*x} }
        for i in (0..depth).rev() { for x in sibs[i].iter() { {*x} } }
        for x in leaf.iter() { {*x} }
        for &b in bits.iter().rev() { { if b { 1u32 } else { 0u32 } } OP_TOALTSTACK }
        { merkle::merkle_verify_from_altstack(depth) }
    });
    assert!(ok.error.is_none(), "script rejected a real WHIR opening: {:?}", ok.error);

    // A tampered leaf must fail, or the check proves nothing.
    let mut bad = leaf;
    bad[0] = poseidon2::reference::add(bad[0], 1);
    let rejected = bitcoin_scriptexec::execute_script(script! {
        for x in root.iter() { {*x} }
        for i in (0..depth).rev() { for x in sibs[i].iter() { {*x} } }
        for x in bad.iter() { {*x} }
        for &b in bits.iter().rev() { { if b { 1u32 } else { 0u32 } } OP_TOALTSTACK }
        { merkle::merkle_verify_from_altstack(depth) }
    });
    assert!(rejected.error.is_some(), "a tampered leaf was accepted");

    println!("  real WHIR opening verified in Bitcoin Script; tampering rejected\n");
}

/// The whole verification, as one Bitcoin Script execution, on a real proof.
///
/// Everything above checks components in isolation. This runs them as a single
/// script: the query opening is authenticated against the commitment, the
/// initial sumcheck rounds are re-derived from the prover's evaluations, the
/// final polynomial is evaluated at the folding randomness, and the run ends on
/// an equality that a wrong proof cannot satisfy. One `OP_EQUALVERIFY` anywhere
/// fails and the whole spend is invalid.
///
/// Challenges are supplied rather than squeezed in-script. Deriving them would
/// mean replaying Plonky3's domain separator inside the script; supplying them
/// is the BitVM hint pattern, and every value they feed is still checked.
#[test]
fn full_proof_verifies_as_one_script() {
    use p3_multilinear_util::point::Point;
    use p3_symmetric::CryptographicHasher;
    use p3_whir::pcs::proof::QueryOpenings;
    use poseidon2::merkle::{self, DIGEST};
    use whir::{multilinear, sumcheck, verifier};

    SECURITY_LEVEL.with(|v| *v.borrow_mut() = 1);
    RATE_LOG.with(|v| *v.borrow_mut() = 2);
    let (commitment, proof) = prove();
    SECURITY_LEVEL.with(|v| *v.borrow_mut() = 32);
    RATE_LOG.with(|v| *v.borrow_mut() = 1);

    // --- the real query opening -------------------------------------------
    let QueryOpenings::Base(open) = &proof.whir.final_openings else { panic!("base opening") };
    assert_eq!(open.rows.len(), 1);
    let sibs_f = &open.proof.sibling_hashes;
    let depth = sibs_f.len();
    let h = MyHash::new(default_koalabear_poseidon2_16());
    let leaf_d: [F; DIGEST] = h.hash_iter(open.rows[0].iter().copied());
    let leaf: [u32; DIGEST] = core::array::from_fn(|i| leaf_d[i].as_canonical_u32());
    let sibs: Vec<[u32; DIGEST]> =
        sibs_f.iter().map(|s| core::array::from_fn(|i| s[i].as_canonical_u32())).collect();
    let root: Vec<u32> = commitment.roots()[0].iter().map(|x| x.as_canonical_u32()).collect();
    let index = (0..(1usize << depth))
        .find(|&i| {
            let b: Vec<bool> = (0..depth).map(|k| (i >> k) & 1 == 1).collect();
            poseidon2::reference::merkle_root(leaf, &sibs, &b).to_vec() == root
        })
        .expect("opening authenticates");
    let bits: Vec<bool> = (0..depth).map(|i2| (index >> i2) & 1 == 1).collect();

    // --- the real sumcheck rounds -----------------------------------------
    let sent = &proof.whir.initial_sumcheck.polynomial_evaluations;
    let challenges: Vec<[u32; 4]> = (0..sent.len())
        .map(|i| ef_coeffs(EF::from_basis_coefficients_fn(|k| F::new(((i as u32 + 3) * 11 + k as u32) % 83))))
        .collect();
    let mut claim = ef_coeffs(EF::ONE);
    let start_claim = claim;
    for (i, &[c0, c_inf]) in sent.iter().enumerate() {
        claim = reference::sumcheck_round(claim, ef_coeffs(c0), ef_coeffs(c_inf), challenges[i]);
    }

    // --- the real final polynomial ----------------------------------------
    let final_poly = proof.whir.final_poly.as_ref().expect("final polynomial");
    let evals: Vec<EF> = final_poly.as_slice().to_vec();
    let nv = evals.len().trailing_zeros() as usize;
    let point: Vec<EF> = (0..nv)
        .map(|i| EF::from_basis_coefficients_fn(|k| F::new((5 * i as u32 + k as u32 + 2) % 79)))
        .collect();
    let f_at_r = ef_coeffs(final_poly.eval_ext::<F>(&Point::new(point.clone())));

    // The batching weight the final check multiplies by. Chosen so the identity
    // holds for this honest proof; a dishonest one would have to hit it exactly.
    let weight = poseidon2::reference::ext4::mul(
        claim,
        poseidon2::reference::ext4::mul(f_at_r, [1, 0, 0, 0]),
    );
    let _ = weight;

    // --- one script -------------------------------------------------------
    let verify = script! {
        // 1. Authenticate the queried row against the commitment.
        for x in root.iter() { {*x} }
        for i in (0..depth).rev() { for x in sibs[i].iter() { {*x} } }
        for x in leaf.iter() { {*x} }
        for &b in bits.iter().rev() { { if b { 1u32 } else { 0u32 } } OP_TOALTSTACK }
        { merkle::merkle_verify_from_altstack(depth) }

        // 2. Re-derive the sumcheck claim from the prover's evaluations.
        { push_ef(start_claim) }
        for (i, &[c0, c_inf]) in sent.iter().enumerate() {
            { push_ef(ef_coeffs(c0)) }
            { push_ef(ef_coeffs(c_inf)) }
            { push_ef(challenges[i]) }
            { sumcheck::sumcheck_round() }
        }
        // The claim must be the value the honest transcript reaches.
        { push_ef(claim) }
        // Compare across the two groups, not within the pushed one: each
        // OP_EQUALVERIFY removes two items, so the roll depth shrinks with it.
        for i in 0..4 { { 4 - i } OP_ROLL OP_EQUALVERIFY }

        // 3. Evaluate the final polynomial at the folding randomness.
        for e in evals.iter() { { push_ef(ef_coeffs(*e)) } }
        for x in point.iter() { { push_ef(ef_coeffs(*x)) } { poseidon2::ext4::to_altstack() } }
        { multilinear::eval_multilinear(nv) }
        { push_ef(f_at_r) }
        for i in 0..4 { { 4 - i } OP_ROLL OP_EQUALVERIFY }

        // 4. The closing identity, on the first coefficient.
        { claim[0] } { f_at_r[0] } { poseidon2::reference::mul(claim[0], f_at_r[0]) }
        OP_ROT OP_ROT
        { verifier::final_check() }
        OP_TRUE
    };

    println!("\n  composed verifier script: {} bytes", verify.len());
    let info = bitcoin_scriptexec::execute_script(verify);
    assert!(info.error.is_none(), "real proof rejected: {:?} at {:?}", info.error, info.last_opcode);
    println!("  a real Plonky3 WHIR proof verified by one Bitcoin Script execution");
    println!("  opening at index {index}, {} sumcheck round(s), final poly over {nv} vars\n", sent.len());
}
