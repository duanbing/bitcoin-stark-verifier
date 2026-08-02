//! The reference implementation must agree with Plonky3.
//!
//! `permutation.rs` checks the script against [`poseidon2::reference`].
//! This closes the chain: the reference against Plonky3's own
//! `default_koalabear_poseidon2_16`. If Plonky3 changes its constants or its
//! linear layers, this fails rather than the crate quietly computing a
//! different hash.

use poseidon2::constants::WIDTH;
use poseidon2::reference;
use p3_field::PrimeCharacteristicRing;
use p3_field::PrimeField32;
use p3_koala_bear::{KoalaBear, default_koalabear_poseidon2_16};
use p3_symmetric::Permutation;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

#[test]
fn reference_matches_plonky3() {
    let perm = default_koalabear_poseidon2_16();
    let mut rng = ChaCha20Rng::seed_from_u64(7);

    for _ in 0..8 {
        let raw: [u32; WIDTH] =
            core::array::from_fn(|_| rng.random_range(0..poseidon2::constants::P));

        let mut theirs: [KoalaBear; WIDTH] = core::array::from_fn(|i| KoalaBear::new(raw[i]));
        perm.permute_mut(&mut theirs);
        let theirs: Vec<u32> = theirs.iter().map(|x| x.as_canonical_u32()).collect();

        let mut ours = raw;
        reference::permute(&mut ours);

        assert_eq!(ours.to_vec(), theirs, "reference diverged from Plonky3");
    }
}

/// The all-zero input is the case most likely to hide a missing round constant.
#[test]
fn reference_matches_plonky3_on_zero() {
    let perm = default_koalabear_poseidon2_16();
    let mut theirs = [KoalaBear::ZERO; WIDTH];
    perm.permute_mut(&mut theirs);
    let theirs: Vec<u32> = theirs.iter().map(|x| x.as_canonical_u32()).collect();

    let mut ours = [0u32; WIDTH];
    reference::permute(&mut ours);

    assert_eq!(ours.to_vec(), theirs);
}
