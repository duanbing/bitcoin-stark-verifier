//! The round in plain Rust, transcribed from Plonky3's `p3-sumcheck`.

use poseidon2::reference as f;

/// The extension element `1`.
pub const EF_ONE: [u32; 4] = [1, 0, 0, 0];

/// `lagrange_weights_01inf` over `EF`: `[1 - r, r, r*(r - 1)]`.
pub fn lagrange_weights_01inf(r: [u32; 4]) -> [[u32; 4]; 3] {
    use poseidon2::reference::ext4;
    [ext4::sub(EF_ONE, r), r, ext4::mul(r, ext4::sub(r, EF_ONE))]
}

/// `extrapolate_01inf(e0, e1, e_inf, r) = e0*w0 + e1*w1 + e_inf*w_inf`.
pub fn extrapolate_01inf(e0: [u32; 4], e1: [u32; 4], e_inf: [u32; 4], r: [u32; 4]) -> [u32; 4] {
    use poseidon2::reference::ext4;
    let [w0, w1, w_inf] = lagrange_weights_01inf(r);
    ext4::add(ext4::add(ext4::mul(e0, w0), ext4::mul(e1, w1)), ext4::mul(e_inf, w_inf))
}

/// One round of `verify_rounds`: `h(1)` comes from the sumcheck constraint, and
/// the new claim is `h(r)`.
pub fn sumcheck_round(claim: [u32; 4], c0: [u32; 4], c_inf: [u32; 4], r: [u32; 4]) -> [u32; 4] {
    use poseidon2::reference::ext4;
    extrapolate_01inf(c0, ext4::sub(claim, c0), c_inf, r)
}

/// `eval_multilinear_recursive` from Plonky3's `multilinear-util`.
///
/// `evals` holds `2^n` values indexed big-endian by the point variables, so the
/// *last* variable pairs adjacent entries and folding runs backwards to
/// `point[0]`. Each step is `e[2j] + x*(e[2j+1] - e[2j])`.
pub fn eval_multilinear(evals: &[[u32; 4]], point: &[[u32; 4]]) -> [u32; 4] {
    use poseidon2::reference::ext4;
    assert_eq!(evals.len(), 1 << point.len());
    let mut cur = evals.to_vec();
    for &x in point.iter().rev() {
        cur = (0..cur.len() / 2)
            .map(|j| {
                let (a, b) = (cur[2 * j], cur[2 * j + 1]);
                ext4::add(a, ext4::mul(x, ext4::sub(b, a)))
            })
            .collect();
    }
    cur[0]
}

/// Sponge rate. Plonky3 uses `DuplexChallenger<_, _, 16, 8>` with this permutation.
pub const RATE: usize = 8;

/// Plonky3's `DuplexChallenger::duplexing`, for a statically known absorb count.
///
/// Overwrite the leading `k` rate slots, zero the rest of the rate, bind `k`
/// into the first capacity element so that length and zero-padding cannot
/// collide, then permute. `k == 0` is a squeeze: permute only.
pub fn duplexing(state: &mut [u32; 16], inputs: &[u32]) {
    let k = inputs.len();
    assert!(k <= RATE);
    for (i, v) in inputs.iter().enumerate() {
        state[i] = *v;
    }
    if k > 0 {
        for s in state.iter_mut().take(RATE).skip(k) {
            *s = 0;
        }
        state[RATE] = f::add(state[RATE], k as u32);
    }
    poseidon2::reference::permute(state);
}

/// The squeezed values: the rate after a duplexing.
pub fn squeeze(state: &mut [u32; 16]) -> [u32; RATE] {
    duplexing(state, &[]);
    state[..RATE].try_into().unwrap()
}

/// `DuplexChallenger::sample_bits`: take a squeezed field element and keep its
/// low `bits` bits. Plonky3 asserts `2^bits < |F|`, so no reduction is needed.
pub fn sample_bits(rate_element: u32, bits: usize) -> u32 {
    assert!((1u64 << bits) < poseidon2::constants::P as u64);
    rate_element & ((1 << bits) - 1)
}
