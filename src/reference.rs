//! A plain-Rust Poseidon2 over KoalaBear, following Plonky3 exactly.
//!
//! This is the oracle the script is checked against, and it is also what the
//! script generator reads its linear layers from: both layers are linear, so
//! [`mds_light_matrix`] and [`internal_matrix`] recover them by applying the
//! functions below to basis vectors. The script therefore cannot drift from the
//! reference — there is one definition of each layer, not two.
//!
//! Everything is canonical `u32`, never Montgomery. Plonky3 stores its
//! constants as canonical literals and converts on the way in, so the values in
//! [`crate::constants`] can be used directly.

use crate::constants::{D, EXTERNAL_FINAL, EXTERNAL_INITIAL, INTERNAL, P, WIDTH};

#[inline]
pub fn add(a: u32, b: u32) -> u32 {
    let s = a as u64 + b as u64;
    (if s >= P as u64 { s - P as u64 } else { s }) as u32
}

#[inline]
pub fn sub(a: u32, b: u32) -> u32 {
    if a >= b {
        a - b
    } else {
        a + P - b
    }
}

#[inline]
pub fn mul(a: u32, b: u32) -> u32 {
    ((a as u64 * b as u64) % P as u64) as u32
}

#[inline]
pub fn double(a: u32) -> u32 {
    add(a, a)
}

/// `a / 2^k`, i.e. `a * (2^k)^-1`.
pub fn div_2exp(a: u32, k: u32) -> u32 {
    let half = ((P as u64 + 1) / 2) as u32;
    let mut acc = a;
    for _ in 0..k {
        acc = mul(acc, half);
    }
    acc
}

/// The S-box, `x^3`.
pub fn sbox(x: u32) -> u32 {
    debug_assert_eq!(D, 3);
    mul(mul(x, x), x)
}

/// Plonky3's `apply_mat4`, the 4x4 MDS block.
fn apply_mat4(x: &mut [u32; 4]) {
    let t01 = add(x[0], x[1]);
    let t23 = add(x[2], x[3]);
    let t0123 = add(t01, t23);
    let t01123 = add(t0123, x[1]);
    let t01233 = add(t0123, x[3]);
    x[3] = add(t01233, double(x[0]));
    x[1] = add(t01123, double(x[2]));
    x[0] = add(t01123, t01);
    x[2] = add(t01233, t23);
}

/// Plonky3's `mds_light_permutation` for a width that is a multiple of four:
/// `M4` on each chunk, then add the four column sums.
pub fn mds_light(state: &mut [u32; WIDTH]) {
    for chunk in state.chunks_exact_mut(4) {
        let mut c: [u32; 4] = chunk.try_into().unwrap();
        apply_mat4(&mut c);
        chunk.copy_from_slice(&c);
    }
    let mut sums = [0u32; 4];
    for (k, s) in sums.iter_mut().enumerate() {
        for j in (0..WIDTH).step_by(4) {
            *s = add(*s, state[j + k]);
        }
    }
    for (i, e) in state.iter_mut().enumerate() {
        *e = add(*e, sums[i % 4]);
    }
}

/// Plonky3's internal linear layer for KoalaBear at width 16.
///
/// `new[i] = full_sum + V[i] * old[i]` with
/// `V = [-2, 1, 2, 1/2, 3, 4, -1/2, -3, -4, 1/2^8, 1/8, 1/2^24, -1/2^8, -1/8, -1/16, -1/2^24]`.
/// Plonky3 handles `state[0]` outside the diagonal, as `part_sum - state[0]`,
/// which is the same thing.
pub fn internal_linear(state: &mut [u32; WIDTH]) {
    let mut part_sum = 0u32;
    for s in state.iter().skip(1) {
        part_sum = add(part_sum, *s);
    }
    let full_sum = add(part_sum, state[0]);
    let s = *state;

    state[0] = sub(part_sum, s[0]);
    state[1] = add(s[1], full_sum);
    state[2] = add(double(s[2]), full_sum);
    state[3] = add(div_2exp(s[3], 1), full_sum);
    state[4] = add(full_sum, add(double(s[4]), s[4]));
    state[5] = add(full_sum, double(double(s[5])));
    state[6] = sub(full_sum, div_2exp(s[6], 1));
    state[7] = sub(full_sum, add(double(s[7]), s[7]));
    state[8] = sub(full_sum, double(double(s[8])));
    state[9] = add(div_2exp(s[9], 8), full_sum);
    state[10] = add(div_2exp(s[10], 3), full_sum);
    state[11] = add(div_2exp(s[11], 24), full_sum);
    state[12] = sub(full_sum, div_2exp(s[12], 8));
    state[13] = sub(full_sum, div_2exp(s[13], 3));
    state[14] = sub(full_sum, div_2exp(s[14], 4));
    state[15] = sub(full_sum, div_2exp(s[15], 24));
}

/// The full permutation.
pub fn permute(state: &mut [u32; WIDTH]) {
    mds_light(state);
    for rc in EXTERNAL_INITIAL.iter() {
        for (s, c) in state.iter_mut().zip(rc.iter()) {
            *s = sbox(add(*s, *c));
        }
        mds_light(state);
    }
    for c in INTERNAL.iter() {
        state[0] = sbox(add(state[0], *c));
        internal_linear(state);
    }
    for rc in EXTERNAL_FINAL.iter() {
        for (s, c) in state.iter_mut().zip(rc.iter()) {
            *s = sbox(add(*s, *c));
        }
        mds_light(state);
    }
}

/// Recover a linear layer's matrix by applying it to basis vectors.
///
/// `out[i][j]` is the coefficient of input `j` in output `i`.
fn matrix_of(f: fn(&mut [u32; WIDTH])) -> [[u32; WIDTH]; WIDTH] {
    let mut m = [[0u32; WIDTH]; WIDTH];
    for j in 0..WIDTH {
        let mut basis = [0u32; WIDTH];
        basis[j] = 1;
        f(&mut basis);
        for i in 0..WIDTH {
            m[i][j] = basis[i];
        }
    }
    m
}

/// The external linear layer as a matrix.
pub fn mds_light_matrix() -> [[u32; WIDTH]; WIDTH] {
    matrix_of(mds_light)
}

/// The internal linear layer as a matrix.
pub fn internal_matrix() -> [[u32; WIDTH]; WIDTH] {
    matrix_of(internal_linear)
}
