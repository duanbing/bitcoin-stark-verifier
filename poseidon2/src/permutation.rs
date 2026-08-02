//! The Poseidon2 permutation in Bitcoin Script.
//!
//! # Stack discipline
//!
//! The state is sixteen canonical field elements, `s[0]` deepest and `s[15]` on
//! top. Every routine here takes that layout and leaves it, so rounds compose by
//! concatenation.
//!
//! Two patterns do all the work.
//!
//! *The S-box layer* walks the state from the top down, rewriting each element
//! and parking it on the altstack. Sixteen pops then restore the original order,
//! because the altstack reverses twice.
//!
//! *The linear layers* never modify the state while reading it. Outputs are
//! accumulated above the untouched inputs, so input `j` always sits at a depth
//! this module can compute — `(15 - j) + outputs_pushed` — and no stack
//! choreography has to be worked out by hand. The inputs are dropped once all
//! sixteen outputs exist.
//!
//! The coefficients come from [`crate::reference`] by applying its layers to
//! basis vectors, so the script and the reference cannot disagree about what the
//! linear layers are.

use crate::constants::{EXTERNAL_FINAL, EXTERNAL_INITIAL, INTERNAL, WIDTH};
use crate::field;
use crate::reference;
use crate::treepp::*;

/// Copy input `j` to the top, given that `pushed` outputs sit above the state.
fn copy_input(j: usize, pushed: usize) -> Script {
    script! { { (WIDTH - 1 - j) + pushed } OP_PICK }
}

/// Multiply the top element by a small coefficient using additions.
///
/// The external layer's coefficients are all tiny, and doubling costs a
/// fraction of [`field::mul_by_constant`], so the small cases are worth
/// special-casing.
fn scale(c: u32) -> Script {
    match c {
        0 => script! { OP_DROP 0 },
        1 => script! {},
        2 => field::double(),
        3 => script! { OP_DUP { field::double() } { field::add() } },
        4 => script! { { field::double() } { field::double() } },
        _ => field::mul_by_constant(c),
    }
}

/// Apply a linear layer given as a matrix over the field.
///
/// Emits each output as a sum of scaled inputs, then removes the old state.
fn linear_layer(m: &[[u32; WIDTH]; WIDTH]) -> Script {
    // Each output is built outside the macro, because `script!` interpolates
    // expressions and these need statements.
    let mut rows: Vec<Script> = Vec::with_capacity(WIDTH);
    for (i, row) in m.iter().enumerate() {
        let terms: Vec<usize> = (0..WIDTH).filter(|&j| row[j] != 0).collect();
        let mut parts: Vec<Script> = Vec::new();
        for (n, &j) in terms.iter().enumerate() {
            // The state is untouched while outputs accumulate above it, so
            // input j sits at a computable depth. Above the state are the `i`
            // finished outputs, plus — for every term after the first — the
            // running accumulator. Each `add` folds the new term back in, so
            // that accumulator is one item however many terms have been summed.
            let above = if n == 0 { i } else { i + 1 };
            parts.push(copy_input(j, above));
            parts.push(scale(row[j]));
            if n > 0 {
                parts.push(field::add());
            }
        }
        if terms.is_empty() {
            parts.push(script! { 0 });
        }
        rows.push(script! { for p in parts { { p } } });
    }
    script! {
        for r in rows { { r } }
        // Stack: s[0..16] out[0..16]. Park the outputs, drop the inputs, restore.
        for _ in 0..WIDTH { OP_TOALTSTACK }
        for _ in 0..WIDTH / 2 { OP_2DROP }
        for _ in 0..WIDTH { OP_FROMALTSTACK }
    }
}

/// The external linear layer as a dense matrix. Correct, and the oracle the
/// structured [`mds_light`] is checked against, but sixteen terms per output.
pub fn mds_light_dense() -> Script {
    linear_layer(&reference::mds_light_matrix())
}

/// The internal linear layer as a dense matrix. See [`mds_light_dense`].
pub fn internal_linear_dense() -> Script {
    linear_layer(&reference::internal_matrix())
}

/// The external linear layer, `mds_light_permutation`.
///
/// Emitted structurally rather than as a matrix. `M4` is block-diagonal, so
/// each element of the first pass depends on only the four members of its own
/// chunk, and the outer circulant then adds one column sum. Sixteen terms per
/// output collapse to four, twice.
pub fn mds_light() -> Script {
    // Pass one: M4 within each chunk of four. From `apply_mat4`,
    //   x0' = 2x0 + 3x1 +  x2 +  x3        x1' =  x0 + 2x1 + 3x2 +  x3
    //   x2' =  x0 +  x1 + 2x2 + 3x3        x3' = 3x0 +  x1 +  x2 + 2x3
    const M4: [[u32; 4]; 4] = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]];
    let mut pass1 = [[0u32; WIDTH]; WIDTH];
    for i in 0..WIDTH {
        let (chunk, row) = (i / 4, i % 4);
        for col in 0..4 {
            pass1[i][chunk * 4 + col] = M4[row][col];
        }
    }
    // Pass two: y_i = x_i' + sum over the four x' sharing i mod 4, which is the
    // same as giving x_i' a coefficient of two.
    let mut pass2 = [[0u32; WIDTH]; WIDTH];
    for i in 0..WIDTH {
        for j in (i % 4..WIDTH).step_by(4) {
            pass2[i][j] = 1;
        }
        pass2[i][i] += 1;
    }
    script! {
        { linear_layer(&pass1) }
        { linear_layer(&pass2) }
    }
}

/// The internal linear layer.
///
/// `new[i] = full_sum + V[i] * old[i]`, so the whole layer is one sum plus
/// sixteen scalings — two terms per output instead of sixteen. The sum is
/// computed once and copied.
pub fn internal_linear() -> Script {
    // V, as the reference applies it. Entries that are divisions become one
    // `mul_by_constant`; the small integer entries become doublings.
    let v = internal_diagonal();
    let mut rows: Vec<Script> = Vec::with_capacity(WIDTH);
    for (i, &c) in v.iter().enumerate() {
        // Above the state sit the running sum and the `i` finished outputs.
        let above = 1 + i;
        rows.push(script! {
            { copy_input(i, above) }
            { scale(c) }
            // Above the sum now sit the `i` finished outputs and this term,
            // so the sum is `i + 1` deep.
            { i + 1 } OP_PICK
            { field::add() }
        });
    }
    script! {
        // full_sum = s[0] + .. + s[15], left above the untouched state.
        { copy_input(0, 0) }
        for j in 1..WIDTH {
            { copy_input(j, 1) }
            { field::add() }
        }
        for r in rows { { r } }
        // Stack: state, sum, outputs. Park the outputs, drop the rest, restore.
        for _ in 0..WIDTH { OP_TOALTSTACK }
        OP_DROP
        for _ in 0..WIDTH / 2 { OP_2DROP }
        for _ in 0..WIDTH { OP_FROMALTSTACK }
    }
}

/// `V` from Plonky3's `internal_layer_mat_mul`, as field elements.
///
/// Recovered from [`reference::internal_matrix`] rather than transcribed: the
/// diagonal entry is the coefficient of input `i` in output `i`, less the one
/// that the all-ones part of the matrix contributes.
fn internal_diagonal() -> [u32; WIDTH] {
    let m = reference::internal_matrix();
    core::array::from_fn(|i| {
        // Row i is `full_sum + V[i] * s[i]`, so the off-diagonal entries are all
        // 1 and the diagonal is `1 + V[i]`.
        reference::sub(m[i][i], m[i][(i + 1) % WIDTH])
    })
}

/// Add a round constant to the top element and cube it.
fn add_rc_and_sbox(c: u32) -> Script {
    script! {
        if c != 0 { { c } { field::add() } }
        { field::cube() }
    }
}

/// A full external round's S-box layer: add constants and cube all sixteen.
fn external_sbox_layer(rc: &[u32; WIDTH]) -> Script {
    script! {
        // s[15] is on top, so walk the constants backwards.
        for i in (0..WIDTH).rev() {
            { add_rc_and_sbox(rc[i]) }
            OP_TOALTSTACK
        }
        for _ in 0..WIDTH { OP_FROMALTSTACK }
    }
}

/// The partial round's S-box layer, which touches `s[0]` only.
fn internal_sbox_layer(c: u32) -> Script {
    script! {
        // Bury the top fifteen, act on s[0], then bring them back.
        for _ in 0..WIDTH - 1 { OP_TOALTSTACK }
        { add_rc_and_sbox(c) }
        for _ in 0..WIDTH - 1 { OP_FROMALTSTACK }
    }
}

/// The permutation as a sequence of independently checkable steps.
///
/// One permutation is 572 KB, well past `MAX_STANDARD_TX_WEIGHT`, so a disprove
/// script cannot execute a whole one. It can execute a single round: the prover
/// commits to the state between rounds, and a challenge names the round it
/// claims is wrong. Each script here takes a state and leaves a state, so a
/// disprove runs exactly one of them against a hinted input and a hinted output.
///
/// Chaining every script in order is `permute()` exactly; `rounds_compose_to_the_permutation`
/// asserts it.
pub fn rounds() -> Vec<Script> {
    let mut out = Vec::with_capacity(1 + EXTERNAL_INITIAL.len() + INTERNAL.len() + EXTERNAL_FINAL.len());
    // The opening linear layer, before any constant is added.
    out.push(mds_light());
    for rc in EXTERNAL_INITIAL.iter() {
        out.push(script! { { external_sbox_layer(rc) } { mds_light() } });
    }
    for c in INTERNAL.iter() {
        out.push(script! { { internal_sbox_layer(*c) } { internal_linear() } });
    }
    for rc in EXTERNAL_FINAL.iter() {
        out.push(script! { { external_sbox_layer(rc) } { mds_light() } });
    }
    out
}

/// The Poseidon2 permutation.
///
/// Input: sixteen canonical KoalaBear elements, `s[0]` deepest.
/// Output: the permuted state, same layout.
pub fn permute() -> Script {
    script! {
        { mds_light() }
        for rc in EXTERNAL_INITIAL.iter() {
            { external_sbox_layer(rc) }
            { mds_light() }
        }
        for c in INTERNAL.iter() {
            { internal_sbox_layer(*c) }
            { internal_linear() }
        }
        for rc in EXTERNAL_FINAL.iter() {
            { external_sbox_layer(rc) }
            { mds_light() }
        }
    }
}

/// Compress two eight-element digests into one, the Merkle step.
///
/// Input: `left[0..8] right[0..8]`, sixteen elements — which is already the
/// permutation's state, and is the point: there is no concatenation to perform,
/// only a state to permute. Output: the first eight elements of the result.
///
/// This is `TruncatedPermutation<_, 2, 8, 16>` in Plonky3's terms, the
/// compression function a `MerkleTreeMmcs` is built from.
pub fn compress() -> Script {
    script! {
        { permute() }
        // Keep s[0..8], drop s[8..16].
        for _ in 0..WIDTH / 2 / 2 { OP_2DROP }
    }
}
