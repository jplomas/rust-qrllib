//! Floating-point layer: the `fpr` helpers, the FFT over `R[x]/(x^n + 1)`, the
//! LDL tree and the discrete Gaussian sampler, transliterated from the Falcon
//! round-3 reference (`fpr.h`, `fft.c`, `sign.c`) and go-qrllib
//! `crypto/internal/falcon1024/{fpr,fft}.go`.
//!
//! The reference rounds every floating-point operation to binary64
//! individually, so reproducing its keys and signatures bit for bit needs the
//! same operation order and no fused multiply-add. Rust never contracts
//! `a * b + c` into an FMA (only `f64::mul_add` does), so plain `f64`
//! arithmetic in the order of the C source rounds exactly as the reference
//! does, on every target. Do not reassociate any expression in this file.

use super::field::{LOG_N, N, SmallPoly};
use super::rng::SamplerPrng;
use super::tables::FPR_GM_TAB_BITS;
use std::sync::OnceLock;

/// FFT representation: N/2 complex values, real parts in `[0, N/2)` and
/// imaginary parts in `[N/2, N)`.
pub(super) type FftPoly = [f64; N];

/// Size of the LDL tree for degree 2^logn.
pub(super) const fn ff_ldl_tree_size(logn: usize) -> usize {
    (logn + 1) << logn
}

/// Size of the full LDL tree for degree 1024.
pub(super) const TREE_SIZE: usize = ff_ldl_tree_size(LOG_N);

pub(super) const FPR_INVERSE_OF_Q: f64 = 1.0 / 12289.0;
#[allow(clippy::excessive_precision)]
const SIGMA_MIN_1024: f64 = 1.2982803343442918539708792538826807;
#[allow(clippy::excessive_precision)]
const INV_2_SQR_SIGMA0: f64 = 0.150865048875372721532312163019;
const LOG2: f64 = core::f64::consts::LN_2;
const INV_LOG2: f64 = core::f64::consts::LOG2_E;
const TWO_TO_52: f64 = 4_503_599_627_370_496.0;
const TWO_TO_63: f64 = 9_223_372_036_854_775_808.0;
pub(super) const TWO_TO_31: f64 = 2_147_483_648.0;
pub(super) const TWO_TO_31_MINUS_1: f64 = 2_147_483_647.0;
pub(super) const TWO_TO_63_MINUS_1: f64 = 9_223_372_036_854_775_807.0;

/// Reference `fpr_inv_sigma` for degrees 2^0 .. 2^10.
#[allow(clippy::excessive_precision)]
const INV_SIGMA: [f64; 11] = [
    0.0,
    0.00690547932959408896,
    0.00681022677671779767,
    0.00671881019107227126,
    0.00658833543700736678,
    0.00646517812076029003,
    0.00634867888280789966,
    0.00623825865290843738,
    0.00613340650209302611,
    0.00603366966815772378,
    0.00593864530953311636,
];

/// Reference `fpr_p2_tab`: 2^(1 - logn).
const FPR_P2_TAB: [f64; 11] =
    [2.0, 1.0, 0.5, 0.25, 0.125, 0.0625, 0.03125, 0.015625, 0.0078125, 0.00390625, 0.001953125];

/// Reference `gaussian0_sampler` table: the 72-bit cumulative distribution
/// of the half-Gaussian, 18 rows of three 24-bit limbs, most significant
/// first.
const GAUSSIAN0_DIST: [u32; 54] = [
    10745844, 3068844, 3741698, 5559083, 1580863, 8248194, 2260429, 13669192, 2736639, 708981,
    4421575, 10046180, 169348, 7122675, 4136815, 30538, 13063405, 7650655, 4132, 14505003, 7826148,
    417, 16768101, 11363290, 31, 8444042, 8086568, 1, 12844466, 265321, 0, 1232676, 13644283, 0,
    38047, 9111839, 0, 870, 6138264, 0, 14, 12545723, 0, 0, 3104126, 0, 0, 28824, 0, 0, 198, 0, 0,
    1,
];

struct GmTables {
    re: [f64; N],
    im: [f64; N],
}

/// The reference `fpr_gm_tab` roots of unity, decoded once from their bit
/// patterns into separate real and imaginary halves.
fn gm_tables() -> &'static GmTables {
    static TABLES: OnceLock<GmTables> = OnceLock::new();
    TABLES.get_or_init(|| {
        let mut re = [0.0; N];
        let mut im = [0.0; N];
        for j in 0..N {
            re[j] = f64::from_bits(FPR_GM_TAB_BITS[j << 1]);
            im[j] = f64::from_bits(FPR_GM_TAB_BITS[(j << 1) + 1]);
        }
        GmTables { re, im }
    })
}

/// Reference `fpr_rint`: rounds to the nearest integer, ties to even, for
/// any |x| < 2^63, with the reference's own integer conversion sequence.
pub(super) fn fpr_rint(x: f64) -> i64 {
    let sx = (x - 1.0) as i64;
    let mut tx = x as i64;
    let mut rp = ((x + TWO_TO_52) as i64).wrapping_sub(TWO_TO_52 as i64);
    let mut rn = ((x - TWO_TO_52) as i64).wrapping_add(TWO_TO_52 as i64);

    let mut m = sx >> 63;
    rn &= m;
    rp &= !m;

    let ub = ((tx as u64) >> 52) as u32;
    m = -i64::from(((ub.wrapping_add(1) & 0xFFF).wrapping_sub(2)) >> 31);
    rp &= m;
    rn &= m;
    tx &= !m;

    tx | rn | rp
}

/// Reference `fpr_trunc`.
pub(super) fn fpr_trunc(x: f64) -> i64 {
    x as i64
}

const FPR_EXPM_P63_COEFFICIENTS: [u64; 13] = [
    0x0000_0004_7411_83A3,
    0x0000_0036_548C_FC06,
    0x0000_024F_DCBF_140A,
    0x0000_171D_939D_E045,
    0x0000_D00C_F58F_6F84,
    0x0006_8068_1CF7_96E3,
    0x002D_82D8_305B_0FEA,
    0x0111_1111_0E06_6FD0,
    0x0555_5555_5507_0F00,
    0x1555_5555_5581_FF00,
    0x4000_0000_0002_B400,
    0x7FFF_FFFF_FFFF_4800,
    0x8000_0000_0000_0000,
];

/// High 64 bits of the 128-bit product a*b.
fn mul_hi(a: u64, b: u64) -> u64 {
    ((u128::from(a) * u128::from(b)) >> 64) as u64
}

/// Reference `fpr_expm_p63` (integer form): 2^63 * ccs * exp(-x).
pub(super) fn fpr_expm_p63(x: f64, ccs: f64) -> u64 {
    let mut y = FPR_EXPM_P63_COEFFICIENTS[0];
    let mut z = ((fpr_trunc(x * TWO_TO_63)) as u64) << 1;
    for &ci in &FPR_EXPM_P63_COEFFICIENTS[1..] {
        y = ci.wrapping_sub(mul_hi(z, y));
    }
    z = ((fpr_trunc(ccs * TWO_TO_63)) as u64) << 1;
    mul_hi(z, y)
}

/// Converts a small polynomial to floating point and runs the forward FFT.
pub(super) fn fft_from_small(dst: &mut [f64], src: &SmallPoly) {
    for (d, &s) in dst.iter_mut().zip(src) {
        *d = f64::from(s);
    }
    fft(dst, LOG_N);
}

/// Reference `gaussian0_sampler`: draws 72 random bits as three 24-bit limbs
/// and counts, with a constant-time borrow chain, the rows the value falls
/// below.
pub(super) fn gaussian0_sample(prng: &mut SamplerPrng) -> i32 {
    let lo = prng.read_u64();
    let hi = u32::from(prng.read_byte());
    let v0 = (lo as u32) & 0xFF_FFFF;
    let v1 = ((lo >> 24) as u32) & 0xFF_FFFF;
    let v2 = ((lo >> 48) as u32) | (hi << 16);

    let mut z = 0_i32;
    for row in GAUSSIAN0_DIST.chunks_exact(3) {
        let (w2, w1, w0) = (row[0], row[1], row[2]);
        let mut cc = v0.wrapping_sub(w0) >> 31;
        cc = v1.wrapping_sub(w1).wrapping_sub(cc) >> 31;
        cc = v2.wrapping_sub(w2).wrapping_sub(cc) >> 31;
        z += cc as i32;
    }
    z
}

/// Reference `BerExp`: returns true with probability ccs * exp(-x).
pub(super) fn ber_exp(prng: &mut SamplerPrng, x: f64, ccs: f64) -> bool {
    let s = fpr_trunc(x * INV_LOG2);
    let r = x - (s as f64) * LOG2;

    let mut sw = s as u32;
    sw ^= (sw ^ 63) & (63_u32.wrapping_sub(sw) >> 31).wrapping_neg();

    // In the sampler's domain sw <= 63. Far outside it (a basis that
    // bypassed the import checks) the clamp above can leave sw >= 64; such a
    // shift yields 0, as it does in go-qrllib, rather than masking the shift
    // amount.
    let z = ((fpr_expm_p63(r, ccs) << 1).wrapping_sub(1)).checked_shr(sw).unwrap_or(0);

    let mut i = 64_u32;
    let mut w;
    loop {
        i -= 8;
        w = u32::from(prng.read_byte()).wrapping_sub(((z >> i) as u32) & 0xFF);
        if w != 0 || i == 0 {
            break;
        }
    }
    (w >> 31) != 0
}

/// Bound on the rejection loop of [`sample_fft_point`] for one coordinate.
/// For a leaf inside the sampler's domain, which every basis the import
/// checks accept has, a draw is accepted with constant probability (a few
/// draws per coordinate on average), so 2^16 consecutive rejections do not
/// happen in honest use. The bound stops a basis whose LDL tree carries NaN
/// or near-zero leaves, reachable only by bypassing those checks, from making
/// signing spin. The reference loops without bound.
pub(super) const MAX_SAMPLER_DRAWS: u32 = 1 << 16;

/// Reference `sampler`: an integer sampled around `mu` with standard
/// deviation 1/`isigma`.
pub(super) fn sample_fft_point(prng: &mut SamplerPrng, mu: f64, isigma: f64) -> f64 {
    let s = mu.floor();
    if prng.exhausted {
        // An earlier coordinate ran out of draws; the attempt is already
        // lost, so finish the tree walk without spending more.
        return s;
    }
    let r = mu - s;
    let dss = (isigma * isigma) * 0.5;
    let ccs = isigma * SIGMA_MIN_1024;

    for _ in 0..MAX_SAMPLER_DRAWS {
        prng.draws += 1;
        let z0 = gaussian0_sample(prng);
        let b = i32::from(prng.read_byte()) & 1;
        let z = b + ((b << 1) - 1) * z0;

        let mut x = f64::from(z) - r;
        x = (x * x) * dss - f64::from(z0 * z0) * INV_2_SQR_SIGMA0;
        if ber_exp(prng, x, ccs) {
            return s + f64::from(z);
        }
    }
    prng.exhausted = true;
    s
}

/// Builds the LDL tree of the Gram matrix `[[g00, g01], [adj(g01), g11]]`
/// (reference `ffLDL_fft`). `tmp` must hold `3 << logn` values.
pub(super) fn ff_ldl_fft(
    tree: &mut [f64],
    g00: &[f64],
    g01: &[f64],
    g11: &[f64],
    logn: usize,
    tmp: &mut [f64],
) {
    // Called at the full degree only; the degree-1 base case lives in
    // ff_ldl_fft_inner.
    debug_assert!(logn >= 1);
    let degree = 1 << logn;
    let hn = degree >> 1;
    let (d00, rest) = tmp.split_at_mut(degree);
    let (d11, rest) = rest.split_at_mut(degree);
    let t = &mut rest[..degree];

    d00.copy_from_slice(&g00[..degree]);
    fft_ldl_mv(d11, &mut tree[..degree], &g00[..degree], &g01[..degree], &g11[..degree], logn);

    {
        let (t0, t1) = t.split_at_mut(hn);
        split_fft(t0, t1, d00, logn);
    }
    {
        let (a, b) = d00.split_at_mut(hn);
        split_fft(a, b, d11, logn);
    }
    d11.copy_from_slice(t);

    let (tree0, tree1) = tree[degree..].split_at_mut(ff_ldl_tree_size(logn - 1));
    {
        let (a, b) = d11.split_at_mut(hn);
        ff_ldl_fft_inner(tree0, a, b, logn - 1, t);
    }
    {
        let (a, b) = d00.split_at_mut(hn);
        ff_ldl_fft_inner(tree1, a, b, logn - 1, t);
    }
}

/// Reference `ffLDL_fft_inner`, for a self-adjoint quasicyclic Gram matrix
/// given by `g0` (diagonal) and `g1` (off-diagonal). `g0` and `g1` are
/// consumed.
fn ff_ldl_fft_inner(
    tree: &mut [f64],
    g0: &mut [f64],
    g1: &mut [f64],
    logn: usize,
    tmp: &mut [f64],
) {
    let degree = 1 << logn;
    if degree == 1 {
        tree[0] = g0[0];
        return;
    }
    let hn = degree >> 1;

    fft_ldl_mv(&mut tmp[..degree], &mut tree[..degree], g0, g1, g0, logn);

    {
        let (a, b) = g1.split_at_mut(hn);
        split_fft(a, b, g0, logn);
    }
    {
        let (a, b) = g0.split_at_mut(hn);
        split_fft(a, b, &tmp[..degree], logn);
    }

    let (tree0, tree1) = tree[degree..].split_at_mut(ff_ldl_tree_size(logn - 1));
    {
        let (a, b) = g1.split_at_mut(hn);
        ff_ldl_fft_inner(tree0, a, b, logn - 1, tmp);
    }
    {
        let (a, b) = g0.split_at_mut(hn);
        ff_ldl_fft_inner(tree1, a, b, logn - 1, tmp);
    }
}

/// Reference `poly_LDLmv_fft`: d11 = g11 - mu * adj(g01) and l10 = adj(mu),
/// with mu = g01 / g00 computed as the `FPC_DIV` macro does.
fn fft_ldl_mv(
    d11: &mut [f64],
    l10: &mut [f64],
    g00: &[f64],
    g01: &[f64],
    g11: &[f64],
    logn: usize,
) {
    let hn = 1 << (logn - 1);
    for i in 0..hn {
        let g00_re = g00[i];
        let g00_im = g00[i + hn];
        let g01_re = g01[i];
        let g01_im = g01[i + hn];
        let g11_re = g11[i];
        let g11_im = g11[i + hn];

        // mu = g01 / g00: invert |g00|^2 once, scale conj(g00), multiply.
        let mut m = g00_re * g00_re + g00_im * g00_im;
        m = 1.0 / m;
        let b_re = g00_re * m;
        let b_im = (-g00_im) * m;
        let mu_re = g01_re * b_re - g01_im * b_im;
        let mu_im = g01_re * b_im + g01_im * b_re;

        // xi = mu * conj(g01), as FPC_MUL with negated g01_im.
        let ng01_im = -g01_im;
        let xi_re = mu_re * g01_re - mu_im * ng01_im;
        let xi_im = mu_re * ng01_im + mu_im * g01_re;

        d11[i] = g11_re - xi_re;
        d11[i + hn] = g11_im - xi_im;
        l10[i] = mu_re;
        l10[i + hn] = -mu_im;
    }
}

/// Replaces every leaf of the tree with sigma / sqrt(leaf) scaled as the
/// reference `ffLDL_binary_normalize` does.
pub(super) fn ff_ldl_binary_normalize(tree: &mut [f64], orig_logn: usize, logn: usize) {
    let degree = 1 << logn;
    if degree == 1 {
        tree[0] = tree[0].sqrt() * INV_SIGMA[orig_logn];
        return;
    }
    let (tree0, tree1) = tree[degree..].split_at_mut(ff_ldl_tree_size(logn - 1));
    ff_ldl_binary_normalize(tree0, orig_logn, logn - 1);
    ff_ldl_binary_normalize(tree1, orig_logn, logn - 1);
}

/// Reference `poly_split_fft`.
pub(super) fn split_fft(f0: &mut [f64], f1: &mut [f64], f: &[f64], logn: usize) {
    let gm = gm_tables();
    let degree = 1 << logn;
    let hn = degree >> 1;
    let qn = hn >> 1;

    f0[0] = f[0];
    f1[0] = f[hn];
    for u in 0..qn {
        let j = u << 1;
        let a_re = f[j];
        let a_im = f[j + hn];
        let b_re = f[j + 1];
        let b_im = f[j + 1 + hn];

        let mut t_re = a_re + b_re;
        let mut t_im = a_im + b_im;
        f0[u] = 0.5 * t_re;
        f0[u + qn] = 0.5 * t_im;

        t_re = a_re - b_re;
        t_im = a_im - b_im;
        let gm_re = gm.re[u + hn];
        let gm_im = -gm.im[u + hn];
        f1[u] = 0.5 * (t_re * gm_re - t_im * gm_im);
        f1[u + qn] = 0.5 * (t_re * gm_im + t_im * gm_re);
    }
}

/// Reference `poly_merge_fft`.
pub(super) fn merge_fft(f: &mut [f64], f0: &[f64], f1: &[f64], logn: usize) {
    let gm = gm_tables();
    let degree = 1 << logn;
    let hn = degree >> 1;
    let qn = hn >> 1;

    f[0] = f0[0];
    f[hn] = f1[0];
    for u in 0..qn {
        let a_re = f0[u];
        let a_im = f0[u + qn];
        let b_re = f1[u];
        let b_im = f1[u + qn];
        let gm_re = gm.re[u + hn];
        let gm_im = gm.im[u + hn];
        let c_re = b_re * gm_re - b_im * gm_im;
        let c_im = b_re * gm_im + b_im * gm_re;

        let j = u << 1;
        f[j] = a_re + c_re;
        f[j + hn] = a_im + c_im;
        f[j + 1] = a_re - c_re;
        f[j + 1 + hn] = a_im - c_im;
    }
}

/// The Fast Fourier sampling recursion of the reference
/// `ffSampling_fft_dyntree`, which `sign_dyn` (the signer behind the NIST
/// API) uses: every level down to the degree-1 leaves goes through the
/// generic split and merge. The reference's expanded-key `ffSampling_fft`
/// inlines the two lowest levels with a different operation order and rounds
/// differently in the last bit; only `sign_dyn` is matched. The LDL values
/// come from the precomputed tree, which holds what `sign_dyn` recomputes.
#[allow(clippy::too_many_arguments)]
fn ff_sampling_fft_recursive<S>(
    samp: &mut S,
    prng: &mut SamplerPrng,
    z0: &mut [f64],
    z1: &mut [f64],
    tree: &[f64],
    t0: &[f64],
    t1: &[f64],
    tmp: &mut [f64],
    logn: usize,
) where
    S: FnMut(&mut SamplerPrng, f64, f64) -> f64,
{
    if logn == 0 {
        let isigma = tree[0];
        z0[0] = samp(prng, t0[0], isigma);
        z1[0] = samp(prng, t1[0], isigma);
        return;
    }

    let degree = 1 << logn;
    let hn = degree >> 1;
    let tree0 = &tree[degree..];
    let tree1 = &tree[degree + ff_ldl_tree_size(logn - 1)..];

    {
        let (a, b) = z1.split_at_mut(hn);
        split_fft(a, &mut b[..hn], &t1[..degree], logn);
    }
    {
        let (tmp_lo, tmp_hi) = tmp.split_at_mut(degree);
        let (ta, tb) = tmp_lo.split_at_mut(hn);
        ff_sampling_fft_recursive(
            samp,
            prng,
            ta,
            tb,
            tree1,
            &z1[..hn],
            &z1[hn..degree],
            tmp_hi,
            logn - 1,
        );
        merge_fft(&mut z1[..degree], ta, tb, logn);
    }

    tmp[..degree].copy_from_slice(&t1[..degree]);
    for i in 0..degree {
        tmp[i] -= z1[i];
    }
    fft_mul(&mut tmp[..degree], &tree[..degree], logn);
    for i in 0..degree {
        tmp[i] += t0[i];
    }

    {
        let (a, b) = z0.split_at_mut(hn);
        split_fft(a, &mut b[..hn], &tmp[..degree], logn);
    }
    {
        let (tmp_lo, tmp_hi) = tmp.split_at_mut(degree);
        let (ta, tb) = tmp_lo.split_at_mut(hn);
        ff_sampling_fft_recursive(
            samp,
            prng,
            ta,
            tb,
            tree0,
            &z0[..hn],
            &z0[hn..degree],
            tmp_hi,
            logn - 1,
        );
        merge_fft(&mut z0[..degree], ta, tb, logn);
    }
}

/// Samples (z0, z1) close to the target (t0, t1) with the LDL tree.
#[allow(clippy::too_many_arguments)]
pub(super) fn ff_sampling_fft<S>(
    samp: &mut S,
    prng: &mut SamplerPrng,
    z0: &mut [f64],
    z1: &mut [f64],
    t0: &[f64],
    t1: &[f64],
    tree: &[f64],
    logn: usize,
) where
    S: FnMut(&mut SamplerPrng, f64, f64) -> f64,
{
    let mut tmp = vec![0.0_f64; 2 * N];
    let degree = 1 << logn;
    ff_sampling_fft_recursive(
        samp,
        prng,
        &mut z0[..degree],
        &mut z1[..degree],
        tree,
        &t0[..degree],
        &t1[..degree],
        &mut tmp[..degree << 1],
        logn,
    );
    super::zeroize_slice(&mut tmp);
}

/// Reference `FFT`, for degree 2^logn with logn >= 1 (every caller's
/// degree is at least 2; the reference's degree-1 no-op is not needed).
pub(super) fn fft(f: &mut [f64], logn: usize) {
    debug_assert!(logn >= 1);
    let gm = gm_tables();
    let hn = 1 << (logn - 1);
    let mut t = hn;
    let mut m = 2;
    for _ in 1..logn {
        let ht = t >> 1;
        let hm = m >> 1;
        let mut j1 = 0;
        for i1 in 0..hm {
            let j2 = j1 + ht;
            let s_re = gm.re[m + i1];
            let s_im = gm.im[m + i1];
            for j in j1..j2 {
                let x_re = f[j];
                let x_im = f[j + hn];
                let y_re0 = f[j + ht];
                let y_im0 = f[j + ht + hn];
                let y_re = y_re0 * s_re - y_im0 * s_im;
                let y_im = y_re0 * s_im + y_im0 * s_re;
                f[j] = x_re + y_re;
                f[j + hn] = x_im + y_im;
                f[j + ht] = x_re - y_re;
                f[j + ht + hn] = x_im - y_im;
            }
            j1 += t;
        }
        t = ht;
        m <<= 1;
    }
}

/// Reference `iFFT`, for degree 2^logn with logn >= 1.
pub(super) fn inverse_fft(f: &mut [f64], logn: usize) {
    debug_assert!(logn >= 1);
    let gm = gm_tables();
    let hn = 1 << (logn - 1);
    let mut t = 1;
    let mut m = 1 << logn;
    for _ in (2..=logn).rev() {
        let hm = m >> 1;
        let dt = t << 1;
        let mut i1 = 0;
        let mut j1 = 0;
        while j1 < hn {
            let j2 = j1 + t;
            let s_re = gm.re[hm + i1];
            let s_im = -gm.im[hm + i1];
            for j in j1..j2 {
                let x_re = f[j];
                let x_im = f[j + hn];
                let y_re = f[j + t];
                let y_im = f[j + t + hn];
                f[j] = x_re + y_re;
                f[j + hn] = x_im + y_im;
                let d_re = x_re - y_re;
                let d_im = x_im - y_im;
                f[j + t] = d_re * s_re - d_im * s_im;
                f[j + t + hn] = d_re * s_im + d_im * s_re;
            }
            i1 += 1;
            j1 += dt;
        }
        t = dt;
        m = hm;
    }

    let scale = FPR_P2_TAB[logn];
    for x in &mut f[..1 << logn] {
        *x *= scale;
    }
}

/// Reference `poly_invnorm2_fft`: 1 / (|a|^2 + |b|^2).
pub(super) fn fft_inv_norm2(dst: &mut [f64], a: &[f64], b: &[f64], logn: usize) {
    let hn = 1 << (logn - 1);
    for i in 0..hn {
        let a_re = a[i];
        let a_im = a[i + hn];
        let b_re = b[i];
        let b_im = b[i + hn];
        dst[i] = 1.0 / ((a_re * a_re + a_im * a_im) + (b_re * b_re + b_im * b_im));
    }
}

/// Reference `poly_adj_fft`: the adjoint, negating the imaginary half.
pub(super) fn fft_adj(a: &mut [f64], logn: usize) {
    let degree = 1 << logn;
    for x in &mut a[degree >> 1..degree] {
        *x = -*x;
    }
}

/// Reference `poly_mul_fft`: a *= b, pointwise in FFT representation.
pub(super) fn fft_mul(a: &mut [f64], b: &[f64], logn: usize) {
    let hn = 1 << (logn - 1);
    for i in 0..hn {
        let a_re = a[i];
        let a_im = a[i + hn];
        let b_re = b[i];
        let b_im = b[i + hn];
        a[i] = a_re * b_re - a_im * b_im;
        a[i + hn] = a_re * b_im + a_im * b_re;
    }
}

/// Reference `poly_mulconst`: multiplies every coefficient by x.
pub(super) fn fft_mul_const(a: &mut [f64], x: f64, logn: usize) {
    for v in &mut a[..1 << logn] {
        *v *= x;
    }
}

/// dst = src * adj(src); the result is real, so the imaginary half is zeroed.
pub(super) fn fft_self_adj(dst: &mut [f64], src: &[f64], logn: usize) {
    let hn = 1 << (logn - 1);
    for i in 0..hn {
        let a_re = src[i];
        let a_im = src[i + hn];
        dst[i] = a_re * a_re + a_im * a_im;
        dst[i + hn] = 0.0;
    }
}

/// Reference `poly_neg`: negates every coefficient.
pub(super) fn fft_neg(a: &mut [f64], logn: usize) {
    for v in &mut a[..1 << logn] {
        *v = -*v;
    }
}

/// dst = a * adj(b).
pub(super) fn fft_mul_adj(dst: &mut [f64], a: &[f64], b: &[f64], logn: usize) {
    let hn = 1 << (logn - 1);
    for i in 0..hn {
        let a_re = a[i];
        let a_im = a[i + hn];
        let b_re = b[i];
        let b_im = -b[i + hn];
        dst[i] = a_re * b_re - a_im * b_im;
        dst[i + hn] = a_re * b_im + a_im * b_re;
    }
}

/// Multiplies by a real (self-adjoint) polynomial.
pub(super) fn fft_mul_auto_adj(a: &mut [f64], b: &[f64], logn: usize) {
    let hn = 1 << (logn - 1);
    for i in 0..hn {
        a[i] *= b[i];
        a[i + hn] *= b[i];
    }
}

/// Reference `poly_add`: a += b.
pub(super) fn fft_add(a: &mut [f64], b: &[f64], logn: usize) {
    for (x, &y) in a[..1 << logn].iter_mut().zip(b) {
        *x += y;
    }
}

/// Reference `poly_sub`: a -= b.
pub(super) fn fft_sub(a: &mut [f64], b: &[f64], logn: usize) {
    for (x, &y) in a[..1 << logn].iter_mut().zip(b) {
        *x -= y;
    }
}

/// Reference `poly_add_muladj_fft`: dst = F * adj(f) + G * adj(g), each
/// product formed separately before the add.
pub(super) fn fft_add_mul_adj(
    dst: &mut [f64],
    big_f: &[f64],
    big_g: &[f64],
    f: &[f64],
    g: &[f64],
    logn: usize,
) {
    let hn = 1 << (logn - 1);
    for i in 0..hn {
        let ff_re = big_f[i];
        let ff_im = big_f[i + hn];
        let gg_re = big_g[i];
        let gg_im = big_g[i + hn];
        let f_re = f[i];
        let f_im = -f[i + hn];
        let g_re = g[i];
        let g_im = -g[i + hn];
        let a_re = ff_re * f_re - ff_im * f_im;
        let a_im = ff_re * f_im + ff_im * f_re;
        let b_re = gg_re * g_re - gg_im * g_im;
        let b_im = gg_re * g_im + gg_im * g_re;
        dst[i] = a_re + b_re;
        dst[i + hn] = a_im + b_im;
    }
}

/// Reference `poly_div_autoadj_fft`: invert once and multiply; a/b and
/// a*(1/b) differ in the last bit.
pub(super) fn fft_div_auto_adj(a: &mut [f64], b: &[f64], logn: usize) {
    let hn = 1 << (logn - 1);
    for i in 0..hn {
        let ib = 1.0 / b[i];
        a[i] *= ib;
        a[i + hn] *= ib;
    }
}
