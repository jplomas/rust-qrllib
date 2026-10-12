//! Arithmetic modulo q = 12289, the NTT, hash-to-point, the key-generation
//! Gaussian and the norm checks, transliterated from the Falcon round-3
//! reference (and go-qrllib `crypto/internal/falcon1024/field.go`).
//!
//! Field elements are `u32` values in `[0, q)`. All integer arithmetic wraps,
//! as it does in C and Go; the constant-time masks below rely on it.

use super::fft::{FftPoly, fft_adj, fft_from_small, fft_inv_norm2, fft_mul_auto_adj, inverse_fft};
use super::tables::{GMB, IGMB};
use super::{ShakeReader, zeroize_slice};
use sha3::digest::XofReader;

/// Polynomial degree.
pub(super) const N: usize = 1024;
/// log2 of the degree.
pub(super) const LOG_N: usize = 10;
/// Field modulus.
pub(super) const Q: u32 = 12289;

/// A polynomial modulo q, coefficients in `[0, q)`.
pub(super) type RingElement = [u32; N];
/// A polynomial with small signed integer coefficients.
pub(super) type SmallPoly = [i32; N];

/// Bound on |F| and |G| coefficients (and on keygen samples).
pub(super) const NTRU_COEFF_BOUND: i32 = 127;

/// Maps a small signed integer into `[0, q)`.
pub(super) fn field_from_small(x: i32) -> u32 {
    let mut y = x as u32;
    y = y.wrapping_add(Q & (y >> 31).wrapping_neg());
    y
}

/// Subtracts q once if `a >= q`, for `a` in `[0, 2q)`, in constant time.
fn field_reduce_once(a: u32) -> u32 {
    let mut x = a.wrapping_sub(Q);
    x = x.wrapping_add(Q & (x >> 31).wrapping_neg());
    x
}

/// Reference `mq_add`: (a + b) mod q.
pub(super) fn field_add(a: u32, b: u32) -> u32 {
    field_reduce_once(a.wrapping_add(b))
}

/// Reference `mq_sub`: (a - b) mod q.
pub(super) fn field_sub(a: u32, b: u32) -> u32 {
    field_reduce_once(a.wrapping_sub(b).wrapping_add(Q))
}

/// 2^32 mod q: multiplying by it moves a value into Montgomery form.
pub(super) const R2: u32 = 10952;

/// Returns 1/x in Montgomery representation (reference `mq_div_12289`
/// exponentiation chain, x^(q-2)).
fn field_inv_montgomery(x: u32) -> u32 {
    let y0 = field_montgomery_mul(x, R2);
    let y1 = field_montgomery_sqr(y0);
    let y2 = field_montgomery_mul(y1, y0);
    let y3 = field_montgomery_mul(y2, y1);
    let y4 = field_montgomery_sqr(y3);
    let y5 = field_montgomery_sqr(y4);
    let y6 = field_montgomery_sqr(y5);
    let y7 = field_montgomery_sqr(y6);
    let y8 = field_montgomery_sqr(y7);
    let y9 = field_montgomery_mul(y8, y2);
    let y10 = field_montgomery_mul(y9, y8);
    let y11 = field_montgomery_sqr(y10);
    let y12 = field_montgomery_sqr(y11);
    let y13 = field_montgomery_mul(y12, y9);
    let y14 = field_montgomery_sqr(y13);
    let y15 = field_montgomery_sqr(y14);
    let y16 = field_montgomery_mul(y15, y10);
    let y17 = field_montgomery_sqr(y16);
    field_montgomery_mul(y17, y0)
}

/// Montgomery squaring: x^2 / 2^16 mod q.
fn field_montgomery_sqr(x: u32) -> u32 {
    field_montgomery_mul(x, x)
}

/// Reference `mq_montymul`: a*b / 2^16 mod q, in `[0, q)`.
pub(super) fn field_montgomery_mul(a: u32, b: u32) -> u32 {
    field_montgomery_reduce(a.wrapping_mul(b))
}

const Q_NEG_INV: u32 = 12287;

/// Montgomery reduction of a 32-bit product: x / 2^16 mod q, in `[0, q)`.
fn field_montgomery_reduce(mut x: u32) -> u32 {
    let w = (x.wrapping_mul(Q_NEG_INV) & 0xFFFF).wrapping_mul(Q);
    x = x.wrapping_add(w) >> 16;
    x = x.wrapping_sub(Q);
    x = x.wrapping_add(Q & (x >> 31).wrapping_neg());
    x
}

/// Maps `[0, q)` to `(-q/2, q/2]`, as the reference `verify_raw` does.
pub(super) fn field_centered_mod(x: u32) -> i32 {
    let mut v = x as i32;
    if v > (Q / 2) as i32 {
        v -= Q as i32;
    }
    v
}

/// Encodes 1024 14-bit coefficients big-endian, four per seven bytes.
pub(super) fn poly_byte_encode(dst: &mut [u8], p: &RingElement) {
    for (chunk, c) in dst.chunks_exact_mut(7).zip(p.chunks_exact(4)) {
        let x = (u64::from(c[0]) << 42)
            | (u64::from(c[1]) << 28)
            | (u64::from(c[2]) << 14)
            | u64::from(c[3]);
        chunk.copy_from_slice(&x.to_be_bytes()[1..]);
    }
}

/// The byte size of a ring element at 14 bits per coefficient.
pub(super) const ENCODING_SIZE_14: usize = 1792;

/// Decodes 14-bit coefficients from [`ENCODING_SIZE_14`] bytes (the caller
/// checks the length), refusing any coefficient that is not below q.
pub(super) fn poly_byte_decode(b: &[u8]) -> Option<RingElement> {
    debug_assert_eq!(b.len(), ENCODING_SIZE_14);
    let mut p = [0_u32; N];
    for (chunk, c) in b.chunks_exact(7).zip(p.chunks_exact_mut(4)) {
        let mut bytes = [0_u8; 8];
        bytes[1..].copy_from_slice(chunk);
        let x = u64::from_be_bytes(bytes);
        c[0] = ((x >> 42) & 0x3FFF) as u32;
        c[1] = ((x >> 28) & 0x3FFF) as u32;
        c[2] = ((x >> 14) & 0x3FFF) as u32;
        c[3] = (x & 0x3FFF) as u32;
        if c.iter().any(|&v| v >= Q) {
            return None;
        }
    }
    Some(p)
}

const HASH_TO_POINT_REJECTION_THRESHOLD: u32 = 5 * Q;

/// Maps a SHAKE256 stream to a uniform ring element, as the reference
/// `hash_to_point_vartime` does: two bytes big-endian per candidate, values
/// of 5q and above rejected.
pub(super) fn hash_to_point(h: &mut ShakeReader) -> RingElement {
    let mut p = [0_u32; N];
    let mut buf = [0_u8; 2];
    let mut i = 0;
    while i < N {
        h.read(&mut buf);
        let w = (u32::from(buf[0]) << 8) | u32::from(buf[1]);
        if w >= HASH_TO_POINT_REJECTION_THRESHOLD {
            continue;
        }
        p[i] = w % Q;
        i += 1;
    }
    p
}

/// Reference `mq_NTT`: forward NTT modulo q, in place.
pub(super) fn ntt(f: &mut [u32]) {
    let mut t = N;
    let mut m = 1;
    while m < N {
        let ht = t >> 1;
        let mut j1 = 0;
        for i in 0..m {
            let s = GMB[m + i];
            let j2 = j1 + ht;
            for j in j1..j2 {
                let u = f[j];
                let v = field_montgomery_mul(f[j + ht], s);
                f[j] = field_add(u, v);
                f[j + ht] = field_sub(u, v);
            }
            j1 += t;
        }
        t = ht;
        m <<= 1;
    }
}

const N_INVERSE_MONTGOMERY: u32 = 64;

/// Reference `mq_iNTT`: inverse NTT modulo q, in place, including the
/// division by n.
pub(super) fn inverse_ntt(f: &mut [u32]) {
    let mut t = 1;
    let mut m = N;
    while m > 1 {
        let hm = m >> 1;
        let dt = t << 1;
        let mut j1 = 0;
        for i in 0..hm {
            let j2 = j1 + t;
            let s = IGMB[hm + i];
            for j in j1..j2 {
                let u = f[j];
                let v = f[j + t];
                f[j] = field_add(u, v);
                let w = field_sub(u, v);
                f[j + t] = field_montgomery_mul(w, s);
            }
            j1 += dt;
        }
        t = dt;
        m = hm;
    }
    for x in f.iter_mut() {
        *x = field_montgomery_mul(*x, N_INVERSE_MONTGOMERY);
    }
}

/// Pointwise Montgomery product in NTT representation: `a[i] = a[i]*b[i] / 2^16`.
pub(super) fn ntt_mul(a: &mut [u32], b: &[u32]) {
    for (x, &y) in a.iter_mut().zip(b) {
        *x = field_montgomery_mul(*x, y);
    }
}

/// Forward NTT followed by conversion to Montgomery form, the representation
/// in which the public key is cached for verification.
pub(super) fn to_ntt_monty(f: &mut [u32]) {
    ntt(f);
    for x in f.iter_mut() {
        *x = field_montgomery_mul(*x, R2);
    }
}

/// Computes `h[i] /= f[i]` for every i with one Fermat inversion of the
/// prefix product (Montgomery's trick) and back-substitution. Returns false
/// if any `f[i]` is zero, leaving `h` untouched.
pub(super) fn divide_ntt_by_batched_inverse(h: &mut [u32], f: &[u32]) -> bool {
    // f and its running products are secret whenever f is (key generation
    // and import both divide by f), so the scratch is wiped on return.
    let mut f_mont = vec![0_u32; N];
    let mut p_mont = vec![0_u32; N];
    let ok = divide_into(h, f, &mut f_mont, &mut p_mont);
    zeroize_slice(&mut f_mont);
    zeroize_slice(&mut p_mont);
    ok
}

/// The body of [`divide_ntt_by_batched_inverse`], with caller-owned scratch
/// for the Montgomery-form divisor and its prefix products.
fn divide_into(h: &mut [u32], f: &[u32], f_mont: &mut [u32], p_mont: &mut [u32]) -> bool {
    for (m, &x) in f_mont.iter_mut().zip(f) {
        if x == 0 {
            return false;
        }
        *m = field_montgomery_mul(x, R2);
    }
    p_mont[0] = f_mont[0];
    for i in 1..N {
        p_mont[i] = field_montgomery_mul(p_mont[i - 1], f_mont[i]);
    }

    let mut inv_run = field_montgomery_mul(field_inv_montgomery(p_mont[N - 1]), R2);
    for i in (1..N).rev() {
        let inv = field_montgomery_mul(inv_run, p_mont[i - 1]);
        h[i] = field_montgomery_mul(h[i], inv);
        inv_run = field_montgomery_mul(inv_run, f_mont[i]);
    }
    h[0] = field_montgomery_mul(h[0], inv_run);
    true
}

/// Samples f or g as the reference `poly_small_mkgauss`: the total parity
/// is forced odd so that the resultant with x^n + 1 can be invertible.
pub(super) fn sample_gaussian_polynomial(rng: &mut ShakeReader) -> SmallPoly {
    let mut p = [0_i32; N];
    let mut parity = 0_i32;
    let mut i = 0;
    while i < N {
        let x = sample_keygen_gaussian(rng);
        //coverage:ignore start reason=statistically-unreachable
        if !(-NTRU_COEFF_BOUND..=NTRU_COEFF_BOUND).contains(&x) {
            // At degree 1024 mkgauss is a single draw from a table whose
            // largest value is 26; the check is the reference's.
            continue;
        }
        //coverage:ignore end
        if i == N - 1 {
            if (parity ^ (x & 1)) == 0 {
                continue;
            }
        } else {
            parity ^= x & 1;
        }
        p[i] = x;
        i += 1;
    }
    p
}

/// Reference `gauss_1024_12289`: the cumulative distribution of the
/// key-generation Gaussian, scaled to 63 bits.
const GAUSS_1024_12289: [u64; 27] = [
    1283868770400643928,
    6416574995475331444,
    4078260278032692663,
    2353523259288686585,
    1227179971273316331,
    575931623374121527,
    242543240509105209,
    91437049221049666,
    30799446349977173,
    9255276791179340,
    2478152334826140,
    590642893610164,
    125206034929641,
    23590435911403,
    3948334035941,
    586753615614,
    77391054539,
    9056793210,
    940121950,
    86539696,
    7062824,
    510971,
    32764,
    1862,
    94,
    4,
    0,
];

/// Reference `mkgauss` at degree 1024: one constant-time table lookup.
fn sample_keygen_gaussian(rng: &mut ShakeReader) -> i32 {
    let mut r = read_shake_u64(rng);
    let neg = (r >> 63) as u32;
    r &= !(1_u64 << 63);
    let mut f = (r.wrapping_sub(GAUSS_1024_12289[0]) >> 63) as u32;

    let mut r = read_shake_u64(rng);
    r &= !(1_u64 << 63);

    let mut v = 0_u32;
    for (k, &bound) in GAUSS_1024_12289.iter().enumerate().skip(1) {
        let t = ((r.wrapping_sub(bound) >> 63) ^ 1) as u32;
        v |= (k as u32) & (t & (f ^ 1)).wrapping_neg();
        f |= t;
    }

    v = (v ^ neg.wrapping_neg()).wrapping_add(neg);
    v as i32
}

/// Reads the next 8 bytes of the SHAKE stream as a little-endian u64.
fn read_shake_u64(rng: &mut ShakeReader) -> u64 {
    let mut buf = [0_u8; 8];
    rng.read(&mut buf);
    u64::from_le_bytes(buf)
}

/// Reports whether any coefficient lies outside `[-bound, bound]`.
pub(super) fn coefficients_exceed_bound(p: &SmallPoly, bound: i32) -> bool {
    p.iter().any(|&x| x < -bound || x > bound)
}

/// The reference keygen check on the squared norm of (f, g): the two
/// saturating sums are added, saturated again, and compared with the bound.
pub(super) fn squared_norm_exceeds_bound(f: &SmallPoly, g: &SmallPoly, bound: u32) -> bool {
    let normf = squared_norm(f);
    let normg = squared_norm(g);
    let norm = normf.wrapping_add(normg) | ((normf | normg) >> 31).wrapping_neg();
    norm >= bound
}

/// The reference keygen check on the Gram-Schmidt norm of the basis, with
/// the same operation order so that the comparison rounds identically.
pub(super) fn orthogonalized_norm_exceeds_bound(f: &SmallPoly, g: &SmallPoly, bound: f64) -> bool {
    let mut rf: Box<FftPoly> = Box::new([0.0; N]);
    let mut rg: Box<FftPoly> = Box::new([0.0; N]);
    let mut inv_norm: Box<FftPoly> = Box::new([0.0; N]);
    fft_from_small(&mut rf[..], f);
    fft_from_small(&mut rg[..], g);
    fft_inv_norm2(&mut inv_norm[..], &rf[..], &rg[..], LOG_N);

    fft_adj(&mut rf[..], LOG_N);
    fft_adj(&mut rg[..], LOG_N);
    for x in rf.iter_mut() {
        *x *= f64::from(Q);
    }
    for x in rg.iter_mut() {
        *x *= f64::from(Q);
    }

    fft_mul_auto_adj(&mut rf[..], &inv_norm[..], LOG_N);
    fft_mul_auto_adj(&mut rg[..], &inv_norm[..], LOG_N);
    inverse_fft(&mut rf[..], LOG_N);
    inverse_fft(&mut rg[..], LOG_N);

    // bnorm += rt1[u]^2, then bnorm += rt2[u]^2, each product rounded before
    // the add. The reference rejects on !(bnorm < max), which also rejects a
    // NaN norm.
    let mut norm = 0.0_f64;
    for (a, b) in rf.iter().zip(rg.iter()) {
        norm += a * a;
        norm += b * b;
    }

    zeroize_slice(&mut rf[..]);
    zeroize_slice(&mut rg[..]);
    zeroize_slice(&mut inv_norm[..]);

    #[allow(clippy::neg_cmp_op_on_partial_ord)]
    let exceeds = !(norm < bound);
    exceeds
}

/// The reference `l2bound` for degree 1024.
pub(super) const SIGNATURE_NORM_BOUND: u32 = 70_265_242;

/// The negation of the reference `is_short_half`: `sqn` is the saturating
/// 32-bit squared norm of s1, to which the squared norm of s2 is added with
/// the same saturation.
pub(super) fn signature_norm_exceeds_partial_bound(mut sqn: u32, s2: &SmallPoly) -> bool {
    let mut ng = (sqn >> 31).wrapping_neg();
    for &z in s2 {
        sqn = sqn.wrapping_add(z.wrapping_mul(z) as u32);
        ng |= sqn;
    }
    sqn |= (ng >> 31).wrapping_neg();
    sqn > SIGNATURE_NORM_BOUND
}

/// The reference `poly_small_sqnorm`: a 32-bit sum of squares forced to the
/// maximum if it ever overflows.
pub(super) fn squared_norm(p: &SmallPoly) -> u32 {
    let mut s = 0_u32;
    let mut ng = 0_u32;
    for &x in p {
        s = s.wrapping_add(x.wrapping_mul(x) as u32);
        ng |= s;
    }
    s | (ng >> 31).wrapping_neg()
}

/// The reference `is_short`: the squared norms of s1 and s2 accumulated
/// together in a saturating 32-bit sum.
pub(super) fn signature_norm_within_bound(s1: &SmallPoly, s2: &SmallPoly) -> bool {
    let mut s = 0_u32;
    let mut ng = 0_u32;
    for (&a, &b) in s1.iter().zip(s2) {
        s = s.wrapping_add(a.wrapping_mul(a) as u32);
        ng |= s;
        s = s.wrapping_add(b.wrapping_mul(b) as u32);
        ng |= s;
    }
    s |= (ng >> 31).wrapping_neg();
    s <= SIGNATURE_NORM_BOUND
}
