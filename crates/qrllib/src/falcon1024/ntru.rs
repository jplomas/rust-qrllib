//! The NTRU equation solver of Falcon key generation (reference `keygen.c`
//! `solve_NTRU` and helpers), transliterated from go-qrllib
//! `crypto/internal/falcon1024/ntru.go`. Given f and g it finds F and G with
//! f*G - g*F = q, working down the field-norm tower with big integers kept
//! in residue (CRT) and NTT form modulo the small primes, then lifting back
//! up with Babai reduction in floating point.

// Index loops are kept where they mirror the reference C line for line.
#![allow(clippy::needless_range_loop)]

use super::fft::{
    TWO_TO_31, TWO_TO_31_MINUS_1, TWO_TO_63_MINUS_1, fft, fft_add, fft_add_mul_adj, fft_adj,
    fft_div_auto_adj, fft_inv_norm2, fft_mul, fft_mul_auto_adj, fft_sub, fpr_rint, inverse_fft,
};
use super::field::{LOG_N, N, NTRU_COEFF_BOUND, Q, SmallPoly};
use super::modp::{
    MASK31, modp_add, modp_intt2, modp_intt2_ext, modp_mkgm2, modp_montymul, modp_norm, modp_ntt2,
    modp_ntt2_ext, modp_poly_rec_res, modp_rx, modp_set, modp_sub, small_prime_derived,
    zint_add_scaled_mul_small, zint_bezout, zint_mod_small_signed, zint_mul_small,
    zint_one_to_plain, zint_rebuild_crt, zint_sub_scaled,
};
use super::tables::SMALL_PRIMES;
use super::zeroize_slice;

/// Reference `MAX_BL_SMALL`: words per coefficient of f and g at each depth.
const MAX_BL_SMALL: [usize; 11] = [1, 1, 2, 2, 4, 7, 14, 27, 53, 106, 209];
/// Reference `MAX_BL_LARGE`: words per coefficient of the unreduced F and G.
const MAX_BL_LARGE: [usize; 10] = [2, 2, 5, 7, 12, 21, 40, 78, 157, 308];

/// Reference `BITLENGTH`: average and standard deviation of the bit length
/// of the coefficients of f and g at each depth.
const BIT_LENGTH: [(i64, i64); 11] = [
    (4, 0),
    (11, 1),
    (24, 1),
    (50, 1),
    (102, 1),
    (202, 2),
    (401, 4),
    (794, 5),
    (1577, 8),
    (3138, 13),
    (6308, 25),
];

/// Reference `DEPTH_INT_FG`: up to this depth the reduction multiplies in
/// NTT form; deeper it uses the schoolbook product.
const DEPTH_INT_FG: usize = 4;

const SOLUTION_LEN: usize = 7 * N;
const MAKE_FG_LEN: usize = 6 * N;
const POLY_SUB_SCALED_NTT_LEN: usize = 1536;
const U32_SCRATCH_LEN: usize = 11 * N;
const FPR_SCRATCH_LEN: usize = 8 * N;
const INTER_FD_GD_MAX: usize = 256;
const INTER_FT_GT_MAX: usize = 1280;
const INTER_N_MAX: usize = 256;

/// The solver's buffers. They hold f, g and partial solutions for F and G,
/// so they are wiped on drop.
struct NtruWorkspace {
    /// F || G carried across depths; also scratch during the deepest stage.
    solution: Vec<u32>,
    u32s: Vec<u32>,
    fprs: Vec<f64>,
    make_fg: Vec<u32>,
    inter_fd: Vec<u32>,
    inter_gd: Vec<u32>,
    inter_ft: Vec<u32>,
    inter_gt: Vec<u32>,
    k: Vec<i32>,
}

impl NtruWorkspace {
    /// Allocates every buffer at its largest size.
    fn new() -> Self {
        Self {
            solution: vec![0; SOLUTION_LEN],
            u32s: vec![0; U32_SCRATCH_LEN],
            fprs: vec![0.0; FPR_SCRATCH_LEN],
            make_fg: vec![0; MAKE_FG_LEN],
            inter_fd: vec![0; INTER_FD_GD_MAX],
            inter_gd: vec![0; INTER_FD_GD_MAX],
            inter_ft: vec![0; INTER_FT_GT_MAX],
            inter_gt: vec![0; INTER_FT_GT_MAX],
            k: vec![0; INTER_N_MAX],
        }
    }
}

impl Drop for NtruWorkspace {
    /// Wipes every buffer.
    fn drop(&mut self) {
        zeroize_slice(&mut self.solution);
        zeroize_slice(&mut self.u32s);
        zeroize_slice(&mut self.fprs);
        zeroize_slice(&mut self.make_fg);
        zeroize_slice(&mut self.inter_fd);
        zeroize_slice(&mut self.inter_gd);
        zeroize_slice(&mut self.inter_ft);
        zeroize_slice(&mut self.inter_gt);
        zeroize_slice(&mut self.k);
    }
}

/// Hands out consecutive disjoint regions of one buffer.
struct Carve<'a, T> {
    rest: &'a mut [T],
}

impl<'a, T> Carve<'a, T> {
    /// Starts carving at the beginning of `buf`.
    fn new(buf: &'a mut [T]) -> Self {
        Self { rest: buf }
    }

    /// The next `len` elements; panics if fewer remain.
    fn take(&mut self, len: usize) -> &'a mut [T] {
        let rest = core::mem::take(&mut self.rest);
        let (head, tail) = rest.split_at_mut(len);
        self.rest = tail;
        head
    }
}

/// Solves f*G - g*F = q for small F and G (reference `solve_NTRU`).
/// Returns `None` when the solver rejects (f, g); key generation then draws
/// a new pair.
pub(super) fn solve_ntru(f: &SmallPoly, g: &SmallPoly) -> Option<(SmallPoly, SmallPoly)> {
    let mut wk = NtruWorkspace::new();

    if !solve_ntru_deepest(f, g, &mut wk.solution) {
        return None;
    }
    for depth in (2..LOG_N).rev() {
        if !solve_ntru_intermediate(f, g, depth, &mut wk) {
            return None;
        }
    }
    //coverage:ignore start reason=statistically-unreachable
    if !solve_ntru_binary_depth1(f, g, &mut wk) {
        // Solver rejection that key generation retries; never observed for
        // (f, g) within the key-generation bounds.
        return None;
    }
    //coverage:ignore end
    solve_ntru_binary_depth0(f, g, &mut wk);

    let big_f = poly_big_to_small(&wk.solution[..N], NTRU_COEFF_BOUND)?;
    let big_g = poly_big_to_small(&wk.solution[N..2 * N], NTRU_COEFF_BOUND)?;
    //coverage:ignore start reason=statistically-unreachable
    if !check_ntru_equation(f, g, &big_f, &big_g, &mut wk.u32s) {
        // The reference's final consistency check; it fails only if an
        // earlier stage returned an inconsistent solution.
        return None;
    }
    //coverage:ignore end
    Some((big_f, big_g))
}

/// Reports whether f*G - g*F = q modulo the first small prime. `scratch`
/// must hold `6 * N` words.
pub(super) fn check_ntru_equation(
    f: &SmallPoly,
    g: &SmallPoly,
    big_f: &SmallPoly,
    big_g: &SmallPoly,
    scratch: &mut [u32],
) -> bool {
    let p = SMALL_PRIMES[0].p;
    let p0i = small_prime_derived()[0].p0i;
    let mut c = Carve::new(scratch);
    let gm = c.take(N);
    let igm = c.take(N);
    let ft = c.take(N);
    let gt = c.take(N);
    let ff = c.take(N);
    let gg = c.take(N);
    modp_mkgm2(gm, igm, LOG_N, SMALL_PRIMES[0].g, p, p0i);
    for i in 0..N {
        ft[i] = modp_set(f[i], p);
        gt[i] = modp_set(g[i], p);
        ff[i] = modp_set(big_f[i], p);
        gg[i] = modp_set(big_g[i], p);
    }
    modp_ntt2(ft, gm, LOG_N, p, p0i);
    modp_ntt2(gt, gm, LOG_N, p, p0i);
    modp_ntt2(ff, gm, LOG_N, p, p0i);
    modp_ntt2(gg, gm, LOG_N, p, p0i);

    let target = modp_montymul(Q, 1, p, p0i);
    (0..N).all(|i| {
        modp_sub(modp_montymul(ft[i], gg[i], p, p0i), modp_montymul(gt[i], ff[i], p, p0i), p)
            == target
    })
}

/// Reference `make_fg`: computes f and g at the given depth of the field-norm
/// tower into `data[..2 * degree * slen]`.
fn make_fg(data: &mut [u32], f: &SmallPoly, g: &SmallPoly, depth: usize, out_ntt: bool) {
    // Callers always ask for depth >= 2, so the reference's depth-0 NTT
    // shortcut is not needed.
    debug_assert!(depth >= 2);
    let p0 = SMALL_PRIMES[0].p;
    for i in 0..N {
        data[i] = modp_set(f[i], p0);
        data[N + i] = modp_set(g[i], p0);
    }
    for d in 0..depth {
        make_fg_step(data, LOG_N - d, d, d != 0, (d + 1) < depth || out_ntt);
    }
}

/// Reference `make_fg_step`: one field-norm step, f(x) -> f(x)f(-x).
fn make_fg_step(data: &mut [u32], logn: usize, depth: usize, in_ntt: bool, out_ntt: bool) {
    let degree = 1 << logn;
    let hn = degree >> 1;
    let slen = MAX_BL_SMALL[depth];
    let tlen = MAX_BL_SMALL[depth + 1];
    let derived = small_prime_derived();

    // Move the source limbs out of the output area first; source and
    // destination may overlap, as with the reference's memmove.
    let fs_off = 2 * hn * tlen;
    data.copy_within(0..2 * degree * slen, fs_off);

    let mut c = Carve::new(data);
    let fd = c.take(hn * tlen);
    let gd = c.take(hn * tlen);
    let fs = c.take(degree * slen);
    let gs = c.take(degree * slen);
    let gm = c.take(degree);
    let igm = c.take(degree);
    let t1 = c.take(degree);
    let extra = if degree < slen { Some(c.take(slen)) } else { None };

    for u in 0..slen {
        let prime = SMALL_PRIMES[u];
        let (p, p0i, r2) = (prime.p, derived[u].p0i, derived[u].r2);
        modp_mkgm2(gm, igm, logn, prime.g, p, p0i);

        for v in 0..degree {
            t1[v] = fs[v * slen + u];
        }
        if !in_ntt {
            modp_ntt2(t1, gm, logn, p, p0i);
        }
        for v in 0..hn {
            let w0 = t1[v << 1];
            let w1 = t1[(v << 1) + 1];
            fd[v * tlen + u] = modp_montymul(modp_montymul(w0, w1, p, p0i), r2, p, p0i);
        }
        if in_ntt {
            modp_intt2_ext(&mut fs[u..], slen, igm, logn, p, p0i);
        }

        for v in 0..degree {
            t1[v] = gs[v * slen + u];
        }
        if !in_ntt {
            modp_ntt2(t1, gm, logn, p, p0i);
        }
        for v in 0..hn {
            let w0 = t1[v << 1];
            let w1 = t1[(v << 1) + 1];
            gd[v * tlen + u] = modp_montymul(modp_montymul(w0, w1, p, p0i), r2, p, p0i);
        }
        if in_ntt {
            modp_intt2_ext(&mut gs[u..], slen, igm, logn, p, p0i);
        }

        if !out_ntt {
            modp_intt2_ext(&mut fd[u..], tlen, igm, logn - 1, p, p0i);
            modp_intt2_ext(&mut gd[u..], tlen, igm, logn - 1, p, p0i);
        }
    }

    {
        let crt: &mut [u32] = match extra {
            Some(buf) => buf,
            None => &mut t1[..slen],
        };
        zint_rebuild_crt(fs, slen, slen, degree, true, crt);
        zint_rebuild_crt(gs, slen, slen, degree, true, crt);
    }

    for u in slen..tlen {
        let prime = SMALL_PRIMES[u];
        let (p, p0i, r2) = (prime.p, derived[u].p0i, derived[u].r2);
        let rx = modp_rx(slen, p, p0i, r2);
        modp_mkgm2(gm, igm, logn, prime.g, p, p0i);

        for v in 0..degree {
            t1[v] = zint_mod_small_signed(&fs[v * slen..v * slen + slen], p, p0i, r2, rx);
        }
        modp_ntt2(t1, gm, logn, p, p0i);
        for v in 0..hn {
            let w0 = t1[v << 1];
            let w1 = t1[(v << 1) + 1];
            fd[v * tlen + u] = modp_montymul(modp_montymul(w0, w1, p, p0i), r2, p, p0i);
        }

        for v in 0..degree {
            t1[v] = zint_mod_small_signed(&gs[v * slen..v * slen + slen], p, p0i, r2, rx);
        }
        modp_ntt2(t1, gm, logn, p, p0i);
        for v in 0..hn {
            let w0 = t1[v << 1];
            let w1 = t1[(v << 1) + 1];
            gd[v * tlen + u] = modp_montymul(modp_montymul(w0, w1, p, p0i), r2, p, p0i);
        }

        if !out_ntt {
            modp_intt2_ext(&mut fd[u..], tlen, igm, logn - 1, p, p0i);
            modp_intt2_ext(&mut gd[u..], tlen, igm, logn - 1, p, p0i);
        }
    }
}

/// Reference `solve_NTRU_deepest`: the resultants of f and g with x^n + 1,
/// then a Bezout relation scaled by q. Leaves F || G at depth 10 in
/// `tmp[..2 * MAX_BL_SMALL[10]]`.
fn solve_ntru_deepest(f: &SmallPoly, g: &SmallPoly, tmp: &mut [u32]) -> bool {
    let wl = MAX_BL_SMALL[LOG_N];
    make_fg(&mut tmp[2 * wl..], f, g, LOG_N, false);

    let (fg_out, rest) = tmp.split_at_mut(2 * wl);
    let (resultants, scratch) = rest.split_at_mut(2 * wl);
    zint_rebuild_crt(resultants, wl, wl, 2, false, scratch);

    let (big_f, big_g) = fg_out.split_at_mut(wl);
    let (fp, gp) = resultants.split_at(wl);
    if !zint_bezout(big_g, big_f, fp, gp, scratch) {
        return false;
    }

    //coverage:ignore start reason=defensively-unreachable
    if zint_mul_small(big_f, Q) != 0 || zint_mul_small(big_g, Q) != 0 {
        // The reference's overflow guard on q*F and q*G.
        return false;
    }
    //coverage:ignore end
    true
}

/// Converts big integers (`word_len` limbs at `src[i * stride]`) to floating
/// point, as the reference `poly_big_to_fp` does. Every caller passes at
/// least one limb.
fn poly_big_to_fp(dst: &mut [f64], src: &[u32], word_len: usize, stride: usize, logn: usize) {
    let degree = 1 << logn;
    debug_assert!(word_len > 0);
    for (i, d) in dst.iter_mut().take(degree).enumerate() {
        let x = &src[i * stride..];
        let neg = (x[word_len - 1] >> 30).wrapping_neg();
        let xm = neg >> 1;
        let mut cc = neg & 1;
        let mut y = 0.0_f64;
        let mut scale = 1.0_f64;
        for &xw in &x[..word_len] {
            let mut w = (xw ^ xm).wrapping_add(cc);
            cc = w >> 31;
            w &= MASK31;
            w = w.wrapping_sub((w << 1) & neg);
            y += f64::from(w as i32) * scale;
            scale *= TWO_TO_31;
        }
        *d = y;
    }
}

/// Reference `poly_big_to_small`: the one-word integers of `src` as a small
/// polynomial, or `None` if a coefficient lies outside [-bound, bound].
fn poly_big_to_small(src: &[u32], bound: i32) -> Option<SmallPoly> {
    let mut dst = [0_i32; N];
    for (d, &s) in dst.iter_mut().zip(src) {
        let x = zint_one_to_plain(s);
        if x < -bound || x > bound {
            return None;
        }
        *d = x;
    }
    Some(dst)
}

/// Reference `poly_sub_scaled`: F -= (k * f) << (31 * sch + scl), with the
/// schoolbook product modulo x^n + 1.
#[allow(clippy::too_many_arguments)]
fn poly_sub_scaled(
    big_f: &mut [u32],
    flen_big: usize,
    fstride_big: usize,
    f: &[u32],
    flen: usize,
    fstride: usize,
    k: &[i32],
    sch: u32,
    scl: u32,
    logn: usize,
) {
    let degree = 1 << logn;
    for u in 0..degree {
        let mut kf = k[u].wrapping_neg();
        let mut x = u * fstride_big;
        for v in 0..degree {
            zint_add_scaled_mul_small(
                &mut big_f[x..x + flen_big],
                &f[v * fstride..v * fstride + flen],
                kf,
                sch,
                scl,
            );
            if u + v == degree - 1 {
                x = 0;
                kf = kf.wrapping_neg();
            } else {
                x += fstride_big;
            }
        }
    }
}

/// Reference `poly_sub_scaled_ntt`: as [`poly_sub_scaled`], multiplying in
/// NTT form modulo `flen + 1` small primes.
#[allow(clippy::too_many_arguments)]
fn poly_sub_scaled_ntt(
    big_f: &mut [u32],
    flen_big: usize,
    fstride_big: usize,
    f: &[u32],
    flen: usize,
    fstride: usize,
    k: &[i32],
    sch: u32,
    scl: u32,
    logn: usize,
    tmp: &mut [u32],
) {
    let degree = 1 << logn;
    let tlen = flen + 1;
    let derived = small_prime_derived();
    let mut c = Carve::new(tmp);
    let gm = c.take(degree);
    let igm = c.take(degree);
    let fk = c.take(degree * tlen);
    let t1 = c.take(degree);

    for u in 0..tlen {
        let prime = SMALL_PRIMES[u];
        let (p, p0i, r2) = (prime.p, derived[u].p0i, derived[u].r2);
        let rx = modp_rx(flen, p, p0i, r2);
        modp_mkgm2(gm, igm, logn, prime.g, p, p0i);
        for v in 0..degree {
            t1[v] = modp_set(k[v], p);
        }
        modp_ntt2(t1, gm, logn, p, p0i);

        for v in 0..degree {
            fk[v * tlen + u] =
                zint_mod_small_signed(&f[v * fstride..v * fstride + flen], p, p0i, r2, rx);
        }
        modp_ntt2_ext(&mut fk[u..], tlen, gm, logn, p, p0i);

        for v in 0..degree {
            let x = v * tlen + u;
            fk[x] = modp_montymul(modp_montymul(t1[v], fk[x], p, p0i), r2, p, p0i);
        }
        modp_intt2_ext(&mut fk[u..], tlen, igm, logn, p, p0i);
    }

    zint_rebuild_crt(fk, tlen, tlen, degree, true, t1);
    for u in 0..degree {
        zint_sub_scaled(
            &mut big_f[u * fstride_big..u * fstride_big + flen_big],
            &fk[u * tlen..u * tlen + tlen],
            sch,
            scl,
        );
    }
}

/// Reference `solve_NTRU_intermediate` for depths 2 ..= 9.
fn solve_ntru_intermediate(
    f: &SmallPoly,
    g: &SmallPoly,
    depth: usize,
    wk: &mut NtruWorkspace,
) -> bool {
    let logn = LOG_N - depth;
    let degree = 1 << logn;
    let hn = degree >> 1;

    let slen = MAX_BL_SMALL[depth];
    let dlen = MAX_BL_SMALL[depth + 1];
    let llen = MAX_BL_LARGE[depth];

    // Snapshot the previous depth's solution before the lift overwrites it.
    let fd = &mut wk.inter_fd[..dlen * hn];
    let gd = &mut wk.inter_gd[..dlen * hn];
    fd.copy_from_slice(&wk.solution[..dlen * hn]);
    gd.copy_from_slice(&wk.solution[dlen * hn..2 * dlen * hn]);

    make_fg(&mut wk.make_fg, f, g, depth, true);
    let (ft, rest) = wk.make_fg.split_at_mut(degree * slen);
    let gt = &mut rest[..degree * slen];

    let big_ft = &mut wk.inter_ft[..degree * llen];
    let big_gt = &mut wk.inter_gt[..degree * llen];

    lift_ntru_solution(&mut wk.u32s, big_ft, big_gt, fd, gd, ft, gt, logn, slen, dlen, llen);

    if !reduce_ntru_solution(
        &mut wk.fprs,
        &mut wk.u32s,
        &mut wk.k,
        big_ft,
        big_gt,
        ft,
        gt,
        depth,
        logn,
        slen,
        llen,
    ) {
        return false;
    }

    for i in 0..degree {
        wk.solution[i * slen..(i + 1) * slen].copy_from_slice(&big_ft[i * llen..i * llen + slen]);
        wk.solution[(degree + i) * slen..(degree + i + 1) * slen]
            .copy_from_slice(&big_gt[i * llen..i * llen + slen]);
    }
    true
}

/// Lifts the previous depth's (F, G) to this depth: F' = F(x^2) g(-x),
/// G' = G(x^2) f(-x), in residue form modulo `llen` primes, then rebuilds
/// the big integers. Leaves ft and gt in plain (non-NTT) CRT-rebuilt form.
#[allow(clippy::too_many_arguments)]
fn lift_ntru_solution(
    scratch: &mut [u32],
    big_ft: &mut [u32],
    big_gt: &mut [u32],
    fd: &[u32],
    gd: &[u32],
    ft: &mut [u32],
    gt: &mut [u32],
    logn: usize,
    slen: usize,
    dlen: usize,
    llen: usize,
) {
    let degree = 1 << logn;
    let hn = degree >> 1;
    let derived = small_prime_derived();

    let mut c = Carve::new(scratch);
    let gm = c.take(degree);
    let igm = c.take(degree);
    let fx = c.take(degree);
    let gx = c.take(degree);
    let fp = c.take(hn);
    let gp = c.take(hn);
    let crt = c.take(llen.max(slen));

    for u in 0..llen {
        let p = SMALL_PRIMES[u].p;
        let (p0i, r2) = (derived[u].p0i, derived[u].r2);
        let rx = modp_rx(dlen, p, p0i, r2);
        for v in 0..hn {
            big_ft[v * llen + u] =
                zint_mod_small_signed(&fd[v * dlen..v * dlen + dlen], p, p0i, r2, rx);
            big_gt[v * llen + u] =
                zint_mod_small_signed(&gd[v * dlen..v * dlen + dlen], p, p0i, r2, rx);
        }
    }

    for u in 0..llen {
        let prime = SMALL_PRIMES[u];
        let (p, p0i, r2) = (prime.p, derived[u].p0i, derived[u].r2);

        if u == slen {
            zint_rebuild_crt(ft, slen, slen, degree, true, &mut crt[..slen]);
            zint_rebuild_crt(gt, slen, slen, degree, true, &mut crt[..slen]);
        }

        modp_mkgm2(gm, igm, logn, prime.g, p, p0i);

        if u < slen {
            for v in 0..degree {
                fx[v] = ft[v * slen + u];
                gx[v] = gt[v * slen + u];
            }
            modp_intt2_ext(&mut ft[u..], slen, igm, logn, p, p0i);
            modp_intt2_ext(&mut gt[u..], slen, igm, logn, p, p0i);
        } else {
            let rx = modp_rx(slen, p, p0i, r2);
            for v in 0..degree {
                fx[v] = zint_mod_small_signed(&ft[v * slen..v * slen + slen], p, p0i, r2, rx);
                gx[v] = zint_mod_small_signed(&gt[v * slen..v * slen + slen], p, p0i, r2, rx);
            }
            modp_ntt2(fx, gm, logn, p, p0i);
            modp_ntt2(gx, gm, logn, p, p0i);
        }

        for v in 0..hn {
            fp[v] = big_ft[v * llen + u];
            gp[v] = big_gt[v * llen + u];
        }
        modp_ntt2(fp, gm, logn - 1, p, p0i);
        modp_ntt2(gp, gm, logn - 1, p, p0i);
        for v in 0..hn {
            let ft_a = fx[v << 1];
            let ft_b = fx[(v << 1) + 1];
            let gt_a = gx[v << 1];
            let gt_b = gx[(v << 1) + 1];
            let m_fp = modp_montymul(fp[v], r2, p, p0i);
            let m_gp = modp_montymul(gp[v], r2, p, p0i);
            big_ft[(v << 1) * llen + u] = modp_montymul(gt_b, m_fp, p, p0i);
            big_ft[((v << 1) + 1) * llen + u] = modp_montymul(gt_a, m_fp, p, p0i);
            big_gt[(v << 1) * llen + u] = modp_montymul(ft_b, m_gp, p, p0i);
            big_gt[((v << 1) + 1) * llen + u] = modp_montymul(ft_a, m_gp, p, p0i);
        }
        modp_intt2_ext(&mut big_ft[u..], llen, igm, logn, p, p0i);
        modp_intt2_ext(&mut big_gt[u..], llen, igm, logn, p, p0i);
    }

    zint_rebuild_crt(big_ft, llen, llen, degree, true, &mut crt[..llen]);
    zint_rebuild_crt(big_gt, llen, llen, degree, true, &mut crt[..llen]);
}

/// 2^e as an f64, what Go's `math.Ldexp(1, e)` returns. Doubling and
/// halving a power of two is exact down to the subnormals, and rounds to 0
/// or infinity exactly where ldexp does.
pub(super) fn ldexp_one(mut e: i64) -> f64 {
    let mut x = 1.0_f64;
    while e > 0 {
        x *= 2.0;
        e -= 1;
    }
    while e < 0 {
        x *= 0.5;
        e += 1;
    }
    x
}

/// Babai reduction of the lifted (F, G) against (f, g), 25 bits at a time,
/// as the reference `solve_NTRU_intermediate` does.
#[allow(clippy::too_many_arguments)]
fn reduce_ntru_solution(
    fprs: &mut [f64],
    u32s: &mut [u32],
    k_buf: &mut [i32],
    big_ft: &mut [u32],
    big_gt: &mut [u32],
    ft: &[u32],
    gt: &[u32],
    depth: usize,
    logn: usize,
    slen: usize,
    llen: usize,
) -> bool {
    let degree = 1 << logn;
    let mut c = Carve::new(fprs);
    let rt1 = c.take(degree);
    let rt2 = c.take(degree);
    let rt3 = c.take(degree);
    let rt4 = c.take(degree);
    let rt5 = c.take(degree >> 1);
    let scaled_ntt = &mut u32s[..POLY_SUB_SCALED_NTT_LEN];
    let k = &mut k_buf[..degree];

    let mut rlen = slen.min(10);
    poly_big_to_fp(rt3, &ft[slen - rlen..], rlen, slen, logn);
    poly_big_to_fp(rt4, &gt[slen - rlen..], rlen, slen, logn);
    let scale_fg_base = 31 * (slen - rlen) as i64;

    let (avg, std) = BIT_LENGTH[depth];
    let min_bits_fg = avg - 6 * std;
    let max_bits_fg = avg + 6 * std;

    fft(rt3, logn);
    fft(rt4, logn);
    fft_inv_norm2(rt5, rt3, rt4, logn);
    fft_adj(rt3, logn);
    fft_adj(rt4, logn);

    let mut fg_len = llen;
    let mut max_bits_fg_solution = 31 * llen as i64;
    let mut scale_k = max_bits_fg_solution - min_bits_fg;

    loop {
        rlen = fg_len.min(10);
        let scale_fg_solution = 31 * (fg_len - rlen) as i64;
        poly_big_to_fp(rt1, &big_ft[fg_len - rlen..], rlen, llen, logn);
        poly_big_to_fp(rt2, &big_gt[fg_len - rlen..], rlen, llen, logn);

        fft(rt1, logn);
        fft(rt2, logn);
        fft_mul(rt1, rt3, logn);
        fft_mul(rt2, rt4, logn);
        fft_add(rt2, rt1, logn);
        fft_mul_auto_adj(rt2, rt5, logn);
        inverse_fft(rt2, logn);

        let scale_correction = scale_k - scale_fg_solution + scale_fg_base;
        let pdc = ldexp_one(-scale_correction);
        for i in 0..degree {
            let x = rt2[i] * pdc;
            // Written as !(<) on both sides so that NaN is rejected too.
            #[allow(clippy::neg_cmp_op_on_partial_ord)]
            if !(-TWO_TO_31_MINUS_1 < x) || !(x < TWO_TO_31_MINUS_1) {
                return false;
            }
            k[i] = fpr_rint(x) as i32;
        }

        let sch = (scale_k / 31) as u32;
        let scl = (scale_k % 31) as u32;
        if depth <= DEPTH_INT_FG {
            poly_sub_scaled_ntt(
                big_ft, fg_len, llen, ft, slen, slen, k, sch, scl, logn, scaled_ntt,
            );
            poly_sub_scaled_ntt(
                big_gt, fg_len, llen, gt, slen, slen, k, sch, scl, logn, scaled_ntt,
            );
        } else {
            poly_sub_scaled(big_ft, fg_len, llen, ft, slen, slen, k, sch, scl, logn);
            poly_sub_scaled(big_gt, fg_len, llen, gt, slen, slen, k, sch, scl, logn);
        }

        let new_max = scale_k + max_bits_fg + 10;
        if new_max < max_bits_fg_solution {
            max_bits_fg_solution = new_max;
            if (fg_len as i64) * 31 >= max_bits_fg_solution + 31 {
                fg_len -= 1;
            }
        }

        if scale_k <= 0 {
            break;
        }
        scale_k = (scale_k - 25).max(0);
    }

    if fg_len < slen {
        for i in 0..degree {
            let fw = (big_ft[i * llen + fg_len - 1] >> 30).wrapping_neg() >> 1;
            let gw = (big_gt[i * llen + fg_len - 1] >> 30).wrapping_neg() >> 1;
            for j in fg_len..slen {
                big_ft[i * llen + j] = fw;
                big_gt[i * llen + j] = gw;
            }
        }
    }
    true
}

/// Reference `solve_NTRU_binary_depth0`: the last lift, to the full degree,
/// done modulo a single prime with a floating-point Babai step.
fn solve_ntru_binary_depth0(f: &SmallPoly, g: &SmallPoly, wk: &mut NtruWorkspace) {
    let hn = N >> 1;
    let p = SMALL_PRIMES[0].p;
    let p0i = small_prime_derived()[0].p0i;
    let r2 = small_prime_derived()[0].r2;

    let mut c = Carve::new(&mut wk.u32s[..]);
    let prev_f = c.take(hn);
    let prev_g = c.take(hn);
    prev_f.copy_from_slice(&wk.solution[..hn]);
    prev_g.copy_from_slice(&wk.solution[hn..N]);
    let fp = c.take(N);
    let gp = c.take(N);
    let ft = c.take(N);
    let gt = c.take(N);
    let gm = c.take(N);
    let igm = c.take(N);
    let t2 = c.take(N);
    let t3 = c.take(N);
    let t4 = c.take(N);
    let t5 = c.take(N);
    let mut cf = Carve::new(&mut wk.fprs[..]);
    let num = cf.take(N);
    let den = cf.take(hn);
    let work = cf.take(N);

    modp_mkgm2(gm, igm, LOG_N, SMALL_PRIMES[0].g, p, p0i);

    for i in 0..hn {
        prev_f[i] = modp_set(zint_one_to_plain(prev_f[i]), p);
        prev_g[i] = modp_set(zint_one_to_plain(prev_g[i]), p);
    }
    modp_ntt2(prev_f, gm, LOG_N - 1, p, p0i);
    modp_ntt2(prev_g, gm, LOG_N - 1, p, p0i);

    for i in 0..N {
        ft[i] = modp_set(f[i], p);
        gt[i] = modp_set(g[i], p);
    }
    modp_ntt2(ft, gm, LOG_N, p, p0i);
    modp_ntt2(gt, gm, LOG_N, p, p0i);

    for i in (0..N).step_by(2) {
        let ft_a = ft[i];
        let ft_b = ft[i + 1];
        let gt_a = gt[i];
        let gt_b = gt[i + 1];
        let m_fp = modp_montymul(prev_f[i >> 1], r2, p, p0i);
        let m_gp = modp_montymul(prev_g[i >> 1], r2, p, p0i);
        fp[i] = modp_montymul(gt_b, m_fp, p, p0i);
        fp[i + 1] = modp_montymul(gt_a, m_fp, p, p0i);
        gp[i] = modp_montymul(ft_b, m_gp, p, p0i);
        gp[i + 1] = modp_montymul(ft_a, m_gp, p, p0i);
    }
    modp_intt2(fp, igm, LOG_N, p, p0i);
    modp_intt2(gp, igm, LOG_N, p, p0i);

    modp_ntt2(fp, gm, LOG_N, p, p0i);
    modp_ntt2(gp, gm, LOG_N, p, p0i);

    t4[0] = modp_set(f[0], p);
    t5[0] = t4[0];
    for i in 1..N {
        t4[i] = modp_set(f[i], p);
        t5[N - i] = modp_set(f[i].wrapping_neg(), p);
    }
    modp_ntt2(t4, gm, LOG_N, p, p0i);
    modp_ntt2(t5, gm, LOG_N, p, p0i);

    for i in 0..N {
        let w = modp_montymul(t5[i], r2, p, p0i);
        t2[i] = modp_montymul(w, fp[i], p, p0i);
        t3[i] = modp_montymul(w, t4[i], p, p0i);
    }

    t4[0] = modp_set(g[0], p);
    t5[0] = t4[0];
    for i in 1..N {
        t4[i] = modp_set(g[i], p);
        t5[N - i] = modp_set(g[i].wrapping_neg(), p);
    }
    modp_ntt2(t4, gm, LOG_N, p, p0i);
    modp_ntt2(t5, gm, LOG_N, p, p0i);

    for i in 0..N {
        let w = modp_montymul(t5[i], r2, p, p0i);
        t2[i] = modp_add(t2[i], modp_montymul(w, gp[i], p, p0i), p);
        t3[i] = modp_add(t3[i], modp_montymul(w, t4[i], p, p0i), p);
    }

    modp_intt2(t2, igm, LOG_N, p, p0i);
    modp_intt2(t3, igm, LOG_N, p, p0i);

    for i in 0..N {
        work[i] = f64::from(modp_norm(t3[i], p));
    }
    fft(work, LOG_N);
    den.copy_from_slice(&work[..hn]);
    for i in 0..N {
        num[i] = f64::from(modp_norm(t2[i], p));
    }
    fft(num, LOG_N);
    fft_div_auto_adj(num, den, LOG_N);
    inverse_fft(num, LOG_N);
    for i in 0..N {
        t2[i] = modp_set(fpr_rint(num[i]) as i32, p);
    }

    for i in 0..N {
        t4[i] = modp_set(f[i], p);
        t5[i] = modp_set(g[i], p);
    }
    modp_ntt2(t2, gm, LOG_N, p, p0i);
    modp_ntt2(t4, gm, LOG_N, p, p0i);
    modp_ntt2(t5, gm, LOG_N, p, p0i);
    for i in 0..N {
        let kw = modp_montymul(t2[i], r2, p, p0i);
        fp[i] = modp_sub(fp[i], modp_montymul(kw, t4[i], p, p0i), p);
        gp[i] = modp_sub(gp[i], modp_montymul(kw, t5[i], p, p0i), p);
    }
    modp_intt2(fp, igm, LOG_N, p, p0i);
    modp_intt2(gp, igm, LOG_N, p, p0i);
    for i in 0..N {
        wk.solution[i] = modp_norm(fp[i], p) as u32;
        wk.solution[N + i] = modp_norm(gp[i], p) as u32;
    }
}

/// Reference `solve_NTRU_binary_depth1`: the lift to depth 1, with the
/// reduction done in floating point in one step.
fn solve_ntru_binary_depth1(f: &SmallPoly, g: &SmallPoly, wk: &mut NtruWorkspace) -> bool {
    let depth = 1;
    let logn = LOG_N - depth;
    let degree = 1 << logn;
    let hn = degree >> 1;
    let slen = MAX_BL_SMALL[depth];
    let dlen = MAX_BL_SMALL[depth + 1];
    let llen = MAX_BL_LARGE[depth];
    let derived = small_prime_derived();

    let mut c = Carve::new(&mut wk.u32s[..]);
    let fd = c.take(dlen * hn);
    let gd = c.take(dlen * hn);
    fd.copy_from_slice(&wk.solution[..dlen * hn]);
    gd.copy_from_slice(&wk.solution[dlen * hn..2 * dlen * hn]);
    let big_ft = c.take(degree * llen);
    let big_gt = c.take(degree * llen);
    let ft = c.take(degree * slen);
    let gt = c.take(degree * slen);
    let gm_full = c.take(N);
    let igm_full = c.take(N);
    let fx = c.take(N);
    let gx = c.take(N);
    let fp = c.take(hn);
    let gp = c.take(hn);
    let crt = c.take(llen.max(slen));
    let mut cf = Carve::new(&mut wk.fprs[..]);
    let rt1 = cf.take(degree);
    let rt2 = cf.take(degree);
    let rt3 = cf.take(degree);
    let rt4 = cf.take(degree);
    let rt5 = cf.take(degree);
    let rt6 = cf.take(degree >> 1);
    let kf = cf.take(degree);
    let kg = cf.take(degree);

    for u in 0..llen {
        let p = SMALL_PRIMES[u].p;
        let (p0i, r2) = (derived[u].p0i, derived[u].r2);
        let rx = modp_rx(dlen, p, p0i, r2);
        for v in 0..hn {
            big_ft[v * llen + u] =
                zint_mod_small_signed(&fd[v * dlen..v * dlen + dlen], p, p0i, r2, rx);
            big_gt[v * llen + u] =
                zint_mod_small_signed(&gd[v * dlen..v * dlen + dlen], p, p0i, r2, rx);
        }
    }

    for u in 0..llen {
        let prime = SMALL_PRIMES[u];
        let (p, p0i, r2) = (prime.p, derived[u].p0i, derived[u].r2);

        modp_mkgm2(gm_full, igm_full, LOG_N, prime.g, p, p0i);

        for v in 0..N {
            fx[v] = modp_set(f[v], p);
            gx[v] = modp_set(g[v], p);
        }
        modp_ntt2(fx, gm_full, LOG_N, p, p0i);
        modp_ntt2(gx, gm_full, LOG_N, p, p0i);
        for e in (logn + 1..=LOG_N).rev() {
            modp_poly_rec_res(fx, e, p, p0i, r2);
            modp_poly_rec_res(gx, e, p, p0i, r2);
        }

        let gm = &gm_full[..degree];
        let igm = &igm_full[..degree];

        for v in 0..hn {
            fp[v] = big_ft[v * llen + u];
            gp[v] = big_gt[v * llen + u];
        }
        modp_ntt2(fp, gm, logn - 1, p, p0i);
        modp_ntt2(gp, gm, logn - 1, p, p0i);

        for v in 0..hn {
            let ft_a = fx[v << 1];
            let ft_b = fx[(v << 1) + 1];
            let gt_a = gx[v << 1];
            let gt_b = gx[(v << 1) + 1];
            let m_fp = modp_montymul(fp[v], r2, p, p0i);
            let m_gp = modp_montymul(gp[v], r2, p, p0i);
            big_ft[(v << 1) * llen + u] = modp_montymul(gt_b, m_fp, p, p0i);
            big_ft[((v << 1) + 1) * llen + u] = modp_montymul(gt_a, m_fp, p, p0i);
            big_gt[(v << 1) * llen + u] = modp_montymul(ft_b, m_gp, p, p0i);
            big_gt[((v << 1) + 1) * llen + u] = modp_montymul(ft_a, m_gp, p, p0i);
        }
        modp_intt2_ext(&mut big_ft[u..], llen, igm, logn, p, p0i);
        modp_intt2_ext(&mut big_gt[u..], llen, igm, logn, p, p0i);

        if u < slen {
            modp_intt2(&mut fx[..degree], igm, logn, p, p0i);
            modp_intt2(&mut gx[..degree], igm, logn, p, p0i);
            for v in 0..degree {
                ft[v * slen + u] = fx[v];
                gt[v * slen + u] = gx[v];
            }
        }
    }

    zint_rebuild_crt(big_ft, llen, llen, degree, true, &mut crt[..llen]);
    zint_rebuild_crt(big_gt, llen, llen, degree, true, &mut crt[..llen]);
    zint_rebuild_crt(ft, slen, slen, degree, true, &mut crt[..slen]);
    zint_rebuild_crt(gt, slen, slen, degree, true, &mut crt[..slen]);

    poly_big_to_fp(rt1, big_ft, llen, llen, logn);
    poly_big_to_fp(rt2, big_gt, llen, llen, logn);
    poly_big_to_fp(rt3, ft, slen, slen, logn);
    poly_big_to_fp(rt4, gt, slen, slen, logn);

    fft(rt1, logn);
    fft(rt2, logn);
    fft(rt3, logn);
    fft(rt4, logn);

    fft_add_mul_adj(rt5, rt1, rt2, rt3, rt4, logn);
    fft_inv_norm2(rt6, rt3, rt4, logn);
    fft_mul_auto_adj(rt5, rt6, logn);

    inverse_fft(rt5, logn);
    for z in rt5.iter_mut() {
        //coverage:ignore start reason=defensively-unreachable
        // Written as !(<) on both sides so that NaN is rejected too.
        #[allow(clippy::neg_cmp_op_on_partial_ord)]
        if !(*z < TWO_TO_63_MINUS_1) || !(-TWO_TO_63_MINUS_1 < *z) {
            return false;
        }
        //coverage:ignore end
        *z = fpr_rint(*z) as f64;
    }
    fft(rt5, logn);

    kf.copy_from_slice(rt3);
    kg.copy_from_slice(rt4);
    fft_mul(kf, rt5, logn);
    fft_mul(kg, rt5, logn);
    fft_sub(rt1, kf, logn);
    fft_sub(rt2, kg, logn);
    inverse_fft(rt1, logn);
    inverse_fft(rt2, logn);

    for i in 0..degree {
        wk.solution[i] = fpr_rint(rt1[i]) as u32;
        wk.solution[degree + i] = fpr_rint(rt2[i]) as u32;
    }
    true
}
