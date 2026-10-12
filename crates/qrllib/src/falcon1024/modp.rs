//! Arithmetic modulo the 31-bit small primes of the NTRU solver, and
//! big integers as little-endian arrays of 31-bit limbs ("zint"),
//! transliterated from the Falcon reference `keygen.c` and go-qrllib
//! `crypto/internal/falcon1024/{modp,zint}.go`.
//!
//! Every operation wraps, as in C and Go; the masks rely on it. Callers own
//! buffer sizes and keep limbs below 2^31.

// Index loops are kept where they mirror the reference C line for line.
#![allow(clippy::needless_range_loop)]

use super::tables::{REV10, SMALL_PRIMES};
use std::sync::OnceLock;

pub(super) const MASK31: u32 = 0x7FFF_FFFF;

pub(super) fn modp_set(x: i32, p: u32) -> u32 {
    let w = x as u32;
    w.wrapping_add(p & (w >> 31).wrapping_neg())
}

pub(super) fn modp_norm(x: u32, p: u32) -> i32 {
    let w = x.wrapping_sub(p & (((p >> 1).wrapping_sub(x)) >> 31).wrapping_neg());
    w as i32
}

pub(super) fn modp_ninv31(p: u32) -> u32 {
    let mut y = 2_u32.wrapping_sub(p);
    for _ in 0..4 {
        y = y.wrapping_mul(2_u32.wrapping_sub(p.wrapping_mul(y)));
    }
    MASK31 & y.wrapping_neg()
}

fn modp_r(p: u32) -> u32 {
    (1_u32 << 31).wrapping_sub(p)
}

pub(super) fn modp_add(a: u32, b: u32, p: u32) -> u32 {
    let mut d = a.wrapping_add(b).wrapping_sub(p);
    d = d.wrapping_add(p & (d >> 31).wrapping_neg());
    d
}

pub(super) fn modp_sub(a: u32, b: u32, p: u32) -> u32 {
    let mut d = a.wrapping_sub(b);
    d = d.wrapping_add(p & (d >> 31).wrapping_neg());
    d
}

pub(super) fn modp_montymul(a: u32, b: u32, p: u32, p0i: u32) -> u32 {
    let mut z = u64::from(a) * u64::from(b);
    let w = (z as u32).wrapping_mul(p0i) & MASK31;
    z = (z + u64::from(w) * u64::from(p)) >> 31;
    let mut d = (z as u32).wrapping_sub(p);
    d = d.wrapping_add(p & (d >> 31).wrapping_neg());
    d
}

pub(super) fn modp_r2(p: u32, p0i: u32) -> u32 {
    let mut z = modp_r(p);
    z = modp_add(z, z, p);
    for _ in 0..5 {
        z = modp_montymul(z, z, p, p0i);
    }
    (z.wrapping_add(p & (z & 1).wrapping_neg())) >> 1
}

/// R^x mod p (Montgomery representation of 2^(31 * x)); x > 0.
pub(super) fn modp_rx(x: usize, p: u32, p0i: u32, r2: u32) -> u32 {
    let x = x - 1;
    let mut r = r2;
    let mut z = modp_r(p);
    let mut i = 0;
    while (1_usize << i) <= x {
        if x & (1 << i) != 0 {
            z = modp_montymul(z, r, p, p0i);
        }
        r = modp_montymul(r, r, p, p0i);
        i += 1;
    }
    z
}

fn modp_div(a: u32, b: u32, p: u32, p0i: u32, r: u32) -> u32 {
    let e = p - 2;
    let mut z = r;
    for i in (0..=30).rev() {
        z = modp_montymul(z, z, p, p0i);
        let z2 = modp_montymul(z, b, p, p0i);
        z ^= (z ^ z2) & ((e >> i) & 1).wrapping_neg();
    }
    z = modp_montymul(z, 1, p, p0i);
    modp_montymul(a, z, p, p0i)
}

/// Builds the NTT roots modulo p for degree 2^logn (reference `modp_mkgm2`).
pub(super) fn modp_mkgm2(gm: &mut [u32], igm: &mut [u32], logn: usize, g: u32, p: u32, p0i: u32) {
    let degree = 1 << logn;
    let r2 = modp_r2(p, p0i);
    let mut g = modp_montymul(g, r2, p, p0i);
    for _ in logn..10 {
        g = modp_montymul(g, g, p, p0i);
    }

    let r = modp_r(p);
    let ig = modp_div(r2, g, p, p0i, r);
    let mut x1 = r;
    let mut x2 = r;
    let k = 10 - logn;
    for &rev in REV10.iter().take(degree) {
        let j = usize::from(rev) >> k;
        gm[j] = x1;
        igm[j] = x2;
        x1 = modp_montymul(x1, g, p, p0i);
        x2 = modp_montymul(x2, ig, p, p0i);
    }
}

/// Forward NTT over elements `a[0], a[stride], ...` (reference
/// `modp_NTT2_ext`).
pub(super) fn modp_ntt2_ext(
    a: &mut [u32],
    stride: usize,
    gm: &[u32],
    logn: usize,
    p: u32,
    p0i: u32,
) {
    if logn == 0 {
        return;
    }
    let degree = 1 << logn;
    let mut t = degree;
    let mut m = 1;
    while m < degree {
        let ht = t >> 1;
        let mut v1 = 0;
        for i in 0..m {
            let s = gm[m + i];
            let mut r1 = v1 * stride;
            let mut r2 = r1 + ht * stride;
            for _ in 0..ht {
                let x = a[r1];
                let y = modp_montymul(a[r2], s, p, p0i);
                a[r1] = modp_add(x, y, p);
                a[r2] = modp_sub(x, y, p);
                r1 += stride;
                r2 += stride;
            }
            v1 += t;
        }
        t = ht;
        m <<= 1;
    }
}

/// Inverse NTT over elements `a[0], a[stride], ...` (reference
/// `modp_iNTT2_ext`).
pub(super) fn modp_intt2_ext(
    a: &mut [u32],
    stride: usize,
    igm: &[u32],
    logn: usize,
    p: u32,
    p0i: u32,
) {
    if logn == 0 {
        return;
    }
    let degree = 1 << logn;
    let mut t = 1;
    let mut m = degree;
    while m > 1 {
        let hm = m >> 1;
        let dt = t << 1;
        let mut v1 = 0;
        for i in 0..hm {
            let s = igm[hm + i];
            let mut r1 = v1 * stride;
            let mut r2 = r1 + t * stride;
            for _ in 0..t {
                let x = a[r1];
                let y = a[r2];
                a[r1] = modp_add(x, y, p);
                a[r2] = modp_montymul(modp_sub(x, y, p), s, p, p0i);
                r1 += stride;
                r2 += stride;
            }
            v1 += dt;
        }
        t = dt;
        m >>= 1;
    }

    let ni = 1_u32 << (31 - logn);
    let mut r = 0;
    for _ in 0..degree {
        a[r] = modp_montymul(a[r], ni, p, p0i);
        r += stride;
    }
}

pub(super) fn modp_ntt2(a: &mut [u32], gm: &[u32], logn: usize, p: u32, p0i: u32) {
    modp_ntt2_ext(a, 1, gm, logn, p, p0i);
}

pub(super) fn modp_intt2(a: &mut [u32], igm: &[u32], logn: usize, p: u32, p0i: u32) {
    modp_intt2_ext(a, 1, igm, logn, p, p0i);
}

/// Reference `modp_poly_rec_res`: the resultant step f(x) -> f(x)f(-x) in
/// NTT representation.
pub(super) fn modp_poly_rec_res(f: &mut [u32], logn: usize, p: u32, p0i: u32, r2: u32) {
    let hn = 1 << (logn - 1);
    for i in 0..hn {
        f[i] = modp_montymul(modp_montymul(f[i << 1], f[(i << 1) + 1], p, p0i), r2, p, p0i);
    }
}

/// Montgomery constants (p0i, R^2) derived from each small prime.
#[derive(Clone, Copy)]
pub(super) struct SmallPrimeDerived {
    pub(super) p0i: u32,
    pub(super) r2: u32,
}

pub(super) fn small_prime_derived() -> &'static [SmallPrimeDerived] {
    static VALUES: OnceLock<Vec<SmallPrimeDerived>> = OnceLock::new();
    VALUES.get_or_init(|| {
        SMALL_PRIMES
            .iter()
            .map(|prime| {
                let p0i = modp_ninv31(prime.p);
                SmallPrimeDerived { p0i, r2: modp_r2(prime.p, p0i) }
            })
            .collect()
    })
}

// ---------------------------------------------------------------------------
// zint: big integers as little-endian arrays of 31-bit limbs.
// ---------------------------------------------------------------------------

/// a -= b when ctl is 1 (unchanged when 0); returns the final borrow.
pub(super) fn zint_sub(a: &mut [u32], b: &[u32], ctl: u32) -> u32 {
    let mut cc = 0_u32;
    let m = ctl.wrapping_neg();
    for (aw, &bw) in a.iter_mut().zip(b) {
        let w = aw.wrapping_sub(bw).wrapping_sub(cc);
        cc = w >> 31;
        *aw ^= ((w & MASK31) ^ *aw) & m;
    }
    cc
}

/// m *= x; returns the carry.
pub(super) fn zint_mul_small(m: &mut [u32], x: u32) -> u32 {
    let mut cc = 0_u32;
    for w in m.iter_mut() {
        let z = u64::from(*w) * u64::from(x) + u64::from(cc);
        *w = (z as u32) & MASK31;
        cc = (z >> 31) as u32;
    }
    cc
}

pub(super) fn zint_mod_small_unsigned(d: &[u32], p: u32, p0i: u32, r2: u32) -> u32 {
    let mut x = 0_u32;
    for &dw in d.iter().rev() {
        x = modp_montymul(x, r2, p, p0i);
        let mut w = dw.wrapping_sub(p);
        w = w.wrapping_add(p & (w >> 31).wrapping_neg());
        x = modp_add(x, w, p);
    }
    x
}

/// `d` must be non-empty; every caller passes at least one limb.
pub(super) fn zint_mod_small_signed(d: &[u32], p: u32, p0i: u32, r2: u32, rx: u32) -> u32 {
    let top = d[d.len() - 1];
    let z = zint_mod_small_unsigned(d, p, p0i, r2);
    modp_sub(z, rx & (top >> 30).wrapping_neg(), p)
}

/// x += y * s, with x one limb longer than y (the carry lands there).
pub(super) fn zint_add_mul_small(x: &mut [u32], y: &[u32], s: u32) {
    let mut cc = 0_u32;
    for (i, &yw) in y.iter().enumerate() {
        let z = u64::from(yw) * u64::from(s) + u64::from(x[i]) + u64::from(cc);
        x[i] = (z as u32) & MASK31;
        cc = (z >> 31) as u32;
    }
    x[y.len()] = cc;
}

/// Normalizes x modulo p to the signed range (-p/2, p/2].
pub(super) fn zint_norm_zero(x: &mut [u32], p: &[u32]) {
    let mut r = 0_u32;
    let mut bb = 0_u32;
    for i in (0..x.len()).rev() {
        let wx = x[i];
        let wp = (p[i] >> 1) | (bb << 30);
        bb = p[i] & 1;
        let mut cc = wp.wrapping_sub(wx);
        cc = (cc.wrapping_neg() >> 31) | (cc >> 31).wrapping_neg();
        r |= cc & ((r & 1).wrapping_sub(1));
    }
    zint_sub(x, p, r >> 31);
}

/// Rebuilds integers from their residues modulo the first `xlen` small
/// primes (reference `zint_rebuild_CRT`). `count` integers start at
/// `xx[v * xstride]`; `tmp` must hold `xlen` words.
pub(super) fn zint_rebuild_crt(
    xx: &mut [u32],
    xlen: usize,
    xstride: usize,
    count: usize,
    normalize_signed: bool,
    tmp: &mut [u32],
) {
    let derived = small_prime_derived();
    tmp[0] = SMALL_PRIMES[0].p;

    for u in 1..xlen {
        let p = SMALL_PRIMES[u].p;
        let s = SMALL_PRIMES[u].s;
        let p0i = derived[u].p0i;
        let r2 = derived[u].r2;

        for v in 0..count {
            let x = &mut xx[v * xstride..v * xstride + xlen];
            let xp = x[u];
            let xq = zint_mod_small_unsigned(&x[..u], p, p0i, r2);
            let xr = modp_montymul(s, modp_sub(xp, xq, p), p, p0i);
            zint_add_mul_small(&mut x[..=u], &tmp[..u], xr);
        }

        let (head, rest) = tmp.split_at_mut(u);
        rest[0] = zint_mul_small(head, p);
    }

    if normalize_signed {
        for u in 0..count {
            let x = &mut xx[u * xstride..u * xstride + xlen];
            zint_norm_zero(x, &tmp[..xlen]);
        }
    }
}

/// a = -a when ctl is 1 (unchanged when 0).
fn zint_negate(a: &mut [u32], ctl: u32) {
    let mut cc = ctl;
    let m = ctl.wrapping_neg() >> 1;
    for w in a.iter_mut() {
        let aw = (*w ^ m).wrapping_add(cc);
        *w = aw & MASK31;
        cc = aw >> 31;
    }
}

fn zint_co_reduce(a: &mut [u32], b: &mut [u32], xa: i64, xb: i64, ya: i64, yb: i64) -> u32 {
    let mut cca = 0_i64;
    let mut ccb = 0_i64;
    let len = a.len();
    for i in 0..len {
        let wa = a[i];
        let wb = b[i];
        let za = u64::from(wa)
            .wrapping_mul(xa as u64)
            .wrapping_add(u64::from(wb).wrapping_mul(xb as u64))
            .wrapping_add(cca as u64);
        let zb = u64::from(wa)
            .wrapping_mul(ya as u64)
            .wrapping_add(u64::from(wb).wrapping_mul(yb as u64))
            .wrapping_add(ccb as u64);
        if i > 0 {
            a[i - 1] = (za as u32) & MASK31;
            b[i - 1] = (zb as u32) & MASK31;
        }
        cca = (za as i64) >> 31;
        ccb = (zb as i64) >> 31;
    }
    a[len - 1] = cca as u32;
    b[len - 1] = ccb as u32;

    let nega = ((cca as u64) >> 63) as u32;
    let negb = ((ccb as u64) >> 63) as u32;
    zint_negate(a, nega);
    zint_negate(b, negb);
    nega | (negb << 1)
}

fn zint_finish_mod(a: &mut [u32], m: &[u32], neg: u32) {
    let mut cc = 0_u32;
    for (&aw, &mw) in a.iter().zip(m) {
        cc = aw.wrapping_sub(mw).wrapping_sub(cc) >> 31;
    }

    let xm = neg.wrapping_neg() >> 1;
    let ym = (neg | (1 - cc)).wrapping_neg();
    cc = neg;
    for (w, &mw) in a.iter_mut().zip(m) {
        let mw = (mw ^ xm) & ym;
        let aw = w.wrapping_sub(mw).wrapping_sub(cc);
        *w = aw & MASK31;
        cc = aw >> 31;
    }
}

#[allow(clippy::too_many_arguments)]
fn zint_co_reduce_mod(
    a: &mut [u32],
    b: &mut [u32],
    m: &[u32],
    m0i: u32,
    xa: i64,
    xb: i64,
    ya: i64,
    yb: i64,
) {
    let mut cca = 0_i64;
    let mut ccb = 0_i64;
    let fa = (a[0].wrapping_mul(xa as u32).wrapping_add(b[0].wrapping_mul(xb as u32)))
        .wrapping_mul(m0i)
        & MASK31;
    let fb = (a[0].wrapping_mul(ya as u32).wrapping_add(b[0].wrapping_mul(yb as u32)))
        .wrapping_mul(m0i)
        & MASK31;
    let len = a.len();
    for i in 0..len {
        let wa = a[i];
        let wb = b[i];
        let za = u64::from(wa)
            .wrapping_mul(xa as u64)
            .wrapping_add(u64::from(wb).wrapping_mul(xb as u64))
            .wrapping_add(u64::from(m[i]).wrapping_mul(u64::from(fa)))
            .wrapping_add(cca as u64);
        let zb = u64::from(wa)
            .wrapping_mul(ya as u64)
            .wrapping_add(u64::from(wb).wrapping_mul(yb as u64))
            .wrapping_add(u64::from(m[i]).wrapping_mul(u64::from(fb)))
            .wrapping_add(ccb as u64);
        if i > 0 {
            a[i - 1] = (za as u32) & MASK31;
            b[i - 1] = (zb as u32) & MASK31;
        }
        cca = (za as i64) >> 31;
        ccb = (zb as i64) >> 31;
    }
    a[len - 1] = cca as u32;
    b[len - 1] = ccb as u32;

    zint_finish_mod(a, m, ((cca as u64) >> 63) as u32);
    zint_finish_mod(b, m, ((ccb as u64) >> 63) as u32);
}

/// Binary extended GCD (reference `zint_bezout`): finds u and v with
/// x*u - y*v = 1 for odd x and y. `tmp` must hold `4 * x.len()` words.
/// Returns false when x and y are not coprime or not both odd.
pub(super) fn zint_bezout(
    u: &mut [u32],
    v: &mut [u32],
    x: &[u32],
    y: &[u32],
    tmp: &mut [u32],
) -> bool {
    let length = x.len();
    debug_assert!(length > 0);

    let (u1, rest) = tmp.split_at_mut(length);
    let (v1, rest) = rest.split_at_mut(length);
    let (a, rest) = rest.split_at_mut(length);
    let b = &mut rest[..length];
    let u0 = &mut u[..length];
    let v0 = &mut v[..length];

    let x0i = modp_ninv31(x[0]);
    let y0i = modp_ninv31(y[0]);

    a.copy_from_slice(x);
    b.copy_from_slice(y);
    u0[0] = 1;
    u0[1..].fill(0);
    v0.fill(0);
    u1.copy_from_slice(y);
    v1.copy_from_slice(x);
    v1[0] = v1[0].wrapping_sub(1);

    let mut num = (62 * length + 30) as u32;
    while num >= 30 {
        let mut c0 = u32::MAX;
        let mut c1 = u32::MAX;
        let mut a0 = 0_u32;
        let mut a1 = 0_u32;
        let mut b0 = 0_u32;
        let mut b1 = 0_u32;
        for j in (0..length).rev() {
            let aw = a[j];
            let bw = b[j];
            a0 ^= (a0 ^ aw) & c0;
            a1 ^= (a1 ^ aw) & c1;
            b0 ^= (b0 ^ bw) & c0;
            b1 ^= (b1 ^ bw) & c1;
            c1 = c0;
            c0 &= (((aw | bw).wrapping_add(MASK31)) >> 31).wrapping_sub(1);
        }

        a1 |= a0 & c1;
        a0 &= !c1;
        b1 |= b0 & c1;
        b0 &= !c1;
        let mut a_hi = (u64::from(a0) << 31).wrapping_add(u64::from(a1));
        let mut b_hi = (u64::from(b0) << 31).wrapping_add(u64::from(b1));
        let mut a_lo = a[0];
        let mut b_lo = b[0];

        let mut pa = 1_i64;
        let mut pb = 0_i64;
        let mut qa = 0_i64;
        let mut qb = 1_i64;
        for i in 0..31 {
            let rz = b_hi.wrapping_sub(a_hi);
            let rt = ((rz ^ ((a_hi ^ b_hi) & (a_hi ^ rz))) >> 63) as u32;

            let oa = (a_lo >> i) & 1;
            let ob = (b_lo >> i) & 1;
            let c_ab = oa & ob & rt;
            let c_ba = oa & ob & !rt;
            let c_a = c_ab | (oa ^ 1);

            a_lo = a_lo.wrapping_sub(b_lo & c_ab.wrapping_neg());
            a_hi = a_hi.wrapping_sub(b_hi & u64::from(c_ab).wrapping_neg());
            pa = pa.wrapping_sub(qa & -i64::from(c_ab));
            pb = pb.wrapping_sub(qb & -i64::from(c_ab));
            b_lo = b_lo.wrapping_sub(a_lo & c_ba.wrapping_neg());
            b_hi = b_hi.wrapping_sub(a_hi & u64::from(c_ba).wrapping_neg());
            qa = qa.wrapping_sub(pa & -i64::from(c_ba));
            qb = qb.wrapping_sub(pb & -i64::from(c_ba));

            a_lo = a_lo.wrapping_add(a_lo & c_a.wrapping_sub(1));
            pa = pa.wrapping_add(pa & (i64::from(c_a) - 1));
            pb = pb.wrapping_add(pb & (i64::from(c_a) - 1));
            a_hi ^= (a_hi ^ (a_hi >> 1)) & u64::from(c_a).wrapping_neg();
            b_lo = b_lo.wrapping_add(b_lo & c_a.wrapping_neg());
            qa = qa.wrapping_add(qa & -i64::from(c_a));
            qb = qb.wrapping_add(qb & -i64::from(c_a));
            b_hi ^= (b_hi ^ (b_hi >> 1)) & u64::from(c_a).wrapping_sub(1);
        }

        let r = zint_co_reduce(a, b, pa, pb, qa, qb);
        pa = pa.wrapping_sub(pa.wrapping_add(pa) & -i64::from(r & 1));
        pb = pb.wrapping_sub(pb.wrapping_add(pb) & -i64::from(r & 1));
        qa = qa.wrapping_sub(qa.wrapping_add(qa) & -i64::from(r >> 1));
        qb = qb.wrapping_sub(qb.wrapping_add(qb) & -i64::from(r >> 1));
        zint_co_reduce_mod(u0, u1, y, y0i, pa, pb, qa, qb);
        zint_co_reduce_mod(v0, v1, x, x0i, pa, pb, qa, qb);

        num -= 30;
    }

    let mut rc = a[0] ^ 1;
    for &w in &a[1..] {
        rc |= w;
    }
    ((1 - ((rc | rc.wrapping_neg()) >> 31)) & x[0] & y[0]) != 0
}

/// x += k * (y << (31 * sch + scl)), y sign-extended (reference
/// `zint_add_scaled_mul_small`).
pub(super) fn zint_add_scaled_mul_small(x: &mut [u32], y: &[u32], k: i32, sch: u32, scl: u32) {
    let top = y[y.len() - 1];
    let ysign = (top >> 30).wrapping_neg() >> 1;
    let mut tw = 0_u32;
    let mut cc = 0_i32;
    for u in sch as usize..x.len() {
        let v = u - sch as usize;
        let wy = if v < y.len() { y[v] } else { ysign };
        let wys = ((wy << scl) & MASK31) | tw;
        tw = wy >> (31 - scl);

        // wys is unsigned and zero-extends, as `(int64_t)wys` does in C.
        let z = (i64::from(wys)
            .wrapping_mul(i64::from(k))
            .wrapping_add(i64::from(x[u]))
            .wrapping_add(i64::from(cc))) as u64;
        x[u] = (z as u32) & MASK31;
        cc = ((z >> 31) as u32) as i32;
    }
}

/// x -= y << (31 * sch + scl), y sign-extended (reference
/// `zint_sub_scaled`).
pub(super) fn zint_sub_scaled(x: &mut [u32], y: &[u32], sch: u32, scl: u32) {
    let top = y[y.len() - 1];
    let ysign = (top >> 30).wrapping_neg() >> 1;
    let mut tw = 0_u32;
    let mut cc = 0_u32;
    for u in sch as usize..x.len() {
        let v = u - sch as usize;
        let wy = if v < y.len() { y[v] } else { ysign };
        let wys = ((wy << scl) & MASK31) | tw;
        tw = wy >> (31 - scl);

        let w = x[u].wrapping_sub(wys).wrapping_sub(cc);
        x[u] = w & MASK31;
        cc = w >> 31;
    }
}

/// Converts a one-limb signed zint to a plain integer.
pub(super) fn zint_one_to_plain(x: u32) -> i32 {
    let w = x | ((x & (1 << 30)) << 1);
    w as i32
}
