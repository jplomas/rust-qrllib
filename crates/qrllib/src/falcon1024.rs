//! Falcon-1024 signatures with the API and byte formats of the NIST round-3
//! submission's reference implementation (`nist.c`), ported from go-qrllib
//! `crypto/falcon1024` and `crypto/internal/falcon1024`.
//!
//! Keys use the `CRYPTO_SECRETKEYBYTES` and `CRYPTO_PUBLICKEYBYTES`
//! encodings, and [`PrivateKey::sign`] produces the `crypto_sign` signed
//! message, which carries the message together with its signature and is
//! opened, rather than verified against a separate message, with [`open`].
//!
//! For signatures kept apart from their message, [`PrivateKey::sign_detached`]
//! and [`verify`] use the compressed signature format of the reference
//! library API (`falcon.h`, `FALCON_SIG_COMPRESSED`), which PQClean and liboqs
//! also use for Falcon-1024. A detached signature carries the same nonce and
//! compressed polynomial as the signed message, under the header byte 0x3A
//! instead of 0x2A. Exactly one encoding of a signature is accepted, in
//! either framing: the compressed polynomial must consume every byte after
//! the nonce. PQClean's falcon-1024 verifier and liboqs also accept the
//! polynomial zero-padded to the 1,280-byte falcon-padded-1024 length; this
//! module rejects that form, so a signature has no second valid encoding.
//! The accepted set is frozen by the vectors shared with go-qrllib
//! (`falcon1024/testdata/signature_encoding_vectors.json`), which every QRL
//! client must reproduce.
//!
//! ```
//! use qrllib::falcon1024::{self, PrivateKey, PublicKey};
//!
//! // A fresh key from OS randomness, or a deterministic one from a 48-byte
//! // seed with PrivateKey::from_seed.
//! let key = PrivateKey::generate()?;
//! let public_key = key.public_key();
//!
//! // Signed message: the message travels inside the signature and `open`
//! // returns it, as crypto_sign / crypto_sign_open do in the reference API.
//! let message = b"The sleeper must awaken";
//! let signed = key.sign(message)?;
//! assert_eq!(falcon1024::open(&public_key, &signed)?, message);
//!
//! // Detached signature (at most FALCON_1024_MAX_SIGNATURE_SIZE bytes),
//! // verified against a message you already hold.
//! let signature = key.sign_detached(message)?;
//! assert!(falcon1024::verify(&public_key, message, &signature));
//!
//! // Keys received as bytes: from_bytes checks the encoding and refuses weak
//! // keys; the private-key import also checks the NTRU equation and the
//! // key-generation bounds, so a key it accepts can always sign.
//! let public_key = PublicKey::from_bytes(public_key.as_bytes())?;
//! let key = PrivateKey::from_bytes(&key.to_bytes()?[..])?;
//! assert!(falcon1024::verify(&public_key, message, &key.sign_detached(message)?));
//! # Ok::<(), qrllib::QrllibError>(())
//! ```
//!
//! # Which Falcon
//!
//! This is Falcon as submitted to round 3 of the NIST post-quantum
//! competition (specification v1.2), bit for bit: keys and signatures equal
//! the reference implementation's, and equal go-qrllib's. NIST's standard for
//! Falcon, FIPS 206 (FN-DSA), is still a draft and is announced to differ
//! from the submission in details, so formats may change when it is final.
//!
//! # Randomness
//!
//! Key generation and signing draw their randomness from a
//! [`RandomSource`]: 48 bytes for a key, and a 40-byte nonce followed by a
//! 48-byte sampler seed for each signature, each in one call, in the order
//! the reference `crypto_sign_keypair` and `crypto_sign` call `randombytes`.
//! The methods without a source use [`OsRandom`]. The sampler seed is as
//! sensitive as the private key for the signature it produces, so a source
//! that repeats bytes belongs in tests only. The nonce is what keeps two
//! signatures of one message apart: a source that repeats the nonce while the
//! sampler seed changes signs the same target twice, and the difference of
//! the two signatures is a short vector of the private lattice.
//!
//! # Domain separation
//!
//! The signed input is the nonce followed by the message, as the round-3
//! submission defines it; there is no context string. A protocol that signs
//! several kinds of data with one key must prefix the message with its own
//! domain separator.
//!
//! # Public keys
//!
//! [`PublicKey::from_bytes`] checks the encoding (header byte, length, every
//! coefficient below q) and then applies the weak-key rule of
//! [`validate_falcon_public_key`]: a key whose polynomial has a small integer
//! multiple that is short hands out a short lattice basis, so anyone could
//! produce signatures the verifier accepts under it. Such keys are refused
//! with [`QrllibError::FalconWeakPublicKey`]; generated keys never have that
//! shape (the false-reject probability is below 2^-1562). The same rule runs
//! on the public half of an imported private key and in key generation.
//!
//! # Private keys, zeroization and timing
//!
//! [`PrivateKey::from_bytes`] applies, after the reference's own checks,
//! three the reference does not: the derived public key must pass the
//! weak-key rule, the four polynomials must solve the NTRU equation
//! f*G - g*F = q, and (f, g) must satisfy the bounds key generation enforces.
//! Every key the reference or this module generates passes. The signing
//! attempt loop is bounded at 128 and the sampler's rejection loop at 2^16
//! draws per coordinate, so a basis that cannot sign returns
//! [`QrllibError::FalconSigningFailed`] instead of spinning.
//! [`PrivateKey::zeroize`] (also run on drop) overwrites the secret material;
//! signing afterwards returns [`QrllibError::FalconSecretKeyZeroized`] while
//! the public key stays available. Verification uses integer arithmetic only.
//! Key generation and signing use native `f64` arithmetic that rounds as the
//! reference does; like the reference, they are not constant-time.

use crate::error::{QrllibError, Result};
use sha3::digest::{ExtendableOutput, Update};
use shake::Shake256;
use zeroize::{Zeroize, Zeroizing};

mod codec;
mod fft;
mod field;
mod modp;
mod ntru;
mod rng;
mod tables;
#[cfg(test)]
mod tests;

use codec::{
    detached_signature_decode, detached_signature_encode, pk_decode, pk_encode,
    signed_message_decode, signed_message_encode, sk_decode, sk_encode,
};
use fft::{
    FPR_INVERSE_OF_Q, FftPoly, TREE_SIZE, ff_ldl_binary_normalize, ff_ldl_fft, ff_sampling_fft,
    fft, fft_add, fft_from_small, fft_mul, fft_mul_adj, fft_mul_const, fft_neg, fft_self_adj,
    fpr_rint, inverse_fft, sample_fft_point,
};
use field::{
    LOG_N, N, NTRU_COEFF_BOUND, Q, R2, RingElement, SmallPoly, coefficients_exceed_bound,
    divide_ntt_by_batched_inverse, field_centered_mod, field_from_small, field_montgomery_mul,
    field_sub, hash_to_point, inverse_ntt, ntt, ntt_mul, orthogonalized_norm_exceeds_bound,
    sample_gaussian_polynomial, signature_norm_exceeds_partial_bound, signature_norm_within_bound,
    squared_norm_exceeds_bound, to_ntt_monty,
};
use rng::SamplerPrng;

/// Size in bytes of an encoded public key (`CRYPTO_PUBLICKEYBYTES`).
pub const FALCON_1024_PUBLIC_KEY_SIZE: usize = 1793;

/// Size in bytes of an encoded private key (`CRYPTO_SECRETKEYBYTES`).
pub const FALCON_1024_PRIVATE_KEY_SIZE: usize = 2305;

/// The most a signed message exceeds the message it carries, in bytes:
/// `CRYPTO_BYTES` of PQClean's `api.h` at commit 0586a824, which equals
/// `FALCON_SIG_COMPRESSED_MAXSIZE`. Bodies are 1,230 +/- 3 bytes, so the
/// limit is not reached by an in-bound key.
pub const FALCON_1024_MAX_SIGNED_MESSAGE_OVERHEAD: usize = 1462;

/// Maximum size in bytes of a detached signature
/// (`FALCON_SIG_COMPRESSED_MAXSIZE` for degree 1024). Signatures are about
/// 1271 bytes on average.
pub const FALCON_1024_MAX_SIGNATURE_SIZE: usize = 1462;

/// Size in bytes of the random input key generation consumes, and of the
/// seed [`PrivateKey::from_seed`] expands.
pub const FALCON_1024_SEED_SIZE: usize = 48;

/// Size in bytes of the per-signature nonce.
const NONCE_SIZE: usize = 40;

/// The bounds key generation enforces on (f, g), re-applied on import.
const FG_BOUND: i32 = 15;
const KEYGEN_SQ_NORM_BOUND: u32 = 16823;
const KEYGEN_B_NORM_BOUND: f64 = 16822.4121;

/// Bound on the signing attempt loop. For a key within the key-generation
/// bounds an attempt is rejected with probability well below one in a
/// thousand, so 128 consecutive rejections cannot happen in honest use; the
/// bound stops a basis built outside the import checks from spinning. The
/// reference loops without bound.
const MAX_SIGN_ATTEMPTS: usize = 128;

/// Weak-key rule: the largest integer multiplier scanned.
const WEAK_KEY_MULTIPLIER_BOUND: u32 = 1024;
/// Weak-key rule: the bound on ||c*h||^2 + c^2 at or below which the key is
/// weak.
const WEAK_KEY_SQUARED_NORM_BOUND: u64 = 1 << 30;

type ShakeReader = <Shake256 as ExtendableOutput>::Reader;

/// Wipes a slice of plain values; used for scratch that is not wrapped in
/// `Zeroizing`.
fn zeroize_slice<T: zeroize::DefaultIsZeroes>(s: &mut [T]) {
    s.zeroize();
}

/// Absorbs `inputs` in order into SHAKE256 and returns its output stream.
fn shake256_reader(inputs: &[&[u8]]) -> ShakeReader {
    let mut h = Shake256::default();
    for input in inputs {
        h.update(input);
    }
    h.finalize_xof()
}

/// Compares two equal-length byte arrays without an early exit.
fn constant_time_eq<const L: usize>(left: &[u8; L], right: &[u8; L]) -> bool {
    let mut diff = 0_u8;
    for (lhs, rhs) in left.iter().zip(right) {
        diff |= lhs ^ rhs;
    }
    diff == 0
}

/// A source of randomness for key generation and signing. Each request is
/// one call, as each `randombytes` call is in the reference, so a
/// deterministic source (such as the NIST KAT DRBG, which reseeds after every
/// call) reproduces the reference's keys and signatures.
pub trait RandomSource {
    /// Fills `dest` entirely, or fails.
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<()>;
}

/// The operating system's random number generator (`getrandom`).
#[derive(Clone, Copy, Debug, Default)]
pub struct OsRandom;

impl RandomSource for OsRandom {
    /// Fills `dest` from `getrandom`.
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
        getrandom::getrandom(dest)?;
        Ok(())
    }
}

/// A validated Falcon-1024 public key.
///
/// A `PublicKey` can only come from [`PublicKey::from_bytes`] or from a
/// [`PrivateKey`], so every key that reaches [`verify`] or [`open`] has
/// passed the encoding checks and the weak-key rule. Equality is a
/// constant-time comparison of the encodings.
#[derive(Clone)]
pub struct PublicKey {
    raw: [u8; FALCON_1024_PUBLIC_KEY_SIZE],
    /// h in NTT and Montgomery form, as verification uses it.
    h_ntt: RingElement,
}

impl core::fmt::Debug for PublicKey {
    /// Shows the encoded key as hex.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PublicKey").field("raw", &hex::encode(self.raw)).finish()
    }
}

impl PublicKey {
    /// Decodes a [`FALCON_1024_PUBLIC_KEY_SIZE`]-byte public key, refusing
    /// malformed encodings and weak keys; see [`validate_falcon_public_key`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let h = pk_decode(bytes)?;
        validate_public_polynomial(&h)?;
        let mut raw = [0_u8; FALCON_1024_PUBLIC_KEY_SIZE];
        raw.copy_from_slice(bytes);
        Ok(Self::from_parts(raw, h))
    }

    /// Encodes h and builds the key; h comes from a valid private key.
    fn from_h(h: &RingElement) -> Self {
        let mut raw = [0_u8; FALCON_1024_PUBLIC_KEY_SIZE];
        pk_encode(&mut raw, h);
        Self::from_parts(raw, *h)
    }

    /// Pairs the encoding with h, converting h to the NTT and Montgomery
    /// form verification uses.
    fn from_parts(raw: [u8; FALCON_1024_PUBLIC_KEY_SIZE], mut h_ntt: RingElement) -> Self {
        to_ntt_monty(&mut h_ntt);
        Self { raw, h_ntt }
    }

    /// Borrows the encoded key.
    pub fn as_bytes(&self) -> &[u8; FALCON_1024_PUBLIC_KEY_SIZE] {
        &self.raw
    }

    /// Returns a copy of the encoded key.
    pub fn to_bytes(&self) -> [u8; FALCON_1024_PUBLIC_KEY_SIZE] {
        self.raw
    }
}

impl PartialEq for PublicKey {
    /// Constant-time comparison of the encodings.
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq(&self.raw, &other.raw)
    }
}

impl Eq for PublicKey {}

/// The private key: its encoding plus the FFT basis and LDL tree signing
/// uses. It is read-only after construction, so it can sign from several
/// threads at once; [`PrivateKey::zeroize`] needs `&mut self`.
pub struct PrivateKey {
    inner: Box<PrivateKeyInner>,
}

struct PrivateKeyInner {
    raw: [u8; FALCON_1024_PRIVATE_KEY_SIZE],
    public: PublicKey,
    b00: FftPoly,
    b01: FftPoly,
    b10: FftPoly,
    b11: FftPoly,
    tree: [f64; TREE_SIZE],
    zeroized: bool,
}

// Redacting Debug: the type owns the private key.
impl core::fmt::Debug for PrivateKey {
    /// Shows no key material.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PrivateKey").finish_non_exhaustive()
    }
}

impl PrivateKey {
    /// Generates a key pair from [`FALCON_1024_SEED_SIZE`] bytes of OS
    /// randomness.
    pub fn generate() -> Result<Self> {
        Self::generate_with_rng(&mut OsRandom)
    }

    /// Generates a key pair from [`FALCON_1024_SEED_SIZE`] bytes drawn from
    /// `rng` in one call, as the reference `crypto_sign_keypair` does.
    pub fn generate_with_rng<R: RandomSource + ?Sized>(rng: &mut R) -> Result<Self> {
        let mut seed = Zeroizing::new([0_u8; FALCON_1024_SEED_SIZE]);
        rng.fill_bytes(&mut seed[..])?;
        Self::from_seed(&seed[..])
    }

    /// Deterministically generates the key from a [`FALCON_1024_SEED_SIZE`]
    /// byte seed, expanding it with SHAKE256 exactly as the reference
    /// `crypto_sign_keypair` expands the bytes it draws, so the key equals
    /// the one [`PrivateKey::generate_with_rng`] produces when its source
    /// yields `seed`.
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        if seed.len() != FALCON_1024_SEED_SIZE {
            return Err(QrllibError::InvalidFalconSeedSize(seed.len(), FALCON_1024_SEED_SIZE));
        }
        let mut rng = shake256_reader(&[seed]);
        let (f, g, big_f, big_g, h) = generate_key_components(&mut rng);
        Ok(Self::from_components(f, g, big_f, big_g, &h))
    }

    /// Decodes a [`FALCON_1024_PRIVATE_KEY_SIZE`]-byte private key. As the
    /// reference `crypto_sign` does, it recomputes G from f, g and F and
    /// rejects encodings for which that fails. It then checks what the
    /// reference does not: that the public half passes the weak-key rule,
    /// that (f, g, F, G) solve f*G - g*F = q, and that (f, g) satisfy the
    /// key-generation bounds. Every key the reference or this module
    /// generates passes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (f, g, big_f) = sk_decode(bytes)?;
        let f = Zeroizing::new(f);
        let g = Zeroizing::new(g);
        let big_f = Zeroizing::new(big_f);

        let big_g = complete_private(&f, &g, &big_f).ok_or(QrllibError::InvalidFalconPrivateKey)?;
        let big_g = Zeroizing::new(big_g);

        //coverage:ignore start reason=defensively-unreachable
        // complete_private has already inverted f mod q; compute_public
        // inverts the same NTT coefficients and cannot fail after it.
        let h = compute_public(&f, &g).ok_or(QrllibError::InvalidFalconPrivateKey)?;
        //coverage:ignore end

        // The public half an encoding derives is held to the same rule as a
        // key received on its own.
        validate_public_polynomial(&h)?;

        // complete_private only checks that the recomputed G is small. The
        // four polynomials must also satisfy f*G - g*F = q, or the matrix is
        // not a basis of the key's lattice and signing never succeeds; such
        // an encoding derives the correct public key, so nothing else can
        // tell it from the genuine one.
        if !ntru_equation_holds(&f, &g, &big_f, &big_g) {
            return Err(QrllibError::InvalidFalconPrivateKey);
        }

        // The five-bit encoding cannot hold a coefficient outside [-15, 15],
        // so the coefficient bound of key generation needs no re-check.
        if squared_norm_exceeds_bound(&f, &g, KEYGEN_SQ_NORM_BOUND)
            || orthogonalized_norm_exceeds_bound(&f, &g, KEYGEN_B_NORM_BOUND)
        {
            return Err(QrllibError::InvalidFalconPrivateKey);
        }

        Ok(Self::from_components(*f, *g, *big_f, *big_g, &h))
    }

    /// Builds the key from (f, g, F, G) and h: encodes the private key and
    /// expands the FFT basis and LDL tree. The inputs are already checked.
    fn from_components(
        f: SmallPoly,
        g: SmallPoly,
        big_f: SmallPoly,
        big_g: SmallPoly,
        h: &RingElement,
    ) -> Self {
        let f = Zeroizing::new(f);
        let g = Zeroizing::new(g);
        let big_f = Zeroizing::new(big_f);
        let big_g = Zeroizing::new(big_g);

        let mut inner = Box::new(PrivateKeyInner {
            raw: [0; FALCON_1024_PRIVATE_KEY_SIZE],
            public: PublicKey::from_h(h),
            b00: [0.0; N],
            b01: [0.0; N],
            b10: [0.0; N],
            b11: [0.0; N],
            tree: [0.0; TREE_SIZE],
            zeroized: false,
        });
        sk_encode(&mut inner.raw, &f, &g, &big_f);
        expand_private_key(&mut inner, &f, &g, &big_f, &big_g);
        Self { inner }
    }

    /// The encoded private key, or [`QrllibError::FalconSecretKeyZeroized`]
    /// after [`PrivateKey::zeroize`].
    pub fn to_bytes(&self) -> Result<Zeroizing<[u8; FALCON_1024_PRIVATE_KEY_SIZE]>> {
        self.signable()?;
        Ok(Zeroizing::new(self.inner.raw))
    }

    /// A copy of the public key; it stays available after zeroization.
    pub fn public_key(&self) -> PublicKey {
        self.inner.public.clone()
    }

    /// Signs `message` with OS randomness and returns the signed message;
    /// see [`PrivateKey::sign_with_rng`].
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.sign_with_rng(&mut OsRandom, message)
    }

    /// Signs `message` and returns the signed message in the format of the
    /// reference `crypto_sign`: a two-byte big-endian signature length, the
    /// 40-byte nonce, the message, and the signature (header byte 0x2A and
    /// the compressed polynomial). It is at most
    /// [`FALCON_1024_MAX_SIGNED_MESSAGE_OVERHEAD`] bytes longer than the
    /// message. `rng` supplies the nonce and then the sampler seed.
    pub fn sign_with_rng<R: RandomSource + ?Sized>(
        &self,
        rng: &mut R,
        message: &[u8],
    ) -> Result<Vec<u8>> {
        let (nonce, s2) = self.sign_core(rng, message)?;
        signed_message_encode(&nonce, message, &s2)
    }

    /// Signs `message` with OS randomness and returns a detached signature;
    /// see [`PrivateKey::sign_detached_with_rng`].
    pub fn sign_detached(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.sign_detached_with_rng(&mut OsRandom, message)
    }

    /// Signs `message` and returns a detached signature in the compressed
    /// format of the reference library API: header byte 0x3A, the 40-byte
    /// nonce and the compressed polynomial, at most
    /// [`FALCON_1024_MAX_SIGNATURE_SIZE`] bytes. It consumes randomness as
    /// [`PrivateKey::sign_with_rng`] does, so the same random bytes yield the
    /// signature that the signed message embeds.
    pub fn sign_detached_with_rng<R: RandomSource + ?Sized>(
        &self,
        rng: &mut R,
        message: &[u8],
    ) -> Result<Vec<u8>> {
        let (nonce, s2) = self.sign_core(rng, message)?;
        detached_signature_encode(&nonce, &s2)
    }

    /// Overwrites the secret material: the encoding, the FFT basis and the
    /// LDL tree. The public key stays available. Signing afterwards returns
    /// [`QrllibError::FalconSecretKeyZeroized`]. Runs on drop as well.
    pub fn zeroize(&mut self) {
        let inner = &mut *self.inner;
        inner.raw.zeroize();
        inner.b00.zeroize();
        inner.b01.zeroize();
        inner.b10.zeroize();
        inner.b11.zeroize();
        inner.tree.zeroize();
        inner.zeroized = true;
    }

    /// Reports whether [`PrivateKey::zeroize`] has run.
    pub fn is_zeroized(&self) -> bool {
        self.inner.zeroized
    }

    /// [`QrllibError::FalconSecretKeyZeroized`] once the key is zeroized.
    fn signable(&self) -> Result<()> {
        if self.inner.zeroized { Err(QrllibError::FalconSecretKeyZeroized) } else { Ok(()) }
    }

    /// The steps signing and detached signing share: draw the nonce and then
    /// the sampler seed, in the order `crypto_sign` calls `randombytes`, hash
    /// the nonce and message to a point and sign it.
    fn sign_core<R: RandomSource + ?Sized>(
        &self,
        rng: &mut R,
        message: &[u8],
    ) -> Result<([u8; NONCE_SIZE], SmallPoly)> {
        self.signable()?;
        let mut nonce = [0_u8; NONCE_SIZE];
        rng.fill_bytes(&mut nonce)?;
        let c0 = hash_to_point(&mut shake256_reader(&[&nonce, message]));

        let mut seed = Zeroizing::new([0_u8; FALCON_1024_SEED_SIZE]);
        rng.fill_bytes(&mut seed[..])?;
        let mut sampler_rng = shake256_reader(&[&seed[..]]);
        let s2 = sign(&mut sampler_rng, &self.inner, &c0)?;
        Ok((nonce, s2))
    }
}

impl PartialEq for PrivateKey {
    /// Constant-time comparison of the encodings; a zeroized key equals
    /// nothing.
    fn eq(&self, other: &Self) -> bool {
        !self.inner.zeroized
            && !other.inner.zeroized
            && constant_time_eq(&self.inner.raw, &other.inner.raw)
    }
}

impl Drop for PrivateKey {
    /// Zeroizes the key; see [`PrivateKey::zeroize`].
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Checks an encoded public key without constructing it: a wrong length is
/// [`QrllibError::InvalidFalconPublicKeySize`], a bad header or a coefficient
/// not below q is [`QrllibError::InvalidFalconPublicKeyEncoding`], and a weak
/// key is [`QrllibError::FalconWeakPublicKey`].
///
/// A weak key is one under which the verifier accepts a signature that
/// anyone can compute from the key alone. Verification accepts (s1, s2)
/// whenever s1 + s2*h = H(nonce || message) and ||(s1, s2)||^2 <= 70,265,242,
/// so a forger needs a short basis of the lattice
/// {(s1, s2): s1 + s2*h = 0 mod q}. An honest key hides that basis; a key of
/// the form h = a/c with a small polynomial a and a small integer c
/// publishes one. Constants and monomials are the simplest members, and
/// 98.6% of the constant keys forge end to end.
///
/// The rule: with h centred in (-q/2, q/2], the key is weak if for some
/// integer c in [1, 1024] the squared norm of the centred coefficients of
/// c*h, plus c^2, is at most 2^30. The scan is integer-only. Generated keys
/// have ||c*h||^2 about 1.29 * 10^10 for every c, so the chance that any of
/// the 1024 multiples falls below 2^30 is under 2^-1562. The rule is
/// sufficient, not complete: a key a/b for a sparse non-integer b is not
/// caught, and such keys never arise from key generation either.
///
/// go-qrllib applies the same rule and is tested against the same vector
/// file (`falcon1024/testdata/weak_public_key_vectors.json`), so a key is
/// accepted or rejected identically across QRL clients.
pub fn validate_falcon_public_key(public_key: &[u8]) -> Result<()> {
    let h = pk_decode(public_key)?;
    validate_public_polynomial(&h)
}

/// Applies the weak-key rule of [`validate_falcon_public_key`] to a decoded
/// polynomial.
fn validate_public_polynomial(h: &RingElement) -> Result<()> {
    match weak_public_key_multiplier(h) {
        Some((multiplier, squared_norm)) => Err(QrllibError::FalconWeakPublicKey {
            multiplier,
            squared_norm,
            bound: WEAK_KEY_SQUARED_NORM_BOUND - u64::from(multiplier * multiplier),
        }),
        None => Ok(()),
    }
}

/// The smallest c in [1, 1024] with ||centred(c*h)||^2 + c^2 <= 2^30, with
/// that squared norm, or `None` when the key is not weak. A multiplier is
/// abandoned as soon as its partial norm passes the bound, after a few dozen
/// coefficients for an honest key; the data is public, so the early exit
/// leaks nothing.
fn weak_public_key_multiplier(h: &RingElement) -> Option<(u32, u64)> {
    for c in 1..=WEAK_KEY_MULTIPLIER_BOUND {
        let mut norm = u64::from(c * c);
        for &hi in h {
            if norm > WEAK_KEY_SQUARED_NORM_BOUND {
                break;
            }
            let mut v = i64::from((c * hi) % Q);
            if v > i64::from(Q / 2) {
                v -= i64::from(Q);
            }
            norm += (v * v) as u64;
        }
        if norm <= WEAK_KEY_SQUARED_NORM_BOUND {
            return Some((c, norm - u64::from(c * c)));
        }
    }
    None
}

/// Verifies `signed_message` and returns the message it carries, as the
/// reference `crypto_sign_open` does. A signed message shorter than its
/// 42-byte prefix is [`QrllibError::FalconSignatureTooShort`]; any other
/// malformed or invalid one is [`QrllibError::InvalidFalconSignature`].
pub fn open(public_key: &PublicKey, signed_message: &[u8]) -> Result<Vec<u8>> {
    let (nonce, message, s2) = signed_message_decode(signed_message)?;
    let c0 = hash_to_point(&mut shake256_reader(&[nonce, message]));
    if !verify_raw(&c0, &s2, &public_key.h_ntt) {
        return Err(QrllibError::InvalidFalconSignature);
    }
    Ok(message.to_vec())
}

/// Reports whether `signature` is a valid detached signature of `message`
/// under `public_key`, with the checks the reference `falcon_verify` applies
/// to the compressed format.
pub fn verify(public_key: &PublicKey, message: &[u8], signature: &[u8]) -> bool {
    verify_detached(public_key, message, signature).is_ok()
}

/// [`verify`] with the reason for a rejection.
fn verify_detached(public_key: &PublicKey, message: &[u8], signature: &[u8]) -> Result<()> {
    let (nonce, s2) = detached_signature_decode(signature)?;
    let c0 = hash_to_point(&mut shake256_reader(&[nonce, message]));
    if verify_raw(&c0, &s2, &public_key.h_ntt) {
        Ok(())
    } else {
        Err(QrllibError::InvalidFalconSignature)
    }
}

/// Reference `verify_raw`: s1 = c0 - s2*h must make (s1, s2) short.
fn verify_raw(c0: &RingElement, s2: &SmallPoly, h_ntt: &RingElement) -> bool {
    let mut t = [0_u32; N];
    for (ti, &s) in t.iter_mut().zip(s2) {
        *ti = field_from_small(s);
    }
    ntt(&mut t);
    ntt_mul(&mut t, h_ntt);
    inverse_ntt(&mut t);

    let mut s1 = [0_i32; N];
    for i in 0..N {
        s1[i] = field_centered_mod(field_sub(c0[i], t[i]));
    }
    signature_norm_within_bound(&s1, s2)
}

/// Reference `keygen`: samples (f, g) until they pass the bounds, the public
/// key is weak-key-free, and the NTRU equation has a small solution. The
/// loop is unbounded, as in the reference.
fn generate_key_components(
    rng: &mut ShakeReader,
) -> (SmallPoly, SmallPoly, SmallPoly, SmallPoly, RingElement) {
    loop {
        let f = Zeroizing::new(sample_gaussian_polynomial(rng));
        let g = Zeroizing::new(sample_gaussian_polynomial(rng));

        //coverage:ignore start reason=statistically-unreachable
        if coefficients_exceed_bound(&f, FG_BOUND) || coefficients_exceed_bound(&g, FG_BOUND) {
            // One keygen draw is at most 26 in magnitude, so this is a tail
            // event; the check mirrors the reference.
            continue;
        }
        //coverage:ignore end
        if squared_norm_exceeds_bound(&f, &g, KEYGEN_SQ_NORM_BOUND) {
            continue;
        }
        if orthogonalized_norm_exceeds_bound(&f, &g, KEYGEN_B_NORM_BOUND) {
            continue;
        }
        let Some(h) = compute_public(&f, &g) else {
            continue;
        };
        //coverage:ignore start reason=statistically-unreachable
        if weak_public_key_multiplier(&h).is_some() {
            // h = g/f is uniform, so a weak public half is a sub-2^-1562
            // event; the check keeps keygen under the import rule.
            continue;
        }
        //coverage:ignore end
        let Some((big_f, big_g)) = ntru::solve_ntru(&f, &g) else {
            continue;
        };
        return (*f, *g, big_f, big_g, h);
    }
}

/// h = g / f mod q, or `None` when f is not invertible.
fn compute_public(f: &SmallPoly, g: &SmallPoly) -> Option<RingElement> {
    let mut f_ntt = Zeroizing::new([0_u32; N]);
    let mut h_ntt = [0_u32; N];
    for i in 0..N {
        f_ntt[i] = field_from_small(f[i]);
        h_ntt[i] = field_from_small(g[i]);
    }
    ntt(&mut f_ntt[..]);
    ntt(&mut h_ntt);
    if !divide_ntt_by_batched_inverse(&mut h_ntt, &f_ntt[..]) {
        return None;
    }
    inverse_ntt(&mut h_ntt);
    Some(h_ntt)
}

/// Reference `complete_private`: G = g*F / f mod q, refused unless every
/// coefficient (centred as the reference does it) is within [-127, 127].
fn complete_private(f: &SmallPoly, g: &SmallPoly, big_f: &SmallPoly) -> Option<SmallPoly> {
    let mut g_ntt = Zeroizing::new([0_u32; N]);
    let mut big_f_ntt = Zeroizing::new([0_u32; N]);
    let mut f_ntt = Zeroizing::new([0_u32; N]);
    for i in 0..N {
        g_ntt[i] = field_from_small(g[i]);
        big_f_ntt[i] = field_from_small(big_f[i]);
        f_ntt[i] = field_from_small(f[i]);
    }
    ntt(&mut g_ntt[..]);
    ntt(&mut big_f_ntt[..]);
    ntt(&mut f_ntt[..]);
    for x in g_ntt.iter_mut() {
        *x = field_montgomery_mul(*x, R2);
    }
    ntt_mul(&mut g_ntt[..], &big_f_ntt[..]);
    if !divide_ntt_by_batched_inverse(&mut g_ntt[..], &f_ntt[..]) {
        return None;
    }
    inverse_ntt(&mut g_ntt[..]);

    let mut big_g = [0_i32; N];
    for (out, &w) in big_g.iter_mut().zip(g_ntt.iter()) {
        let gi = complete_private_center(w);
        if !(-NTRU_COEFF_BOUND..=NTRU_COEFF_BOUND).contains(&gi) {
            return None;
        }
        *out = gi;
    }
    Some(big_g)
}

/// Centres a residue the way `complete_private` does: every residue of q/2
/// and above has q subtracted (`verify_raw` keeps q/2 itself).
fn complete_private_center(w: u32) -> i32 {
    let w = w.wrapping_sub(Q & !((w.wrapping_sub(Q / 2) >> 31).wrapping_neg()));
    w as i32
}

/// Reports whether f*G - g*F = q, with scratch that is wiped afterwards.
fn ntru_equation_holds(f: &SmallPoly, g: &SmallPoly, big_f: &SmallPoly, big_g: &SmallPoly) -> bool {
    let mut scratch = Zeroizing::new(vec![0_u32; 6 * N]);
    ntru::check_ntru_equation(f, g, big_f, big_g, &mut scratch)
}

/// Computes the FFT basis and the LDL tree with the arithmetic of the
/// reference `expand_privkey` (equivalently, the Gram matrix and on-the-fly
/// LDL of `sign_dyn`).
fn expand_private_key(
    key: &mut PrivateKeyInner,
    f: &SmallPoly,
    g: &SmallPoly,
    big_f: &SmallPoly,
    big_g: &SmallPoly,
) {
    fft_from_small(&mut key.b01, f);
    fft_from_small(&mut key.b00, g);
    fft_from_small(&mut key.b11, big_f);
    fft_from_small(&mut key.b10, big_g);
    fft_neg(&mut key.b01, LOG_N);
    fft_neg(&mut key.b11, LOG_N);

    let mut buf = Zeroizing::new(vec![0.0_f64; 4 * N + 3 * N]);
    let (g00, rest) = buf.split_at_mut(N);
    let (g01, rest) = rest.split_at_mut(N);
    let (g11, rest) = rest.split_at_mut(N);
    let (tmp, ldl_scratch) = rest.split_at_mut(N);

    fft_self_adj(g00, &key.b00, LOG_N);
    fft_self_adj(tmp, &key.b01, LOG_N);
    fft_add(g00, tmp, LOG_N);

    fft_mul_adj(g01, &key.b00, &key.b10, LOG_N);
    fft_mul_adj(tmp, &key.b01, &key.b11, LOG_N);
    fft_add(g01, tmp, LOG_N);

    fft_self_adj(g11, &key.b10, LOG_N);
    fft_self_adj(tmp, &key.b11, LOG_N);
    fft_add(g11, tmp, LOG_N);

    ff_ldl_fft(&mut key.tree, g00, g01, g11, LOG_N, ldl_scratch);
    ff_ldl_binary_normalize(&mut key.tree, LOG_N, LOG_N);
}

/// The reference `sign_dyn` loop: each attempt seeds a fresh sampler PRNG
/// from the continuing SHAKE stream.
fn sign(rng: &mut ShakeReader, key: &PrivateKeyInner, c0: &RingElement) -> Result<SmallPoly> {
    let mut prng = Box::new(SamplerPrng::new());
    for _ in 0..MAX_SIGN_ATTEMPTS {
        prng.init(rng);
        if let Some(s2) = sign_attempt(&mut sample_fft_point, &mut prng, key, c0) {
            return Ok(s2);
        }
        if prng.exhausted {
            // The sampler could not produce a coordinate within its budget.
            // That is a property of the basis, not of this attempt's
            // randomness, so further attempts would only repeat it.
            break;
        }
    }
    Err(QrllibError::FalconSigningFailed)
}

/// The reference `do_sign_dyn`, with the Gram matrix and LDL values taken
/// from the precomputed expansion of the key. `None` when the attempt is
/// rejected.
fn sign_attempt<S>(
    samp: &mut S,
    prng: &mut SamplerPrng,
    key: &PrivateKeyInner,
    c0: &RingElement,
) -> Option<SmallPoly>
where
    S: FnMut(&mut SamplerPrng, f64, f64) -> f64,
{
    let mut buf = Zeroizing::new(vec![0.0_f64; 7 * N]);
    let (t0, rest) = buf.split_at_mut(N);
    let (t1, rest) = rest.split_at_mut(N);
    let (sample_x, rest) = rest.split_at_mut(N);
    let (sample_y, rest) = rest.split_at_mut(N);
    let (lattice_x, rest) = rest.split_at_mut(N);
    let (lattice_y, tmp) = rest.split_at_mut(N);

    for (t, &c) in t0.iter_mut().zip(c0) {
        *t = f64::from(c);
    }
    fft(t0, LOG_N);

    t1.copy_from_slice(t0);
    fft_mul(t1, &key.b01, LOG_N);
    fft_mul_const(t1, -FPR_INVERSE_OF_Q, LOG_N);
    fft_mul(t0, &key.b11, LOG_N);
    fft_mul_const(t0, FPR_INVERSE_OF_Q, LOG_N);

    ff_sampling_fft(samp, prng, sample_x, sample_y, t0, t1, &key.tree, LOG_N);
    if prng.exhausted {
        return None;
    }

    lattice_x.copy_from_slice(sample_x);
    fft_mul(lattice_x, &key.b00, LOG_N);
    tmp.copy_from_slice(sample_y);
    fft_mul(tmp, &key.b10, LOG_N);
    fft_add(lattice_x, tmp, LOG_N);

    lattice_y.copy_from_slice(sample_x);
    fft_mul(lattice_y, &key.b01, LOG_N);
    tmp.copy_from_slice(sample_y);
    fft_mul(tmp, &key.b11, LOG_N);
    fft_add(lattice_y, tmp, LOG_N);

    inverse_fft(lattice_x, LOG_N);
    inverse_fft(lattice_y, LOG_N);

    let mut s2 = [0_i32; N];
    let mut sqn = 0_u32;
    let mut ng = 0_u32;
    for i in 0..N {
        let s1 = (c0[i] as i32).wrapping_sub(fpr_rint(lattice_x[i]) as i32);
        sqn = sqn.wrapping_add(s1.wrapping_mul(s1) as u32);
        ng |= sqn;
        // The reference stores s2 in 16-bit integers before the norm check,
        // so the value is truncated the same way here.
        s2[i] = i32::from(fpr_rint(lattice_y[i]).wrapping_neg() as i16);
    }
    sqn |= (ng >> 31).wrapping_neg();

    if signature_norm_exceeds_partial_bound(sqn, &s2) {
        s2.zeroize();
        return None;
    }
    Some(s2)
}
