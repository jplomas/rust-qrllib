//! Key and signature encodings of the Falcon round-3 reference
//! (`codec.c`, `nist.c` and the `falcon.h` compressed format), transliterated
//! from go-qrllib `crypto/internal/falcon1024/codec.go`.

use super::field::{
    ENCODING_SIZE_14, LOG_N, N, RingElement, SmallPoly, poly_byte_decode, poly_byte_encode,
};
use super::{
    FALCON_1024_MAX_SIGNATURE_SIZE, FALCON_1024_MAX_SIGNED_MESSAGE_OVERHEAD,
    FALCON_1024_PRIVATE_KEY_SIZE, FALCON_1024_PUBLIC_KEY_SIZE, NONCE_SIZE,
};
use crate::error::{QrllibError, Result};

const HEADER_SIZE: usize = 1;

struct CompressedBitReader<'a> {
    src: &'a [u8],
    pos: usize,
    current: u8,
    bits: u32,
}

impl CompressedBitReader<'_> {
    /// The next bit, most significant first, or `None` past the end.
    fn read_bit(&mut self) -> Option<u32> {
        if self.bits == 0 {
            let &byte = self.src.get(self.pos)?;
            self.current = byte;
            self.pos += 1;
            self.bits = 8;
        }
        self.bits -= 1;
        Some(u32::from(self.current >> self.bits) & 1)
    }

    /// The next `count` bits as a big-endian integer, or `None` past the end.
    fn read_bits(&mut self, count: u32) -> Option<u32> {
        let mut v = 0;
        for _ in 0..count {
            v = (v << 1) | self.read_bit()?;
        }
        Some(v)
    }

    /// The unread low bits of the current byte, which a canonical encoding
    /// leaves zero.
    fn trailing_bits(&self) -> u8 {
        if self.bits == 0 { 0 } else { self.current & ((1_u8 << self.bits) - 1) }
    }
}

const MAX_COMPRESSED_COEFFICIENT: i32 = 2047;

/// Reference `comp_decode`: each coefficient is sign bit, low seven bits of
/// the magnitude, then the high bits in unary. Returns the polynomial and the
/// bytes consumed. A negative zero, a magnitude above 2047, a truncated input
/// or nonzero padding bits in the last byte are refused.
pub(super) fn compressed_decode(src: &[u8]) -> Result<(SmallPoly, usize)> {
    let mut p = [0_i32; N];
    let mut r = CompressedBitReader { src, pos: 0, current: 0, bits: 0 };

    for coefficient in p.iter_mut() {
        let b = r.read_bits(8).ok_or(QrllibError::InvalidFalconSignature)?;
        let negative = b & 0x80 != 0;
        let mut magnitude = (b & 0x7F) as i32;
        loop {
            if r.read_bit().ok_or(QrllibError::InvalidFalconSignature)? == 1 {
                break;
            }
            magnitude += 128;
            if magnitude > MAX_COMPRESSED_COEFFICIENT {
                return Err(QrllibError::InvalidFalconSignature);
            }
        }
        if negative {
            if magnitude == 0 {
                return Err(QrllibError::InvalidFalconSignature);
            }
            magnitude = -magnitude;
        }
        *coefficient = magnitude;
    }

    if r.trailing_bits() != 0 {
        return Err(QrllibError::InvalidFalconSignature);
    }
    Ok((p, r.pos))
}

/// Reference `comp_encode`. Returns the bytes written, or
/// [`QrllibError::FalconSigningFailed`] when a coefficient is out of range or
/// the encoding does not fit `dst`.
pub(super) fn compressed_encode(dst: &mut [u8], s: &SmallPoly) -> Result<usize> {
    if s.iter().any(|&x| !(-MAX_COMPRESSED_COEFFICIENT..=MAX_COMPRESSED_COEFFICIENT).contains(&x)) {
        return Err(QrllibError::FalconSigningFailed);
    }

    let mut acc = 0_u32;
    let mut acc_bits = 0_u32;
    let mut written = 0;
    for &x in s {
        let (t, sign) = if x < 0 { (x.unsigned_abs(), 0x80) } else { (x as u32, 0) };
        let low = sign | (t & 0x7F);
        let high = t >> 7;

        acc = (acc << 8) | low;
        acc_bits += 8;
        acc = (acc << (high + 1)) | 1;
        acc_bits += high + 1;

        while acc_bits >= 8 {
            acc_bits -= 8;
            let slot = dst.get_mut(written).ok_or(QrllibError::FalconSigningFailed)?;
            *slot = (acc >> acc_bits) as u8;
            written += 1;
        }
    }
    if acc_bits > 0 {
        let slot = dst.get_mut(written).ok_or(QrllibError::FalconSigningFailed)?;
        *slot = (acc << (8 - acc_bits)) as u8;
        written += 1;
    }
    Ok(written)
}

const PRIVATE_KEY_HEADER: u8 = 0x50 + LOG_N as u8;
const FG_BITS: u32 = 5;
const NTRU_F_BITS: u32 = 8;

/// The byte length of a trim_i8 encoding at `bits` bits per coefficient.
const fn trim_i8_len(bits: u32) -> usize {
    (N * bits as usize).div_ceil(8)
}

/// Encodes (f, g, F) as the 2305-byte `CRYPTO_SECRETKEYBYTES` key: header
/// 0x5A, f and g at five bits per coefficient, F at eight. The caller
/// guarantees every coefficient fits its field.
pub(super) fn sk_encode(
    dst: &mut [u8; FALCON_1024_PRIVATE_KEY_SIZE],
    f: &SmallPoly,
    g: &SmallPoly,
    big_f: &SmallPoly,
) {
    dst[0] = PRIVATE_KEY_HEADER;
    let mut offset = HEADER_SIZE;
    offset += trim_i8_encode(&mut dst[offset..], f, FG_BITS);
    offset += trim_i8_encode(&mut dst[offset..], g, FG_BITS);
    offset += trim_i8_encode(&mut dst[offset..], big_f, NTRU_F_BITS);
    debug_assert_eq!(offset, FALCON_1024_PRIVATE_KEY_SIZE);
}

/// Decodes a `CRYPTO_SECRETKEYBYTES` key into (f, g, F), refusing a wrong
/// length or header and the excluded field value -2^(bits-1).
pub(super) fn sk_decode(src: &[u8]) -> Result<(SmallPoly, SmallPoly, SmallPoly)> {
    if src.len() != FALCON_1024_PRIVATE_KEY_SIZE {
        return Err(QrllibError::InvalidFalconPrivateKeySize(
            src.len(),
            FALCON_1024_PRIVATE_KEY_SIZE,
        ));
    }
    if src[0] != PRIVATE_KEY_HEADER {
        return Err(QrllibError::InvalidFalconPrivateKey);
    }
    let mut offset = HEADER_SIZE;
    let f = trim_i8_decode(&src[offset..], FG_BITS)?;
    offset += trim_i8_len(FG_BITS);
    let g = trim_i8_decode(&src[offset..], FG_BITS)?;
    offset += trim_i8_len(FG_BITS);
    let big_f = trim_i8_decode(&src[offset..], NTRU_F_BITS)?;
    Ok((f, g, big_f))
}

/// Reference `trim_i8_encode`. For n = 1024 both widths fill whole bytes.
fn trim_i8_encode(dst: &mut [u8], p: &SmallPoly, bits: u32) -> usize {
    let out_len = trim_i8_len(bits);
    if bits == 8 {
        for (d, &x) in dst.iter_mut().zip(p) {
            *d = x as i8 as u8;
        }
        return out_len;
    }
    let mask = (1_u32 << bits) - 1;
    let mut acc = 0_u32;
    let mut acc_bits = 0;
    let mut written = 0;
    for &x in p {
        acc = (acc << bits) | ((x as u32) & mask);
        acc_bits += bits;
        while acc_bits >= 8 {
            acc_bits -= 8;
            dst[written] = (acc >> acc_bits) as u8;
            written += 1;
        }
    }
    out_len
}

/// Reference `trim_i8_decode`.
fn trim_i8_decode(src: &[u8], bits: u32) -> Result<SmallPoly> {
    let mut p = [0_i32; N];
    if bits == 8 {
        for (c, &b) in p.iter_mut().zip(&src[..N]) {
            let x = b as i8;
            if x == i8::MIN {
                return Err(QrllibError::InvalidFalconPrivateKey);
            }
            *c = i32::from(x);
        }
        return Ok(p);
    }

    let mask = (1_u32 << bits) - 1;
    let sign_bit = 1_i32 << (bits - 1);
    let full_range = 1_i32 << bits;
    let mut acc = 0_u32;
    let mut acc_bits = 0;
    let mut consumed = 0;
    for c in p.iter_mut() {
        while acc_bits < bits {
            acc = (acc << 8) | u32::from(src[consumed]);
            consumed += 1;
            acc_bits += 8;
        }
        acc_bits -= bits;
        let mut x = ((acc >> acc_bits) & mask) as i32;
        if x >= sign_bit {
            if x == sign_bit {
                return Err(QrllibError::InvalidFalconPrivateKey);
            }
            x -= full_range;
        }
        *c = x;
        acc &= (1_u32 << acc_bits).wrapping_sub(1);
    }
    Ok(p)
}

const PUBLIC_KEY_HEADER: u8 = LOG_N as u8;

/// Encodes h as `crypto_sign_keypair` does: header 0x0A, then 14-bit packing.
pub(super) fn pk_encode(dst: &mut [u8; FALCON_1024_PUBLIC_KEY_SIZE], h: &RingElement) {
    dst[0] = PUBLIC_KEY_HEADER;
    poly_byte_encode(&mut dst[HEADER_SIZE..], h);
}

/// Decodes a `CRYPTO_PUBLICKEYBYTES` key: header 0x0A, then 1024 14-bit
/// coefficients, each below q.
pub(super) fn pk_decode(src: &[u8]) -> Result<RingElement> {
    if src.len() != FALCON_1024_PUBLIC_KEY_SIZE {
        return Err(QrllibError::InvalidFalconPublicKeySize(
            src.len(),
            FALCON_1024_PUBLIC_KEY_SIZE,
        ));
    }
    if src[0] != PUBLIC_KEY_HEADER {
        return Err(QrllibError::InvalidFalconPublicKeyEncoding);
    }
    debug_assert_eq!(src.len() - HEADER_SIZE, ENCODING_SIZE_14);
    poly_byte_decode(&src[HEADER_SIZE..]).ok_or(QrllibError::InvalidFalconPublicKeyEncoding)
}

/// Signature header of the reference NIST API (`nist.c`): 0x20 + logn.
const SIGNATURE_HEADER: u8 = 0x20 + LOG_N as u8;
const SIGNED_MESSAGE_LENGTH_SIZE: usize = 2;
pub(super) const SIGNED_MESSAGE_PREFIX_SIZE: usize = SIGNED_MESSAGE_LENGTH_SIZE + NONCE_SIZE;
/// The room PQClean's `crypto_sign` gives `comp_encode`: `CRYPTO_BYTES` less
/// the length prefix, the nonce and the signature header byte.
pub(super) const MAX_COMPRESSED_SIGNATURE_SIZE: usize =
    FALCON_1024_MAX_SIGNED_MESSAGE_OVERHEAD - SIGNED_MESSAGE_PREFIX_SIZE - HEADER_SIZE;

/// Builds the reference `crypto_sign` output: two-byte big-endian signature
/// length, nonce, message, header byte, compressed s2. Fails rather than
/// retries when the compressed polynomial does not fit, as the reference
/// does.
pub(super) fn signed_message_encode(
    nonce: &[u8; NONCE_SIZE],
    message: &[u8],
    s2: &SmallPoly,
) -> Result<Vec<u8>> {
    let mut sig = [0_u8; HEADER_SIZE + MAX_COMPRESSED_SIGNATURE_SIZE];
    sig[0] = SIGNATURE_HEADER;
    let written = compressed_encode(&mut sig[HEADER_SIZE..], s2)?;
    let sig_len = HEADER_SIZE + written;

    let mut sm = Vec::with_capacity(SIGNED_MESSAGE_PREFIX_SIZE + message.len() + sig_len);
    sm.extend_from_slice(&(sig_len as u16).to_be_bytes());
    sm.extend_from_slice(nonce);
    sm.extend_from_slice(message);
    sm.extend_from_slice(&sig[..sig_len]);
    Ok(sm)
}

/// Parses a signed message with the checks of the reference
/// `crypto_sign_open`; the compressed polynomial must consume the signature
/// field exactly. Returns (nonce, message, s2) borrowing from `sm`.
pub(super) fn signed_message_decode(sm: &[u8]) -> Result<(&[u8], &[u8], SmallPoly)> {
    if sm.len() < SIGNED_MESSAGE_PREFIX_SIZE {
        return Err(QrllibError::FalconSignatureTooShort(SIGNED_MESSAGE_PREFIX_SIZE));
    }
    let sig_len = (usize::from(sm[0]) << 8) | usize::from(sm[1]);
    if sig_len > sm.len() - SIGNED_MESSAGE_PREFIX_SIZE {
        return Err(QrllibError::InvalidFalconSignature);
    }
    let msg_len = sm.len() - SIGNED_MESSAGE_PREFIX_SIZE - sig_len;

    let nonce = &sm[SIGNED_MESSAGE_LENGTH_SIZE..SIGNED_MESSAGE_PREFIX_SIZE];
    let message = &sm[SIGNED_MESSAGE_PREFIX_SIZE..SIGNED_MESSAGE_PREFIX_SIZE + msg_len];
    let sig = &sm[SIGNED_MESSAGE_PREFIX_SIZE + msg_len..];

    if sig_len < HEADER_SIZE || sig[0] != SIGNATURE_HEADER {
        return Err(QrllibError::InvalidFalconSignature);
    }
    let (s2, consumed) = compressed_decode(&sig[HEADER_SIZE..])?;
    if consumed != sig_len - HEADER_SIZE {
        return Err(QrllibError::InvalidFalconSignature);
    }
    Ok((nonce, message, s2))
}

/// Header byte of the compressed format of the reference library API
/// (`falcon.h`): 0x30 + logn.
const DETACHED_SIGNATURE_HEADER: u8 = 0x30 + LOG_N as u8;
pub(super) const DETACHED_SIGNATURE_PREFIX_SIZE: usize = HEADER_SIZE + NONCE_SIZE;

/// Builds a `FALCON_SIG_COMPRESSED` signature: header, nonce, compressed
/// polynomial, nothing more.
pub(super) fn detached_signature_encode(
    nonce: &[u8; NONCE_SIZE],
    s2: &SmallPoly,
) -> Result<Vec<u8>> {
    let mut sig = [0_u8; FALCON_1024_MAX_SIGNATURE_SIZE];
    sig[0] = DETACHED_SIGNATURE_HEADER;
    sig[HEADER_SIZE..DETACHED_SIGNATURE_PREFIX_SIZE].copy_from_slice(nonce);
    let written = compressed_encode(&mut sig[DETACHED_SIGNATURE_PREFIX_SIZE..], s2)?;
    Ok(sig[..DETACHED_SIGNATURE_PREFIX_SIZE + written].to_vec())
}

/// Parses a compressed-format signature with the checks of the reference
/// `falcon_verify`: header byte, the nonce, and a compressed polynomial
/// consuming exactly the remaining bytes. The zero-padded
/// falcon-padded-1024 form is therefore refused. Returns (nonce, s2).
pub(super) fn detached_signature_decode(sig: &[u8]) -> Result<(&[u8], SmallPoly)> {
    if sig.len() < DETACHED_SIGNATURE_PREFIX_SIZE {
        return Err(QrllibError::FalconSignatureTooShort(DETACHED_SIGNATURE_PREFIX_SIZE));
    }
    if sig[0] != DETACHED_SIGNATURE_HEADER {
        return Err(QrllibError::InvalidFalconSignature);
    }
    let (s2, consumed) = compressed_decode(&sig[DETACHED_SIGNATURE_PREFIX_SIZE..])?;
    if consumed != sig.len() - DETACHED_SIGNATURE_PREFIX_SIZE {
        return Err(QrllibError::InvalidFalconSignature);
    }
    Ok((&sig[HEADER_SIZE..DETACHED_SIGNATURE_PREFIX_SIZE], s2))
}
