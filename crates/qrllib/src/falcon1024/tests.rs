//! Falcon-1024 tests, ported from go-qrllib `crypto/falcon1024` and
//! `crypto/internal/falcon1024`. The interoperability anchors are:
//!
//! - the reference `verify_raw` vectors and `test_falcon.c` key components;
//! - the full round-3 KAT transcript (`falcon1024-KAT.rsp`), rebuilt through
//!   the NIST DRBG and checked by its SHA-1, plus the compressed signature of
//!   every case;
//! - the signature-encoding and weak-key vectors shared with go-qrllib.

use super::*;
use crate::QrllibError;
use aes::Aes256;
use aes::cipher::{Array, BlockCipherEncrypt, KeyInit};
use serde::Deserialize;
use sha1::Sha1;
use sha2::{Digest, Sha256};

const VERIFY_RAW_KAT: &str = include_str!("testdata/verify_raw_kat.json");
const SIGN_DYN_KAT: &str = include_str!("testdata/sign_dyn_round3_kat.json");
const REFERENCE_NTRU: &str = include_str!("testdata/reference_ntru_1024.json");
const SIGNATURE_ENCODING: &str = include_str!("testdata/signature_encoding_vectors.json");
const WEAK_KEYS: &str = include_str!("testdata/weak_public_key_vectors.json");

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifyRawFixture {
    public_key_hex: String,
    tests: Vec<VerifyRawVector>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifyRawVector {
    nonce_hex: String,
    message: String,
    signature_hex: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignDynVector {
    count: usize,
    compressed_length: usize,
    #[serde(rename = "compressedSHA256")]
    compressed_sha256: String,
}

#[derive(Deserialize)]
struct ReferenceNtru {
    f: String,
    g: String,
    #[serde(rename = "F")]
    big_f: String,
    #[serde(rename = "G")]
    big_g: String,
}

fn verify_raw_fixture() -> VerifyRawFixture {
    let fixture: VerifyRawFixture = serde_json::from_str(VERIFY_RAW_KAT).expect("verify_raw KAT");
    assert_eq!(fixture.tests.len(), 10);
    fixture
}

fn reference_public_key_bytes() -> Vec<u8> {
    hex::decode(verify_raw_fixture().public_key_hex).expect("hex")
}

fn small_poly_from_hex(s: &str) -> SmallPoly {
    let bytes = hex::decode(s).expect("hex");
    assert_eq!(bytes.len(), N);
    let mut p = [0_i32; N];
    for (c, b) in p.iter_mut().zip(bytes) {
        *c = i32::from(b as i8);
    }
    p
}

fn reference_ntru() -> (SmallPoly, SmallPoly, SmallPoly, SmallPoly) {
    let r: ReferenceNtru = serde_json::from_str(REFERENCE_NTRU).expect("reference ntru");
    (
        small_poly_from_hex(&r.f),
        small_poly_from_hex(&r.g),
        small_poly_from_hex(&r.big_f),
        small_poly_from_hex(&r.big_g),
    )
}

/// Replays fixed bytes as a randomness source, failing once they run out.
struct Replay<'a> {
    bytes: &'a [u8],
}

impl RandomSource for Replay<'_> {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
        if dest.len() > self.bytes.len() {
            return Err(QrllibError::Randomness("replay exhausted".into()));
        }
        let (head, tail) = self.bytes.split_at(dest.len());
        dest.copy_from_slice(head);
        self.bytes = tail;
        Ok(())
    }
}

fn replay(bytes: &[u8]) -> Replay<'_> {
    Replay { bytes }
}

fn seed_key(byte: u8) -> PrivateKey {
    PrivateKey::from_seed(&[byte; FALCON_1024_SEED_SIZE]).expect("key from seed")
}

// ---------------------------------------------------------------------------
// NIST KAT DRBG (AES-256 CTR_DRBG without derivation function, rng.c).
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct NistDrbg {
    key: [u8; 32],
    v: [u8; 16],
}

impl NistDrbg {
    fn new(entropy: &[u8]) -> Self {
        let mut d = Self { key: [0; 32], v: [0; 16] };
        d.update(Some(entropy));
        d
    }

    fn increment(&mut self) {
        for b in self.v.iter_mut().rev() {
            *b = b.wrapping_add(1);
            if *b != 0 {
                return;
            }
        }
    }

    fn encrypt_v(cipher: &Aes256, v: &[u8; 16]) -> [u8; 16] {
        let mut block = Array::from(*v);
        cipher.encrypt_block(&mut block);
        block.into()
    }

    fn update(&mut self, provided: Option<&[u8]>) {
        let cipher = Aes256::new_from_slice(&self.key).expect("key");
        let mut tmp = [0_u8; 48];
        for i in 0..3 {
            self.increment();
            tmp[16 * i..16 * i + 16].copy_from_slice(&Self::encrypt_v(&cipher, &self.v));
        }
        if let Some(provided) = provided {
            for (t, p) in tmp.iter_mut().zip(provided) {
                *t ^= p;
            }
        }
        self.key.copy_from_slice(&tmp[..32]);
        self.v.copy_from_slice(&tmp[32..]);
    }

    fn read(&mut self, mut buf: &mut [u8]) {
        let cipher = Aes256::new_from_slice(&self.key).expect("key");
        while !buf.is_empty() {
            self.increment();
            let block = Self::encrypt_v(&cipher, &self.v);
            let n = buf.len().min(16);
            buf[..n].copy_from_slice(&block[..n]);
            buf = &mut buf[n..];
        }
        self.update(None);
    }
}

/// Every call is one `randombytes` invocation, which matters because the
/// DRBG reseeds itself after each one.
impl RandomSource for NistDrbg {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
        self.read(dest);
        Ok(())
    }
}

fn kat_entropy() -> [u8; 48] {
    core::array::from_fn(|i| i as u8)
}

// ---------------------------------------------------------------------------
// Reference vectors.
// ---------------------------------------------------------------------------

#[test]
fn verify_raw_reference_vectors() {
    let fixture = verify_raw_fixture();
    let public_key = PublicKey::from_bytes(&hex::decode(&fixture.public_key_hex).unwrap()).unwrap();
    for tc in &fixture.tests {
        let nonce = hex::decode(&tc.nonce_hex).unwrap();
        let sig = hex::decode(&tc.signature_hex).unwrap();
        assert_eq!(sig.len(), 1 + 2 * N);
        assert_eq!(sig[0], LOG_N as u8);
        let mut s2 = [0_i32; N];
        for (i, c) in s2.iter_mut().enumerate() {
            *c = i32::from(i16::from_be_bytes([sig[1 + 2 * i], sig[2 + 2 * i]]));
        }
        let c0 = hash_to_point(&mut shake256_reader(&[&nonce, tc.message.as_bytes()]));
        assert!(verify_raw(&c0, &s2, &public_key.h_ntt), "{}", tc.message);
    }
}

#[test]
fn reference_key_components() {
    let (f, g, big_f, big_g) = reference_ntru();
    let want = reference_public_key_bytes();

    let h = compute_public(&f, &g).expect("invertible f");
    let public_key = PublicKey::from_h(&h);
    assert_eq!(public_key.as_bytes()[..], want[..]);
    assert_eq!(pk_decode(&want).unwrap(), h);

    assert_eq!(complete_private(&f, &g, &big_f).expect("G"), big_g);
    assert!(ntru_equation_holds(&f, &g, &big_f, &big_g));

    // Signing with the reference key produces signatures the reference
    // public key accepts.
    let key = PrivateKey::from_components(f, g, big_f, big_g, &h);
    for (message, seed) in [
        ("reference sign tree sample 0", "sign tree rng 0"),
        ("reference sign tree sample 1", "sign tree rng 1"),
    ] {
        let c0 = hash_to_point(&mut shake256_reader(&[message.as_bytes()]));
        let s2 = sign(&mut shake256_reader(&[seed.as_bytes()]), &key.inner, &c0).unwrap();
        assert!(verify_raw(&c0, &s2, &public_key.h_ntt));
    }
}

fn write_line(h: &mut Sha1, s: &str) {
    Digest::update(h, s.as_bytes());
    Digest::update(h, b"\n");
}

fn write_hex_line(h: &mut Sha1, prefix: &str, data: &[u8]) {
    Digest::update(h, prefix.as_bytes());
    Digest::update(h, hex::encode_upper(data).as_bytes());
    Digest::update(h, b"\n");
}

/// Rebuilds the round-3 KAT transcript the way the NIST KAT generator does
/// (the DRBG stands in for randombytes; key generation draws its seed from
/// it, and signing draws the nonce and then the sampler seed) and checks the
/// SHA-1 of `KAT/falcon1024-KAT.rsp` in falcon-round3.zip.
#[test]
fn round3_kat_digest() {
    let mut drbg = NistDrbg::new(&kat_entropy());
    let mut h = Sha1::new();
    write_line(&mut h, "# Falcon-1024");
    write_line(&mut h, "");

    for count in 0..100 {
        let mut seed = [0_u8; 48];
        drbg.read(&mut seed);
        let mut msg = vec![0_u8; 33 * (count + 1)];
        drbg.read(&mut msg);

        let outer = drbg.clone();
        let mut inner = NistDrbg::new(&seed);
        let key = PrivateKey::generate_with_rng(&mut inner).unwrap();
        let public_key = key.public_key();
        let sm = key.sign_with_rng(&mut inner, &msg).unwrap();
        assert!(sm.len() <= msg.len() + FALCON_1024_MAX_SIGNED_MESSAGE_OVERHEAD);
        assert_eq!(open(&public_key, &sm).unwrap(), msg, "count {count}");
        drbg = outer;

        write_line(&mut h, &format!("count = {count}"));
        write_hex_line(&mut h, "seed = ", &seed);
        write_line(&mut h, &format!("mlen = {}", msg.len()));
        write_hex_line(&mut h, "msg = ", &msg);
        write_hex_line(&mut h, "pk = ", public_key.as_bytes());
        write_hex_line(&mut h, "sk = ", &key.to_bytes().unwrap()[..]);
        write_line(&mut h, &format!("smlen = {}", sm.len()));
        write_hex_line(&mut h, "sm = ", &sm);
        write_line(&mut h, "");
    }

    assert_eq!(hex::encode(h.finalize()), "affdeb3aa83bf9a2039fa9c17d65fd3e3b9828e2");
}

/// Drives `count` KAT cases, handing each case's key, hashed point and
/// sampler SHAKE stream to `f`.
fn for_each_round3_kat_sign_input(
    count: usize,
    mut f: impl FnMut(usize, &PrivateKey, &RingElement, &mut ShakeReader),
) {
    let mut drbg = NistDrbg::new(&kat_entropy());
    for i in 0..count {
        let mut seed = [0_u8; 48];
        drbg.read(&mut seed);
        let mut msg = vec![0_u8; 33 * (i + 1)];
        drbg.read(&mut msg);

        let outer = drbg.clone();
        let mut inner = NistDrbg::new(&seed);
        let mut key_seed = [0_u8; 48];
        inner.read(&mut key_seed);
        let key = PrivateKey::from_seed(&key_seed).unwrap();
        let mut nonce = [0_u8; NONCE_SIZE];
        inner.read(&mut nonce);
        let c0 = hash_to_point(&mut shake256_reader(&[&nonce, &msg]));
        let mut sign_seed = [0_u8; 48];
        inner.read(&mut sign_seed);
        f(i, &key, &c0, &mut shake256_reader(&[&sign_seed]));
        drbg = outer;
    }
}

/// Pins the compressed s2 of every KAT case so a failure names the case.
#[test]
fn round3_kat_sign_dyn_vectors() {
    let vectors: Vec<SignDynVector> = serde_json::from_str(SIGN_DYN_KAT).unwrap();
    assert_eq!(vectors.len(), 100);
    for_each_round3_kat_sign_input(vectors.len(), |count, key, c0, rng| {
        let tc = &vectors[count];
        assert_eq!(tc.count, count);
        let s2 = sign(rng, &key.inner, c0).unwrap();
        assert!(verify_raw(c0, &s2, &key.inner.public.h_ntt));
        let mut comp = vec![0_u8; codec::MAX_COMPRESSED_SIGNATURE_SIZE];
        let written = codec::compressed_encode(&mut comp, &s2).unwrap();
        assert_eq!(written, tc.compressed_length, "count {count}");
        assert_eq!(
            hex::encode(Sha256::digest(&comp[..written])),
            tc.compressed_sha256,
            "count {count}"
        );
    });
}

/// With the KAT randomness, a detached signature carries the nonce and
/// polynomial of the official signed message.
#[test]
fn detached_signature_matches_round3_kat_signed_messages() {
    let mut drbg = NistDrbg::new(&kat_entropy());
    for count in 0..8 {
        let mut seed = [0_u8; 48];
        drbg.read(&mut seed);
        let mut msg = vec![0_u8; 33 * (count + 1)];
        drbg.read(&mut msg);

        let outer = drbg.clone();
        let mut inner = NistDrbg::new(&seed);
        let key = PrivateKey::generate_with_rng(&mut inner).unwrap();
        let signing = inner.clone();
        let sm = key.sign_with_rng(&mut inner, &msg).unwrap();
        let mut inner = signing;
        let sig = key.sign_detached_with_rng(&mut inner, &msg).unwrap();
        assert_eq!(sig, detached_from_signed_message(&sm, msg.len()), "count {count}");
        assert!(verify(&key.public_key(), &msg, &sig));
        drbg = outer;
    }
}

fn detached_from_signed_message(sm: &[u8], msg_len: usize) -> Vec<u8> {
    let sig_offset = codec::SIGNED_MESSAGE_PREFIX_SIZE + msg_len;
    assert_eq!(sm[sig_offset], 0x2A);
    let mut sig = vec![0x3A];
    sig.extend_from_slice(&sm[2..codec::SIGNED_MESSAGE_PREFIX_SIZE]);
    sig.extend_from_slice(&sm[sig_offset + 1..]);
    sig
}

// ---------------------------------------------------------------------------
// Encodings and the public API.
// ---------------------------------------------------------------------------

#[test]
fn private_key_encoding_round_trip() {
    let seed: Vec<u8> = (0..48).collect();
    let key = PrivateKey::from_seed(&seed).unwrap();
    let sk = key.to_bytes().unwrap();
    assert_eq!(sk.len(), FALCON_1024_PRIVATE_KEY_SIZE);
    assert_eq!(sk[0], 0x5A);

    let decoded = PrivateKey::from_bytes(&sk[..]).unwrap();
    assert!(decoded == key);
    assert_eq!(decoded.public_key(), key.public_key());

    // The decoded key signs identically: G and the expanded basis are
    // recomputed from f, g and F as the reference crypto_sign does.
    let randomness = [0x5C_u8; NONCE_SIZE + FALCON_1024_SEED_SIZE];
    let msg = b"falcon-1024 private key encoding";
    assert_eq!(
        decoded.sign_with_rng(&mut replay(&randomness), msg).unwrap(),
        key.sign_with_rng(&mut replay(&randomness), msg).unwrap()
    );

    let mut zero_f = sk.to_vec();
    zero_f[1..1 + 640].fill(0);
    let mut bad_header = sk.to_vec();
    bad_header[0] ^= 0xFF;
    let mut long = sk.to_vec();
    long.push(0);
    for bad in [&[][..], &sk[..FALCON_1024_PRIVATE_KEY_SIZE - 1], &long, &bad_header, &zero_f] {
        assert!(PrivateKey::from_bytes(bad).is_err());
    }
    for len in [0, 47, 49] {
        assert!(matches!(
            PrivateKey::from_seed(&vec![0; len]),
            Err(QrllibError::InvalidFalconSeedSize(l, 48)) if l == len
        ));
    }
}

#[test]
fn excluded_trim_i8_values_are_refused() {
    let key = seed_key(0);
    let sk = key.to_bytes().unwrap();
    // F is stored one signed byte per coefficient; -128 is excluded.
    let mut bad_f = sk.to_vec();
    bad_f[1 + 640 + 640] = 0x80;
    assert!(matches!(PrivateKey::from_bytes(&bad_f), Err(QrllibError::InvalidFalconPrivateKey)));
    // f is stored at five bits per coefficient; 0b10000 (-16) is excluded.
    let mut bad_small = sk.to_vec();
    bad_small[1] = (bad_small[1] & 0x07) | 0x80;
    assert!(matches!(
        PrivateKey::from_bytes(&bad_small),
        Err(QrllibError::InvalidFalconPrivateKey)
    ));
}

#[test]
fn sign_draws_nonce_then_seed() {
    let key = PrivateKey::from_seed(&[0; 48]).unwrap();
    let randomness: Vec<u8> = (1..=(NONCE_SIZE + FALCON_1024_SEED_SIZE + 1) as u8).collect();
    let mut source = replay(&randomness);
    let msg = b"falcon-1024 randomness order";
    let sm = key.sign_with_rng(&mut source, msg).unwrap();
    assert_eq!(source.bytes.len(), 1, "sign consumes exactly nonce + seed");
    assert_eq!(&sm[2..42], &randomness[..NONCE_SIZE]);
    assert_eq!(&sm[42..42 + msg.len()], msg);
    let sig_len = usize::from(u16::from_be_bytes([sm[0], sm[1]]));
    assert_eq!(sig_len, sm.len() - 42 - msg.len());
    assert_eq!(sm[42 + msg.len()], 0x2A);

    for short in [0, NONCE_SIZE - 1, NONCE_SIZE, NONCE_SIZE + FALCON_1024_SEED_SIZE - 1] {
        assert!(matches!(
            key.sign_with_rng(&mut replay(&randomness[..short]), msg),
            Err(QrllibError::Randomness(_))
        ));
    }
}

#[test]
fn open_accepts_valid_and_rejects_malformed() {
    let key = seed_key(0);
    let public_key = key.public_key();
    let other = seed_key(1).public_key();
    let randomness = [0xA5_u8; NONCE_SIZE + FALCON_1024_SEED_SIZE];

    for msg in [&b""[..], b"x", &b"falcon-1024 open ".repeat(50)] {
        let sm = key.sign_with_rng(&mut replay(&randomness), msg).unwrap();
        assert_eq!(open(&public_key, &sm).unwrap(), msg);
        assert!(open(&other, &sm).is_err());
    }

    let msg = b"falcon-1024 open rejects";
    let sm = key.sign_with_rng(&mut replay(&randomness), msg).unwrap();
    let sig_offset = 42 + msg.len();
    let mutate = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut v = sm.clone();
        f(&mut v);
        v
    };
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("shorter than the prefix", sm[..41].to_vec()),
        ("prefix only", sm[..42].to_vec()),
        ("signature length beyond the end", mutate(&|v| v[1] += 1)),
        ("signature length too small", mutate(&|v| v[1] -= 1)),
        ("bad signature header", mutate(&|v| v[sig_offset] ^= 0x10)),
        (
            "extra byte inside the signature",
            mutate(&|v| {
                let len = u16::from_be_bytes([v[0], v[1]]) + 1;
                v[..2].copy_from_slice(&len.to_be_bytes());
                v.push(0);
            }),
        ),
        ("extra byte after the signature", mutate(&|v| v.push(0))),
        ("truncated signature", sm[..sm.len() - 1].to_vec()),
        ("flipped nonce bit", mutate(&|v| v[2] ^= 1)),
        ("flipped message bit", mutate(&|v| v[42] ^= 1)),
        ("flipped signature bit", mutate(&|v| *v.last_mut().unwrap() ^= 0x80)),
    ];
    for (name, bad) in cases {
        assert!(open(&public_key, &bad).is_err(), "open accepted {name}");
    }
    assert!(matches!(open(&public_key, &sm[..41]), Err(QrllibError::FalconSignatureTooShort(42))));
}

#[test]
fn detached_signatures() {
    let key = seed_key(0);
    let public_key = key.public_key();
    let other = seed_key(1).public_key();
    let randomness: Vec<u8> =
        (0..NONCE_SIZE + FALCON_1024_SEED_SIZE).map(|i| (3 * i) as u8).collect();

    for msg in [&b""[..], b"x", &b"falcon-1024 detached ".repeat(40)] {
        let mut source = replay(&randomness);
        let sig = key.sign_detached_with_rng(&mut source, msg).unwrap();
        assert!(source.bytes.is_empty());
        assert!(sig.len() > codec::DETACHED_SIGNATURE_PREFIX_SIZE);
        assert!(sig.len() <= FALCON_1024_MAX_SIGNATURE_SIZE);
        assert_eq!(sig[0], 0x3A);
        assert_eq!(&sig[1..41], &randomness[..NONCE_SIZE]);
        assert!(verify(&public_key, msg, &sig));
        assert!(!verify(&other, msg, &sig));

        let sm = key.sign_with_rng(&mut replay(&randomness), msg).unwrap();
        assert_eq!(sig, detached_from_signed_message(&sm, msg.len()));
    }

    let msg = b"falcon-1024 detached rejects";
    let sig = key.sign_detached_with_rng(&mut replay(&randomness), msg).unwrap();
    let mutate = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut v = sig.clone();
        f(&mut v);
        v
    };
    let cases: Vec<(&str, &[u8], Vec<u8>)> = vec![
        ("empty signature", msg, vec![]),
        ("shorter than the nonce", msg, sig[..40].to_vec()),
        ("no polynomial", msg, sig[..41].to_vec()),
        ("signed-message header", msg, mutate(&|v| v[0] = 0x2A)),
        ("constant-time format header", msg, mutate(&|v| v[0] = 0x5A)),
        ("degree-512 header", msg, mutate(&|v| v[0] = 0x39)),
        ("trailing byte", msg, mutate(&|v| v.push(0))),
        ("truncated polynomial", msg, sig[..sig.len() - 1].to_vec()),
        ("flipped nonce bit", msg, mutate(&|v| v[1] ^= 1)),
        ("flipped polynomial bit", msg, mutate(&|v| *v.last_mut().unwrap() ^= 0x80)),
        ("different message", b"falcon-1024 detached reject", sig.clone()),
    ];
    for (name, m, bad) in cases {
        assert!(!verify(&public_key, m, &bad), "verify accepted {name}");
    }
    assert!(matches!(
        verify_detached(&public_key, msg, &sig[..40]),
        Err(QrllibError::FalconSignatureTooShort(41))
    ));

    for short in [0, NONCE_SIZE, NONCE_SIZE + FALCON_1024_SEED_SIZE - 1] {
        assert!(key.sign_detached_with_rng(&mut replay(&randomness[..short]), msg).is_err());
    }
}

#[test]
fn compressed_codec_edges() {
    // Every coefficient at its extremes round-trips; one beyond is refused.
    let mut s = [0_i32; N];
    for (i, c) in s.iter_mut().enumerate() {
        *c = match i % 4 {
            0 => 2047,
            1 => -2047,
            2 => 0,
            _ => -1,
        };
    }
    let mut buf = vec![0_u8; 8 * N];
    let written = codec::compressed_encode(&mut buf, &s).unwrap();
    let (decoded, consumed) = codec::compressed_decode(&buf[..written]).unwrap();
    assert_eq!(decoded, s);
    assert_eq!(consumed, written);

    s[0] = 2048;
    assert!(matches!(
        codec::compressed_encode(&mut buf, &s),
        Err(QrllibError::FalconSigningFailed)
    ));
    s[0] = 0;
    assert!(matches!(
        codec::compressed_encode(&mut buf[..10], &s),
        Err(QrllibError::FalconSigningFailed)
    ));

    // Negative zero: sign bit set, magnitude 0, terminator bit.
    let mut neg_zero = vec![0x80, 0x80];
    neg_zero.extend(std::iter::repeat_n(0, 2 * N));
    assert!(codec::compressed_decode(&neg_zero).is_err());
    // Truncated input.
    assert!(codec::compressed_decode(&buf[..written - 1]).is_err());
    // A magnitude above 2047 (sixteen zero unary bits).
    assert!(codec::compressed_decode(&[0x00, 0x00, 0x00, 0x00]).is_err());
}

#[test]
fn public_key_decoding() {
    let key = seed_key(7);
    let pk = key.public_key().to_bytes();
    assert_eq!(PublicKey::from_bytes(&pk).unwrap(), key.public_key());
    assert!(validate_falcon_public_key(&pk).is_ok());

    assert!(matches!(
        PublicKey::from_bytes(&pk[..1792]),
        Err(QrllibError::InvalidFalconPublicKeySize(1792, 1793))
    ));
    let mut bad_header = pk;
    bad_header[0] = 0x09;
    assert!(matches!(
        PublicKey::from_bytes(&bad_header),
        Err(QrllibError::InvalidFalconPublicKeyEncoding)
    ));
    // First coefficient set to q (0x3001 in the top 14 bits).
    let mut out_of_range = pk;
    out_of_range[1] = 0xC0;
    out_of_range[2] = (out_of_range[2] & 0x03) | 0x04;
    assert!(matches!(
        PublicKey::from_bytes(&out_of_range),
        Err(QrllibError::InvalidFalconPublicKeyEncoding)
    ));
}

#[test]
fn zeroize_lifecycle() {
    let mut key = seed_key(3);
    let public_key = key.public_key();
    let copy = PrivateKey::from_bytes(&key.to_bytes().unwrap()[..]).unwrap();
    assert!(copy == key);
    let sm = key.sign(b"before").unwrap();

    key.zeroize();
    assert!(key.is_zeroized());
    assert!(matches!(key.sign(b"after"), Err(QrllibError::FalconSecretKeyZeroized)));
    assert!(matches!(key.sign_detached(b"after"), Err(QrllibError::FalconSecretKeyZeroized)));
    assert!(matches!(key.to_bytes(), Err(QrllibError::FalconSecretKeyZeroized)));
    assert!(key.inner.raw.iter().all(|&b| b == 0));
    assert!(key.inner.tree.iter().all(|&x| x == 0.0));
    assert!(key != copy);
    assert!(copy != key);
    assert_eq!(key.public_key(), public_key);
    assert_eq!(open(&key.public_key(), &sm).unwrap(), b"before");
    key.zeroize();
    assert!(key.is_zeroized());
    assert_eq!(format!("{key:?}"), "PrivateKey { .. }");
}

#[test]
fn concurrent_signing_with_one_key() {
    let key = seed_key(9);
    let public_key = key.public_key();
    std::thread::scope(|scope| {
        for t in 0..4_u8 {
            let key = &key;
            let public_key = &public_key;
            scope.spawn(move || {
                for i in 0..4_u8 {
                    let msg = [t, i];
                    let sig = key.sign_detached(&msg).unwrap();
                    assert!(verify(public_key, &msg, &sig));
                }
            });
        }
    });
}

// ---------------------------------------------------------------------------
// Private-key import checks.
// ---------------------------------------------------------------------------

#[test]
fn import_rejects_inconsistent_ntru_solutions() {
    let key = seed_key(0);
    let sk = key.to_bytes().unwrap();
    let (f, g, big_f) = sk_decode(&sk[..]).unwrap();

    let encode = |big_f: &SmallPoly| {
        let mut raw = [0_u8; FALCON_1024_PRIVATE_KEY_SIZE];
        sk_encode(&mut raw, &f, &g, big_f);
        raw
    };
    // x*F (negacyclic shift), -F and f in place of F all derive the correct
    // public key but break f*G - g*F = q.
    let mut shifted = [0_i32; N];
    shifted[0] = -big_f[N - 1];
    shifted[1..].copy_from_slice(&big_f[..N - 1]);
    let negated = big_f.map(|x| -x);
    for (name, candidate) in [("x*F", shifted), ("-F", negated), ("f", f)] {
        let raw = encode(&candidate);
        let result = PrivateKey::from_bytes(&raw);
        assert!(matches!(result, Err(QrllibError::InvalidFalconPrivateKey)), "{name}: {result:?}");
    }
}

// ---------------------------------------------------------------------------
// Shared vectors.
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncodingVectorFile {
    public_key: String,
    message: String,
    vectors: Vec<EncodingVector>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncodingVector {
    name: String,
    kind: EncodingKind,
    bytes: String,
    expected: Verdict,
}

#[derive(Deserialize, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
enum EncodingKind {
    Detached,
    SignedMessage,
}

#[derive(Deserialize, PartialEq, Debug, Clone, Copy)]
#[serde(rename_all = "camelCase")]
enum Verdict {
    Valid,
    Invalid,
}

/// The signature acceptance set every QRL client must reproduce: exactly one
/// encoding per signature, the zero-padded forms refused.
#[test]
fn shared_signature_encoding_vectors() {
    let file: EncodingVectorFile = serde_json::from_str(SIGNATURE_ENCODING).unwrap();
    let public_key = PublicKey::from_bytes(&hex::decode(&file.public_key).unwrap()).unwrap();
    let message = hex::decode(&file.message).unwrap_or_else(|_| file.message.clone().into_bytes());
    assert!(!file.vectors.is_empty());
    for v in &file.vectors {
        let bytes = hex::decode(&v.bytes).unwrap();
        let accepted = match v.kind {
            EncodingKind::Detached => verify(&public_key, &message, &bytes),
            EncodingKind::SignedMessage => match open(&public_key, &bytes) {
                Ok(opened) => {
                    assert_eq!(opened, message, "{}", v.name);
                    true
                }
                Err(_) => false,
            },
        };
        assert_eq!(accepted, v.expected == Verdict::Valid, "{}", v.name);
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WeakKeyFile {
    multiplier_bound: u32,
    squared_norm_bound: u64,
    public_keys: Vec<WeakPublicKeyVector>,
    private_keys: Vec<WeakPrivateKeyVector>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WeakPublicKeyVector {
    name: String,
    pk: String,
    expected: PublicVerdict,
    multiplier: u32,
    squared_norm: u64,
}

#[derive(Deserialize, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
enum PublicVerdict {
    Strong,
    Weak,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WeakPrivateKeyVector {
    name: String,
    sk: String,
    expected: PrivateVerdict,
}

#[derive(Deserialize, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
enum PrivateVerdict {
    Valid,
    Weak,
    Invalid,
}

/// The weak-key rule vectors shared with go-qrllib: verdict, first
/// multiplier and squared norm for public keys, and the import verdict for
/// private keys.
#[test]
fn shared_weak_key_vectors() {
    let file: WeakKeyFile = serde_json::from_str(WEAK_KEYS).unwrap();
    assert_eq!(file.multiplier_bound, WEAK_KEY_MULTIPLIER_BOUND);
    assert_eq!(file.squared_norm_bound, WEAK_KEY_SQUARED_NORM_BOUND);
    assert!(file.public_keys.len() >= 10 && !file.private_keys.is_empty());

    for v in &file.public_keys {
        let pk = hex::decode(&v.pk).unwrap();
        let h = pk_decode(&pk).unwrap();
        let found = weak_public_key_multiplier(&h).unwrap_or((0, 0));
        assert_eq!(found, (v.multiplier, v.squared_norm), "{}", v.name);
        let result = PublicKey::from_bytes(&pk);
        match v.expected {
            PublicVerdict::Strong => assert!(result.is_ok(), "{}", v.name),
            PublicVerdict::Weak => assert!(
                matches!(
                    result,
                    Err(QrllibError::FalconWeakPublicKey { multiplier, squared_norm, bound })
                        if multiplier == v.multiplier
                            && squared_norm == v.squared_norm
                            && bound == (1 << 30) - u64::from(v.multiplier * v.multiplier)
                ),
                "{}",
                v.name
            ),
        }
        assert_eq!(validate_falcon_public_key(&pk).is_ok(), v.expected == PublicVerdict::Strong);
    }

    for v in &file.private_keys {
        let sk = hex::decode(&v.sk).unwrap();
        let result = PrivateKey::from_bytes(&sk);
        match v.expected {
            PrivateVerdict::Valid => assert!(result.is_ok(), "{}", v.name),
            PrivateVerdict::Weak => assert!(
                matches!(result, Err(QrllibError::FalconWeakPublicKey { .. })),
                "{}: {result:?}",
                v.name
            ),
            PrivateVerdict::Invalid => assert!(
                matches!(result, Err(QrllibError::InvalidFalconPrivateKey)),
                "{}: {result:?}",
                v.name
            ),
        }
    }
}

#[test]
fn constant_and_monomial_keys_are_weak() {
    for (index, value) in [(0, 1_u32), (0, 5000), (0, Q - 1), (17, 1), (1023, 6144)] {
        let mut h = [0_u32; N];
        h[index] = value;
        let mut pk = [0_u8; FALCON_1024_PUBLIC_KEY_SIZE];
        pk_encode(&mut pk, &h);
        assert!(matches!(
            validate_falcon_public_key(&pk),
            Err(QrllibError::FalconWeakPublicKey { .. })
        ));
    }
}

// ---------------------------------------------------------------------------
// Bounded loops.
// ---------------------------------------------------------------------------

/// Leaves far outside the sampler's domain (1/sigma huge) make BerExp
/// reject every draw, so the first coordinate exhausts its draw budget, the
/// rest of the tree walk spends nothing, and signing stops after one attempt
/// instead of spinning.
#[test]
fn sampler_budget_ends_signing() {
    let key = seed_key(0);
    let mut broken = PrivateKey::from_bytes(&key.to_bytes().unwrap()[..]).unwrap();
    broken.inner.tree.fill(1e10);

    let c0 = hash_to_point(&mut shake256_reader(&[b"spin"]));
    let mut prng = SamplerPrng::new();
    prng.init(&mut shake256_reader(&[b"sampler budget"]));
    assert!(sign_attempt(&mut sample_fft_point, &mut prng, &broken.inner, &c0).is_none());
    assert!(prng.exhausted);
    assert_eq!(prng.draws, u64::from(fft::MAX_SAMPLER_DRAWS));

    assert!(matches!(broken.sign(b"spin"), Err(QrllibError::FalconSigningFailed)));
}

/// NaN leaves are accepted by the sampler (a NaN converts to 0 in Rust), so
/// every attempt is rejected by the norm check and the attempt bound ends
/// signing.
#[test]
fn nan_tree_ends_signing() {
    let key = seed_key(0);
    let mut broken = PrivateKey::from_bytes(&key.to_bytes().unwrap()[..]).unwrap();
    broken.inner.tree.fill(f64::NAN);
    assert!(matches!(broken.sign(b"spin"), Err(QrllibError::FalconSigningFailed)));
}

#[test]
fn sampler_prng_refills_at_the_buffer_end() {
    let mut prng = SamplerPrng::new();
    prng.init(&mut shake256_reader(&[b"refill"]));
    let first: Vec<u8> = (0..512).map(|_| prng.read_byte()).collect();
    let next = prng.read_byte();
    let mut again = SamplerPrng::new();
    again.init(&mut shake256_reader(&[b"refill"]));
    let replayed: Vec<u8> = (0..513).map(|_| again.read_byte()).collect();
    assert_eq!(&replayed[..512], &first[..]);
    assert_eq!(replayed[512], next);
    // The second buffer is a fresh ChaCha20 batch, not a repeat.
    assert_ne!(&first[..64], &(0..64).map(|_| prng.read_byte()).collect::<Vec<_>>()[..]);
}

/// f = g makes the two resultants equal, so they are not coprime and the
/// deepest stage of the solver rejects the pair.
#[test]
fn solve_ntru_rejects_equal_f_and_g() {
    let mut f = [0_i32; N];
    f[0] = 3;
    f[1] = -2;
    f[5] = 1;
    assert!(ntru::solve_ntru(&f, &f).is_none());
}

/// For (f, g) inside the key-generation bounds the solver still rejects a
/// fraction of inputs at the intermediate depths; key generation retries.
/// The search is deterministic and small enough to run every time.
#[test]
fn solve_ntru_rejects_some_in_bound_pairs() {
    let mut rng = shake256_reader(&[b"ntru intermediate rejection"]);
    for _ in 0..400 {
        let f = sample_gaussian_polynomial(&mut rng);
        let g = sample_gaussian_polynomial(&mut rng);
        if squared_norm_exceeds_bound(&f, &g, KEYGEN_SQ_NORM_BOUND)
            || orthogonalized_norm_exceeds_bound(&f, &g, KEYGEN_B_NORM_BOUND)
            || compute_public(&f, &g).is_none()
        {
            continue;
        }
        if ntru::solve_ntru(&f, &g).is_none() {
            return;
        }
    }
    panic!("no in-bound (f, g) rejected by the solver within the search budget");
}

/// An F that does not come from the solver recomputes a G outside
/// [-127, 127], which the reference complete_private refuses.
#[test]
fn import_rejects_unrecoverable_g() {
    let key = seed_key(0);
    let sk = key.to_bytes().unwrap();
    let (f, g, mut big_f) = sk_decode(&sk[..]).unwrap();
    big_f[0] += if big_f[0] < 0 { 1 } else { -1 };
    assert!(complete_private(&f, &g, &big_f).is_none());
    let mut raw = [0_u8; FALCON_1024_PRIVATE_KEY_SIZE];
    sk_encode(&mut raw, &f, &g, &big_f);
    assert!(matches!(PrivateKey::from_bytes(&raw), Err(QrllibError::InvalidFalconPrivateKey)));
}

/// A basis that never yields a short vector exhausts the attempt loop.
#[test]
fn attempt_budget_ends_signing() {
    let key = seed_key(0);
    let mut broken = PrivateKey::from_bytes(&key.to_bytes().unwrap()[..]).unwrap();
    // Scaling b10 / b11 moves every lattice point far from the target.
    for x in broken.inner.b00.iter_mut().chain(broken.inner.b10.iter_mut()) {
        *x *= 64.0;
    }
    assert!(matches!(broken.sign(b"reject"), Err(QrllibError::FalconSigningFailed)));
}

#[test]
fn fpr_rint_rounds_half_to_even() {
    for (x, want) in [
        (0.5, 0),
        (1.5, 2),
        (2.5, 2),
        (-0.5, 0),
        (-1.5, -2),
        (-2.5, -2),
        (3.49, 3),
        (-3.51, -4),
        (4_503_599_627_370_497.0, 4_503_599_627_370_497),
        (-4_503_599_627_370_497.0, -4_503_599_627_370_497),
    ] {
        assert_eq!(fpr_rint(x), want, "{x}");
    }
}

// ---------------------------------------------------------------------------
// Pinned outputs shared with go-qrllib (key_derivation_test.go,
// sign_loop_test.go). Checking that signatures verify would not notice a
// change in key generation, sampling or signing arithmetic that still yields
// valid signatures; the digests do.
// ---------------------------------------------------------------------------

/// Two seeds whose key pair changes when x*y + z is fused into one
/// rounding (found on arm64 and amd64 v3 builds of go-qrllib). Rust never
/// fuses, so these pin the reference rounding on every target, wasm32
/// included.
#[test]
fn key_derivation_does_not_depend_on_architecture() {
    for (seed, public_digest, secret_digest) in [
        (
            "f0df1fb67e6c98493a8073308367acb59a14d8296b3849c3011e5a985f998a99df94a03c120d16898fa32fa8dd07ecb6",
            "de3a7e53632f67a6cd84c7a59ba1ec8b6aeb363e314fcdc46e60a9c89befd478",
            "a0c1fa34e6da969be4567a14089e4c4e61796d0d12613b047eb73ca4e474b7a1",
        ),
        (
            "f304a51b76fcfd80c4cdc27c617c3b41acdca39529af22adf1920f701827a4e377379ef484dea2521ea067feac23d591",
            "f14d7e7fcce2c5674f78ec46d730142cc30c15d64ae68f062608cc5edcaa9cbc",
            "ea55c41af57d01c0b9226389e791a3b6b0f9c3b8e83d5f712740bf19a8ab338e",
        ),
    ] {
        let key = PrivateKey::from_seed(&hex::decode(seed).unwrap()).unwrap();
        assert_eq!(hex::encode(Sha256::digest(key.public_key().as_bytes())), public_digest);
        assert_eq!(hex::encode(Sha256::digest(&key.to_bytes().unwrap()[..])), secret_digest);
    }
}

fn absorb_small_poly(digest: &mut Shake256, p: &SmallPoly) {
    let mut buf = [0_u8; 2 * N];
    for (chunk, &x) in buf.chunks_exact_mut(2).zip(p) {
        chunk.copy_from_slice(&(x as i16).to_le_bytes());
    }
    Update::update(digest, &buf);
}

fn finish_digest(digest: Shake256) -> String {
    use sha3::digest::XofReader;
    let mut out = [0_u8; 32];
    digest.finalize_xof().read(&mut out);
    hex::encode(out)
}

fn read_stream<const L: usize>(rng: &mut ShakeReader) -> [u8; L] {
    use sha3::digest::XofReader;
    let mut out = [0_u8; L];
    rng.read(&mut out);
    out
}

fn key_from_stream(rng: &mut ShakeReader) -> PrivateKey {
    let (f, g, big_f, big_g, h) = generate_key_components(rng);
    PrivateKey::from_components(f, g, big_f, big_g, &h)
}

/// 200 signatures by the first key of the keygen loop, all drawn from one
/// SHAKE stream, each absorbed as 1024 little-endian int16 values.
#[test]
fn sign_self_verify_loop_digest() {
    let key = key_from_stream(&mut shake256_reader(&[b"keygen :"]));
    let public_key = key.public_key();
    let mut rng = shake256_reader(&[b"sign :"]);
    let mut digest = Shake256::default();
    for i in 0..200 {
        let msg: [u8; 50] = read_stream(&mut rng);
        let c0 = hash_to_point(&mut shake256_reader(&[&msg]));
        let s2 = sign(&mut rng, &key.inner, &c0).unwrap();
        assert!(verify_raw(&c0, &s2, &public_key.h_ntt), "signature {i}");
        absorb_small_poly(&mut digest, &s2);
    }
    assert_eq!(
        finish_digest(digest),
        "250f93901c18fe41a1867869d25c0c10db32c35e10ee337f0d6ca3f73eee308a"
    );
}

/// Whether s2 is invertible modulo x^n + 1 and q.
fn is_invertible(s2: &SmallPoly) -> bool {
    let mut t = s2.map(field_from_small);
    ntt(&mut t);
    t.iter().all(|&x| x != 0)
}

/// Twelve key pairs from one SHAKE stream, each signing a message from the
/// same stream (re-signing until s2 is invertible), absorbed as the public
/// key followed by the signature.
#[test]
fn keygen_self_sign_loop_digest() {
    let mut rng = shake256_reader(&[b"keygen :"]);
    let mut digest = Shake256::default();
    for i in 0..12 {
        let key = key_from_stream(&mut rng);
        let public_key = key.public_key();
        let msg: [u8; 50] = read_stream(&mut rng);
        let c0 = hash_to_point(&mut shake256_reader(&[&msg]));
        let mut s2 = sign(&mut rng, &key.inner, &c0).unwrap();
        while !is_invertible(&s2) {
            s2 = sign(&mut rng, &key.inner, &c0).unwrap();
        }
        assert!(verify_raw(&c0, &s2, &public_key.h_ntt), "key {i}");
        Update::update(&mut digest, public_key.as_bytes());
        absorb_small_poly(&mut digest, &s2);
    }
    assert_eq!(
        finish_digest(digest),
        "72bcb4a3b250a8052d5f8069400ecb1f316d4fcacfdce850955cc64d1eff5b1f"
    );
}

#[test]
fn ldexp_one_matches_powers_of_two() {
    for (e, want) in [
        (0, 1.0),
        (3, 8.0),
        (-226, f64::from_bits((1023 - 226) << 52)),
        (-1074, f64::from_bits(1)),
        (-1075, 0.0),
        (1024, f64::INFINITY),
    ] {
        assert_eq!(ntru::ldexp_one(e).to_bits(), f64::to_bits(want), "{e}");
    }
}

#[test]
fn compressed_decode_and_encode_boundaries() {
    // Empty input fails on the first eight-bit read; one byte fails in the
    // unary run that follows it.
    assert!(codec::compressed_decode(&[]).is_err());
    assert!(codec::compressed_decode(&[0x00]).is_err());

    // 1023 zeros and one 128 take 9217 bits: 1152 whole bytes and a partial
    // last byte.
    let mut s = [0_i32; N];
    s[0] = 128;
    let mut buf = vec![0_u8; 2 * N];
    let written = codec::compressed_encode(&mut buf, &s).unwrap();
    assert_eq!(written, 1153);
    assert!(matches!(
        codec::compressed_encode(&mut buf[..1152], &s),
        Err(QrllibError::FalconSigningFailed)
    ));
    assert_eq!(codec::compressed_decode(&buf[..written]).unwrap(), (s, written));

    // A set padding bit in the partial last byte is refused.
    let mut padded = buf[..written].to_vec();
    padded[written - 1] |= 1;
    assert!(codec::compressed_decode(&padded).is_err());
}

#[test]
fn os_random_key_generation_and_debug_output() {
    let key = PrivateKey::generate().unwrap();
    let public_key = key.public_key();
    let debug = format!("{public_key:?}");
    assert!(debug.starts_with("PublicKey { raw: \"0a"));
    assert!(verify(&public_key, b"m", &key.sign_detached(b"m").unwrap()));

    let mut failing = replay(&[]);
    assert!(matches!(PrivateKey::generate_with_rng(&mut failing), Err(QrllibError::Randomness(_))));
    assert_eq!(format!("{:?}", OsRandom), "OsRandom");
}
