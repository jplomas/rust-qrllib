//! NIST ACVP ML-DSA-87 keyGen / sigGen / sigVer conformance tests (FIPS 204).
//!
//! Reads the merged vector files produced by `.github/acvp/merge_vectors.py`
//! (`keygen.json`, `siggen.json`, `sigver.json`) from the directory named by the
//! `ACVP_VECTORS_DIR` environment variable; when it is unset the tests log a
//! skip notice and pass. Lives in-crate alongside the Wycheproof harness so
//! the two FIPS 204 conformance suites share one location and one convention:
//! the primitive is exercised as the standard specifies, and key validation
//! is checked separately (here, that every NIST-generated public key passes
//! [`super::validate_mldsa_public_key`]). See `.github/acvp/README.md`.

use std::{env, fs, path::PathBuf};

use super::{
    K, ML_DSA_87_CRYPTO_SEED_SIZE, ML_DSA_87_PUBLIC_KEY_SIZE, ML_DSA_87_SECRET_KEY_SIZE,
    ML_DSA_87_SIGNATURE_SIZE, MlDsa87, PolyVecK, PolyVecL, PublicKey, RND_BYTES, TR_BYTES,
    context_prefix, crypto_sign_signature_internal, crypto_sign_verify_internal, pack_pk,
    poly_vec_k_add, poly_vec_k_cadd_q, poly_vec_k_inv_ntt_to_mont, poly_vec_k_power2_round,
    poly_vec_k_reduce, poly_vec_l_ntt, poly_vec_matrix_expand,
    poly_vec_matrix_point_wise_montgomery, unpack_sk, verify_bytes,
};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AcvpKeyGenVector {
    tc_id: u32,
    seed: String,
    pk: String,
    sk: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AcvpSigGenVector {
    tc_id: u32,
    deterministic: bool,
    signature_interface: String,
    sk: String,
    message: String,
    context: String,
    rnd: String,
    signature: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AcvpSigVerVector {
    tc_id: u32,
    signature_interface: String,
    pk: String,
    message: String,
    context: String,
    signature: String,
    test_passed: bool,
}

/// The domain prefix of the signature interface: `0x00 || |ctx| || ctx` for
/// the external interface, nothing for the internal one (`M'` as given).
fn interface_prefix(tc_id: u32, interface: &str, context: &[u8]) -> Vec<u8> {
    match interface {
        "external" => context_prefix(context).expect("ACVP context fits 255 bytes"),
        "internal" => Vec::new(),
        //coverage:ignore start reason=defensively-unreachable
        other => panic!("tc{tc_id}: unsupported signature interface {other:?}"),
        //coverage:ignore end
    }
}

/// Rebuilds the public key a secret key belongs to: `t1` is the high part of
/// `A*s1 + s2`, as in key generation (go-qrllib `acvpPublicKeyFromSecretKey`).
fn public_key_from_secret_key(
    secret_key: &[u8; ML_DSA_87_SECRET_KEY_SIZE],
) -> [u8; ML_DSA_87_PUBLIC_KEY_SIZE] {
    let mut rho = [0_u8; ML_DSA_87_CRYPTO_SEED_SIZE];
    let mut key = [0_u8; ML_DSA_87_CRYPTO_SEED_SIZE];
    let mut tr = [0_u8; TR_BYTES];
    let mut t0 = PolyVecK::default();
    let mut s1 = PolyVecL::default();
    let mut s2 = PolyVecK::default();
    unpack_sk(&mut rho, &mut key, &mut tr, &mut t0, &mut s1, &mut s2, secret_key);

    let mut matrix = [PolyVecL::default(); K];
    let mut t1 = PolyVecK::default();
    poly_vec_l_ntt(&mut s1);
    poly_vec_matrix_expand(&mut matrix, &rho);
    poly_vec_matrix_point_wise_montgomery(&mut t1, &matrix, &s1);
    poly_vec_k_reduce(&mut t1);
    poly_vec_k_inv_ntt_to_mont(&mut t1);
    let current = t1;
    poly_vec_k_add(&mut t1, &current, &s2);
    poly_vec_k_cadd_q(&mut t1);
    let rounded = t1;
    poly_vec_k_power2_round(&mut t1, &mut t0, &rounded);

    let mut public_key = [0_u8; ML_DSA_87_PUBLIC_KEY_SIZE];
    pack_pk(&mut public_key, &rho, &t1);
    public_key
}

fn acvp_vectors_dir() -> Option<PathBuf> {
    env::var_os("ACVP_VECTORS_DIR").map(PathBuf::from)
}

#[test]
fn acvp_keygen_matches_nist_vectors() {
    // Coverage: the coverage run always sets ACVP_VECTORS_DIR, so the skip
    // arm (for environments without the NIST vectors) is never taken here.
    let Some(vectors_dir) = acvp_vectors_dir() else {
        //coverage:ignore start reason=defensively-unreachable
        eprintln!("ACVP_VECTORS_DIR not set; skipping ML-DSA ACVP keygen test");
        return;
        //coverage:ignore end
    };

    let data = fs::read_to_string(vectors_dir.join("keygen.json")).expect("read keygen.json");
    let vectors: Vec<AcvpKeyGenVector> = serde_json::from_str(&data).expect("parse keygen.json");
    assert!(!vectors.is_empty(), "no ACVP keygen vectors found");
    eprintln!("Running ACVP ML-DSA-87 keyGen: {} vectors", vectors.len());

    for vector in vectors {
        let seed_bytes = hex::decode(&vector.seed).expect("seed hex");
        assert_eq!(seed_bytes.len(), 32, "tc{}", vector.tc_id);
        let expected_pk = hex::decode(&vector.pk).expect("public key hex");
        let expected_sk = hex::decode(&vector.sk).expect("secret key hex");

        let mut seed = [0_u8; 32];
        seed.copy_from_slice(&seed_bytes);
        let signer = MlDsa87::from_seed(seed)
            .unwrap_or_else(|e| panic!("tc{}: key generation failed: {}", vector.tc_id, e));

        assert_eq!(signer.public_key_bytes().len(), ML_DSA_87_PUBLIC_KEY_SIZE);
        assert_eq!(signer.secret_key_bytes().len(), ML_DSA_87_SECRET_KEY_SIZE);
        assert_eq!(
            signer.public_key_bytes().as_slice(),
            expected_pk.as_slice(),
            "tc{}",
            vector.tc_id
        );
        assert_eq!(
            signer.secret_key_bytes().as_slice(),
            expected_sk.as_slice(),
            "tc{}",
            vector.tc_id
        );
        // Validation must never reject a NIST-generated key: an honest key
        // has about 1280 large t1 coefficients against the 76 the weak-key
        // rule requires.
        let public_key = PublicKey::from_bytes(&expected_pk)
            .unwrap_or_else(|e| panic!("tc{}: NIST public key rejected: {}", vector.tc_id, e));
        assert_eq!(public_key, signer.public_key(), "tc{}", vector.tc_id);
    }
}

#[test]
fn acvp_siggen_matches_nist_vectors() {
    // Coverage: the coverage run always sets ACVP_VECTORS_DIR, so the skip
    // arm (for environments without the NIST vectors) is never taken here.
    let Some(vectors_dir) = acvp_vectors_dir() else {
        //coverage:ignore start reason=defensively-unreachable
        eprintln!("ACVP_VECTORS_DIR not set; skipping ML-DSA ACVP siggen test");
        return;
        //coverage:ignore end
    };

    let data = fs::read_to_string(vectors_dir.join("siggen.json")).expect("read siggen.json");
    let vectors: Vec<AcvpSigGenVector> = serde_json::from_str(&data).expect("parse siggen.json");
    assert!(!vectors.is_empty(), "no ACVP siggen vectors found");
    eprintln!("Running ACVP ML-DSA-87 sigGen: {} vectors", vectors.len());

    for vector in vectors {
        let secret_key = hex::decode(&vector.sk).expect("secret key hex");
        let message = hex::decode(&vector.message).expect("message hex");
        let context = hex::decode(&vector.context).expect("context hex");
        let expected_signature = hex::decode(&vector.signature).expect("signature hex");

        assert_eq!(secret_key.len(), ML_DSA_87_SECRET_KEY_SIZE, "tc{}", vector.tc_id);
        assert_eq!(expected_signature.len(), ML_DSA_87_SIGNATURE_SIZE, "tc{}", vector.tc_id);

        let mut secret_key_bytes = [0_u8; ML_DSA_87_SECRET_KEY_SIZE];
        secret_key_bytes.copy_from_slice(&secret_key);

        // FIPS 204 §3.4: rnd is 32 zero bytes for the deterministic variant
        // and the value NIST supplies for the hedged one. The public signing
        // API is hedged with fresh randomness (TOB-QRLLIB-6), so the vectors
        // are reproduced through the internal entry point that takes an
        // explicit rnd, which the public paths call into.
        let mut rnd = [0_u8; RND_BYTES];
        if !vector.deterministic {
            let rnd_bytes = hex::decode(&vector.rnd).expect("rnd hex");
            assert_eq!(rnd_bytes.len(), RND_BYTES, "tc{}", vector.tc_id);
            rnd.copy_from_slice(&rnd_bytes);
        }
        let prefix = interface_prefix(vector.tc_id, &vector.signature_interface, &context);

        let mut signature = [0_u8; ML_DSA_87_SIGNATURE_SIZE];
        crypto_sign_signature_internal(&mut signature, &prefix, &message, &rnd, &secret_key_bytes)
            .unwrap_or_else(|e| panic!("tc{}: signing failed: {e}", vector.tc_id));
        assert_eq!(signature.as_slice(), expected_signature.as_slice(), "tc{}", vector.tc_id);

        // The signature must also verify under the key's public key, which
        // the weak-key rule must accept (an honest NIST key always passes).
        let public_key_bytes = public_key_from_secret_key(&secret_key_bytes);
        let public_key = PublicKey::from_bytes(&public_key_bytes)
            .unwrap_or_else(|e| panic!("tc{}: NIST public key rejected: {e}", vector.tc_id));
        let verified = if vector.signature_interface == "external" {
            verify_bytes(&context, &message, &signature, &public_key)
                .unwrap_or_else(|e| panic!("tc{}: verification failed: {e}", vector.tc_id))
        } else {
            crypto_sign_verify_internal(&signature, &prefix, &message, &public_key_bytes)
        };
        assert!(verified, "tc{}: produced signature does not verify", vector.tc_id);
    }
}

#[test]
fn acvp_sigver_matches_nist_vectors() {
    // Coverage: the coverage run always sets ACVP_VECTORS_DIR, so the skip
    // arm (for environments without the NIST vectors) is never taken here.
    let Some(vectors_dir) = acvp_vectors_dir() else {
        //coverage:ignore start reason=defensively-unreachable
        eprintln!("ACVP_VECTORS_DIR not set; skipping ML-DSA ACVP sigver test");
        return;
        //coverage:ignore end
    };

    let data = fs::read_to_string(vectors_dir.join("sigver.json")).expect("read sigver.json");
    let vectors: Vec<AcvpSigVerVector> = serde_json::from_str(&data).expect("parse sigver.json");
    assert!(!vectors.is_empty(), "no ACVP sigver vectors found");
    eprintln!("Running ACVP ML-DSA-87 sigVer: {} vectors", vectors.len());

    for vector in vectors {
        let public_key = hex::decode(&vector.pk).expect("public key hex");
        let message = hex::decode(&vector.message).expect("message hex");
        let context = hex::decode(&vector.context).expect("context hex");
        let signature = hex::decode(&vector.signature).expect("signature hex");
        assert_eq!(public_key.len(), ML_DSA_87_PUBLIC_KEY_SIZE, "tc{}", vector.tc_id);
        let mut public_key_bytes = [0_u8; ML_DSA_87_PUBLIC_KEY_SIZE];
        public_key_bytes.copy_from_slice(&public_key);

        // A signature of the wrong length is invalid (FIPS 204 §3.6.2). The
        // external interface goes through `PublicKey::from_bytes`, which also
        // applies the weak-key rule; a key it rejects verifies nothing. The
        // internal interface takes the raw bytes.
        let got = signature.len() == ML_DSA_87_SIGNATURE_SIZE && {
            let mut signature_bytes = [0_u8; ML_DSA_87_SIGNATURE_SIZE];
            signature_bytes.copy_from_slice(&signature);
            match vector.signature_interface.as_str() {
                "external" => PublicKey::from_bytes(&public_key).is_ok_and(|key| {
                    verify_bytes(&context, &message, &signature_bytes, &key).unwrap_or(false)
                }),
                "internal" => {
                    crypto_sign_verify_internal(&signature_bytes, &[], &message, &public_key_bytes)
                }
                //coverage:ignore start reason=defensively-unreachable
                other => panic!("tc{}: unsupported signature interface {other:?}", vector.tc_id),
                //coverage:ignore end
            }
        };
        assert_eq!(got, vector.test_passed, "tc{}: NIST verdict", vector.tc_id);
    }
}
