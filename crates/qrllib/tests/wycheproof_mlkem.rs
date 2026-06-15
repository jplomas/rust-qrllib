//! Wycheproof / CCTV ML-KEM-1024 vector verification, ported from
//! `go-qrllib`'s `crypto/internal/mlkem1024/wycheproof_test.go`.
//!
//! Vectors are consumed directly from upstream at CI time (never vendored):
//!
//!   - C2SP/wycheproof  `testvectors_v1/mlkem_1024_{keygen_seed,encaps,test}_test.json`
//!     via `WYCHEPROOF_VECTORS_DIR`
//!   - C2SP/CCTV         `ML-KEM/modulus/ML-KEM-1024.txt` (decompressed from the
//!     upstream `.txt.gz`) via `CCTV_VECTORS_DIR`
//!
//! When the env vars are unset each test logs a skip and exits successfully, so
//! day-to-day `cargo test` does not require the vectors. See
//! `.github/wycheproof/README.md` for setup and provenance.
//!
//! These exercise only the public API plus
//! [`EncapsulationKey::encapsulate_deterministic`] (the derandomized
//! encapsulation entry point the Wycheproof encaps vectors require).

use std::{
    env, fs,
    path::{Path, PathBuf},
};

use qrllib::{DecapsulationKey, EncapsulationKey};
use serde::Deserialize;

#[derive(Deserialize)]
struct KeyGenFile {
    algorithm: String,
    #[serde(rename = "testGroups")]
    test_groups: Vec<KeyGenGroup>,
}

#[derive(Deserialize)]
struct KeyGenGroup {
    #[serde(rename = "parameterSet")]
    parameter_set: String,
    tests: Vec<KeyGenTest>,
}

#[derive(Deserialize)]
struct KeyGenTest {
    #[serde(rename = "tcId")]
    tc_id: u32,
    seed: String,
    #[serde(default)]
    ek: String,
    result: String,
}

#[derive(Deserialize)]
struct EncapsFile {
    algorithm: String,
    #[serde(rename = "testGroups")]
    test_groups: Vec<EncapsGroup>,
}

#[derive(Deserialize)]
struct EncapsGroup {
    #[serde(rename = "parameterSet")]
    parameter_set: String,
    tests: Vec<EncapsTest>,
}

#[derive(Deserialize)]
struct EncapsTest {
    #[serde(rename = "tcId")]
    tc_id: u32,
    #[serde(default)]
    ek: String,
    #[serde(default)]
    m: String,
    #[serde(default)]
    c: String,
    #[serde(rename = "K", default)]
    k: String,
    result: String,
    #[serde(default)]
    flags: Vec<String>,
}

#[derive(Deserialize)]
struct DecapsFile {
    algorithm: String,
    #[serde(rename = "testGroups")]
    test_groups: Vec<DecapsGroup>,
}

#[derive(Deserialize)]
struct DecapsGroup {
    #[serde(rename = "parameterSet")]
    parameter_set: String,
    tests: Vec<DecapsTest>,
}

#[derive(Deserialize)]
struct DecapsTest {
    #[serde(rename = "tcId")]
    tc_id: u32,
    #[serde(default)]
    comment: String,
    seed: String,
    #[serde(default)]
    c: String,
    #[serde(rename = "K", default)]
    k: String,
    result: String,
    #[serde(default)]
    flags: Vec<String>,
}

fn wycheproof_dir() -> Option<PathBuf> {
    env::var_os("WYCHEPROOF_VECTORS_DIR").map(PathBuf::from)
}

fn decode(value: &str) -> Vec<u8> {
    hex::decode(value).expect("wycheproof hex")
}

fn load<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    let data =
        fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
    serde_json::from_str(&data).unwrap_or_else(|e| panic!("parse {}: {}", path.display(), e))
}

#[test]
fn wycheproof_mlkem1024_keygen_matches_expected_outcomes() {
    let Some(dir) = wycheproof_dir() else {
        eprintln!("WYCHEPROOF_VECTORS_DIR not set; skipping Wycheproof ML-KEM-1024 keyGen test");
        return;
    };
    let file: KeyGenFile = load(&dir.join("mlkem_1024_keygen_seed_test.json"));
    assert_eq!(file.algorithm, "ML-KEM", "unexpected algorithm");

    let (mut pass, mut n) = (0u32, 0u32);
    for group in &file.test_groups {
        if group.parameter_set != "ML-KEM-1024" {
            continue;
        }
        for tc in &group.tests {
            n += 1;
            let result = DecapsulationKey::from_seed(&decode(&tc.seed));
            match tc.result.as_str() {
                "valid" => {
                    let dk = result.unwrap_or_else(|e| panic!("tc{}: from_seed: {e}", tc.tc_id));
                    assert_eq!(
                        dk.encapsulation_key().bytes().as_slice(),
                        decode(&tc.ek).as_slice(),
                        "tc{}: encapsulation-key mismatch",
                        tc.tc_id
                    );
                    pass += 1;
                }
                "invalid" => {
                    assert!(result.is_err(), "tc{}: expected rejection", tc.tc_id);
                    pass += 1;
                }
                other => panic!("tc{}: unknown result {other:?}", tc.tc_id),
            }
        }
    }
    assert!(n > 0, "no ML-KEM-1024 keyGen vectors processed");
    eprintln!("Wycheproof ML-KEM-1024 KeyGen: pass={pass}");
}

#[test]
fn wycheproof_mlkem1024_encaps_matches_expected_outcomes() {
    let Some(dir) = wycheproof_dir() else {
        eprintln!("WYCHEPROOF_VECTORS_DIR not set; skipping Wycheproof ML-KEM-1024 encaps test");
        return;
    };
    let file: EncapsFile = load(&dir.join("mlkem_1024_encaps_test.json"));
    assert_eq!(file.algorithm, "ML-KEM", "unexpected algorithm");

    let (mut pass, mut n, mut modulus) = (0u32, 0u32, 0u32);
    for group in &file.test_groups {
        if group.parameter_set != "ML-KEM-1024" {
            continue;
        }
        for tc in &group.tests {
            n += 1;
            let ek = EncapsulationKey::from_bytes(&decode(&tc.ek));
            match tc.result.as_str() {
                "valid" => {
                    let ek = ek.unwrap_or_else(|e| panic!("tc{}: from_bytes: {e}", tc.tc_id));
                    let m: [u8; 32] = decode(&tc.m).try_into().expect("32-byte m");
                    let (shared, ciphertext) = ek.encapsulate_deterministic(&m);
                    assert_eq!(
                        ciphertext.as_slice(),
                        decode(&tc.c).as_slice(),
                        "tc{}: ct (flags={:?})",
                        tc.tc_id,
                        tc.flags
                    );
                    assert_eq!(
                        shared.as_slice(),
                        decode(&tc.k).as_slice(),
                        "tc{}: K (flags={:?})",
                        tc.tc_id,
                        tc.flags
                    );
                    pass += 1;
                }
                "invalid" => {
                    assert!(
                        ek.is_err(),
                        "tc{}: expected ek rejection (flags={:?})",
                        tc.tc_id,
                        tc.flags
                    );
                    pass += 1;
                    if tc.flags.iter().any(|f| f == "ModulusOverflow") {
                        modulus += 1;
                    }
                }
                other => panic!("tc{}: unknown result {other:?}", tc.tc_id),
            }
        }
    }
    assert!(n > 0, "no ML-KEM-1024 encaps vectors processed");
    eprintln!(
        "Wycheproof ML-KEM-1024 Encaps: pass={pass} (incl. {modulus} ModulusOverflow rejections)"
    );
}

#[test]
fn wycheproof_mlkem1024_decaps_matches_expected_outcomes() {
    let Some(dir) = wycheproof_dir() else {
        eprintln!("WYCHEPROOF_VECTORS_DIR not set; skipping Wycheproof ML-KEM-1024 decaps test");
        return;
    };
    let file: DecapsFile = load(&dir.join("mlkem_1024_test.json"));
    assert_eq!(file.algorithm, "ML-KEM", "unexpected algorithm");

    let (mut pass, mut n, mut strcmp) = (0u32, 0u32, 0u32);
    for group in &file.test_groups {
        if group.parameter_set != "ML-KEM-1024" {
            continue;
        }
        for tc in &group.tests {
            n += 1;
            let dk = DecapsulationKey::from_seed(&decode(&tc.seed));
            let ct = decode(&tc.c);
            match tc.result.as_str() {
                "valid" => {
                    // Includes implicit-rejection cases: a malformed-but-right-length
                    // ciphertext must yield the pseudo-random rejection key, never an
                    // error. Strcmp-flagged vectors fail if the implicit-rejection
                    // comparison is not constant-time / byte-exact.
                    let dk = dk.unwrap_or_else(|e| panic!("tc{}: from_seed: {e}", tc.tc_id));
                    let shared = dk
                        .decapsulate(&ct)
                        .unwrap_or_else(|e| panic!("tc{}: decapsulate: {e}", tc.tc_id));
                    assert_eq!(
                        shared.as_slice(),
                        decode(&tc.k).as_slice(),
                        "tc{}: shared-secret mismatch (comment={:?} flags={:?})",
                        tc.tc_id,
                        tc.comment,
                        tc.flags
                    );
                    pass += 1;
                    if tc.flags.iter().any(|f| f == "Strcmp") {
                        strcmp += 1;
                    }
                }
                "invalid" => {
                    // Structural rejection (wrong-length seed or ciphertext) must
                    // surface as an error at the API boundary.
                    let rejected = dk.map(|k| k.decapsulate(&ct).is_err()).unwrap_or(true);
                    assert!(
                        rejected,
                        "tc{}: expected rejection (comment={:?})",
                        tc.tc_id, tc.comment
                    );
                    pass += 1;
                }
                other => panic!("tc{}: unknown result {other:?}", tc.tc_id),
            }
        }
    }
    assert!(n > 0, "no ML-KEM-1024 decaps vectors processed");
    eprintln!(
        "Wycheproof ML-KEM-1024 Decaps: pass={pass} (incl. {strcmp} Strcmp implicit-rejection vectors)"
    );
}

#[test]
fn cctv_mlkem1024_modulus_keys_are_all_rejected() {
    let Some(dir) = env::var_os("CCTV_VECTORS_DIR").map(PathBuf::from) else {
        eprintln!("CCTV_VECTORS_DIR not set; skipping CCTV ML-KEM-1024 modulus test");
        return;
    };
    // Upstream ships `ML-KEM-1024.txt.gz`; the CI / local setup decompresses it
    // to `.txt` so this test stays free of a gzip dependency.
    let path = dir.join("modulus").join("ML-KEM-1024.txt");
    let data =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));

    let (mut n, mut rejected) = (0u32, 0u32);
    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        n += 1;
        if EncapsulationKey::from_bytes(&decode(line)).is_err() {
            rejected += 1;
        } else {
            panic!("line {n}: out-of-range (modulus-overflow) encapsulation key was ACCEPTED");
        }
    }
    assert!(n > 0, "no CCTV ML-KEM-1024 modulus vectors found");
    eprintln!("CCTV ML-KEM-1024 modulus: {rejected}/{n} invalid encapsulation keys rejected");
}
