# NIST ACVP Test Vector Verification

This directory contains tooling for testing `rust-qrllib`'s ML-DSA-87 and ML-KEM-1024 implementations against official NIST ACVP (Automated Cryptographic Validation Protocol) test vectors.

## How It Works

The GitHub Action (`.github/workflows/acvp.yml`) clones the NIST ACVP-Server repository at its latest commit and extracts the test vectors at runtime. Vectors are never vendored — they always come directly from NIST's repository.

**ML-DSA-87:**

1. **Clone**: Sparse checkout of `github.com/usnistgov/ACVP-Server` (only the ML-DSA JSON files)
2. **Merge**: `merge_vectors.py` combines the ACVP `prompt.json` (inputs) and `expectedResults.json` (expected outputs) into simplified test vector files, filtered to ML-DSA-87
3. **Test**: the in-crate `mldsa::acvp` module (`crates/qrllib/src/mldsa/acvp.rs`) runs the vectors through Rust key generation, signing and verification functions, comparing byte-exact output and accept/reject verdicts, and additionally checks that every NIST-generated public key passes `validate_mldsa_public_key` (validation must never reject an honest key)

**ML-KEM-1024:**

1. **Clone**: Sparse checkout of the `ML-KEM-keyGen-FIPS203` and `ML-KEM-encapDecap-FIPS203` JSON files
2. **Test**: the `acvp` module in `crates/qrllib/src/mlkem.rs` reads the raw NIST `prompt.json` / `expectedResults.json` pair directly (no merge step) via `MLKEM_ACVP_VECTORS_DIR`. It runs as an in-crate lib test because the ACVP `decapsulation` cases use the FIPS 203 *expanded* decapsulation-key encoding, which requires private-field access the public API does not expose.

## What's Tested

| Test | Vectors | Description |
|------|---------|-------------|
| `mldsa::acvp::acvp_keygen_matches_nist_vectors` (ML-DSA-87) | 25 | Seed -> (pk, sk) matches NIST expected output; pk passes `validate_mldsa_public_key` |
| `mldsa::acvp::acvp_siggen_matches_nist_vectors` (ML-DSA-87) | 60 | sk + message (+ context) (+ rnd) -> signature matches NIST expected output and verifies |
| `mldsa::acvp::acvp_sigver_matches_nist_vectors` (ML-DSA-87) | 30 | pk + message (+ context) + signature -> accept/reject matches NIST's verdict |
| `acvp_keygen_matches_nist_vectors` (ML-KEM-1024) | 25 | seed (d‖z) -> (ek, expanded dk) matches NIST expected output |
| `acvp_encap_decap_matches_nist_vectors` (ML-KEM-1024) | 55 | encapsulation (25), decapsulation (10), decapsulationKeyCheck (10), encapsulationKeyCheck (10) |

ML-DSA signature vectors cover every group the implementation can serve: both the **deterministic** variant (`rnd` = 32 zero bytes) and the **hedged** variant with the `rnd` value NIST supplies, through both the **external** interface (`M' = 0x00 || |ctx| || ctx || M`) and the **internal** interface (`M'` as given). The **pre-hash** (HashML-DSA) and **external-mu** groups are skipped: the crate implements pure ML-DSA and computes mu itself, like the pq-crystals reference.

The public ML-DSA-87 API is **hedged by default** per FIPS 204 §3.4 (TOB-QRLLIB-6), so it cannot reproduce a fixed vector byte for byte; the harness uses the crate-private `crypto_sign_signature_internal` / `crypto_sign_verify_internal` entry points, which the public paths call into, with the explicit `rnd` the vector prescribes. This matches go-qrllib's widened ACVP coverage.

## Running Locally

```bash
# Clone the ACVP-Server repo
git clone --depth 1 https://github.com/usnistgov/ACVP-Server.git /tmp/acvp-server

# Extract and merge ML-DSA-87 vectors
python3 .github/acvp/merge_vectors.py \
  --keygen-prompt /tmp/acvp-server/gen-val/json-files/ML-DSA-keyGen-FIPS204/prompt.json \
  --keygen-results /tmp/acvp-server/gen-val/json-files/ML-DSA-keyGen-FIPS204/expectedResults.json \
  --siggen-prompt /tmp/acvp-server/gen-val/json-files/ML-DSA-sigGen-FIPS204/prompt.json \
  --siggen-results /tmp/acvp-server/gen-val/json-files/ML-DSA-sigGen-FIPS204/expectedResults.json \
  --sigver-prompt /tmp/acvp-server/gen-val/json-files/ML-DSA-sigVer-FIPS204/prompt.json \
  --sigver-results /tmp/acvp-server/gen-val/json-files/ML-DSA-sigVer-FIPS204/expectedResults.json \
  --parameter-set ML-DSA-87 \
  --output-dir /tmp/acvp-vectors

# Run the tests
ACVP_VECTORS_DIR=/tmp/acvp-vectors cargo test --package qrllib --lib 'mldsa::acvp::' -- --nocapture
```

For ML-KEM-1024 the raw NIST format is consumed directly (no merge step):

```bash
# Sparse-checkout the ML-KEM suites
git clone --depth 1 --no-checkout --filter=blob:none \
  https://github.com/usnistgov/ACVP-Server.git /tmp/acvp-server
cd /tmp/acvp-server && git sparse-checkout init --cone
git sparse-checkout set \
  gen-val/json-files/ML-KEM-keyGen-FIPS203 \
  gen-val/json-files/ML-KEM-encapDecap-FIPS203
git checkout && cd -

# Run the tests (MLKEM_ACVP_VECTORS_DIR points at the dir holding the two suites)
MLKEM_ACVP_VECTORS_DIR=/tmp/acvp-server/gen-val/json-files \
  cargo test --package qrllib --lib 'mlkem::acvp::' -- --nocapture
```

## Why Not the Other Algorithms?

| Algorithm | ACVP Vectors Available? | Compatible? | Reason |
|-----------|------------------------|-------------|--------|
| **ML-DSA-87** | Yes (ML-DSA FIPS 204) | Yes | Direct match |
| **SPHINCS+** | No (SLH-DSA FIPS 205 only) | No | `rust-qrllib` implements SPHINCS+ SHAKE-256s-**robust** (pre-FIPS submission). FIPS 205 (SLH-DSA) dropped the robust variant and only standardized the simple variant. Different thash construction means different outputs. Cross-verified against sphincsplus reference (consistent-basew branch) instead. |
| **XMSS** | No | N/A | ACVP coverage is not available. `XMSS-SHA2_10_256` is instead cross-verified bidirectionally against the pinned RFC 8391 reference construction; see [the cross-verification guide](../cross-verify/README.md). |

## ACVP Vector Format

The NIST ACVP-Server stores vectors in two files per algorithm:

- `prompt.json` — Test inputs (seed, message, sk, pk, context, rnd, signature)
- `expectedResults.json` — Expected outputs (pk, sk, signature, testPassed)

These are linked by `tcId` within test groups. `merge_vectors.py` joins them and filters to the requested parameter set.
