# Security Policy

## Reporting Security Vulnerabilities

If you discover a security vulnerability in `rust-qrllib`, please report it responsibly:

1. Do not open a public issue.
2. Email security concerns to [security@theqrl.org](mailto:security@theqrl.org).
3. Or report via [https://www.theqrl.org/security-report/](https://www.theqrl.org/security-report/).
4. Include detailed steps to reproduce.
5. Allow reasonable time for a fix before public disclosure.

## Threat Model

### Assumptions

The library assumes:

- A trusted host, Rust toolchain, and JavaScript runtime for WASM consumers.
- A functioning operating-system CSPRNG for key generation, hedged signing, and
  randomized encapsulation.
- Callers authenticate the data and protocol context they intend to sign.
- XMSS callers maintain one durable, monotonic OTS-index authority per key.

### What the library protects against

- Signature forgery under the security assumptions of the configured scheme.
- Malformed public inputs reaching unchecked public API paths: wrong lengths and
  unsupported identifiers return typed errors or verification failure.
- Accidental reuse of one in-memory XMSS signer through cloning or concurrent
  mutable access in safe Rust.
- Residual secret material in owned Rust buffers after normal drop, on a
  best-effort basis described below.

### What the library does not protect against

- Compromised hosts, malicious dependencies or toolchains, physical memory
  probing, swap/hibernation capture, or side-channel-capable co-tenants.
- Weak or subverted system randomness.
- Application-level replay, authorization, rate limiting, transaction intent,
  or display/UI substitution attacks.
- XMSS index reuse across processes, devices, database rollbacks, or restored
  backups.
- Copies of secrets made by callers, debuggers, serializers, the JavaScript
  engine, or the browser before Rust zeroization runs.

### Signing modes (ML-DSA-87)

ML-DSA-87 is **hedged by default** per FIPS 204 §3.4 — the FIPS-recommended mode (TOB-QRLLIB-6):

- **Hedged (default).** `sign` / `sign_attached` draw a fresh 32-byte value from the system RNG on every call. Two signs of the same `(secret_key, [context,] message)` produce **distinct** signature bytes; both verify under the same public key. Verification is unchanged and existing verifiers — on-chain or off — are unaffected.
- **Deterministic (FIPS 204 §3.4 opt-in).** `sign_deterministic` / `sign_attached_deterministic` use a fixed all-zero per-signature value, so the same `(secret_key, [context,] message)` always yields byte-identical signatures. **Use only when the deterministic property is itself a security or protocol requirement** — for example, RANDAO-style verifiable beacon contributions where each validator must produce the same signature for the same input, or ACVP / KAT test-vector reproduction.

Deterministic signing is vulnerable to fault-injection attacks: an adversary who can flip a single bit during the `z` computation can differentiate two signatures of the same message and recover `s1`/`s2` by lattice differential analysis. Hedged signing frustrates this attack because two signings of the same message use different internal randomness. SPHINCS+-256s robust is randomised-by-default per its parameter-set definition and does not expose a separate deterministic mode.

The free signing function `sign_with_secret_key` (ML-DSA-87) follows the same convention: hedged by default, with `sign_with_secret_key_deterministic` as the explicit opt-in. ACVP, KAT, and cross-verification test vectors that pin specific signature bytes route through the deterministic entry points.

### Public-key validation (ML-DSA-87)

A weak ML-DSA-87 public key is one under which the verifier accepts a
signature anyone can compute from the key alone. Key generation never
produces one. FIPS 204 Algorithm 8 has no key-validity step, and the
Wycheproof vectors this crate is checked against require the all-zero key
(tcId 66 and 174) and the all-1023 key (tcId 240) to verify, so the verifier
(`crypto_sign_verify_mldsa`) is unchanged and the check happens at key
construction instead.

`mldsa::PublicKey` has a private inner array and two constructors:
`PublicKey::from_bytes`, which returns `QrllibError::WeakPublicKey` or
`QrllibError::InvalidPublicKeySize`, and key generation, which validates its
own output. `verify_bytes`, `open` and `verify_mldsa87_wallet_signature` take
`&PublicKey`, so an unvalidated key cannot reach a verifier.
`validate_mldsa_public_key(&[u8])` is the same check for raw bytes; its
rustdoc states the rule (at least 76 of the 2048 `t1` coefficients must be
large, where large means `96..=415` or `608..=927`) and its derivation.

The Wycheproof and ACVP harnesses and the shared weak-key vector tests live
in-crate (`crates/qrllib/src/mldsa/wycheproof.rs`, `acvp.rs` and
`weak_keys.rs`) and use a `#[cfg(test)]`-only unchecked constructor so they
can drive the primitive on weak keys. go-qrllib, qrypto.js and wallet.js
apply the same rule and run the same vector file
(`crates/qrllib/src/mldsa/testdata/weak_public_key_vectors.json`), so a key
is accepted or rejected identically across QRL clients.

### Secret-key validation (ML-DSA-87)

The `s1` and `s2` coefficients of a packed secret key are 3-bit fields; 5,
6 and 7 are not encodings key generation writes, and a coefficient outside
`[-2, 2]` breaks the norm bound the signing loop relies on for its
zero-knowledge property. Every signing path checks `s1` and `s2` after
unpacking and returns `QrllibError::InvalidMlDsaSecretKeyEncoding` on such
a key, with the unpacked secret material zeroized on that path as on every
other; `validate_mldsa_secret_key(&[u8])` is the same check ahead of time
and is what `sign_with_secret_key` applies first. `rho`, `K`, `tr` and `t0`
have no invalid encoding and are not examined, and neither is whether `t0`
and `tr` are consistent with `rho`, `s1` and `s2`: an inconsistent key passes
and signs (more slowly at the extremes of `t0`, where per-attempt acceptance
drops from about 0.25 to about 0.09). A wrong `tr` changes the challenge, so
no such signature verifies under the key's own public half; a wrong `t0` only
changes the hints, so a small change leaves most signatures valid and a large
one leaves none. A caller importing raw secret-key bytes from an untrusted
source should check a signature against the expected public key. The rejection loop is
bounded to 1024 attempts (`QrllibError::RejectionBudgetExceeded`), a
below-2^-440 event for a key that passes the check. go-qrllib and qrypto.js
apply the same check and bound; the tests live in-crate
(`crates/qrllib/src/mldsa/secret_keys.rs`).

### Memory hygiene

Every secret-bearing public type — `Seed`, `ExtendedSeed`, `MlDsa87`, `SphincsPlus256s`, `Xmss`, `MlDsa87Wallet`, `SphincsPlus256sWallet`, `LegacyXmssWallet` — implements `Drop` that zeroizes its backing buffer. Callers do not need to call `.zeroize()` explicitly for the scope-exit path to clear secrets from memory. Explicit `.zeroize()` is retained for long-lived signers that need to clear state mid-lifetime.

Accessor methods that return owned secret bytes (`seed`, `secret_key`, `secret_key_bytes`) return `zeroize::Zeroizing<T>`, so caller-held copies inherit the same drop-clear semantics. The owned wrapper dereferences transparently to the underlying byte array or `Vec<u8>` and works unchanged with `hex::encode`, `Sha256::digest`, `.iter()`, and the library's verify helpers.

After an explicit `.zeroize()`, a signer that is still reachable will not produce a bogus signature from the all-zero key: `sign`, `sign_attached`, and the `*_with_secret_key` free functions return `QrllibError::MlDsaSecretKeyZeroized` / `SphincsPlusSecretKeyZeroized` / `XmssSecretKeyZeroized`.

#### Guarantee boundary

Zeroization is defense in depth, not proof that no secret copy remains. Rust may
move values, allocator pages may retain prior contents, optimized code and FFI
may create copies, and operating systems may page memory to disk. `zeroize`
provides volatile writes and compiler fences for the buffers it owns; it cannot
wipe copies outside those buffers. WASM adds a second boundary: Rust can clear
linear-memory state, but JavaScript strings are immutable and cannot be
reliably erased.

Use an HSM or equivalent protected execution environment where process-memory
zeroization is not a sufficient control.

### API Precondition Guarantees

Every exported function in `crates/qrllib/src/` is documented with the precondition contract it enforces. The Rust type system carries most of these by construction; the table below names the contracts a reader coming from the Go-side audit would expect to find (TOB-QRLLIB cross-cutting item: precondition validation at every exported API entry point).

| Surface | Contract |
|---------|----------|
| Public-key references | ML-DSA-87 verify / open entry points take `&mldsa::PublicKey`, a validated type whose only constructors are `PublicKey::from_bytes` and key generation; every other verify / open entry point takes `&[u8]` or `&[u8; N]`. None can be null in safe Rust (vs the Go-side TOB-11 nil-pk dereference class). |
| ML-DSA-87 public-key validity | `PublicKey::from_bytes` returns `QrllibError::WeakPublicKey` for a weak key and `QrllibError::InvalidPublicKeySize` for a wrong length. The FIPS 204 Algorithm 8 primitive performs no key validation, as the standard specifies; see "Public-key validation (ML-DSA-87)" above. |
| Falcon-1024 keys | `falcon1024::PublicKey::from_bytes` returns `InvalidFalconPublicKeySize`, `InvalidFalconPublicKeyEncoding` (header, coefficient not below q) or `FalconWeakPublicKey`; `verify` / `open` take the validated `&falcon1024::PublicKey`. `PrivateKey::from_bytes` returns `InvalidFalconPrivateKeySize`, `InvalidFalconPrivateKey` (encoding, G not recoverable, NTRU equation, key-generation bounds) or `FalconWeakPublicKey`. See "Falcon-1024" below. |
| Falcon-1024 signatures | `open` returns `FalconSignatureTooShort` below the 42-byte prefix and `InvalidFalconSignature` for any other malformed or invalid signed message; `verify` returns `false`. Signing returns `FalconSigningFailed` when a bounded loop runs out and `Randomness` when the `RandomSource` fails. |
| ML-DSA-87 secret-key encoding | `validate_mldsa_secret_key` and every signing path return `QrllibError::InvalidMlDsaSecretKeyEncoding` for an `s1` or `s2` coefficient outside `[-2, 2]`; see "Secret-key validation (ML-DSA-87)" above. |
| Wrong-size buffer inputs | Length-validating constructors return `Err(QrllibError::Invalid*Size(actual, expected))` rather than panicking; the variant names are stable. |
| Parameter-set identifiers | `WalletType`, `XmssHashFunction`, `XmssHeight` are sum-type enums / validated newtypes constructed via `TryFrom<u8>` / `new(value)`; invalid bytes return typed errors (`QrllibError::UnknownWalletType`, `QrllibError::InvalidXmssHashFunction`, `QrllibError::InvalidXmssHeight`). There is no safe-Rust way to construct an out-of-range instance. |
| Wallet issuance gating | Every `SphincsPlus256sWallet` constructor returns `Err(QrllibError::WalletTypeNotIssuable(...))` unless `experimental-sphincsplus-issuance` (or `cfg(test)`) is set (TOB-QRLLIB-4). `WalletType::SphincsPlus256s` is `is_valid() == is_issuable() == is_verifiable() == false`, so `Descriptor::is_valid()` rejects the SPHINCS+ descriptor and `get_address` / `ExtendedSeed` / `verify_sphincsplus_wallet_signature` refuse it, matching go-qrllib's `wallettype` and `descriptor` gates. |
| XMSS verify preconditions | `verify_xmss` / `verify_xmss_with_custom_wots_param_w` return `false` for a public key that is not exactly 64 bytes (`root \|\| pub_seed`; trailing bytes no longer alias one key) and for a WOTS `w` outside {4, 16, 256}. An invalid hash function is unrepresentable (see TOB-QRLLIB-13 below). WOTS parameters match `w` exactly against {4, 16, 256} (`QrllibError::InvalidXmssWotsParameter`), so `get_xmss_height_from_sig_size` refuses widths such as 5, 17 or 257 whose truncated log2 is 2, 4 or 8. Mirrors go-qrllib's 2026-10 precondition hardening. |
| XMSS key-generation preconditions | `XmssHeight` admits h = 2 (even, in `[2, XMSS_MAX_HEIGHT]`), but BDS traversal needs h > k = 2, so `Xmss::initialize_tree` and `initialize_tree_from_expanded_seed` return `QrllibError::InvalidXmssBdsParams` for it; usable heights start at 4. The internal keypair core checks the parameter set, the output buffer lengths (`QrllibError::InvalidXmssKeyLength`) and that the BDS state was built for the same `(h, n, k)` (`QrllibError::InvalidXmssBdsParams`) before writing anything, like go-qrllib's `XMSSFastGenKeyPair`. |
| v1 descriptor parity (legacy XMSS) | `legacy_xmss` accepts what the v1 (QRL mainnet) node accepted, per qrllib v1.2.4, so every funded v1 address stays migratable: reserved byte 2 is ignored on parse and written as 0, and the address-format nibble is checked only at address derivation (`get_xmss_address_from_pk`, `is_valid_xmss_address`), not in `verify_legacy_xmss`. Tests: `legacy_xmss::tests::v1_mainnet_parity`, shared with go-qrllib's `v1_mainnet_parity_test.go`. |
| Stateful XMSS index | `Xmss` and `LegacyXmssWallet` do **not** implement `Clone`; accidental duplication that would cause OTS index reuse is a compile error. Index persistence remains the caller's responsibility — see `Xmss::sign` rustdoc and the "XMSS State Management" section above. |
| Secret-bearing types | `Drop` zeroizes; accessor methods returning owned secret bytes wrap them in `zeroize::Zeroizing<T>`. Post-`.zeroize()` re-use surfaces `QrllibError::*SecretKeyZeroized` rather than producing a bogus signature. |
| Signing mode | `sign` / `sign_attached` are hedged by default per FIPS 204 §3.4 (TOB-QRLLIB-6); `sign_deterministic` / `sign_attached_deterministic` are the explicit opt-in for protocols that need byte-identical signatures. |
| Panic policy | Production code panics **only** on invariant violations that mark a regression in upstream validation (currently the single `chunks_exact(4)` tripwire in `sphincsplus::bytes_to_addr`); malformed user input always returns a typed `Result::Err`. |

### Audit-derived design choices (mapping from `go-qrllib` Trail of Bits findings)

The Trail of Bits audit was scoped to the Go implementation (`go-qrllib`). Several of its findings have no Rust-port analogue because the Rust port's type system, ownership model, or API surface already eliminates the failure mode. They are recorded here so a reader coming from the Go advisory can see the Rust-side reasoning:

- **Invalid XMSS hash-function values (TOB-QRLLIB-13).** The Go advisory describes a path where `xmss.HashFunction(99)` — a raw integer cast that bypasses the validating constructor — reaches `coreHash`'s dispatch switch, falls through the missing `default`, leaves the output buffer zero-initialised, and produces a degenerate zero-rooted XMSS whose signatures cross-verify with each other's public keys. The Rust port's [`XmssHashFunction`](crates/qrllib/src/xmss.rs) is a closed `enum` constructed via `TryFrom<u8>`, which returns `QrllibError::InvalidXmssHashFunction(value)` on any byte outside `{0, 1, 2}`. There is no safe-Rust way to instantiate an out-of-range `XmssHashFunction`, so the attack vector cannot exist at the type-system level.
- **Nil public-key dereferences (TOB-QRLLIB-11).** All Rust verify / open entry points take `&[u8]` slices, fixed-size `&[u8; N]` array references, or (ML-DSA-87) the validated `&mldsa::PublicKey`, none of which can be null in safe Rust. The Go-side nil-pk guard requirements have no Rust analogue.
- **`Open` collapsing distinct failure modes into `nil` (TOB-QRLLIB-14).** Rust verify / open helpers already return `Result<…, QrllibError>` or `Option<&[u8]>` per idiomatic Rust error handling. The Go-side rewrite to typed sentinels is already-by-construction in Rust.
- **Inconsistent ML-DSA secret-material zeroisation (TOB-QRLLIB-10).** Every secret-bearing public type implements `Drop` that zeroizes its backing buffer, and accessors that return owned secret bytes wrap them in `zeroize::Zeroizing<T>` so callers inherit the same clear-on-drop semantics (see the **Memory hygiene** section above).
- **XMSS height accepts out-of-range values (TOB-QRLLIB-2).** [`XmssHeight`](crates/qrllib/src/xmss.rs) is a validated newtype constructed via `XmssHeight::new(value)`, which returns `QrllibError::InvalidXmssHeight(value)` on any value outside the allowed range; the validating constructor is the only way to obtain an `XmssHeight`.

Go-side findings that do apply to Rust are recorded in the affected rustdoc and
covered by `crates/qrllib/tests/audit_remediation_suite.rs` and the focused
hardening tests; references retain the relevant TOB-QRLLIB identifier.

### Browser surface (wasm)

The `qrllib-wasm` crate exposes two API shapes:

- **Handle-based (recommended).** `create_*_wallet`, `open_*_wallet`, `wallet_snapshot`, `wallet_sign`, `close_wallet`, `close_all_wallets`. The extended seed crosses the wasm/JS boundary exactly once (at `open_*_wallet` time); thereafter a plain `u32` handle is passed back and forth. `close_wallet` removes the registry entry, and the wallet's `Drop` zeroizes the in-wasm state. JavaScript strings never hold the seed between calls.
- **Legacy string-based.** `sign_message`, `sign_sphincsplus_message`, `sign_xmss_message`, and the paired `*_from_extended_seed_hex` / `generate_*` helpers. Retained for backwards compatibility. These re-accept the seed as a JavaScript string on every call; the seed persists in the JS heap across calls and cannot be zeroized from Rust. New browser consumers should prefer the handle-based API.

## Algorithm Notes

| Algorithm | Status | State | Signing / failure behavior | Notes |
|-----------|--------|-------|----------------------------|-------|
| ML-DSA-87 | Primary | Stateless | Hedged by default; deterministic opt-in | FIPS 204, NIST level 5 |
| ML-KEM-1024 | Supported | Stateless | Implicit rejection returns a pseudorandom shared secret for a correct-length invalid ciphertext; wrong lengths return a typed error | FIPS 203 KEM; standalone, not wallet-integrated |
| Falcon-1024 | Supported primitive | Stateless | Randomized signing; bounded attempt and sampler loops return `FalconSigningFailed` | Round-3 submission, not FIPS 206 FN-DSA; standalone, not wallet-integrated; see below |
| SPHINCS+-256s robust | Supported primitive | Stateless | Randomized signing | SPHINCS+ submission parameter set, not FIPS 205 SLH-DSA; wallet issuance **and** verification gated by default |
| XMSS | Legacy migration only | **Stateful** | Deterministic; OTS index must never repeat | QRL compatibility construction; see the provenance notes in README |

### Falcon-1024 (round-3 submission, pre-FIPS 206)

`qrllib::falcon1024` is ported from go-qrllib `crypto/falcon1024` and shares its
rules, vectors and byte formats.

| Property | Status |
| --- | --- |
| Post-quantum secure | Yes (NTRU lattice assumptions); NIST Level 5 |
| EUF-CMA secure | Yes, per the Falcon specification |
| Deterministic signing | No. Each signature draws a 40-byte nonce and then a 48-byte sampler seed from the caller's `RandomSource` (`OsRandom` for the methods without one). The sampler seed is as sensitive as the private key for the signature it produces; a source that repeats bytes belongs in tests only. The nonce must not repeat while the seed changes: two signatures of one message under one nonce differ by a short vector of the private lattice. A caller that wants deterministic signatures derives both values from a pseudorandom function of the key and the message. |
| Stateless | Yes |
| Side-channel resistant | Verification is integer-only. Key generation and signing use native `f64` and, like the reference, are not constant-time; see "Side-channel boundary". |
| Signature malleability | No: the compressed encoding rejects a `-0` coefficient, magnitudes above 2047, non-zero padding bits and trailing bytes, and both framings require the signature to consume exactly the bytes it claims, so a signature has exactly one accepted encoding. PQClean's falcon-1024 verifier and liboqs also accept the polynomial zero-padded to the 1,280-byte falcon-padded-1024 length, in both framings; this crate rejects that form, as go-qrllib does. The accepted set is frozen by `crates/qrllib/src/falcon1024/testdata/signature_encoding_vectors.json` (shared with go-qrllib), and the cross-verification job pins both behaviours. |
| Public-key validation | `PublicKey::from_bytes` (and `validate_falcon_public_key`, for callers holding raw bytes) rejects weak keys, those under which the verifier would accept a signature anyone can compute. A key `h = a/c` with a small polynomial `a` and a small integer `c` publishes a short basis of its lattice, and rounding a message hash against it gives a signature inside the norm bound; every constant and monomial key is of that form. The rule: with `h` centred, the key is weak if for some integer `c` in `[1, 1024]` the squared norm of the centred coefficients of `c·h`, plus `c²`, is at most `2^30`. Honest keys have `‖c·h‖² ≈ 1.29·10^10` for every `c`; the chance that a generated key is rejected is below `2^-1562`. The same rule runs on the public half of an imported private key and in key generation; the primitive verifier is unchanged. It is sufficient, not complete: a key built as `a/b` for a sparse non-integer `b` is not caught. The rule is integer-only and is applied identically by every QRL client against `crates/qrllib/src/falcon1024/testdata/weak_public_key_vectors.json`. Error: `QrllibError::FalconWeakPublicKey`. |
| Private-key import | `PrivateKey::from_bytes` recomputes G as the reference `crypto_sign` does and then applies three checks the reference does not: the public half must pass the weak-key rule; (f, g, F, G) must solve `f·G − g·F = q` (an encoding whose F is replaced by `x·F`, `−F` or `f` derives the correct public key but cannot sign); and (f, g) must satisfy the key-generation bounds (squared norm below 16823, Gram-Schmidt norm below 16822.4121). Every key the reference or this crate generates passes. Signing is bounded at 128 attempts and at 2^16 sampler draws per coordinate and returns `QrllibError::FalconSigningFailed` when either bound is hit, so a basis that cannot sign never spins. |
| Domain separation | None in the primitive: the signed input is the nonce followed by the message, as the round-3 submission defines it. A protocol that signs several kinds of data with one key must prefix its own domain separator. FIPS 206 adds a context string and changes the hashing, so the prefix will need revisiting when the standard is final. |
| Standard status | Falcon as submitted to round 3 of the NIST competition (specification v1.2), bit for bit with the reference implementation (size constants from PQClean's `api.h`): the full round-3 KAT transcript is rebuilt in the test suite and checked by its SHA-1, go-qrllib's pinned key-derivation and signing-loop digests are reproduced, and CI compares keys and signatures byte for byte with PQClean on amd64 and arm64. Rust never fuses `a * b + c` into one rounding, so the native `f64` sampler rounds as the reference does on every target. FIPS 206 (FN-DSA) is still a draft and is announced to differ from the submission. |
| Zeroization | `PrivateKey::zeroize` (also run on drop) wipes the encoded key, the FFT basis and the LDL tree; signing afterwards returns `QrllibError::FalconSecretKeyZeroized` and the public key stays available. The sampler PRNG, the sampler seed and the NTRU solver workspace are wiped when they go out of scope. |

### XMSS provenance and standards alignment

QRL deployed its XMSS construction before [RFC 8391](https://www.rfc-editor.org/rfc/rfc8391.html)
was published in May 2018. The eventual RFC specified a construction
that is closely aligned with QRL for the overlapping SHA2-256 and SHAKE256
parameter families. In particular, their signature byte layout is compatible,
and RFC 8391 section 3.1.7 permits pseudorandom private-key generation while
giving `PRF(seed, toByte(i, 32))` as an example. That example matches the
private WOTS-string derivation retained by QRL.

This history matters because XMSS roots form part of QRL v1 public keys and
addresses on an immutable blockchain. Replacing the deployed derivation would
not transparently upgrade an existing key: it would derive a different tree
root and therefore a different address. Preserving the construction is a
consensus-compatibility requirement, not an attempt to retrofit a later
profile onto historical keys.

The compatibility surface has explicit boundaries:

- `Sha2_256` and `Shake256` use the RFC 8391 signature construction for the
  overlapping `n=32` parameter families. The `xmss::rfc8391` module maps the
  six supported height-10/16/20 OIDs and converts between QRL's three-byte
  descriptor/public-key convention and the RFC's four-byte OID layout.
- The external CI test proves both signing directions against the pinned XMSS
  reference for `XMSS-SHA2_10_256`: Rust signs and the reference verifies, then
  the reference signs from the same 96-byte expanded seed and Rust verifies.
  The adapter maps the other supported OIDs, but the workflow does not claim
  independent reference coverage for every mapped parameter set.
- QRL's 48-byte seed is SHAKE256-expanded into `SK_SEED || SK_PRF || PUB_SEED`.
  RFC 8391 does not prescribe that outer wallet-seed convention; the interop
  module therefore also accepts the 96 bytes directly.
- `Shake128` is a pre-standardisation QRL-specific variant with no RFC OID. It
  remains available only so existing v1 addresses can be parsed, verified, and
  signed; it is not recommended for new keys.

[NIST SP 800-208](https://csrc.nist.gov/pubs/sp/800/208/final), published in
October 2020, is a later and deliberately stricter profile of stateful
hash-based signatures. Following public analysis of multi-target security, it
selected `PRFkeygen(SK_SEED, PUB_SEED || ADRS)` for private-string generation.
It also restricts approved parameter sets and requires key and signature
generation in non-exporting hardware cryptographic modules. Those requirements
post-date QRL's deployed keys and are not this library's compatibility target.
Accordingly, `rust-qrllib` should not be represented as an SP 800-208-conforming
cryptographic module. That scope statement does not mean QRL signatures are
malformed: for the overlapping construction they retain RFC-format
interoperability as described and tested above.

The cross-verification workflow pins `xmss-reference` commit `7793c40`, the
last revision using the compatible RFC-example derivation. Upstream commit
[`3e28db2`](https://github.com/XMSS/xmss-reference/commit/3e28db2) subsequently
introduced the SP 800-208-style `PRFkeygen` construction. The pin is therefore
intentional and auditable rather than an untracked dependency on an old
revision.

## Address Security

Modern QRL addresses are 64 bytes:

```text
SHAKE256(descriptor || public_key)[:64]
```

Their string form is an uppercase `Q` followed by 128 hexadecimal characters.
`format_address` emits lowercase hex; `to_checksum_address` emits the canonical
EIP-55-style mixed-case checksum used by `go-qrllib` and wallet.js.

`is_valid_address` is permissive about the **hex body** only: it accepts
uniform-case input or a correctly checksummed mixed-case form. The `Q` prefix
must be uppercase, so `rust-qrllib` and `go-qrllib` accept exactly the same set
of address strings. Applications that require typo
detection should use `is_valid_checksum_address`. The checksum is not an
authentication mechanism; an attacker who controls the display path can show a
valid checksum for an attacker-controlled address.

## Side-channel boundary

The ML-DSA verification challenge comparison and ML-KEM re-encryption check use
full-width constant-time equality helpers. ML-KEM decapsulation performs
implicit rejection without branching on ciphertext validity. These properties
do not make the whole library, Rust standard library, allocator, browser, or CPU
constant-time.

Falcon-1024 verification is integer-only (NTT mod q and a saturating
squared-norm sum). Key generation and signing use native `f64`; like the
reference implementation they are not constant-time. The Gaussian sampler
keeps the reference's control flow (its data-dependent branches, the `BerExp`
byte loop and the rejection loop, are in the C code too), but the timing of
hardware floating-point operations is outside the library's control. Do not
run Falcon signing where a co-resident attacker can time it.

Signing includes parameter-defined rejection sampling, and execution time may
vary with public inputs, random nonces, runtime scheduling, cache state, and the
target platform. Deployments requiring hardware-level resistance to local
timing, cache, fault-injection, or memory attacks should use an independently
evaluated hardened implementation or HSM.

## XMSS State Management

XMSS security is broken if the same OTS index is used twice.

The type system closes one failure mode: `Xmss` and `LegacyXmssWallet` deliberately do not implement `Clone`, so the accidental `wallet.clone()` path that would cause immediate one-time-key reuse is a compile error. This does **not** close the broader surface — serialising the secret-key bytes, persisting to disk, and re-instantiating later is a legitimate pattern that the library must support, and it is the application's responsibility to ensure the new instance starts at an OTS index greater than or equal to the highest used index.

Production XMSS usage must:

- Persist the updated index before using or broadcasting a signature.
- Maintain an append-only high-water mark for used indices.
- Reject concurrent signing from the same XMSS instance.
- Treat restored backups as unsafe until index history is reconciled.
- Rotate keys before exhausting the tree.

The required ordering is:

```text
1. Generate the signature; the in-memory index advances.
2. Persist the new high-water mark to durable, monotonic storage.
3. Verify that persistence succeeded.
4. Only then release or broadcast the signature.
```

| Failure mode | Consequence | Required control |
|--------------|-------------|------------------|
| Process or power loss before persistence | The previous index may be loaded again | Never release the signature before the new index is durable |
| Concurrent signers | Two instances may consume the same index | One serialized signing authority per key |
| Backup or snapshot restore | Stored state can move backwards | Reconcile against an external append-only high-water mark |
| Database rollback | Used indices can reappear as available | Monotonic or append-only storage with rollback detection |
| Tree exhaustion | No unused OTS keys remain | Monitor capacity and rotate early |

## Canonicality And Negative Testing

Rust regression suites cover malformed input, canonicality, KATs, thread-safety behavior, and legacy fuzz corpora:

- `crates/qrllib/tests/parity_suite.rs`
- `crates/qrllib/tests/kat_vectors.rs`
- `crates/qrllib/tests/thread_fuzz_suite.rs`
- ML-DSA-87 NIST ACVP keyGen + sigGen and C2SP/wycheproof verify (the in-crate `acvp` and `wycheproof` modules under `crates/qrllib/src/mldsa/`, including the weak-key `ZeroPublicKey` and `MissingReduction` groups), consumed from upstream at CI time.
- ML-DSA-87 weak-key vectors shared with go-qrllib, qrypto.js and wallet.js (the in-crate `weak_keys` module and `crates/qrllib/src/mldsa/testdata/weak_public_key_vectors.json`).
- Falcon-1024 (the in-crate `tests` module under `crates/qrllib/src/falcon1024/`): the reference `verify_raw` vectors and `test_falcon.c` key components, the round-3 KAT transcript digest and per-case compressed signatures, go-qrllib's pinned key-derivation and signing-loop digests, the signature-encoding and weak-key vectors shared with go-qrllib, malformed signed messages and detached signatures (truncation, `-0`, over-long unary runs, padding bits, trailing bytes, wrong headers and length fields), forbidden private-key encodings and inconsistent NTRU solutions, and the bounded signing loops.
- `crates/qrllib/tests/mlkem_cross_vectors.rs` — ML-KEM-1024 key generation, encapsulation, and decapsulation cross-verified byte-for-byte against `go-qrllib`.
- ML-KEM-1024 NIST ACVP keyGen + encapDecap (the `acvp` module in `crates/qrllib/src/mlkem.rs`) and the C2SP/wycheproof + C2SP/CCTV corpora (`crates/qrllib/tests/wycheproof_mlkem.rs`), consumed from upstream at CI time. See `.github/acvp/README.md` and `.github/wycheproof/README.md`.
- `crates/qrllib/tests/hardening_suite.rs` — regression coverage for the randomised-signing entry points, the `QrllibError::RejectionBudgetExceeded` variant, the uppercase-`Q` address-prefix requirement, and the post-zeroize rejection of every sign/seal path (ML-DSA, SPHINCS+, and XMSS).

## Dependency Security

- Rust direct dependencies are exact-pinned in `Cargo.toml` and resolved in `Cargo.lock`; CI runs Cargo with `--locked`.
- Demo npm direct dependencies are exact-pinned in `package.json`; CI installs with `npm ci` from `package-lock.json`.
- GitHub Actions are pinned by commit SHA with version comments for auditability.
- `cargo audit` scans RustSec advisories.
- `cargo deny` enforces advisories, dependency bans, source policy, and license policy.
- Dependabot tracks Rust crates, demo npm dependencies, and GitHub Actions.

## Release Verification

All releases include checksums, SBOMs, and GitHub/Sigstore-backed attestations.

Verify release metadata with GitHub CLI:

```bash
gh attestation verify Cargo.toml --owner theQRL
gh attestation verify Cargo.lock --owner theQRL
gh attestation verify deny.toml --owner theQRL
gh attestation verify release-plz.toml --owner theQRL
gh attestation verify sbom-spdx.json --owner theQRL
```

Verify checksums:

```bash
curl -LO https://github.com/theQRL/rust-qrllib/releases/download/qrllib-vX.Y.Z/checksums-sha256.txt
sha256sum -c checksums-sha256.txt
```

Verify SLSA provenance:

```bash
# Install slsa-verifier from https://github.com/slsa-framework/slsa-verifier
curl -LO https://github.com/theQRL/rust-qrllib/releases/download/qrllib-vX.Y.Z/provenance.intoto.jsonl
slsa-verifier verify-artifact Cargo.toml \
  --provenance-path provenance.intoto.jsonl \
  --source-uri github.com/theQRL/rust-qrllib
```

Release artifacts:

| Artifact | Purpose |
|----------|---------|
| `Cargo.toml`, `Cargo.lock` | Workspace dependency state |
| `deny.toml`, `release-plz.toml` | Policy and release inputs |
| `checksums-sha256.txt`, `checksums-sha512.txt` | Integrity verification |
| `sbom-spdx.json`, `sbom-cyclonedx.json` | Software composition |
| `provenance.intoto.jsonl` | SLSA provenance |

## Secure Development Practices

Cryptographic changes require review, passing Rust CI, passing security checks, and no new unresolved warnings from `cargo clippy`, `cargo audit`, or `cargo deny`.

## Version Support

| Version | Support |
|---------|---------|
| Latest release | Full support |
| Previous minor release | Security fixes where practical |
| Older releases | Unsupported; upgrade to the latest release |

## Contact

For security concerns, email [security@theqrl.org](mailto:security@theqrl.org)
or use the [QRL security report form](https://www.theqrl.org/security-report/).
