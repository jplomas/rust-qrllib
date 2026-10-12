//! Cross-verifies rust-qrllib Falcon-1024 against PQClean's falcon-1024
//! "clean" implementation, the round-3 reference code (integer-emulated
//! floating point, `sign_dyn`) behind the NIST API this crate follows. Ported
//! from go-qrllib `.github/cross-verify/falcon1024_crossverify.go`.
//!
//! Both sides draw every random byte from the same SHAKE256 stream: the C
//! harness (`.github/cross-verify/falcon1024_crossverify_ref.c`) defines
//! `randombytes()` over PQClean's own SHAKE256 with the same label. Key
//! generation consumes 48 bytes, each signing call a 40-byte nonce and then a
//! 48-byte sampler seed, and the messages come from the stream as well. So
//! beyond mutual verification the check requires byte-identical public keys,
//! private keys, signed messages and detached signatures.
//!
//! Usage:
//!
//! ```text
//! cargo run -p qrllib --example falcon1024_crossverify -- generate /tmp/falcon1024_rust.bin
//! cargo run -p qrllib --example falcon1024_crossverify -- check    /tmp/falcon1024_ref.bin
//! ```
//!
//! The file holds, per entry, public key, private key, message, signed
//! message and detached signature, each prefixed with its big-endian 32-bit
//! length.

use std::{env, fs, process::ExitCode};

use qrllib::falcon1024::{self, PrivateKey, PublicKey, RandomSource};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use shake::Shake256;

const ENTRIES: usize = 8;
const LABEL_RUST: &str = "rust-qrllib Falcon-1024 cross-verification: rust-qrllib generates";
const LABEL_REF: &str = "rust-qrllib Falcon-1024 cross-verification: PQClean generates";

/// The falcon-padded-1024 signature length. PQClean's falcon-1024 verifier
/// accepts a compressed signature zero-padded to it; rust-qrllib accepts
/// exactly one encoding. Both behaviours are pinned by the two harnesses.
const PADDED_SIGNATURE_SIZE: usize = 1280;
const NONCE_SIZE: usize = 40;

struct Stream(<Shake256 as ExtendableOutput>::Reader);

impl Stream {
    fn new(label: &str) -> Self {
        let mut h = Shake256::default();
        h.update(label.as_bytes());
        Self(h.finalize_xof())
    }
}

impl RandomSource for Stream {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> qrllib::Result<()> {
        self.0.read(dest);
        Ok(())
    }
}

#[derive(Default)]
struct Entry {
    pk: Vec<u8>,
    sk: Vec<u8>,
    msg: Vec<u8>,
    sm: Vec<u8>,
    sig: Vec<u8>,
}

impl Entry {
    fn fields(&self) -> [&Vec<u8>; 5] {
        [&self.pk, &self.sk, &self.msg, &self.sm, &self.sig]
    }
}

fn generate(label: &str) -> Result<Vec<Entry>, String> {
    let mut rnd = Stream::new(label);
    let mut out = Vec::with_capacity(ENTRIES);
    for i in 0..ENTRIES {
        let key = PrivateKey::generate_with_rng(&mut rnd)
            .map_err(|e| format!("entry {i}: key generation: {e}"))?;
        let public_key = key.public_key();
        let mut msg = vec![0_u8; 33 * (i + 1)];
        rnd.fill_bytes(&mut msg).map_err(|e| e.to_string())?;
        let sm = key.sign_with_rng(&mut rnd, &msg).map_err(|e| format!("entry {i}: sign: {e}"))?;
        let sig = key
            .sign_detached_with_rng(&mut rnd, &msg)
            .map_err(|e| format!("entry {i}: sign_detached: {e}"))?;
        if falcon1024::open(&public_key, &sm).ok().as_deref() != Some(&msg[..]) {
            return Err(format!("entry {i}: self-check of the signed message failed"));
        }
        if !falcon1024::verify(&public_key, &msg, &sig) {
            return Err(format!("entry {i}: self-check of the detached signature failed"));
        }
        let sk = key.to_bytes().map_err(|e| e.to_string())?.to_vec();
        out.push(Entry { pk: public_key.to_bytes().to_vec(), sk, msg, sm, sig });
    }
    Ok(out)
}

fn write_entries(path: &str, entries: &[Entry]) -> Result<(), String> {
    let mut buf = Vec::new();
    for e in entries {
        for field in e.fields() {
            buf.extend_from_slice(&(field.len() as u32).to_be_bytes());
            buf.extend_from_slice(field);
        }
    }
    fs::write(path, buf).map_err(|e| format!("cannot write {path}: {e}"))
}

fn read_entries(path: &str) -> Result<Vec<Entry>, String> {
    let data = fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let mut rest = &data[..];
    let mut next = || -> Result<Vec<u8>, String> {
        if rest.len() < 4 {
            return Err("truncated file".into());
        }
        let n = u32::from_be_bytes(rest[..4].try_into().expect("4 bytes")) as usize;
        rest = &rest[4..];
        if rest.len() < n {
            return Err("truncated file".into());
        }
        let field = rest[..n].to_vec();
        rest = &rest[n..];
        Ok(field)
    };
    let mut entries = Vec::new();
    for _ in 0..ENTRIES {
        entries.push(Entry { pk: next()?, sk: next()?, msg: next()?, sm: next()?, sig: next()? });
    }
    if next().is_ok() {
        return Err(format!("file holds more than {ENTRIES} entries"));
    }
    Ok(entries)
}

/// Regenerates the C harness's entries from its stream, requires them to be
/// byte-identical, and opens and verifies the C outputs with rust-qrllib.
fn check(path: &str) -> Result<(), String> {
    let theirs = read_entries(path)?;
    let ours = generate(LABEL_REF)?;
    for (i, (a, b)) in ours.iter().zip(&theirs).enumerate() {
        let names =
            ["public key", "private key", "message", "signed message", "detached signature"];
        for ((name, x), y) in names.iter().zip(a.fields()).zip(b.fields()) {
            if x != y {
                return Err(format!(
                    "entry {i}: {name} differs from PQClean's ({} vs {} bytes)",
                    x.len(),
                    y.len()
                ));
            }
        }

        let public_key =
            PublicKey::from_bytes(&b.pk).map_err(|e| format!("entry {i}: public key: {e}"))?;
        PrivateKey::from_bytes(&b.sk).map_err(|e| format!("entry {i}: private key: {e}"))?;
        if falcon1024::open(&public_key, &b.sm).ok().as_deref() != Some(&b.msg[..]) {
            return Err(format!("entry {i}: open rejected PQClean's signed message"));
        }
        if !falcon1024::verify(&public_key, &b.msg, &b.sig) {
            return Err(format!("entry {i}: verify rejected PQClean's detached signature"));
        }
        let mut tampered = b.msg.clone();
        tampered[0] ^= 1;
        if falcon1024::verify(&public_key, &tampered, &b.sig) {
            return Err(format!(
                "entry {i}: verify accepted PQClean's signature for another message"
            ));
        }

        // Negative vectors: the zero-padded forms PQClean accepts must not
        // verify here, in either format.
        if b.sig.len() < PADDED_SIGNATURE_SIZE {
            let mut padded = b.sig.clone();
            padded.resize(PADDED_SIGNATURE_SIZE, 0);
            if falcon1024::verify(&public_key, &b.msg, &padded) {
                return Err(format!("entry {i}: verify accepted a zero-padded detached signature"));
            }
        }
        let sig_len = usize::from(u16::from_be_bytes([b.sm[0], b.sm[1]]));
        if let Some(pad) =
            PADDED_SIGNATURE_SIZE.checked_sub(NONCE_SIZE + sig_len).filter(|&p| p > 0)
        {
            let mut sm_padded = b.sm.clone();
            sm_padded.resize(b.sm.len() + pad, 0);
            sm_padded[..2].copy_from_slice(&((sig_len + pad) as u16).to_be_bytes());
            if falcon1024::open(&public_key, &sm_padded).is_ok() {
                return Err(format!("entry {i}: open accepted a zero-padded signed message"));
            }
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let usage = || {
        eprintln!("usage: falcon1024_crossverify (generate|check) <file>");
        ExitCode::from(2)
    };
    let [_, mode, path] = &args[..] else {
        return usage();
    };
    let result = match mode.as_str() {
        "generate" => generate(LABEL_RUST).and_then(|entries| write_entries(path, &entries)),
        "check" => check(path),
        _ => return usage(),
    };
    if let Err(error) = result {
        eprintln!("FAIL: {error}");
        return ExitCode::FAILURE;
    }
    if mode == "generate" {
        println!("rust-qrllib Falcon-1024: wrote {ENTRIES} entries to {path}");
    } else {
        println!("rust-qrllib Falcon-1024 <-> PQClean falcon-1024: {ENTRIES} entries PASSED");
        println!(
            "  - same stream -> identical public key, private key, signed message and detached signature"
        );
        println!(
            "  - PQClean signed message opens and detached signature verifies under rust-qrllib"
        );
        println!("  - zero-padded (falcon-padded-1024 length) forms are rejected by rust-qrllib");
    }
    ExitCode::SUCCESS
}
