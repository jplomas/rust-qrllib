//! The Falcon reference sampler PRNG (`prng_init` / `prng_refill` with
//! ChaCha20), transliterated from go-qrllib
//! `crypto/internal/falcon1024/rng.go`.

// Index loops are kept where they mirror the reference C line for line.
#![allow(clippy::needless_range_loop)]

use super::ShakeReader;
use sha3::digest::XofReader;
use zeroize::Zeroize;

const CHACHA_CONST: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// The reference ChaCha20-based PRNG that feeds the Gaussian sampler. Its
/// stream is as sensitive as the private key for the signature it produces,
/// so it is wiped on drop.
pub(super) struct SamplerPrng {
    buf: [u8; 512],
    ptr: usize,
    state: [u32; 12],
    counter: u64,
    /// Rejection-loop iterations of the sampler since the last seeding.
    pub(super) draws: u64,
    /// Set when one coordinate used up `MAX_SAMPLER_DRAWS`, which ends the
    /// signing attempt.
    pub(super) exhausted: bool,
}

impl SamplerPrng {
    /// An unseeded PRNG; [`SamplerPrng::init`] seeds it.
    pub(super) fn new() -> Self {
        Self { buf: [0; 512], ptr: 0, state: [0; 12], counter: 0, draws: 0, exhausted: false }
    }

    /// Reference `prng_init`: 56 bytes of the SHAKE stream become 48 bytes
    /// of ChaCha state and an 8-byte counter.
    pub(super) fn init(&mut self, rng: &mut ShakeReader) {
        let mut seed = [0_u8; 56];
        rng.read(&mut seed);
        for (i, word) in self.state.iter_mut().enumerate() {
            *word = u32::from_le_bytes(seed[4 * i..4 * i + 4].try_into().expect("4 bytes"));
        }
        self.counter = u64::from_le_bytes(seed[48..56].try_into().expect("8 bytes"));
        self.draws = 0;
        self.exhausted = false;
        seed.zeroize();
        self.refill();
    }

    /// Reference `prng_get_u8`: the next byte, refilling at the buffer end.
    pub(super) fn read_byte(&mut self) -> u8 {
        let v = self.buf[self.ptr];
        self.ptr += 1;
        if self.ptr == self.buf.len() {
            self.refill();
        }
        v
    }

    /// Reference `prng_get_u64`: refills early rather than straddling the
    /// buffer end, which may discard up to nine tail bytes.
    pub(super) fn read_u64(&mut self) -> u64 {
        if self.ptr >= self.buf.len() - 9 {
            self.refill();
        }
        let v = u64::from_le_bytes(self.buf[self.ptr..self.ptr + 8].try_into().expect("8 bytes"));
        self.ptr += 8;
        v
    }

    /// Reference `prng_refill`: eight ChaCha20 blocks with consecutive
    /// counters, interleaved into the buffer.
    fn refill(&mut self) {
        let mut counter = self.counter;
        for block in 0..8 {
            let mut state = [
                CHACHA_CONST[0],
                CHACHA_CONST[1],
                CHACHA_CONST[2],
                CHACHA_CONST[3],
                self.state[0],
                self.state[1],
                self.state[2],
                self.state[3],
                self.state[4],
                self.state[5],
                self.state[6],
                self.state[7],
                self.state[8],
                self.state[9],
                self.state[10] ^ (counter as u32),
                self.state[11] ^ ((counter >> 32) as u32),
            ];

            for _ in 0..10 {
                quarter_round(&mut state, 0, 4, 8, 12);
                quarter_round(&mut state, 1, 5, 9, 13);
                quarter_round(&mut state, 2, 6, 10, 14);
                quarter_round(&mut state, 3, 7, 11, 15);
                quarter_round(&mut state, 0, 5, 10, 15);
                quarter_round(&mut state, 1, 6, 11, 12);
                quarter_round(&mut state, 2, 7, 8, 13);
                quarter_round(&mut state, 3, 4, 9, 14);
            }

            for v in 0..4 {
                state[v] = state[v].wrapping_add(CHACHA_CONST[v]);
            }
            for v in 4..14 {
                state[v] = state[v].wrapping_add(self.state[v - 4]);
            }
            state[14] = state[14].wrapping_add(self.state[10] ^ (counter as u32));
            state[15] = state[15].wrapping_add(self.state[11] ^ ((counter >> 32) as u32));
            counter = counter.wrapping_add(1);

            // Eight blocks interleaved by word, the reference buffer layout.
            for (word, value) in state.iter().enumerate() {
                let off = (block << 2) + (word << 5);
                self.buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
            }
            state.zeroize();
        }
        self.counter = counter;
        self.ptr = 0;
    }
}

impl Drop for SamplerPrng {
    /// Wipes the buffer, the ChaCha state and the counters.
    fn drop(&mut self) {
        self.buf.zeroize();
        self.state.zeroize();
        self.counter = 0;
        self.ptr = 0;
        self.draws = 0;
        self.exhausted = false;
    }
}

/// The ChaCha20 quarter round on words a, b, c and d of `state`.
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(7);
}
