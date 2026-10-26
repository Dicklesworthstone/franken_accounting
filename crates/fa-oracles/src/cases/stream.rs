//! The deterministic draw stream (docs/FORENSIC_CASE_STUDIES_PLAN.md §3.7;
//! bead fa-yugf.14, A6): block n is SHA-256(seed ‖ n as u64 LE), and every
//! draw takes the next 8 bytes of the stream. A6's filler and A5a's
//! witnesses draw from it, so a variant's content is a pure function of its
//! seed and never of the platform, the clock or an RNG.

use crate::sha256;

/// A stream over a 32-byte seed.
#[derive(Clone, Debug)]
pub struct Stream {
    seed: [u8; 32],
    counter: u64,
    block: [u8; 32],
    used: usize,
}

impl Stream {
    #[must_use]
    pub const fn new(seed: [u8; 32]) -> Self {
        Self {
            seed,
            counter: 0,
            block: [0; 32],
            used: 32,
        }
    }

    /// The stream of SHA-256 of `parts` joined by one 0x00 byte each, so no
    /// two part lists share a seed.
    #[must_use]
    pub fn from_parts(parts: &[&[u8]]) -> Self {
        let mut bytes = Vec::new();
        for (i, p) in parts.iter().enumerate() {
            if i > 0 {
                bytes.push(0);
            }
            bytes.extend_from_slice(p);
        }
        Self::new(sha256::digest(&bytes))
    }

    /// The next 8 bytes as a little-endian u64.
    pub fn next_u64(&mut self) -> u64 {
        if self.used + 8 > 32 {
            let mut input = Vec::with_capacity(40);
            input.extend_from_slice(&self.seed);
            input.extend_from_slice(&self.counter.to_le_bytes());
            self.block = sha256::digest(&input);
            self.counter += 1;
            self.used = 0;
        }
        let mut word = [0u8; 8];
        word.copy_from_slice(&self.block[self.used..self.used + 8]);
        self.used += 8;
        u64::from_le_bytes(word)
    }

    /// A uniform draw from `0..n` by rejection (no modulo bias); 0 when `n`
    /// is 0.
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        let zone = u64::MAX - (u64::MAX % n) - 1;
        loop {
            let x = self.next_u64();
            if x <= zone {
                return x % n;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stream_is_sha256_of_seed_and_counter() {
        let seed = sha256::digest(b"seed");
        let mut s = Stream::new(seed);
        let mut want = Vec::new();
        want.extend_from_slice(&seed);
        want.extend_from_slice(&0u64.to_le_bytes());
        let block = sha256::digest(&want);
        let mut first = [0u8; 8];
        first.copy_from_slice(&block[..8]);
        assert_eq!(s.next_u64(), u64::from_le_bytes(first));
        // Four words per block, then block 1.
        for _ in 0..3 {
            s.next_u64();
        }
        let mut want = Vec::new();
        want.extend_from_slice(&seed);
        want.extend_from_slice(&1u64.to_le_bytes());
        let block = sha256::digest(&want);
        first.copy_from_slice(&block[..8]);
        assert_eq!(s.next_u64(), u64::from_le_bytes(first));
    }

    #[test]
    fn same_parts_give_the_same_draws_and_bounds_hold() {
        let a: Vec<u64> = {
            let mut s = Stream::from_parts(&[b"case", b"v", b"1"]);
            (0..64).map(|_| s.below(7)).collect()
        };
        let b: Vec<u64> = {
            let mut s = Stream::from_parts(&[b"case", b"v", b"1"]);
            (0..64).map(|_| s.below(7)).collect()
        };
        assert_eq!(a, b);
        assert!(a.iter().all(|x| *x < 7));
        let c: Vec<u64> = {
            let mut s = Stream::from_parts(&[b"case", b"v1", b""]);
            (0..64).map(|_| s.below(7)).collect()
        };
        assert_ne!(a, c, "the 0x00 separator keeps part lists apart");
    }
}
