//! A std-only SHA-256 (FIPS 180-4), the case harness's own.
//!
//! Engine independence (docs/FORENSIC_CASE_STUDIES_PLAN.md §3.1): the case
//! model hashes quotes, canonical value bytes, Exhibit B row blocks, tier-row
//! digests and filler seeds, and it must not share a hash implementation
//! with the engine it checks. The only other implementation in the workspace
//! is private to fa-docket (`crates/fa-docket/src/intake.rs`), so fa-oracles
//! carries its own, checked against the FIPS 180-4 example vectors
//! ([`FIPS_180_4_VECTORS`]) and against independently computed digests at
//! every padding boundary (the crate's `tests/sha256.rs`).

/// The first 32 bits of the fractional parts of the cube roots of the first
/// 64 primes (FIPS 180-4 §4.2.2).
const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// The initial hash value (FIPS 180-4 §5.3.3).
const H0: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// One 512-bit block of the compression function (FIPS 180-4 §6.2.2).
fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    let (words, _) = block.as_chunks::<4>();
    for (slot, word) in w.iter_mut().zip(words) {
        *slot = u32::from_be_bytes(*word);
    }
    for t in 16..64 {
        let s0 = w[t - 15].rotate_right(7) ^ w[t - 15].rotate_right(18) ^ (w[t - 15] >> 3);
        let s1 = w[t - 2].rotate_right(17) ^ w[t - 2].rotate_right(19) ^ (w[t - 2] >> 10);
        w[t] = w[t - 16]
            .wrapping_add(s0)
            .wrapping_add(w[t - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for (k, wt) in K.iter().zip(w.iter()) {
        let big_s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(big_s1)
            .wrapping_add(ch)
            .wrapping_add(*k)
            .wrapping_add(*wt);
        let big_s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = big_s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    for (slot, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *slot = slot.wrapping_add(v);
    }
}

/// The SHA-256 digest of `bytes`.
#[must_use]
pub fn digest(bytes: &[u8]) -> [u8; 32] {
    let mut state = H0;
    let (blocks, rest) = bytes.as_chunks::<64>();
    for block in blocks {
        compress(&mut state, block);
    }
    // Padding (FIPS 180-4 §5.1.1): 0x80, zeros, then the message length in
    // bits as a big-endian u64, in one block when the remainder leaves room
    // for the nine bytes, else in two. The length is taken modulo 2^64, as
    // the standard specifies.
    let mut tail = [0u8; 128];
    tail[..rest.len()].copy_from_slice(rest);
    tail[rest.len()] = 0x80;
    let tail_len = if rest.len() < 56 { 64 } else { 128 };
    let bit_len = u64::try_from(bytes.len())
        .expect("a slice length fits in u64")
        .wrapping_mul(8);
    tail[tail_len - 8..tail_len].copy_from_slice(&bit_len.to_be_bytes());
    for block in tail[..tail_len].as_chunks::<64>().0 {
        compress(&mut state, block);
    }
    let mut out = [0u8; 32];
    for (dst, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(state) {
        *dst = word.to_be_bytes();
    }
    out
}

/// A digest as 64 lower-case hex characters.
#[must_use]
pub fn hex(digest: &[u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for byte in digest {
        s.push(char::from(DIGITS[usize::from(byte >> 4)]));
        s.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    s
}

/// The message of a test vector: literal bytes, or one byte repeated (the
/// FIPS one-million-`a` vector).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Message {
    Bytes(&'static [u8]),
    Repeat { byte: u8, count: usize },
}

impl Message {
    /// The message's bytes.
    #[must_use]
    pub fn bytes(self) -> Vec<u8> {
        match self {
            Self::Bytes(b) => b.to_vec(),
            Self::Repeat { byte, count } => vec![byte; count],
        }
    }
}

/// One known-answer vector: a name, a message, and its digest in hex.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vector {
    pub name: &'static str,
    pub message: Message,
    pub digest_hex: &'static str,
}

/// The SHA-256 example vectors of FIPS 180-4 (NIST's "Examples with
/// intermediate values" for SHA-256): the one-block message "abc", the
/// two-block 448-bit message, the 896-bit message, one million `a`, and the
/// empty message.
pub const FIPS_180_4_VECTORS: [Vector; 5] = [
    Vector {
        name: "empty message",
        message: Message::Bytes(b""),
        digest_hex: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    Vector {
        name: "abc (one block)",
        message: Message::Bytes(b"abc"),
        digest_hex: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    },
    Vector {
        name: "448-bit message (two blocks)",
        message: Message::Bytes(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        digest_hex: "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    },
    Vector {
        name: "896-bit message",
        message: Message::Bytes(
            b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        ),
        digest_hex: "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
    },
    Vector {
        name: "one million 'a'",
        message: Message::Repeat {
            byte: b'a',
            count: 1_000_000,
        },
        digest_hex: "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
    },
];

/// Checks `table` against [`digest`], naming the first vector whose
/// computed digest differs, with both values.
///
/// # Errors
///
/// The message names the vector, the expected and the computed digest.
pub fn check_vectors(table: &[Vector]) -> Result<(), String> {
    for v in table {
        let computed = hex(&digest(&v.message.bytes()));
        if computed != v.digest_hex {
            return Err(format!(
                "SHA-256 vector `{}`: expected {}, computed {computed}",
                v.name, v.digest_hex
            ));
        }
    }
    Ok(())
}
