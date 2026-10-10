//! BLAKE3 in hash mode, written from the specification for this crate alone.
//!
//! The verifier must be auditable in isolation (plan §13.3), so it does not
//! link the producer's hash (`fgdb-crypto`): a shared hashing bug would make
//! a forged proof and its check agree. This is the portable reference
//! construction — 1024-byte chunks of 64-byte blocks, the BLAKE2s-derived
//! compression function with 7 rounds and the fixed message permutation,
//! and the lazily merged chaining-value stack — with only the 32-byte hash
//! output, because nothing here needs keyed mode, key derivation, or XOF.
//!
//! Correctness evidence: the official-convention test vectors in this
//! module's tests (every chunk and tree boundary through 100 chunks), and
//! fa-notary's differential test against `fgdb-crypto` on the same inputs.

const IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

const BLOCK_LEN: usize = 64;
const CHUNK_LEN: usize = 1024;

const CHUNK_START: u32 = 1 << 0;
const CHUNK_END: u32 = 1 << 1;
const PARENT: u32 = 1 << 2;
const ROOT: u32 = 1 << 3;

fn g(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    s[a] = s[a].wrapping_add(s[b]).wrapping_add(x);
    s[d] = (s[d] ^ s[a]).rotate_right(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_right(12);
    s[a] = s[a].wrapping_add(s[b]).wrapping_add(y);
    s[d] = (s[d] ^ s[a]).rotate_right(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_right(7);
}

fn round(s: &mut [u32; 16], m: &[u32; 16]) {
    // Columns.
    g(s, 0, 4, 8, 12, m[0], m[1]);
    g(s, 1, 5, 9, 13, m[2], m[3]);
    g(s, 2, 6, 10, 14, m[4], m[5]);
    g(s, 3, 7, 11, 15, m[6], m[7]);
    // Diagonals.
    g(s, 0, 5, 10, 15, m[8], m[9]);
    g(s, 1, 6, 11, 12, m[10], m[11]);
    g(s, 2, 7, 8, 13, m[12], m[13]);
    g(s, 3, 4, 9, 14, m[14], m[15]);
}

fn permute(m: &mut [u32; 16]) {
    let mut p = [0u32; 16];
    for (dst, src) in p.iter_mut().zip(MSG_PERMUTATION) {
        *dst = m[src];
    }
    *m = p;
}

fn compress(
    cv: &[u32; 8],
    block: &[u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 16] {
    let counter_lo = u32::try_from(counter & 0xffff_ffff).unwrap_or(0);
    let counter_hi = u32::try_from(counter >> 32).unwrap_or(0);
    let mut s = [
        cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7], IV[0], IV[1], IV[2], IV[3],
        counter_lo, counter_hi, block_len, flags,
    ];
    let mut m = *block;
    for r in 0..7 {
        round(&mut s, &m);
        if r < 6 {
            permute(&mut m);
        }
    }
    for i in 0..8 {
        s[i] ^= s[i + 8];
        s[i + 8] ^= cv[i];
    }
    s
}

fn words(block: &[u8; BLOCK_LEN]) -> [u32; 16] {
    let mut w = [0u32; 16];
    for (word, bytes) in w.iter_mut().zip(block.as_chunks::<4>().0) {
        *word = u32::from_le_bytes(*bytes);
    }
    w
}

fn first8(s: &[u32; 16]) -> [u32; 8] {
    [s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]
}

/// A compression input not yet compressed: either a chaining value for the
/// tree above it, or — with `ROOT` — the hash itself.
struct Output {
    input_cv: [u32; 8],
    block: [u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
}

impl Output {
    fn chaining_value(&self) -> [u32; 8] {
        first8(&compress(
            &self.input_cv,
            &self.block,
            self.counter,
            self.block_len,
            self.flags,
        ))
    }

    fn root_hash(&self) -> [u8; 32] {
        let s = compress(
            &self.input_cv,
            &self.block,
            0,
            self.block_len,
            self.flags | ROOT,
        );
        let mut out = [0u8; 32];
        for (dst, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(first8(&s)) {
            *dst = word.to_le_bytes();
        }
        out
    }
}

fn parent_output(left: &[u32; 8], right: &[u32; 8]) -> Output {
    let mut block = [0u32; 16];
    block[..8].copy_from_slice(left);
    block[8..].copy_from_slice(right);
    Output {
        input_cv: IV,
        block,
        counter: 0,
        block_len: BLOCK_LEN as u32,
        flags: PARENT,
    }
}

struct ChunkState {
    cv: [u32; 8],
    chunk_counter: u64,
    block: [u8; BLOCK_LEN],
    block_len: usize,
    blocks_compressed: usize,
}

impl ChunkState {
    fn new(chunk_counter: u64) -> Self {
        Self {
            cv: IV,
            chunk_counter,
            block: [0; BLOCK_LEN],
            block_len: 0,
            blocks_compressed: 0,
        }
    }

    fn len(&self) -> usize {
        BLOCK_LEN * self.blocks_compressed + self.block_len
    }

    fn start_flag(&self) -> u32 {
        if self.blocks_compressed == 0 {
            CHUNK_START
        } else {
            0
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            // A full block is compressed only once more input arrives, so
            // the chunk's last block is always left for `output`.
            if self.block_len == BLOCK_LEN {
                self.cv = first8(&compress(
                    &self.cv,
                    &words(&self.block),
                    self.chunk_counter,
                    BLOCK_LEN as u32,
                    self.start_flag(),
                ));
                self.blocks_compressed += 1;
                self.block = [0; BLOCK_LEN];
                self.block_len = 0;
            }
            let take = (BLOCK_LEN - self.block_len).min(input.len());
            self.block[self.block_len..self.block_len + take].copy_from_slice(&input[..take]);
            self.block_len += take;
            input = &input[take..];
        }
    }

    fn output(&self) -> Output {
        Output {
            input_cv: self.cv,
            block: words(&self.block),
            counter: self.chunk_counter,
            block_len: self.block_len as u32,
            flags: self.start_flag() | CHUNK_END,
        }
    }
}

/// An incremental BLAKE3 hasher (hash mode, 32-byte output).
pub struct Hasher {
    chunk: ChunkState,
    /// Chaining values of completed subtrees, smallest on top.
    cv_stack: Vec<[u32; 8]>,
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher {
    #[must_use]
    pub fn new() -> Self {
        Self {
            chunk: ChunkState::new(0),
            cv_stack: Vec::new(),
        }
    }

    /// Merge the completed chunk numbered `total_chunks - 1` into the stack:
    /// one parent per trailing zero bit of `total_chunks`.
    fn push_chunk_cv(&mut self, mut cv: [u32; 8], mut total_chunks: u64) {
        while total_chunks & 1 == 0 {
            let Some(left) = self.cv_stack.pop() else {
                break;
            };
            cv = parent_output(&left, &cv).chaining_value();
            total_chunks >>= 1;
        }
        self.cv_stack.push(cv);
    }

    pub fn update(&mut self, mut input: &[u8]) -> &mut Self {
        while !input.is_empty() {
            // A full chunk is finalized only once more input arrives, so
            // the last chunk is always left for the root.
            if self.chunk.len() == CHUNK_LEN {
                let cv = self.chunk.output().chaining_value();
                let total_chunks = self.chunk.chunk_counter + 1;
                self.push_chunk_cv(cv, total_chunks);
                self.chunk = ChunkState::new(total_chunks);
            }
            let take = (CHUNK_LEN - self.chunk.len()).min(input.len());
            self.chunk.update(&input[..take]);
            input = &input[take..];
        }
        self
    }

    #[must_use]
    pub fn finalize(&self) -> [u8; 32] {
        let mut output = self.chunk.output();
        for left in self.cv_stack.iter().rev() {
            output = parent_output(left, &output.chaining_value());
        }
        output.root_hash()
    }
}

/// `BLAKE3(input)`.
#[must_use]
pub fn hash(input: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(input);
    h.finalize()
}

/// `BLAKE3(domain ‖ parts…)`: every digest in the accumulator formats is
/// domain-separated this way.
#[must_use]
pub fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(domain);
    for p in parts {
        h.update(p);
    }
    h.finalize()
}

/// Lowercase hex, for reports and goldens.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from(DIGITS[usize::from(b >> 4)]));
        s.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The official BLAKE3 test-vector convention: input byte `i` is
    /// `i % 251`. These hashes are the plain-hash column of the vectors that
    /// FrankenGraphDB's `fgdb-crypto/tests/blake3_vectors.rs` froze from the
    /// official `blake3` crate (provenance recorded there; generated
    /// 2026-07-28). Copied as data, not code: the implementation above is
    /// this crate's own. Lengths cover every block, chunk, and tree-shape
    /// boundary through 100 chunks.
    const VECTORS: &[(usize, &str)] = &[
        (
            0,
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        ),
        (
            1,
            "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
        ),
        (
            2,
            "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63",
        ),
        (
            3,
            "e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f",
        ),
        (
            4,
            "f30f5ab28fe047904037f77b6da4fea1e27241c5d132638d8bedce9d40494f32",
        ),
        (
            63,
            "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b",
        ),
        (
            64,
            "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98",
        ),
        (
            65,
            "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee",
        ),
        (
            127,
            "d81293fda863f008c09e92fc382a81f5a0b4a1251cba1634016a0f86a6bd640d",
        ),
        (
            128,
            "f17e570564b26578c33bb7f44643f539624b05df1a76c81f30acd548c44b45ef",
        ),
        (
            129,
            "683aaae9f3c5ba37eaaf072aed0f9e30bac0865137bae68b1fde4ca2aebdcb12",
        ),
        (
            1023,
            "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11",
        ),
        (
            1024,
            "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
        ),
        (
            1025,
            "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444",
        ),
        (
            2048,
            "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a",
        ),
        (
            2049,
            "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b6879522563030",
        ),
        (
            3072,
            "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2",
        ),
        (
            3073,
            "7124b49501012f81cc7f11ca069ec9226cecb8a2c850cfe644e327d22d3e1cd3",
        ),
        (
            4096,
            "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e969",
        ),
        (
            4097,
            "9b4052b38f1c5fc8b1f9ff7ac7b27cd242487b3d890d15c96a1c25b8aa0fb995",
        ),
        (
            5120,
            "9cadc15fed8b5d854562b26a9536d9707cadeda9b143978f319ab34230535833",
        ),
        (
            5121,
            "628bd2cb2004694adaab7bbd778a25df25c47b9d4155a55f8fbd79f2fe154cff",
        ),
        (
            6144,
            "3e2e5b74e048f3add6d21faab3f83aa44d3b2278afb83b80b3c35164ebeca205",
        ),
        (
            6145,
            "f1323a8631446cc50536a9f705ee5cb619424d46887f3c376c695b70e0f0507f",
        ),
        (
            7168,
            "61da957ec2499a95d6b8023e2b0e604ec7f6b50e80a9678b89d2628e99ada77a",
        ),
        (
            7169,
            "a003fc7a51754a9b3c7fae0367ab3d782dccf28855a03d435f8cfe74605e7817",
        ),
        (
            8192,
            "aae792484c8efe4f19e2ca7d371d8c467ffb10748d8a5a1ae579948f718a2a63",
        ),
        (
            8193,
            "bab6c09cb8ce8cf459261398d2e7aef35700bf488116ceb94a36d0f5f1b7bc3b",
        ),
        (
            16384,
            "f875d6646de28985646f34ee13be9a576fd515f76b5b0a26bb324735041ddde4",
        ),
        (
            31744,
            "62b6960e1a44bcc1eb1a611a8d6235b6b4b78f32e7abc4fb4c6cdcce94895c47",
        ),
        (
            102400,
            "bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085",
        ),
    ];

    fn input(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn official_convention_vectors() {
        for (len, expected) in VECTORS {
            assert_eq!(hex(&hash(&input(*len))), *expected, "length {len}");
        }
    }

    /// Streaming is a pure function of the concatenated input: every split
    /// point and every feed size gives the one-shot hash.
    #[test]
    fn streaming_equals_one_shot_at_every_split() {
        for len in [0usize, 1, 63, 64, 65, 1023, 1024, 1025, 2049, 3073, 8193] {
            let data = input(len);
            let expected = hash(&data);
            for split in [0, 1, 63, 64, 65, 1023, 1024, 1025, len / 2, len] {
                let split = split.min(len);
                let mut h = Hasher::new();
                h.update(&data[..split]).update(&data[split..]);
                assert_eq!(h.finalize(), expected, "len {len} split {split}");
            }
            for feed in [1usize, 7, 64, 1000] {
                let mut h = Hasher::new();
                for piece in data.chunks(feed) {
                    h.update(piece);
                }
                assert_eq!(h.finalize(), expected, "len {len} feed {feed}");
            }
        }
    }

    #[test]
    fn hash_parts_is_hash_of_the_concatenation() {
        assert_eq!(
            hash_parts(b"fa:", &[b"acc", b"-leaf"]),
            hash(b"fa:acc-leaf")
        );
        assert_eq!(hex(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
    }
}
