//! Evidence intake pipeline (plan §9.1–§9.3; bead `fa-646`):
//! - Deterministic PDF text-layer extraction (`extract_pdf_text_layer`) with
//!   pure-Rust RFC 1950/1951 `/FlateDecode` decompression and ISO 32000-2
//!   §7.6.4.3 Algorithm 2.A (`/Filter /Standard /V 5 /R 5`, AES-256-CBC +
//!   SHA-256) empty-user-password decryption (`replayable = true`, preserving
//!   the source document's provenance grade).
//! - Subprocess adapters for `franken_ocr` (`focr`) and `franken_whisper` (`fw`)
//!   that record derived text `Document`s linked via `DERIVED_FROM` to the
//!   source image/PDF/audio `Document`, graded `AgentUpload` (`4`, advisory /
//!   self-sourced, requiring an independent human `Reviewed` attestation before
//!   satisfying `evidence_policy.toml` minimums), with `replayable = false`.
//! - Structural boundary: derived text extraction produces `Document`s for
//!   search, redaction, and human review (`record_review`); it never parses or
//!   constructs `Amount`s, `LegPayload`s, or `EntryProposal`s.

use std::path::{Path, PathBuf};
use std::process::Command;

use fa_journal::refusal::code;
use fa_journal::{
    DerivedExtractionMetadata, Document, ExtractionMethod, Refusal, encode_extraction_derivation,
    exit,
};
use fa_model::Oid;
use fgdb_types::VId;

/// Registered `evidence_policy.toml` grade tag for `HumanUpload`.
pub const GRADE_HUMAN_UPLOAD: u8 = 3;
/// Registered `evidence_policy.toml` grade tag for `AgentUpload` (self-sourced / advisory).
pub const GRADE_AGENT_UPLOAD: u8 = 4;
/// Registered `evidence_policy.toml` kind tag for `Workpaper`. (It was 8,
/// Remittance's tag, until fa-s3wz; only this crate's tests ever passed it.)
pub const KIND_WORKPAPER: u8 = 21;

/// Maximum decompressed PDF stream size (16 MiB) to prevent zip-bomb expansion.
const MAX_INFLATED_STREAM_BYTES: usize = 16 * 1024 * 1024;

/// Result of extracting a derived text `Document` from a source `Document`.
///
/// Structural invariant: this type carries only a `Document`, its
/// `DerivedExtractionMetadata`, and the parent `source_oid`. No `Amount` or
/// `LegPayload` is ever produced by the evidence intake pipeline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivedDocumentResult {
    pub document: Document,
    pub metadata: DerivedExtractionMetadata,
    pub source_oid: Oid,
}

/// Outcome of an external subprocess extraction tool (`focr` or `fw`).
///
/// When the external binary (or its required model package) is absent on the
/// host, the adapter returns `ExternalToolOutcome::Unrun` rather than faking a
/// pass or inventing text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExternalToolOutcome<T> {
    Completed(T),
    Unrun { binary: String, reason: String },
}

impl<T> ExternalToolOutcome<T> {
    #[must_use]
    pub const fn is_unrun(&self) -> bool {
        matches!(self, Self::Unrun { .. })
    }

    #[must_use]
    pub const fn is_completed(&self) -> bool {
        matches!(self, Self::Completed(_))
    }
}

fn intake_refusal(message: impl Into<String>, fix: impl Into<String>) -> Refusal {
    Refusal::new(
        code::EXTRACTION_FAILED,
        exit::REFUSAL,
        message,
        "plan §9.1–§9.3 (evidence intake pipeline and honest provenance grading); FA-INV-05",
        fix,
    )
}

// ============================================================================
// 1. Pure-Rust bounded RFC 1950/1951 zlib / DEFLATE inflater
// ============================================================================

/// Error returned when inflating a `/FlateDecode` PDF stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeflateError {
    TruncatedZlibHeader,
    InvalidZlibHeader,
    UnsupportedPresetDict,
    UnexpectedEof,
    InvalidBlockType(u8),
    StoredLenMismatch,
    EmptyHuffmanTree,
    OversubscribedHuffmanTree,
    InvalidHuffmanCode,
    InvalidCodeLengthRepeat,
    DistanceBeforeStart,
    OutputLimitExceeded { max_bytes: usize },
    Adler32Mismatch { expected: u32, actual: u32 },
}

impl core::fmt::Display for DeflateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TruncatedZlibHeader => f.write_str("deflate.truncated_zlib_header"),
            Self::InvalidZlibHeader => f.write_str("deflate.invalid_zlib_header"),
            Self::UnsupportedPresetDict => f.write_str("deflate.unsupported_preset_dict"),
            Self::UnexpectedEof => f.write_str("deflate.unexpected_eof"),
            Self::InvalidBlockType(b) => write!(f, "deflate.invalid_block_type({b})"),
            Self::StoredLenMismatch => f.write_str("deflate.stored_len_mismatch"),
            Self::EmptyHuffmanTree => f.write_str("deflate.empty_huffman_tree"),
            Self::OversubscribedHuffmanTree => f.write_str("deflate.oversubscribed_huffman_tree"),
            Self::InvalidHuffmanCode => f.write_str("deflate.invalid_huffman_code"),
            Self::InvalidCodeLengthRepeat => f.write_str("deflate.invalid_code_length_repeat"),
            Self::DistanceBeforeStart => f.write_str("deflate.distance_before_start"),
            Self::OutputLimitExceeded { max_bytes } => {
                write!(f, "deflate.output_limit_exceeded({max_bytes})")
            }
            Self::Adler32Mismatch { expected, actual } => {
                write!(
                    f,
                    "deflate.adler32_mismatch(expected=0x{expected:08x}, actual=0x{actual:08x})"
                )
            }
        }
    }
}

const MAX_BITS: usize = 15;

const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LENGTH_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
const CL_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    bit_buf: u64,
    bit_count: u8,
}

impl<'a> BitReader<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            bit_buf: 0,
            bit_count: 0,
        }
    }

    fn ensure(&mut self, n: u8) -> Result<(), DeflateError> {
        while self.bit_count < n {
            if self.pos >= self.data.len() {
                return Err(DeflateError::UnexpectedEof);
            }
            self.bit_buf |= u64::from(self.data[self.pos]) << self.bit_count;
            self.pos += 1;
            self.bit_count += 8;
        }
        Ok(())
    }

    fn read_bits(&mut self, n: u8) -> Result<u32, DeflateError> {
        if n == 0 {
            return Ok(0);
        }
        self.ensure(n)?;
        let mask = (1u64 << n) - 1;
        let val = (self.bit_buf & mask) as u32;
        self.bit_buf >>= n;
        self.bit_count -= n;
        Ok(val)
    }

    fn align_to_byte(&mut self) {
        let discard = self.bit_count % 8;
        self.bit_buf >>= discard;
        self.bit_count -= discard;
    }

    fn read_u16_le(&mut self) -> Result<u16, DeflateError> {
        let lo = self.read_bits(8)? as u16;
        let hi = self.read_bits(8)? as u16;
        Ok(lo | (hi << 8))
    }

    fn read_bytes(&mut self, out: &mut Vec<u8>, len: usize) -> Result<(), DeflateError> {
        debug_assert_eq!(self.bit_count % 8, 0);
        let mut rem = len;
        while self.bit_count > 0 && rem > 0 {
            out.push((self.bit_buf & 0xFF) as u8);
            self.bit_buf >>= 8;
            self.bit_count -= 8;
            rem -= 1;
        }
        if self.pos + rem > self.data.len() {
            return Err(DeflateError::UnexpectedEof);
        }
        out.extend_from_slice(&self.data[self.pos..self.pos + rem]);
        self.pos += rem;
        Ok(())
    }

    fn read_u32_be(&mut self) -> Result<u32, DeflateError> {
        self.align_to_byte();
        let b0 = self.read_bits(8)?;
        let b1 = self.read_bits(8)?;
        let b2 = self.read_bits(8)?;
        let b3 = self.read_bits(8)?;
        Ok((b0 << 24) | (b1 << 16) | (b2 << 8) | b3)
    }
}

struct HuffmanTree {
    counts: [u16; MAX_BITS + 1],
    symbols: Vec<u16>,
    max_len: usize,
}

impl HuffmanTree {
    fn from_lengths(lengths: &[u8]) -> Result<Self, DeflateError> {
        let mut counts = [0u16; MAX_BITS + 1];
        let mut max_len = 0usize;
        for &len in lengths {
            let l = len as usize;
            if l > MAX_BITS {
                return Err(DeflateError::OversubscribedHuffmanTree);
            }
            if l > 0 {
                counts[l] += 1;
                if l > max_len {
                    max_len = l;
                }
            }
        }
        if max_len == 0 {
            return Err(DeflateError::EmptyHuffmanTree);
        }
        let mut left = 1i32;
        for &count in counts.iter().take(MAX_BITS + 1).skip(1) {
            left <<= 1;
            left -= i32::from(count);
            if left < 0 {
                return Err(DeflateError::OversubscribedHuffmanTree);
            }
        }
        let mut offsets = [0u16; MAX_BITS + 1];
        let mut total = 0u16;
        for bits in 1..=max_len {
            offsets[bits] = total;
            total += counts[bits];
        }
        let mut symbols = vec![0u16; total as usize];
        for (sym, &len) in lengths.iter().enumerate() {
            let l = len as usize;
            if l > 0 {
                let idx = offsets[l] as usize;
                symbols[idx] = sym as u16;
                offsets[l] += 1;
            }
        }
        Ok(Self {
            counts,
            symbols,
            max_len,
        })
    }

    fn decode(&self, reader: &mut BitReader<'_>) -> Result<u16, DeflateError> {
        let mut code = 0i32;
        let mut first = 0i32;
        let mut index = 0i32;
        for len in 1..=self.max_len {
            code |= reader.read_bits(1)? as i32;
            let count = i32::from(self.counts[len]);
            if code - count < first {
                return Ok(self.symbols[(index + (code - first)) as usize]);
            }
            index += count;
            first += count;
            first <<= 1;
            code <<= 1;
        }
        Err(DeflateError::InvalidHuffmanCode)
    }
}

fn fixed_trees() -> Result<(HuffmanTree, HuffmanTree), DeflateError> {
    let mut lit_lengths = [0u8; 288];
    lit_lengths[..=143].fill(8);
    lit_lengths[144..=255].fill(9);
    lit_lengths[256..=279].fill(7);
    lit_lengths[280..=287].fill(8);
    let dist_lengths = [5u8; 32];
    Ok((
        HuffmanTree::from_lengths(&lit_lengths)?,
        HuffmanTree::from_lengths(&dist_lengths)?,
    ))
}

fn read_dynamic_trees(
    reader: &mut BitReader<'_>,
) -> Result<(HuffmanTree, Option<HuffmanTree>), DeflateError> {
    let hlit = (reader.read_bits(5)? as usize) + 257;
    let hdist = (reader.read_bits(5)? as usize) + 1;
    let hclen = (reader.read_bits(4)? as usize) + 4;
    if hlit > 286 || hdist > 30 {
        return Err(DeflateError::InvalidHuffmanCode);
    }
    let mut cl_lengths = [0u8; 19];
    for i in 0..hclen {
        cl_lengths[CL_ORDER[i]] = reader.read_bits(3)? as u8;
    }
    let cl_tree = HuffmanTree::from_lengths(&cl_lengths)?;
    let total = hlit + hdist;
    let mut lengths = Vec::with_capacity(total);
    while lengths.len() < total {
        let sym = cl_tree.decode(reader)?;
        match sym {
            0..=15 => lengths.push(sym as u8),
            16 => {
                let prev = *lengths
                    .last()
                    .ok_or(DeflateError::InvalidCodeLengthRepeat)?;
                let repeat = (reader.read_bits(2)? as usize) + 3;
                if lengths.len() + repeat > total {
                    return Err(DeflateError::InvalidCodeLengthRepeat);
                }
                lengths.resize(lengths.len() + repeat, prev);
            }
            17 => {
                let repeat = (reader.read_bits(3)? as usize) + 3;
                if lengths.len() + repeat > total {
                    return Err(DeflateError::InvalidCodeLengthRepeat);
                }
                lengths.resize(lengths.len() + repeat, 0);
            }
            18 => {
                let repeat = (reader.read_bits(7)? as usize) + 11;
                if lengths.len() + repeat > total {
                    return Err(DeflateError::InvalidCodeLengthRepeat);
                }
                lengths.resize(lengths.len() + repeat, 0);
            }
            _ => return Err(DeflateError::InvalidCodeLengthRepeat),
        }
    }
    let lit_tree = HuffmanTree::from_lengths(&lengths[..hlit])?;
    let dist_slice = &lengths[hlit..];
    let dist_tree = if dist_slice.iter().all(|&b| b == 0) {
        None
    } else {
        Some(HuffmanTree::from_lengths(dist_slice)?)
    };
    Ok((lit_tree, dist_tree))
}

fn adler32(data: &[u8]) -> u32 {
    const MOD_ADLER: u32 = 65521;
    let mut a = 1u32;
    let mut b = 0u32;
    for chunk in data.chunks(5552) {
        for &byte in chunk {
            a += u32::from(byte);
            b += a;
        }
        a %= MOD_ADLER;
        b %= MOD_ADLER;
    }
    (b << 16) | a
}

/// Decompress a zlib-wrapped (RFC 1950) or raw DEFLATE (RFC 1951) byte stream
/// with a strict output bound (`max_output`).
pub fn inflate_zlib(input: &[u8], max_output: usize) -> Result<Vec<u8>, DeflateError> {
    if input.len() < 2 {
        return Err(DeflateError::TruncatedZlibHeader);
    }
    let cmf = input[0];
    let flg = input[1];
    let is_zlib = (cmf & 0x0F) == 8
        && ((cmf >> 4) <= 7)
        && ((u16::from(cmf) * 256 + u16::from(flg)) % 31 == 0);
    if is_zlib && (flg & 0x20) != 0 {
        return Err(DeflateError::UnsupportedPresetDict);
    }
    let payload = if is_zlib { &input[2..] } else { input };
    let mut reader = BitReader::new(payload);
    let mut out = Vec::new();

    loop {
        let bfinal = reader.read_bits(1)?;
        let btype = reader.read_bits(2)? as u8;
        match btype {
            0 => {
                reader.align_to_byte();
                let len = reader.read_u16_le()?;
                let nlen = reader.read_u16_le()?;
                if len != !nlen {
                    return Err(DeflateError::StoredLenMismatch);
                }
                let block_len = len as usize;
                if out.len().saturating_add(block_len) > max_output {
                    return Err(DeflateError::OutputLimitExceeded {
                        max_bytes: max_output,
                    });
                }
                reader.read_bytes(&mut out, block_len)?;
            }
            1 | 2 => {
                let (lit_tree, dist_tree) = if btype == 1 {
                    let (l, d) = fixed_trees()?;
                    (l, Some(d))
                } else {
                    read_dynamic_trees(&mut reader)?
                };
                loop {
                    let sym = lit_tree.decode(&mut reader)?;
                    if sym < 256 {
                        if out.len() >= max_output {
                            return Err(DeflateError::OutputLimitExceeded {
                                max_bytes: max_output,
                            });
                        }
                        out.push(sym as u8);
                    } else if sym == 256 {
                        break;
                    } else {
                        let len_idx = (sym as usize) - 257;
                        if len_idx >= LENGTH_BASE.len() {
                            return Err(DeflateError::InvalidHuffmanCode);
                        }
                        let extra_bits = LENGTH_EXTRA[len_idx];
                        let length = (LENGTH_BASE[len_idx] as usize)
                            + (reader.read_bits(extra_bits)? as usize);
                        let d_tree = dist_tree.as_ref().ok_or(DeflateError::EmptyHuffmanTree)?;
                        let dist_sym = d_tree.decode(&mut reader)? as usize;
                        if dist_sym >= DIST_BASE.len() {
                            return Err(DeflateError::InvalidHuffmanCode);
                        }
                        let dist_extra = DIST_EXTRA[dist_sym];
                        let distance = (DIST_BASE[dist_sym] as usize)
                            + (reader.read_bits(dist_extra)? as usize);
                        if distance == 0 || distance > out.len() {
                            return Err(DeflateError::DistanceBeforeStart);
                        }
                        if out.len().saturating_add(length) > max_output {
                            return Err(DeflateError::OutputLimitExceeded {
                                max_bytes: max_output,
                            });
                        }
                        for _ in 0..length {
                            let b = out[out.len() - distance];
                            out.push(b);
                        }
                    }
                }
            }
            other => return Err(DeflateError::InvalidBlockType(other)),
        }
        if bfinal == 1 {
            break;
        }
    }

    if is_zlib {
        let expected = reader.read_u32_be()?;
        let actual = adler32(&out);
        if expected != actual {
            return Err(DeflateError::Adler32Mismatch { expected, actual });
        }
    }
    Ok(out)
}

// ============================================================================
// 2. Pure-Rust ISO 32000-2 §7.6.4.3 Algorithm 2.A PDF Standard Security (AES-256)
// ============================================================================

/// Error returned by the PDF Standard Security empty-user-password decryptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PdfCryptoError {
    NotStandardSecurity,
    UnsupportedAlgorithm { version: i32, revision: i32 },
    MissingEncryptionEntry(&'static str),
    MalformedEncryptionEntry(&'static str),
    EmptyUserPasswordRejected,
    InvalidCiphertextLength,
    InvalidPkcs7Padding,
}

impl PdfCryptoError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NotStandardSecurity => "pdf_crypto.not_standard_security",
            Self::UnsupportedAlgorithm { .. } => "pdf_crypto.unsupported_algorithm",
            Self::MissingEncryptionEntry(_) => "pdf_crypto.missing_encryption_entry",
            Self::MalformedEncryptionEntry(_) => "pdf_crypto.malformed_encryption_entry",
            Self::EmptyUserPasswordRejected => "pdf_crypto.empty_user_password_rejected",
            Self::InvalidCiphertextLength => "pdf_crypto.invalid_ciphertext_length",
            Self::InvalidPkcs7Padding => "pdf_crypto.invalid_pkcs7_padding",
        }
    }
}

impl core::fmt::Display for PdfCryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotStandardSecurity => f.write_str(
                "pdf_crypto.not_standard_security: PDF does not declare /Filter /Standard",
            ),
            Self::UnsupportedAlgorithm { version, revision } => write!(
                f,
                "pdf_crypto.unsupported_algorithm: /V {version} /R {revision} (supported: /V 5 /R 5 AES-256)"
            ),
            Self::MissingEncryptionEntry(key) => {
                write!(f, "pdf_crypto.missing_encryption_entry: missing {key}")
            }
            Self::MalformedEncryptionEntry(key) => {
                write!(f, "pdf_crypto.malformed_encryption_entry: malformed {key}")
            }
            Self::EmptyUserPasswordRejected => f.write_str(
                "pdf_crypto.empty_user_password_rejected: PDF requires a non-empty user password",
            ),
            Self::InvalidCiphertextLength => f.write_str(
                "pdf_crypto.invalid_ciphertext_length: stream is not a multiple of 16 bytes",
            ),
            Self::InvalidPkcs7Padding => f.write_str(
                "pdf_crypto.invalid_pkcs7_padding: decrypted stream failed PKCS#7 check",
            ),
        }
    }
}

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity((data.len() + 72) & !63);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            let j = i * 4;
            *word = u32::from_be_bytes([chunk[j], chunk[j + 1], chunk[j + 2], chunk[j + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

const AES_SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const AES_INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

const RCON: [u8; 8] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80];

#[inline]
const fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    let mut i = 0;
    while i < 8 {
        if (b & 1) != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
        i += 1;
    }
    p
}

fn aes256_expand_key(key: &[u8; 32]) -> [[u8; 16]; 15] {
    let mut w = [[0u8; 4]; 60];
    for (i, word) in w.iter_mut().take(8).enumerate() {
        word.copy_from_slice(&key[i * 4..i * 4 + 4]);
    }
    for i in 8..60 {
        let mut temp = w[i - 1];
        if i % 8 == 0 {
            temp = [
                AES_SBOX[temp[1] as usize] ^ RCON[(i / 8) - 1],
                AES_SBOX[temp[2] as usize],
                AES_SBOX[temp[3] as usize],
                AES_SBOX[temp[0] as usize],
            ];
        } else if i % 8 == 4 {
            temp = [
                AES_SBOX[temp[0] as usize],
                AES_SBOX[temp[1] as usize],
                AES_SBOX[temp[2] as usize],
                AES_SBOX[temp[3] as usize],
            ];
        }
        let prev = w[i - 8];
        w[i] = [
            prev[0] ^ temp[0],
            prev[1] ^ temp[1],
            prev[2] ^ temp[2],
            prev[3] ^ temp[3],
        ];
    }
    let mut round_keys = [[0u8; 16]; 15];
    for (r, rk) in round_keys.iter_mut().enumerate() {
        for c in 0..4 {
            rk[c * 4..c * 4 + 4].copy_from_slice(&w[r * 4 + c]);
        }
    }
    round_keys
}

fn add_round_key(state: &mut [u8; 16], rk: &[u8; 16]) {
    for (s, k) in state.iter_mut().zip(rk.iter()) {
        *s ^= *k;
    }
}

fn inv_shift_rows(s: &mut [u8; 16]) {
    let t = s[13];
    s[13] = s[9];
    s[9] = s[5];
    s[5] = s[1];
    s[1] = t;

    s.swap(2, 10);
    s.swap(6, 14);

    let t = s[3];
    s[3] = s[7];
    s[7] = s[11];
    s[11] = s[15];
    s[15] = t;
}

fn inv_sub_bytes(s: &mut [u8; 16]) {
    for b in s.iter_mut() {
        *b = AES_INV_SBOX[*b as usize];
    }
}

fn inv_mix_columns(s: &mut [u8; 16]) {
    for c in 0..4 {
        let i = c * 4;
        let (a0, a1, a2, a3) = (s[i], s[i + 1], s[i + 2], s[i + 3]);
        s[i] = gmul(a0, 0x0e) ^ gmul(a1, 0x0b) ^ gmul(a2, 0x0d) ^ gmul(a3, 0x09);
        s[i + 1] = gmul(a0, 0x09) ^ gmul(a1, 0x0e) ^ gmul(a2, 0x0b) ^ gmul(a3, 0x0d);
        s[i + 2] = gmul(a0, 0x0d) ^ gmul(a1, 0x09) ^ gmul(a2, 0x0e) ^ gmul(a3, 0x0b);
        s[i + 3] = gmul(a0, 0x0b) ^ gmul(a1, 0x0d) ^ gmul(a2, 0x09) ^ gmul(a3, 0x0e);
    }
}

fn aes256_decrypt_block(block: &[u8; 16], rks: &[[u8; 16]; 15]) -> [u8; 16] {
    let mut state = *block;
    add_round_key(&mut state, &rks[14]);
    for round in (1..14).rev() {
        inv_shift_rows(&mut state);
        inv_sub_bytes(&mut state);
        add_round_key(&mut state, &rks[round]);
        inv_mix_columns(&mut state);
    }
    inv_shift_rows(&mut state);
    inv_sub_bytes(&mut state);
    add_round_key(&mut state, &rks[0]);
    state
}

fn aes256_cbc_decrypt_no_pad(
    key: &[u8; 32],
    iv: &[u8; 16],
    ciphertext: &[u8],
) -> Result<Vec<u8>, PdfCryptoError> {
    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(16) {
        return Err(PdfCryptoError::InvalidCiphertextLength);
    }
    let rks = aes256_expand_key(key);
    let mut out = Vec::with_capacity(ciphertext.len());
    let mut prev = *iv;
    for chunk in ciphertext.as_chunks::<16>().0 {
        let mut blk = [0u8; 16];
        blk.copy_from_slice(chunk);
        let mut dec = aes256_decrypt_block(&blk, &rks);
        for (d, p) in dec.iter_mut().zip(prev.iter()) {
            *d ^= *p;
        }
        out.extend_from_slice(&dec);
        prev = blk;
    }
    Ok(out)
}

fn aes256_cbc_decrypt_pkcs7(
    key: &[u8; 32],
    iv: &[u8; 16],
    ciphertext: &[u8],
) -> Result<Vec<u8>, PdfCryptoError> {
    let mut out = aes256_cbc_decrypt_no_pad(key, iv, ciphertext)?;
    let pad = *out.last().ok_or(PdfCryptoError::InvalidPkcs7Padding)? as usize;
    if pad == 0 || pad > 16 || pad > out.len() {
        return Err(PdfCryptoError::InvalidPkcs7Padding);
    }
    if !out[out.len() - pad..].iter().all(|&b| b as usize == pad) {
        return Err(PdfCryptoError::InvalidPkcs7Padding);
    }
    out.truncate(out.len() - pad);
    Ok(out)
}

#[cfg(test)]
pub(crate) fn aes256_encrypt_block(block: &[u8; 16], rks: &[[u8; 16]; 15]) -> [u8; 16] {
    let mut s = *block;
    add_round_key(&mut s, &rks[0]);
    for rk in rks.iter().take(14).skip(1) {
        for b in s.iter_mut() {
            *b = AES_SBOX[*b as usize];
        }
        let t = s[1];
        s[1] = s[5];
        s[5] = s[9];
        s[9] = s[13];
        s[13] = t;
        s.swap(2, 10);
        s.swap(6, 14);
        let t = s[15];
        s[15] = s[11];
        s[11] = s[7];
        s[7] = s[3];
        s[3] = t;
        for c in 0..4 {
            let i = c * 4;
            let (a0, a1, a2, a3) = (s[i], s[i + 1], s[i + 2], s[i + 3]);
            s[i] = gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3;
            s[i + 1] = a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3;
            s[i + 2] = a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3);
            s[i + 3] = gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2);
        }
        add_round_key(&mut s, rk);
    }
    for b in s.iter_mut() {
        *b = AES_SBOX[*b as usize];
    }
    let t = s[1];
    s[1] = s[5];
    s[5] = s[9];
    s[9] = s[13];
    s[13] = t;
    s.swap(2, 10);
    s[6..=14].swap(0, 8);
    let t = s[15];
    s[15] = s[11];
    s[11] = s[7];
    s[7] = s[3];
    s[3] = t;
    add_round_key(&mut s, &rks[14]);
    s
}

#[cfg(test)]
pub(crate) fn aes256_cbc_encrypt_no_pad(
    key: &[u8; 32],
    iv: &[u8; 16],
    plaintext: &[u8],
) -> Vec<u8> {
    assert_eq!(plaintext.len() % 16, 0);
    let rks = aes256_expand_key(key);
    let mut out = Vec::with_capacity(plaintext.len());
    let mut prev = *iv;
    for chunk in plaintext.as_chunks::<16>().0 {
        let mut blk = [0u8; 16];
        for i in 0..16 {
            blk[i] = chunk[i] ^ prev[i];
        }
        let enc = aes256_encrypt_block(&blk, &rks);
        out.extend_from_slice(&enc);
        prev = enc;
    }
    out
}

#[cfg(test)]
pub(crate) fn aes256_cbc_encrypt_pkcs7(key: &[u8; 32], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    let pad = 16 - (plaintext.len() % 16);
    let mut padded = Vec::with_capacity(plaintext.len() + pad);
    padded.extend_from_slice(plaintext);
    padded.resize(plaintext.len() + pad, pad as u8);
    aes256_cbc_encrypt_no_pad(key, iv, &padded)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Returns `true` if `pdf_bytes` declares a Standard Security encryption dictionary.
#[must_use]
pub fn is_standard_security_encrypted(pdf_bytes: &[u8]) -> bool {
    find_subslice(pdf_bytes, b"/Encrypt").is_some()
        && find_subslice(pdf_bytes, b"/Filter /Standard")
            .or_else(|| find_subslice(pdf_bytes, b"/Filter/Standard"))
            .is_some()
}

fn parse_int_entry(dict: &[u8], key: &[u8]) -> Option<i32> {
    let mut pos = 0;
    while let Some(rel) = find_subslice(&dict[pos..], key) {
        let after = pos + rel + key.len();
        if after < dict.len() && dict[after].is_ascii_alphabetic() {
            pos = after;
            continue;
        }
        let mut i = after;
        while i < dict.len() && dict[i].is_ascii_whitespace() {
            i += 1;
        }
        let start = i;
        if i < dict.len() && (dict[i] == b'-' || dict[i] == b'+') {
            i += 1;
        }
        while i < dict.len() && dict[i].is_ascii_digit() {
            i += 1;
        }
        if i > start
            && let Ok(s) = core::str::from_utf8(&dict[start..i])
            && let Ok(v) = s.parse::<i32>()
        {
            return Some(v);
        }
        pos = after;
    }
    None
}

fn decode_hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn parse_pdf_byte_string_after(dict: &[u8], key: &'static str) -> Result<Vec<u8>, PdfCryptoError> {
    let kb = key.as_bytes();
    let mut pos = 0;
    while let Some(rel) = find_subslice(&dict[pos..], kb) {
        let after = pos + rel + kb.len();
        if after < dict.len() && dict[after].is_ascii_alphabetic() {
            pos = after;
            continue;
        }
        let mut i = after;
        while i < dict.len() && dict[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= dict.len() {
            break;
        }
        if dict[i] == b'<' {
            i += 1;
            let mut out = Vec::new();
            let mut high: Option<u8> = None;
            while i < dict.len() && dict[i] != b'>' {
                if dict[i].is_ascii_whitespace() {
                    i += 1;
                    continue;
                }
                let nib = decode_hex_nibble(dict[i])
                    .ok_or(PdfCryptoError::MalformedEncryptionEntry(key))?;
                if let Some(h) = high.take() {
                    out.push((h << 4) | nib);
                } else {
                    high = Some(nib);
                }
                i += 1;
            }
            if let Some(h) = high {
                out.push(h << 4);
            }
            return Ok(out);
        } else if dict[i] == b'(' {
            i += 1;
            let mut depth = 1usize;
            let mut out = Vec::new();
            while i < dict.len() && depth > 0 {
                let b = dict[i];
                if b == b'\\' && i + 1 < dict.len() {
                    i += 1;
                    let esc = dict[i];
                    match esc {
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'(' | b')' | b'\\' => out.push(esc),
                        b'0'..=b'7' => {
                            let mut val = esc - b'0';
                            for _ in 0..2 {
                                if i + 1 < dict.len() && (b'0'..=b'7').contains(&dict[i + 1]) {
                                    i += 1;
                                    val = (val << 3) | (dict[i] - b'0');
                                } else {
                                    break;
                                }
                            }
                            out.push(val);
                        }
                        _ => out.push(esc),
                    }
                } else if b == b'(' {
                    depth += 1;
                    out.push(b);
                } else if b == b')' {
                    depth -= 1;
                    if depth > 0 {
                        out.push(b);
                    }
                } else {
                    out.push(b);
                }
                i += 1;
            }
            return Ok(out);
        }
        pos = after;
    }
    Err(PdfCryptoError::MissingEncryptionEntry(key))
}

/// Recover the 32-byte file encryption key using the empty user password `b""`
/// under ISO 32000-2 §7.6.4.3 Algorithm 2.A (`/V 5 /R 5`, AES-256).
pub fn recover_file_encryption_key_v5_r5(
    u_entry: &[u8],
    ue_entry: &[u8],
) -> Result<[u8; 32], PdfCryptoError> {
    if u_entry.len() < 48 {
        return Err(PdfCryptoError::MalformedEncryptionEntry("/U"));
    }
    if ue_entry.len() < 32 {
        return Err(PdfCryptoError::MalformedEncryptionEntry("/UE"));
    }
    let expected_hash = &u_entry[0..32];
    let validation_salt = &u_entry[32..40];
    let key_salt = &u_entry[40..48];

    // With empty password "", SHA-256("" || validation_salt) == SHA-256(validation_salt).
    let actual_hash = sha256(validation_salt);
    if actual_hash.as_slice() != expected_hash {
        return Err(PdfCryptoError::EmptyUserPasswordRejected);
    }

    let intermediate_key = sha256(key_salt);
    let zero_iv = [0u8; 16];
    let fek_vec = aes256_cbc_decrypt_no_pad(&intermediate_key, &zero_iv, &ue_entry[0..32])?;
    let mut fek = [0u8; 32];
    fek.copy_from_slice(&fek_vec);
    Ok(fek)
}

/// Decrypt all encrypted streams of a Standard Security (`/Filter /Standard /V 5 /R 5`)
/// PDF using the empty user password.
pub fn decrypt_pdf_standard_security(pdf_bytes: &[u8]) -> Result<Vec<u8>, PdfCryptoError> {
    let filter_pos = find_subslice(pdf_bytes, b"/Filter /Standard")
        .or_else(|| find_subslice(pdf_bytes, b"/Filter/Standard"))
        .ok_or(PdfCryptoError::NotStandardSecurity)?;

    let win_start = filter_pos.saturating_sub(256);
    let win_end = (filter_pos + 1024).min(pdf_bytes.len());
    let dict_window = &pdf_bytes[win_start..win_end];

    let v = parse_int_entry(dict_window, b"/V").unwrap_or(0);
    let r = parse_int_entry(dict_window, b"/R").unwrap_or(0);
    if v != 5 || r != 5 {
        return Err(PdfCryptoError::UnsupportedAlgorithm {
            version: v,
            revision: r,
        });
    }

    let u_bytes = parse_pdf_byte_string_after(dict_window, "/U")?;
    let ue_bytes = parse_pdf_byte_string_after(dict_window, "/UE")?;
    let fek = recover_file_encryption_key_v5_r5(&u_bytes, &ue_bytes)?;

    let mut out = Vec::with_capacity(pdf_bytes.len());
    let mut cursor = 0usize;

    while cursor < pdf_bytes.len() {
        let Some(rel_stream) = find_subslice(&pdf_bytes[cursor..], b"stream") else {
            out.extend_from_slice(&pdf_bytes[cursor..]);
            break;
        };
        let stream_kw = cursor + rel_stream;
        if stream_kw >= 3 && &pdf_bytes[stream_kw - 3..stream_kw] == b"end" {
            out.extend_from_slice(&pdf_bytes[cursor..stream_kw + 6]);
            cursor = stream_kw + 6;
            continue;
        }
        let mut data_start = stream_kw + 6;
        if data_start < pdf_bytes.len() && pdf_bytes[data_start] == b'\r' {
            data_start += 1;
        }
        if data_start < pdf_bytes.len() && pdf_bytes[data_start] == b'\n' {
            data_start += 1;
        } else {
            out.extend_from_slice(&pdf_bytes[cursor..stream_kw + 6]);
            cursor = stream_kw + 6;
            continue;
        }

        let Some(rel_end) = find_subslice(&pdf_bytes[data_start..], b"endstream") else {
            out.extend_from_slice(&pdf_bytes[cursor..]);
            break;
        };
        let mut data_end = data_start + rel_end;
        if data_end > data_start && pdf_bytes[data_end - 1] == b'\n' {
            data_end -= 1;
            if data_end > data_start && pdf_bytes[data_end - 1] == b'\r' {
                data_end -= 1;
            }
        } else if data_end > data_start && pdf_bytes[data_end - 1] == b'\r' {
            data_end -= 1;
        }

        let raw_stream = &pdf_bytes[data_start..data_end];
        if raw_stream.len() >= 32 && raw_stream.len().is_multiple_of(16) {
            let mut iv = [0u8; 16];
            iv.copy_from_slice(&raw_stream[0..16]);
            let decrypted = aes256_cbc_decrypt_pkcs7(&fek, &iv, &raw_stream[16..])?;
            out.extend_from_slice(&pdf_bytes[cursor..data_start]);
            out.extend_from_slice(&decrypted);
            out.push(b'\n');
            out.extend_from_slice(b"endstream");
            cursor = data_start + rel_end + 9;
        } else {
            out.extend_from_slice(&pdf_bytes[cursor..data_start + rel_end + 9]);
            cursor = data_start + rel_end + 9;
        }
    }

    if let Some(enc_pos) = find_subslice(&out, b"/Encrypt") {
        out[enc_pos..enc_pos + 8].copy_from_slice(b"/EncNull");
    }
    Ok(out)
}

// ============================================================================
// 3. Deterministic PDF Text-Layer Extractor
// ============================================================================

fn parse_pdf_literal_string(bytes: &[u8], start_after_open_paren: usize) -> (String, usize) {
    let mut i = start_after_open_paren;
    let mut depth = 1usize;
    let mut raw = Vec::new();
    while i < bytes.len() && depth > 0 {
        let b = bytes[i];
        if b == b'\\' && i + 1 < bytes.len() {
            i += 1;
            let esc = bytes[i];
            match esc {
                b'n' => raw.push(b'\n'),
                b'r' => raw.push(b'\r'),
                b't' => raw.push(b'\t'),
                b'b' => raw.push(8),
                b'f' => raw.push(12),
                b'(' | b')' | b'\\' => raw.push(esc),
                b'\r' => {
                    if i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
                        i += 1;
                    }
                }
                b'\n' => {}
                b'0'..=b'7' => {
                    let mut val = esc - b'0';
                    for _ in 0..2 {
                        if i + 1 < bytes.len() && (b'0'..=b'7').contains(&bytes[i + 1]) {
                            i += 1;
                            val = (val << 3) | (bytes[i] - b'0');
                        } else {
                            break;
                        }
                    }
                    raw.push(val);
                }
                _ => raw.push(esc),
            }
        } else if b == b'(' {
            depth += 1;
            raw.push(b);
        } else if b == b')' {
            depth -= 1;
            if depth > 0 {
                raw.push(b);
            }
        } else {
            raw.push(b);
        }
        i += 1;
    }
    (decode_pdf_bytes_to_utf8(&raw), i)
}

fn parse_pdf_hex_string(bytes: &[u8], start_after_lt: usize) -> (String, usize) {
    let mut i = start_after_lt;
    let mut raw = Vec::new();
    let mut high: Option<u8> = None;
    while i < bytes.len() && bytes[i] != b'>' {
        if let Some(nib) = decode_hex_nibble(bytes[i]) {
            if let Some(h) = high.take() {
                raw.push((h << 4) | nib);
            } else {
                high = Some(nib);
            }
        }
        i += 1;
    }
    if let Some(h) = high {
        raw.push(h << 4);
    }
    if i < bytes.len() && bytes[i] == b'>' {
        i += 1;
    }
    (decode_pdf_bytes_to_utf8(&raw), i)
}

fn decode_pdf_bytes_to_utf8(raw: &[u8]) -> String {
    if raw.len() >= 2 && raw[0] == 0xFE && raw[1] == 0xFF {
        let mut units = Vec::with_capacity((raw.len() - 2) / 2);
        for chunk in raw[2..].as_chunks::<2>().0 {
            units.push(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        return String::from_utf16_lossy(&units);
    }
    match core::str::from_utf8(raw) {
        Ok(s) => s.to_string(),
        Err(_) => raw.iter().map(|&b| char::from(b)).collect(),
    }
}

fn extract_text_from_content_stream(stream: &[u8], out: &mut String) {
    let mut pos = 0usize;
    while let Some(rel_bt) = find_subslice(&stream[pos..], b"BT") {
        let bt_start = pos + rel_bt;
        let before_ok = bt_start == 0 || !stream[bt_start - 1].is_ascii_alphabetic();
        let after_bt = bt_start + 2;
        let after_ok = after_bt >= stream.len() || !stream[after_bt].is_ascii_alphabetic();
        if !before_ok || !after_ok {
            pos = after_bt;
            continue;
        }
        let block_end =
            find_subslice(&stream[after_bt..], b"ET").map_or(stream.len(), |rel| after_bt + rel);
        let block = &stream[after_bt..block_end];

        let mut bpos = 0usize;
        let mut block_text = String::new();
        while bpos < block.len() {
            let b = block[bpos];
            if b == b'(' {
                let (s, next) = parse_pdf_literal_string(block, bpos + 1);
                block_text.push_str(&s);
                bpos = next;
            } else if b == b'<' && bpos + 1 < block.len() && block[bpos + 1] != b'<' {
                let (s, next) = parse_pdf_hex_string(block, bpos + 1);
                block_text.push_str(&s);
                bpos = next;
            } else if b == b'[' {
                bpos += 1;
                while bpos < block.len() && block[bpos] != b']' {
                    if block[bpos] == b'(' {
                        let (s, next) = parse_pdf_literal_string(block, bpos + 1);
                        block_text.push_str(&s);
                        bpos = next;
                    } else if block[bpos] == b'<'
                        && bpos + 1 < block.len()
                        && block[bpos + 1] != b'<'
                    {
                        let (s, next) = parse_pdf_hex_string(block, bpos + 1);
                        block_text.push_str(&s);
                        bpos = next;
                    } else {
                        bpos += 1;
                    }
                }
                if bpos < block.len() && block[bpos] == b']' {
                    bpos += 1;
                }
            } else if b == b'T' && bpos + 1 < block.len() && block[bpos + 1] == b'*' {
                if !block_text.is_empty() && !block_text.ends_with('\n') {
                    block_text.push('\n');
                }
                bpos += 2;
            } else if b == b'\'' {
                if !block_text.is_empty() && !block_text.ends_with('\n') {
                    block_text.push('\n');
                }
                bpos += 1;
            } else {
                bpos += 1;
            }
        }

        let trimmed = block_text.trim();
        if !trimmed.is_empty() {
            if !out.is_empty() && !out.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(trimmed);
        }
        pos = (block_end + 2).min(stream.len());
    }
}

/// Deterministically extract the UTF-8 text layer from `pdf_bytes`.
///
/// - If the PDF declares `/Filter /Standard`, attempts empty-user-password
///   decryption via [`decrypt_pdf_standard_security`]; a non-empty user
///   password or unsupported cipher refuses with `FA-REF-193` naming the
///   [`PdfCryptoError`] code.
/// - Inflates `/FlateDecode` streams via [`inflate_zlib`].
pub fn extract_pdf_text_string(pdf_bytes: &[u8]) -> Result<String, Refusal> {
    if !pdf_bytes.starts_with(b"%PDF-") {
        return Err(intake_refusal(
            "pdf_extract.invalid_header: document does not start with %PDF-",
            "the text layer needs a PDF; OCR an image or a scan instead (fa document extract <oid> --tool focr)",
        ));
    }

    let working_bytes: std::borrow::Cow<'_, [u8]> = if is_standard_security_encrypted(pdf_bytes) {
        let decrypted = decrypt_pdf_standard_security(pdf_bytes).map_err(|err| {
            intake_refusal(
                err.to_string(),
                "decrypt the PDF with the user password before intake or supply an unencrypted / empty-user-password PDF",
            )
        })?;
        std::borrow::Cow::Owned(decrypted)
    } else {
        std::borrow::Cow::Borrowed(pdf_bytes)
    };

    let bytes = working_bytes.as_ref();
    let mut extracted = String::new();
    let mut cursor = 0usize;

    while let Some(rel_stream) = find_subslice(&bytes[cursor..], b"stream") {
        let stream_kw = cursor + rel_stream;
        if stream_kw >= 3 && &bytes[stream_kw - 3..stream_kw] == b"end" {
            cursor = stream_kw + 6;
            continue;
        }
        let dict_start = stream_kw.saturating_sub(256);
        let dict_slice = &bytes[dict_start..stream_kw];
        let is_flate = find_subslice(dict_slice, b"/FlateDecode").is_some();

        let mut data_start = stream_kw + 6;
        if data_start < bytes.len() && bytes[data_start] == b'\r' {
            data_start += 1;
        }
        if data_start < bytes.len() && bytes[data_start] == b'\n' {
            data_start += 1;
        } else {
            cursor = stream_kw + 6;
            continue;
        }

        let Some(rel_end) = find_subslice(&bytes[data_start..], b"endstream") else {
            break;
        };
        let mut data_end = data_start + rel_end;
        if data_end > data_start && bytes[data_end - 1] == b'\n' {
            data_end -= 1;
            if data_end > data_start && bytes[data_end - 1] == b'\r' {
                data_end -= 1;
            }
        } else if data_end > data_start && bytes[data_end - 1] == b'\r' {
            data_end -= 1;
        }

        let raw_stream = &bytes[data_start..data_end];
        if is_flate {
            let inflated = inflate_zlib(raw_stream, MAX_INFLATED_STREAM_BYTES).map_err(|err| {
                intake_refusal(
                    format!("pdf_extract.flate_decode_failed: {err}"),
                    "supply a PDF with valid RFC 1950/1951 /FlateDecode streams",
                )
            })?;
            extract_text_from_content_stream(&inflated, &mut extracted);
        } else {
            extract_text_from_content_stream(raw_stream, &mut extracted);
        }

        cursor = data_start + rel_end + 9;
    }

    if extracted.is_empty() {
        return Err(intake_refusal(
            "pdf_extract.empty_text_layer: PDF contains no extractable text-layer operators",
            "an image-only scan has no text layer; OCR it (fa document extract <oid> --tool focr), whose text is not replayable and is graded by who ran it",
        ));
    }

    Ok(extracted)
}

/// Deterministically extract the text layer from `source_doc` and construct a
/// derived `Document` (`replayable = true`) that preserves `source_doc.grade`
/// and binds `source_doc.oid()` in its `fa:derived-document:v1` envelope.
pub fn extract_pdf_text_layer(
    source_doc: &Document,
    retrieved_by: VId,
    derived_kind: u8,
) -> Result<DerivedDocumentResult, Refusal> {
    let extracted_text = extract_pdf_text_string(&source_doc.bytes)?;
    let source_oid = source_doc.oid();
    let metadata = DerivedExtractionMetadata {
        method: ExtractionMethod::PdfTextLayer,
        tool_name: "fa-docket/pdf-text-layer".to_string(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        model_artifact_hash: None,
        command_line: Vec::new(),
        replayable: true,
        extracted_text,
        raw_tool_output: Vec::new(),
    };
    let derived_bytes = encode_extraction_derivation(&[source_oid], &metadata)?;
    let document = Document {
        book_id: source_doc.book_id,
        kind: derived_kind,
        mime: "text/plain;charset=utf-8".to_string(),
        grade: source_doc.grade,
        retrieved_by,
        bytes: derived_bytes,
    };
    Ok(DerivedDocumentResult {
        document,
        metadata,
        source_oid,
    })
}

// ============================================================================
// 4. Subprocess Adapters: franken_ocr (`focr`) and franken_whisper (`fw`)
// ============================================================================

/// Configuration for invoking `franken_ocr` (`focr`) as a subprocess grader.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FocrConfig {
    /// Executable name or path (defaults to `"focr"`).
    pub binary: String,
    /// Optional explicit `--model` path forwarded to `focr ocr`.
    pub model_path: Option<PathBuf>,
    /// Optional extra CLI flags forwarded before `<IMAGE>`.
    pub extra_args: Vec<String>,
    /// When `true` (default), exit code 3 (`model_not_found`) is reported as
    /// `ExternalToolOutcome::Unrun` rather than a hard failure.
    pub treat_missing_model_as_unrun: bool,
}

impl Default for FocrConfig {
    fn default() -> Self {
        Self {
            binary: "focr".to_string(),
            model_path: None,
            extra_args: Vec::new(),
            treat_missing_model_as_unrun: true,
        }
    }
}

/// Configuration for invoking `franken_whisper` (`fw`) as a subprocess grader.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FwConfig {
    /// Executable name or path (defaults to `"fw"`).
    pub binary: String,
    /// Optional explicit `--model` hint forwarded to `fw robot run`.
    pub model_hint: Option<String>,
    /// Optional extra CLI flags forwarded to `fw robot run`.
    pub extra_args: Vec<String>,
    /// When `true` (default), missing backend/model readiness (`FW-BACKEND-UNAVAILABLE`
    /// or `FW-CMD-MISSING`) is reported as `ExternalToolOutcome::Unrun`.
    pub treat_missing_model_as_unrun: bool,
}

impl Default for FwConfig {
    fn default() -> Self {
        Self {
            binary: "fw".to_string(),
            model_hint: None,
            extra_args: Vec::new(),
            treat_missing_model_as_unrun: true,
        }
    }
}

/// Resolve an executable binary name or path via `PATH`.
#[must_use]
pub fn resolve_binary_in_path(binary: &str) -> Option<PathBuf> {
    let candidate = Path::new(binary);
    if binary.contains('/') || binary.contains('\\') {
        return candidate.is_file().then(|| candidate.to_path_buf());
    }
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let full = dir.join(binary);
        if full.is_file() {
            return Some(full);
        }
    }
    None
}

fn probe_tool_version(binary_path: &Path, fallback_name: &str) -> String {
    if let Ok(out) = Command::new(binary_path).arg("--version").output()
        && out.status.success()
    {
        let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !text.is_empty() {
            return text;
        }
    }
    format!("{fallback_name}-unknown")
}

fn extract_json_string_field(line: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{key}\"");
    let mut search_from = 0usize;
    while let Some(rel) = line[search_from..].find(&pattern) {
        let after_key = search_from + rel + pattern.len();
        let rest = line[after_key..].trim_start();
        let Some(after_colon) = rest.strip_prefix(':') else {
            search_from = after_key;
            continue;
        };
        let after_colon = after_colon.trim_start();
        let Some(after_quote) = after_colon.strip_prefix('"') else {
            search_from = after_key;
            continue;
        };
        let mut out = String::new();
        let mut chars = after_quote.chars();
        while let Some(c) = chars.next() {
            if c == '"' {
                return Some(out);
            }
            if c == '\\' {
                if let Some(esc) = chars.next() {
                    match esc {
                        'n' => out.push('\n'),
                        'r' => out.push('\r'),
                        't' => out.push('\t'),
                        '"' => out.push('"'),
                        '\\' => out.push('\\'),
                        '/' => out.push('/'),
                        'u' => {
                            let mut hex = String::with_capacity(4);
                            for _ in 0..4 {
                                if let Some(h) = chars.next() {
                                    hex.push(h);
                                }
                            }
                            if let Ok(code) = u32::from_str_radix(&hex, 16)
                                && let Some(ch) = char::from_u32(code)
                            {
                                out.push(ch);
                            }
                        }
                        other => out.push(other),
                    }
                }
            } else {
                out.push(c);
            }
        }
        search_from = after_key;
    }
    None
}

fn parse_hex_32(s: &str) -> Option<[u8; 32]> {
    let trimmed = s.strip_prefix("blake3:").unwrap_or(s).trim();
    if trimmed.len() != 64 {
        return None;
    }
    let bytes = trimmed.as_bytes();
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = decode_hex_nibble(bytes[i * 2])?;
        let lo = decode_hex_nibble(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn parse_tool_output_text_and_hash(
    stdout_str: &str,
    primary_keys: &[&str],
) -> (String, Option<[u8; 32]>, Option<String>) {
    let mut extracted_segments = Vec::new();
    let mut final_text: Option<String> = None;
    let mut model_hash: Option<[u8; 32]> = None;
    let mut reported_version: Option<String> = None;

    for line in stdout_str.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if model_hash.is_none() {
            for hkey in [
                "model_artifact_hash",
                "model_hash",
                "weights_sha256",
                "weights_blake3",
            ] {
                if let Some(hstr) = extract_json_string_field(trimmed, hkey)
                    && let Some(parsed) = parse_hex_32(&hstr)
                {
                    model_hash = Some(parsed);
                    break;
                }
            }
        }
        if reported_version.is_none() {
            for vkey in ["tool_version", "version"] {
                if let Some(v) = extract_json_string_field(trimmed, vkey)
                    && !v.is_empty()
                {
                    reported_version = Some(v);
                    break;
                }
            }
        }
        let event = extract_json_string_field(trimmed, "event");
        for &key in primary_keys {
            if let Some(val) = extract_json_string_field(trimmed, key)
                && !val.is_empty()
            {
                if matches!(
                    event.as_deref(),
                    Some("run_complete" | "complete" | "result" | "transcript")
                ) {
                    final_text = Some(val);
                } else {
                    extracted_segments.push(val);
                }
                break;
            }
        }
    }

    let text = if let Some(t) = final_text {
        t
    } else if !extracted_segments.is_empty() {
        extracted_segments.join("\n")
    } else {
        for &key in primary_keys {
            if let Some(val) = extract_json_string_field(stdout_str, key)
                && !val.is_empty()
            {
                return (val, model_hash, reported_version);
            }
        }
        String::new()
    };

    (text, model_hash, reported_version)
}

/// Run `franken_ocr` (`focr`) as a subprocess grader on `input_path`, producing
/// a derived text `Document` linked to `source_doc` via `DERIVED_FROM`.
///
/// - If `config.binary` is not installed in `PATH`, returns
///   `Ok(ExternalToolOutcome::Unrun { .. })` (never fakes a pass).
/// - Grades the resulting derived `Document` as `GRADE_AGENT_UPLOAD` (`4`,
///   self-sourced / advisory) with `replayable = false`, regardless of who
///   invoked the tool, so it cannot satisfy `evidence_policy.toml` minimums
///   until an independent human records a `Reviewed` attestation.
pub fn run_focr_extraction(
    source_doc: &Document,
    input_path: &Path,
    retrieved_by: VId,
    derived_kind: u8,
    config: &FocrConfig,
) -> Result<ExternalToolOutcome<DerivedDocumentResult>, Refusal> {
    let Some(binary_path) = resolve_binary_in_path(&config.binary) else {
        return Ok(ExternalToolOutcome::Unrun {
            binary: config.binary.clone(),
            reason: format!("binary `{}` not found in PATH", config.binary),
        });
    };

    let mut argv = vec![
        config.binary.clone(),
        "ocr".to_string(),
        "--json".to_string(),
    ];
    if let Some(model) = &config.model_path {
        argv.push("--model".to_string());
        argv.push(model.display().to_string());
    }
    for extra in &config.extra_args {
        argv.push(extra.clone());
    }
    argv.push(input_path.display().to_string());

    let output = Command::new(&binary_path)
        .args(&argv[1..])
        .output()
        .map_err(|err| {
            intake_refusal(
                format!("focr.spawn_failed: {err}"),
                "verify that the focr binary is executable",
            )
        })?;

    let code = output.status.code().unwrap_or(-1);
    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let stderr_str = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() {
        if config.treat_missing_model_as_unrun
            && (code == 3
                || stdout_str.contains("model_not_found")
                || stderr_str.contains("model_not_found")
                || stderr_str.contains("focr pull"))
        {
            return Ok(ExternalToolOutcome::Unrun {
                binary: config.binary.clone(),
                reason: format!(
                    "focr model weights not installed (exit {code}): {}",
                    stderr_str.trim()
                ),
            });
        }
        return Err(intake_refusal(
            format!(
                "focr.subprocess_failed (exit {code}): {}",
                stderr_str.trim()
            ),
            "check the input image/PDF or run `focr doctor`",
        ));
    }

    let (extracted_text, parsed_hash, parsed_version) =
        parse_tool_output_text_and_hash(&stdout_str, &["markdown", "text"]);
    if extracted_text.trim().is_empty() {
        return Err(intake_refusal(
            "focr.empty_output: subprocess succeeded but emitted no markdown/text field",
            "verify that `focr ocr --json` emits structured JSON with `markdown` or `text`",
        ));
    }

    let tool_version = parsed_version.unwrap_or_else(|| probe_tool_version(&binary_path, "focr"));
    let source_oid = source_doc.oid();
    let metadata = DerivedExtractionMetadata {
        method: ExtractionMethod::FrankenOcr,
        tool_name: "focr".to_string(),
        tool_version,
        model_artifact_hash: parsed_hash,
        command_line: recorded_command_line(argv, input_path, &source_oid),
        replayable: false,
        extracted_text,
        raw_tool_output: output.stdout,
    };
    let derived_bytes = encode_extraction_derivation(&[source_oid], &metadata)?;
    let document = Document {
        book_id: source_doc.book_id,
        kind: derived_kind,
        mime: "text/plain;charset=utf-8".to_string(),
        grade: GRADE_AGENT_UPLOAD,
        retrieved_by,
        bytes: derived_bytes,
    };
    Ok(ExternalToolOutcome::Completed(DerivedDocumentResult {
        document,
        metadata,
        source_oid,
    }))
}

/// The command line a derived document records: `argv` with the host path
/// of the tool's input replaced by the source's handle `D:<oid>`. Provenance
/// names what was read, not where a temporary copy of it happened to live,
/// so the same source and tool record the same invocation on any host.
fn recorded_command_line(
    mut argv: Vec<String>,
    input_path: &Path,
    source_oid: &Oid,
) -> Vec<String> {
    let shown = input_path.display().to_string();
    let handle = format!("D:{}", fa_journal::evidence::hex(&source_oid.0));
    for arg in &mut argv {
        if *arg == shown {
            arg.clone_from(&handle);
        }
    }
    argv
}

/// Run `franken_whisper` (`fw`) as a subprocess grader on `input_path`,
/// producing a derived text `Document` linked to `source_doc` via `DERIVED_FROM`.
///
/// - If `config.binary` is not installed in `PATH`, returns
///   `Ok(ExternalToolOutcome::Unrun { .. })` (never fakes a pass).
/// - Grades the resulting derived `Document` as `GRADE_AGENT_UPLOAD` (`4`,
///   self-sourced / advisory) with `replayable = false`, requiring an
///   independent human `Reviewed` attestation before counting toward
///   `evidence_policy.toml` minimums.
pub fn run_fw_extraction(
    source_doc: &Document,
    input_path: &Path,
    retrieved_by: VId,
    derived_kind: u8,
    config: &FwConfig,
) -> Result<ExternalToolOutcome<DerivedDocumentResult>, Refusal> {
    let Some(binary_path) = resolve_binary_in_path(&config.binary) else {
        return Ok(ExternalToolOutcome::Unrun {
            binary: config.binary.clone(),
            reason: format!("binary `{}` not found in PATH", config.binary),
        });
    };

    let mut argv = vec![
        config.binary.clone(),
        "robot".to_string(),
        "run".to_string(),
        "--no-persist".to_string(),
    ];
    if let Some(model) = &config.model_hint {
        argv.push("--model".to_string());
        argv.push(model.clone());
    }
    for extra in &config.extra_args {
        argv.push(extra.clone());
    }
    argv.push("--input".to_string());
    argv.push(input_path.display().to_string());

    let output = Command::new(&binary_path)
        .args(&argv[1..])
        .output()
        .map_err(|err| {
            intake_refusal(
                format!("fw.spawn_failed: {err}"),
                "verify that the fw binary is executable",
            )
        })?;

    let code = output.status.code().unwrap_or(-1);
    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let stderr_str = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() {
        if config.treat_missing_model_as_unrun
            && (stdout_str.contains("FW-BACKEND-UNAVAILABLE")
                || stdout_str.contains("FW-CMD-MISSING")
                || stderr_str.contains("FW-BACKEND-UNAVAILABLE")
                || stderr_str.contains("FW-CMD-MISSING")
                || stderr_str.contains("fw pull"))
        {
            return Ok(ExternalToolOutcome::Unrun {
                binary: config.binary.clone(),
                reason: format!(
                    "fw backend/model unavailable (exit {code}): {}",
                    stderr_str.trim()
                ),
            });
        }
        return Err(intake_refusal(
            format!("fw.subprocess_failed (exit {code}): {}", stderr_str.trim()),
            "check the input audio file or run `fw doctor`",
        ));
    }

    let (extracted_text, parsed_hash, parsed_version) =
        parse_tool_output_text_and_hash(&stdout_str, &["transcript", "text"]);
    if extracted_text.trim().is_empty() {
        return Err(intake_refusal(
            "fw.empty_output: subprocess succeeded but emitted no transcript/text field",
            "verify that `fw robot run` emits NDJSON events with `transcript` or `text`",
        ));
    }

    let tool_version = parsed_version.unwrap_or_else(|| probe_tool_version(&binary_path, "fw"));
    let source_oid = source_doc.oid();
    let metadata = DerivedExtractionMetadata {
        method: ExtractionMethod::FrankenWhisper,
        tool_name: "fw".to_string(),
        tool_version,
        model_artifact_hash: parsed_hash,
        command_line: recorded_command_line(argv, input_path, &source_oid),
        replayable: false,
        extracted_text,
        raw_tool_output: output.stdout,
    };
    let derived_bytes = encode_extraction_derivation(&[source_oid], &metadata)?;
    let document = Document {
        book_id: source_doc.book_id,
        kind: derived_kind,
        mime: "text/plain;charset=utf-8".to_string(),
        grade: GRADE_AGENT_UPLOAD,
        retrieved_by,
        bytes: derived_bytes,
    };
    Ok(ExternalToolOutcome::Completed(DerivedDocumentResult {
        document,
        metadata,
        source_oid,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::Budget;
    use asupersync::runtime::RuntimeBuilder;
    use fa_journal::{
        AccountSpec, BookContext, BookSpec, Capability, LegalEntitySpec, PostRequest, UnitPolicy,
        add_document, create_book, create_periods, decode_extraction_derivation,
        explain_entry_evidence, install_chart, post, record_review,
    };
    use fa_model::{
        AccountType, EntryClass, EntryOrigin, EntryPayload, Erasable, EvidenceRef, Id128,
        LEGAL_ENTITY_DIMENSION, LegPayload, SealKey, SymbolTable, account_vid, entity_value_vid,
        principal_vid,
    };
    use fa_money::{Amount, Side, UnitRegistry};
    use fa_time::{DateDay, FiscalCalendar, PeriodKind, PeriodTransition};
    use fgdb::{Database, DatabaseKeys};
    use fgdb_types::context::PurposeContexts;
    use fgdb_types::ids::DatabaseSecurityNamespaceId;

    const BOOK_ID: Id128 = Id128([0x64; 16]);
    const HUMAN_UPLOADER: VId = VId(0x1001);
    const AGENT_UPLOADER: VId = VId(0x1002);
    const HUMAN_REVIEWER: VId = VId(0x1003);

    fn build_plain_pdf(content_stream: &[u8]) -> Vec<u8> {
        let mut pdf = Vec::new();
        pdf.extend_from_slice(b"%PDF-1.7\n1 0 obj\n<< /Length ");
        pdf.extend_from_slice(content_stream.len().to_string().as_bytes());
        pdf.extend_from_slice(b" >>\nstream\n");
        pdf.extend_from_slice(content_stream);
        pdf.extend_from_slice(b"\nendstream\nendobj\n%%EOF\n");
        pdf
    }

    /// Encode `data` as a valid RFC 1950 zlib stream using stored DEFLATE blocks
    /// and an exact Adler-32 trailer.
    fn zlib_compress_stored(data: &[u8]) -> Vec<u8> {
        assert!(data.len() <= u16::MAX as usize);
        let mut out = Vec::new();
        // RFC 1950 header: CMF = 0x78 (deflate, 32K window), FLG = 0x01 (check bits so 0x7801 % 31 == 0)
        out.push(0x78);
        out.push(0x01);
        // Final stored block header: BFINAL=1, BTYPE=00 -> first byte = 0x01
        out.push(0x01);
        let len = data.len() as u16;
        let nlen = !len;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&nlen.to_le_bytes());
        out.extend_from_slice(data);
        out.extend_from_slice(&adler32(data).to_be_bytes());
        out
    }

    fn build_flate_pdf(content_stream: &[u8]) -> Vec<u8> {
        let compressed = zlib_compress_stored(content_stream);
        let mut pdf = Vec::new();
        pdf.extend_from_slice(b"%PDF-1.7\n1 0 obj\n<< /Filter /FlateDecode /Length ");
        pdf.extend_from_slice(compressed.len().to_string().as_bytes());
        pdf.extend_from_slice(b" >>\nstream\n");
        pdf.extend_from_slice(&compressed);
        pdf.extend_from_slice(b"\nendstream\nendobj\n%%EOF\n");
        pdf
    }

    fn build_encrypted_v5_r5_pdf(content_stream: &[u8], user_password: &[u8]) -> Vec<u8> {
        let fek = [0x42u8; 32];
        let val_salt = [0x11u8; 8];
        let key_salt = [0x22u8; 8];

        let mut val_input = Vec::from(user_password);
        val_input.extend_from_slice(&val_salt);
        let u_hash = sha256(&val_input);

        let mut u_entry = Vec::with_capacity(48);
        u_entry.extend_from_slice(&u_hash);
        u_entry.extend_from_slice(&val_salt);
        u_entry.extend_from_slice(&key_salt);

        let mut key_input = Vec::from(user_password);
        key_input.extend_from_slice(&key_salt);
        let intermediate_key = sha256(&key_input);
        let ue_entry = aes256_cbc_encrypt_no_pad(&intermediate_key, &[0u8; 16], &fek);

        let iv = [0x33u8; 16];
        let ciphertext = aes256_cbc_encrypt_pkcs7(&fek, &iv, content_stream);
        let mut enc_stream = Vec::with_capacity(16 + ciphertext.len());
        enc_stream.extend_from_slice(&iv);
        enc_stream.extend_from_slice(&ciphertext);

        let to_hex = |bytes: &[u8]| -> String {
            let mut s = String::with_capacity(bytes.len() * 2);
            for b in bytes {
                s.push_str(&format!("{b:02x}"));
            }
            s
        };

        let mut pdf = Vec::new();
        let header = format!(
            "%PDF-1.7\n1 0 obj\n<< /Encrypt << /Filter /Standard /V 5 /R 5 /U <{}> /UE <{}> >> >>\nendobj\n2 0 obj\n<< /Length {} >>\nstream\n",
            to_hex(&u_entry),
            to_hex(&ue_entry),
            enc_stream.len()
        );
        pdf.extend_from_slice(header.as_bytes());
        pdf.extend_from_slice(&enc_stream);
        pdf.extend_from_slice(b"\nendstream\nendobj\n%%EOF\n");
        pdf
    }

    #[test]
    fn workpaper_tag_matches_registry() {
        let policy = fa_registry::evidence_policy::EvidencePolicy::embedded().unwrap();
        let kind = |name: &str| policy.kind_by_name(name).map(|kind| kind.tag);
        let grade = |name: &str| policy.grade_by_name(name).map(|grade| grade.tag);
        assert_eq!(kind("Workpaper"), Some(KIND_WORKPAPER));
        // The tag this constant used to carry names another kind.
        assert_eq!(kind("Remittance"), Some(8));
        assert_eq!(grade("HumanUpload"), Some(GRADE_HUMAN_UPLOAD));
        assert_eq!(grade("AgentUpload"), Some(GRADE_AGENT_UPLOAD));
        assert!(
            policy
                .grade_by_tag(GRADE_AGENT_UPLOAD)
                .unwrap()
                .self_sourced
        );
        assert!(
            !policy
                .grade_by_tag(GRADE_HUMAN_UPLOAD)
                .unwrap()
                .self_sourced
        );
    }

    #[test]
    fn pdf_text_layer_extraction_plain_and_flate_is_deterministic_and_preserves_grade() {
        let stream = b"BT /F1 12 Tf (ACME SUPPLIES INC.) Tj T* [(INVOICE #2026-1042) -120 (  TOTAL DUE: $1,234.56 USD)] TJ ET";
        let expected_text = "ACME SUPPLIES INC.\nINVOICE #2026-1042  TOTAL DUE: $1,234.56 USD";

        let plain_doc = Document {
            book_id: BOOK_ID,
            kind: 1, // Invoice
            mime: "application/pdf".to_string(),
            grade: GRADE_HUMAN_UPLOAD,
            retrieved_by: HUMAN_UPLOADER,
            bytes: build_plain_pdf(stream),
        };
        let flate_doc = Document {
            book_id: BOOK_ID,
            kind: 1,
            mime: "application/pdf".to_string(),
            grade: GRADE_HUMAN_UPLOAD,
            retrieved_by: HUMAN_UPLOADER,
            bytes: build_flate_pdf(stream),
        };

        let res_plain_1 =
            extract_pdf_text_layer(&plain_doc, HUMAN_UPLOADER, KIND_WORKPAPER).unwrap();
        let res_plain_2 =
            extract_pdf_text_layer(&plain_doc, HUMAN_UPLOADER, KIND_WORKPAPER).unwrap();
        let res_flate = extract_pdf_text_layer(&flate_doc, HUMAN_UPLOADER, KIND_WORKPAPER).unwrap();

        assert_eq!(res_plain_1.metadata.extracted_text, expected_text);
        assert_eq!(res_flate.metadata.extracted_text, expected_text);
        assert!(res_plain_1.metadata.replayable);
        assert!(res_flate.metadata.replayable);
        assert_eq!(res_plain_1.document.grade, GRADE_HUMAN_UPLOAD);
        assert_eq!(res_flate.document.grade, GRADE_HUMAN_UPLOAD);
        assert_eq!(res_plain_1.document.oid(), res_plain_2.document.oid());
        assert_eq!(res_plain_1.document.bytes, res_plain_2.document.bytes);

        let (sources, decoded) = decode_extraction_derivation(&res_flate.document.bytes).unwrap();
        assert_eq!(sources, vec![flate_doc.oid()]);
        assert_eq!(decoded.extracted_text, expected_text);
    }

    #[test]
    fn encrypted_pdf_standard_security_empty_password_decrypts_and_non_empty_refuses() {
        let stream =
            b"BT /F1 11 Tf (CONFIDENTIAL INVOICE 2026-9001) Tj T* (TOTAL DUE: $1,234.56 USD) Tj ET";
        let expected_text = "CONFIDENTIAL INVOICE 2026-9001\nTOTAL DUE: $1,234.56 USD";

        // 1. Positive case: empty user password decrypts and extracts golden text.
        let empty_pw_pdf = build_encrypted_v5_r5_pdf(stream, b"");
        assert!(is_standard_security_encrypted(&empty_pw_pdf));
        let empty_pw_doc = Document {
            book_id: BOOK_ID,
            kind: 1,
            mime: "application/pdf".to_string(),
            grade: GRADE_HUMAN_UPLOAD,
            retrieved_by: HUMAN_UPLOADER,
            bytes: empty_pw_pdf,
        };
        let extracted =
            extract_pdf_text_layer(&empty_pw_doc, HUMAN_UPLOADER, KIND_WORKPAPER).unwrap();
        assert_eq!(extracted.metadata.extracted_text, expected_text);
        assert!(extracted.metadata.replayable);

        // 2. Negative case: non-empty user password refuses with typed error code.
        let locked_pdf = build_encrypted_v5_r5_pdf(stream, b"hunter2-non-empty");
        let locked_doc = Document {
            book_id: BOOK_ID,
            kind: 1,
            mime: "application/pdf".to_string(),
            grade: GRADE_HUMAN_UPLOAD,
            retrieved_by: HUMAN_UPLOADER,
            bytes: locked_pdf,
        };
        let err = extract_pdf_text_layer(&locked_doc, HUMAN_UPLOADER, KIND_WORKPAPER).unwrap_err();
        assert_eq!((err.code, err.exit), ("FA-REF-193", exit::REFUSAL));
        assert!(
            err.message
                .contains("pdf_crypto.empty_user_password_rejected"),
            "unexpected refusal message: {}",
            err.message
        );
    }

    #[test]
    fn subprocess_adapters_report_unrun_when_binary_absent_and_grade_agent_upload_when_present() {
        let source_img = Document {
            book_id: BOOK_ID,
            kind: 1,
            mime: "image/png".to_string(),
            grade: GRADE_HUMAN_UPLOAD,
            retrieved_by: HUMAN_UPLOADER,
            bytes: b"\x89PNG\r\n\x1a\nscanned-receipt-image".to_vec(),
        };
        let source_wav = Document {
            book_id: BOOK_ID,
            kind: 9,
            mime: "audio/wav".to_string(),
            grade: GRADE_HUMAN_UPLOAD,
            retrieved_by: HUMAN_UPLOADER,
            bytes: b"RIFF\x24\x00\x00\x00WAVEfmt voice-approval".to_vec(),
        };

        // 1. Absent binary -> ExternalToolOutcome::Unrun (never a fake pass).
        let unrun_focr = run_focr_extraction(
            &source_img,
            Path::new("/nonexistent/scan.png"),
            HUMAN_UPLOADER,
            KIND_WORKPAPER,
            &FocrConfig {
                binary: "focr-definitely-not-installed-binary".to_string(),
                ..FocrConfig::default()
            },
        )
        .unwrap();
        assert!(unrun_focr.is_unrun());

        let unrun_fw = run_fw_extraction(
            &source_wav,
            Path::new("/nonexistent/call.wav"),
            HUMAN_UPLOADER,
            KIND_WORKPAPER,
            &FwConfig {
                binary: "fw-definitely-not-installed-binary".to_string(),
                ..FwConfig::default()
            },
        )
        .unwrap();
        assert!(unrun_fw.is_unrun());

        // 2. Deterministic subprocess fixture scripts emitting the exact focr/fw robot JSON/NDJSON contracts.
        let tmp_dir =
            std::env::temp_dir().join(format!("fa-docket-intake-test-{}", std::process::id()));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let fake_focr = tmp_dir.join("mock-focr.sh");
        let fake_fw = tmp_dir.join("mock-fw.sh");
        let img_path = tmp_dir.join("receipt.png");
        let wav_path = tmp_dir.join("approval.wav");
        std::fs::write(&img_path, &source_img.bytes).unwrap();
        std::fs::write(&wav_path, &source_wav.bytes).unwrap();

        std::fs::write(
            &fake_focr,
            "#!/usr/bin/env bash\n\
             if [[ \"$1\" == \"--version\" ]]; then echo \"focr 0.2.0\"; exit 0; fi\n\
             echo '{\"event\":\"run_complete\",\"tool_version\":\"focr 0.2.0\",\"model_artifact_hash\":\"abababababababababababababababababababababababababababababababab\",\"markdown\":\"VENDOR: ACME CORP\\nTOTAL DUE: $1,234.56 USD\"}'\n",
        )
        .unwrap();
        std::fs::write(
            &fake_fw,
            "#!/usr/bin/env bash\n\
             if [[ \"$1\" == \"--version\" ]]; then echo \"fw 1.1.0\"; exit 0; fi\n\
             echo '{\"event\":\"stage\",\"stage\":\"normalize\"}'\n\
             echo '{\"event\":\"run_complete\",\"tool_version\":\"fw 1.1.0\",\"model_artifact_hash\":\"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\",\"transcript\":\"Approved invoice total due $1,234.56 USD for March.\"}'\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&fake_focr, std::fs::Permissions::from_mode(0o755)).unwrap();
            std::fs::set_permissions(&fake_fw, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        // Notice: even though `HUMAN_UPLOADER` invokes the subprocess adapter,
        // the derived document is graded `GRADE_AGENT_UPLOAD` (4) with `replayable = false`!
        let focr_outcome = run_focr_extraction(
            &source_img,
            &img_path,
            HUMAN_UPLOADER,
            KIND_WORKPAPER,
            &FocrConfig {
                binary: fake_focr.display().to_string(),
                ..FocrConfig::default()
            },
        )
        .unwrap();
        let ExternalToolOutcome::Completed(focr_res) = focr_outcome else {
            panic!("expected Completed from mock-focr");
        };
        assert_eq!(focr_res.document.grade, GRADE_AGENT_UPLOAD);
        assert!(!focr_res.metadata.replayable);
        assert_eq!(focr_res.metadata.method, ExtractionMethod::FrankenOcr);
        assert_eq!(focr_res.metadata.model_artifact_hash, Some([0xAB; 32]));
        assert_eq!(
            focr_res.metadata.extracted_text,
            "VENDOR: ACME CORP\nTOTAL DUE: $1,234.56 USD"
        );
        assert_eq!(focr_res.source_oid, source_img.oid());

        let fw_outcome = run_fw_extraction(
            &source_wav,
            &wav_path,
            AGENT_UPLOADER,
            KIND_WORKPAPER,
            &FwConfig {
                binary: fake_fw.display().to_string(),
                ..FwConfig::default()
            },
        )
        .unwrap();
        let ExternalToolOutcome::Completed(fw_res) = fw_outcome else {
            panic!("expected Completed from mock-fw");
        };
        assert_eq!(fw_res.document.grade, GRADE_AGENT_UPLOAD);
        assert!(!fw_res.metadata.replayable);
        assert_eq!(fw_res.metadata.method, ExtractionMethod::FrankenWhisper);
        assert_eq!(fw_res.metadata.model_artifact_hash, Some([0xCD; 32]));
        assert_eq!(
            fw_res.metadata.extracted_text,
            "Approved invoice total due $1,234.56 USD for March."
        );
        assert_eq!(fw_res.source_oid, source_wav.oid());
    }

    #[test]
    fn unreviewed_ocr_derived_document_is_refused_at_commit_and_explain_evidence_walks_derived_from()
     {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let keys = DatabaseKeys::new(
            [0x61; 32],
            DatabaseSecurityNamespaceId([0x62; 32]),
            [0x63; 32],
        );
        let mut db = runtime
            .block_on(async { Database::open_memory(&cx.commit(), keys).await })
            .unwrap();

        let units = UnitRegistry::with_defaults();
        let usd = units.lookup("USD").unwrap();
        let calendar = FiscalCalendar::monthly("std", 1, 1).unwrap();
        let symbols = SymbolTable::compiled();
        let spec = BookSpec {
            book_id: BOOK_ID,
            name: "Docket Intake Book".to_string(),
            base_unit: usd,
            calendar: calendar.clone(),
            time_zone_policy: None,
            entities: vec![LegalEntitySpec {
                code: "HOLDCO".to_string(),
                name: "HoldCo Inc.".to_string(),
                functional_unit: usd,
            }],
            opening_date: None,
        };
        runtime
            .block_on(create_book(&mut db, &cx, &spec, &units, &symbols))
            .unwrap();
        let book = BookContext {
            book_id: BOOK_ID,
            calendar,
            units,
            seal_key: SealKey([0x65; 32]),
            symbols,
        };
        let seal_str = |s: &str, tag: u8| -> Erasable<String> {
            Erasable::seal(
                &s.to_string(),
                None,
                &book.seal_key,
                [tag; 32],
                [tag.wrapping_add(1); 24],
            )
        };

        let controller = principal_vid("controller");
        let cap_schema = Capability::embedded(controller, &["schema_change"]).unwrap();
        let (_, periods) = runtime
            .block_on(create_periods(
                &mut db,
                &cx,
                &book,
                2026,
                controller,
                seal_str("create 2026 periods", 1),
                &cap_schema,
            ))
            .unwrap()
            .unwrap();
        let p03_code = periods
            .iter()
            .find(|p| {
                p.contains(DateDay::from_ymd(2026, 3, 15).unwrap()) && p.kind == PeriodKind::Normal
            })
            .unwrap()
            .code
            .clone();

        let d_jan1 = DateDay::from_ymd(2026, 1, 1).unwrap();
        let chart = vec![
            AccountSpec {
                code: "1000".to_string(),
                name: "Cash".to_string(),
                account_type: AccountType::ASSET.0,
                normal_balance: 0,
                is_leaf: true,
                unit_policy: UnitPolicy::Single(usd),
                parent_code: None,
                limit: None,
            },
            AccountSpec {
                code: "6000".to_string(),
                name: "Office Expense".to_string(),
                account_type: AccountType::EXPENSE.0,
                normal_balance: 0,
                is_leaf: true,
                unit_policy: UnitPolicy::Single(usd),
                parent_code: None,
                limit: None,
            },
        ];
        runtime
            .block_on(install_chart(
                &mut db,
                &cx,
                &book,
                &chart,
                controller,
                d_jan1,
                b"docket-chart-1",
                seal_str("install chart", 2),
                &cap_schema,
            ))
            .unwrap()
            .unwrap();

        let cap_period =
            Capability::embedded(controller, &["post", "schema_change", "close"]).unwrap();
        runtime
            .block_on(fa_journal::transition_period(
                &mut db,
                &cx,
                &book,
                &p03_code,
                PeriodTransition::Open,
                controller,
                1,
                b"open-p03",
                seal_str("open P03", 3),
                &cap_period,
                &[],
            ))
            .unwrap()
            .unwrap();

        // 1. Add source image document (HumanUpload).
        let source_img = Document {
            book_id: BOOK_ID,
            kind: 1, // Invoice
            mime: "image/png".to_string(),
            grade: GRADE_HUMAN_UPLOAD,
            retrieved_by: HUMAN_UPLOADER,
            bytes: b"\x89PNG\r\n\x1a\nraw-scanned-invoice-bytes".to_vec(),
        };
        let added_src = runtime
            .block_on(add_document(&mut db, &cx, &book, &source_img))
            .unwrap()
            .unwrap();

        // 2. Construct an OCR-derived document containing "TOTAL DUE: $1,234.56 USD"
        //    graded AgentUpload (4) with replayable = false.
        let ocr_meta = DerivedExtractionMetadata {
            method: ExtractionMethod::FrankenOcr,
            tool_name: "focr".to_string(),
            tool_version: "0.2.0".to_string(),
            model_artifact_hash: Some([0xAB; 32]),
            command_line: vec![
                "focr".to_string(),
                "ocr".to_string(),
                "--json".to_string(),
                "invoice.png".to_string(),
            ],
            replayable: false,
            extracted_text: "INVOICE #991\nTOTAL DUE: $1,234.56 USD".to_string(),
            raw_tool_output: br#"{"markdown":"INVOICE #991\nTOTAL DUE: $1,234.56 USD"}"#.to_vec(),
        };
        let ocr_doc = Document {
            book_id: BOOK_ID,
            kind: 1, // Invoice
            mime: "text/plain;charset=utf-8".to_string(),
            grade: GRADE_AGENT_UPLOAD,
            retrieved_by: AGENT_UPLOADER,
            bytes: encode_extraction_derivation(&[added_src.oid], &ocr_meta).unwrap(),
        };
        let added_ocr = runtime
            .block_on(add_document(&mut db, &cx, &book, &ocr_doc))
            .unwrap()
            .unwrap();

        // 3. Attempting to post an ORIGINAL entry citing ONLY the unreviewed
        //    AgentUpload OCR document is refused with FA-REF-086!
        let cash = account_vid(BOOK_ID, "1000");
        let expense = account_vid(BOOK_ID, "6000");
        let holdco_val = entity_value_vid(BOOK_ID, "HOLDCO");
        let mut leg_dr = LegPayload::simple(Side::Debit, expense, Amount::new(usd, 123_456));
        leg_dr.dimension_set = vec![(LEGAL_ENTITY_DIMENSION, holdco_val)];
        let mut leg_cr = LegPayload::simple(Side::Credit, cash, Amount::new(usd, 123_456));
        leg_cr.dimension_set = vec![(LEGAL_ENTITY_DIMENSION, holdco_val)];
        let legs = vec![leg_dr, leg_cr];
        let unit_totals = EntryPayload::fold_unit_totals(&legs).unwrap();
        let proposal = EntryPayload {
            schema_minor: fa_model::entry::SCHEMA_MINOR,
            book_id: BOOK_ID,
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: DateDay::from_ymd(2026, 3, 15).unwrap(),
            document_date: None,
            description: seal_str("Invoice 991", 4),
            effective_period: None,
            legs,
            control: None,
            unit_totals,
            base_totals: None,
            idempotency_key: b"docket-ocr-post-1".to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([0x77; 32]),
                intent_kind: 1,
            },
            principal_ref: HUMAN_UPLOADER,
            session_ref: None,
            evidence: vec![EvidenceRef {
                document_oid: added_ocr.oid,
                doc_commit: added_ocr.doc_commit,
                role: 1, // PrimarySupport
            }],
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            tags: Vec::new(),
            extensions: Vec::new(),
        };
        let cap_post = Capability::embedded(HUMAN_UPLOADER, &["read", "post"]).unwrap();
        let refused = runtime
            .block_on(post(
                &mut db,
                &cx,
                &book,
                PostRequest {
                    proposal: proposal.clone(),
                    approvals: Vec::new(),
                    capability: cap_post.clone(),
                    plan_certificate: None,
                },
            ))
            .unwrap()
            .unwrap_err();
        assert_eq!(refused.code, "FA-REF-086");

        // 4. An independent human reviewer records a `Reviewed` attestation on the
        //    OCR-derived document against the source image document.
        let cap_review = Capability::embedded(HUMAN_REVIEWER, &["approve"]).unwrap();
        runtime
            .block_on(record_review(
                &mut db,
                &cx,
                &book,
                &cap_review,
                HUMAN_REVIEWER,
                added_ocr.oid,
                vec![added_src.oid],
            ))
            .unwrap()
            .unwrap();

        // 5. Posting now succeeds!
        let posted = runtime
            .block_on(post(
                &mut db,
                &cx,
                &book,
                PostRequest {
                    proposal,
                    approvals: Vec::new(),
                    capability: cap_post,
                    plan_certificate: None,
                },
            ))
            .unwrap()
            .unwrap();
        let entry_vid = match posted {
            fa_journal::Posted::Committed { entry_ref, .. } => entry_ref.vid,
            other => panic!("expected Committed, got {other:?}"),
        };

        // 6. `explain_entry_evidence` walks `DERIVED_FROM` from the cited OCR
        //    document back to `added_src` and surfaces the extraction metadata!
        let ex = explain_entry_evidence(&db, &book, entry_vid)
            .unwrap()
            .unwrap();
        assert!(ex.minimum_satisfied);
        assert_eq!(ex.documents.len(), 1);
        let doc_summary = &ex.documents[0];
        assert_eq!(doc_summary.document_oid, added_ocr.oid);
        assert_eq!(doc_summary.grade, GRADE_AGENT_UPLOAD);
        assert!(doc_summary.review.is_some());

        let ext = doc_summary
            .extraction
            .as_ref()
            .expect("extraction metadata present");
        assert_eq!(ext.method, "franken_ocr");
        assert_eq!(ext.tool_name, "focr");
        assert_eq!(ext.tool_version, "0.2.0");
        assert_eq!(ext.model_artifact_hash, Some([0xAB; 32]));
        assert!(!ext.replayable);

        assert_eq!(doc_summary.derived_from.len(), 1);
        let parent_summary = &doc_summary.derived_from[0];
        assert_eq!(parent_summary.document_oid, added_src.oid);
        assert_eq!(parent_summary.doc_commit, added_src.doc_commit);
        assert_eq!(parent_summary.grade, GRADE_HUMAN_UPLOAD);
        assert!(parent_summary.edge_recorded);
    }
}
