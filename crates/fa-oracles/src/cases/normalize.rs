//! Quote normalization and `quote_sha256` (docs/FORENSIC_CASE_STUDIES_PLAN.md
//! §4.4; bead fa-yugf.7, A3a).
//!
//! Identical to `tools/case-fetch/case_fetch.py`'s `normalize`, and tested
//! on the same `[[normalize]]` rows of `data/binding_fixtures.toml`:
//! decode UTF-8 (invalid UTF-8 is an error, never replaced); replace every
//! run of U+0009, U+000A, U+000B, U+000C, U+000D, U+0020 and U+00A0 with one
//! U+0020; trim. No case folding, no Unicode normalization, typographic
//! quotes kept. Neither Python's `str.split()` nor Rust's
//! `char::is_whitespace` is used: they disagree on U+001C–U+001F.

use core::fmt;

use crate::sha256;

/// The characters a run of which normalizes to one space.
pub const WHITESPACE: [char; 7] = ['\t', '\n', '\u{b}', '\u{c}', '\r', ' ', '\u{a0}'];

/// Why bytes do not normalize.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NormalizeError {
    /// The bytes are not UTF-8 (the offset of the first invalid byte).
    InvalidUtf8 { offset: usize },
}

impl fmt::Display for NormalizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUtf8 { offset } => write!(f, "invalid UTF-8 at byte {offset}"),
        }
    }
}

impl core::error::Error for NormalizeError {}

/// Normalized text from bytes.
///
/// # Errors
///
/// `InvalidUtf8`, never a replacement character.
pub fn normalize(bytes: &[u8]) -> Result<String, NormalizeError> {
    let text = core::str::from_utf8(bytes).map_err(|e| NormalizeError::InvalidUtf8 {
        offset: e.valid_up_to(),
    })?;
    Ok(normalize_str(text))
}

/// Normalized text from a string.
#[must_use]
pub fn normalize_str(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut gap = false;
    for c in text.chars() {
        if WHITESPACE.contains(&c) {
            gap = true;
            continue;
        }
        if gap && !out.is_empty() {
            out.push(' ');
        }
        gap = false;
        out.push(c);
    }
    out
}

/// The SHA-256 of a quote's normalized bytes, lower-case hex.
#[must_use]
pub fn quote_sha256(quote: &str) -> String {
    sha256::hex(&sha256::digest(normalize_str(quote).as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BINDING: &str = include_str!("../../data/binding_fixtures.toml");

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn normalization_matches_the_shared_fixtures() {
        let doc = fa_registry::toml::parse(BINDING).expect("binding_fixtures.toml");
        let rows = doc.arrays.get("normalize").expect("[[normalize]] rows");
        assert!(rows.len() >= 6);
        for row in rows {
            let s = |k: &str| row.get(k).and_then(|v| v.as_str()).expect(k);
            let input = hex(s("input_hex"));
            let want = String::from_utf8(hex(s("normalized_hex"))).expect("utf-8");
            let got = normalize(&input).expect("normalizes");
            assert_eq!(got, want, "row {}", s("id"));
            assert_eq!(
                quote_sha256(&String::from_utf8(input).expect("utf-8")),
                s("quote_sha256"),
                "row {}",
                s("id")
            );
        }
    }

    #[test]
    fn invalid_utf8_is_an_error_never_a_replacement() {
        assert_eq!(
            normalize(b"ab\xffcd"),
            Err(NormalizeError::InvalidUtf8 { offset: 2 })
        );
    }

    #[test]
    fn rust_whitespace_is_not_the_rule() {
        // Python's str.split() splits on U+001C, Rust's char::is_whitespace
        // does not; Rust's counts U+2003 (em space). The rule keeps both.
        assert!(!'\u{1c}'.is_whitespace());
        assert!('\u{2003}'.is_whitespace());
        assert_eq!(normalize_str("a\u{1c}b"), "a\u{1c}b");
        assert_eq!(normalize_str("a\u{2003}b"), "a\u{2003}b");
        assert_eq!(normalize_str("  a \u{a0}\u{a0} b\r\n"), "a b");
    }
}
