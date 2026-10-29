//! Sentence alignment (docs/FORENSIC_CASE_STUDIES_PLAN.md §4.4; bead
//! fa-yugf.7, A3a), the same rules as `tools/case-fetch/case_fetch.py`'s
//! `sentence_bounds`, tested on the same `[[sentence]]` rows of
//! `data/binding_fixtures.toml`:
//! - a quote starts at the text's start, or after a sentence end and
//!   whitespace;
//! - it ends with `[.?!]` and an optional closing `"`, `)` or `”` followed by
//!   whitespace or the end, or followed by a footnote marker glued to it
//!   (1–3 digits, the terminator after a letter, then a space and an
//!   upper-case letter: "amounts.84 In"), which the sentence keeps;
//! - a `.` whose preceding token (after a leading `(`, `[` or quote mark) is
//!   a registered abbreviation is not a boundary;
//! - a block boundary (a blank line or a page break of the raw text) is also
//!   a boundary.
//!
//! Positions are byte offsets into the normalized text. The heading-only
//! rule needs the anchor's lines, so it runs in `verify` (A9) and reaches the
//! Rust side through the receipt's `aligned`.

use core::ops::Range;
use std::collections::BTreeSet;

use super::normalize::{WHITESPACE, normalize_str};
use crate::sha256;

/// The registered abbreviations.
pub const ABBREVIATIONS: [&str; 9] = ["p", "pp", "Inc", "Co", "No", "U.S", "Mr", "Ms", "Dr"];

/// A text normalized, with its sentence starts and ends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sentences {
    pub norm: String,
    pub starts: BTreeSet<usize>,
    pub ends: BTreeSet<usize>,
}

impl Sentences {
    /// The raw text's normalization and boundaries.
    #[must_use]
    pub fn new(raw: &str) -> Self {
        let mut norm = String::with_capacity(raw.len());
        let mut block_starts = BTreeSet::new();
        let mut block_ends = BTreeSet::new();
        let (mut gap, mut newlines, mut paged) = (false, 0usize, false);
        for c in raw.chars() {
            if WHITESPACE.contains(&c) {
                gap = true;
                if c == '\n' {
                    newlines += 1;
                } else if c == '\u{c}' {
                    paged = true;
                }
                continue;
            }
            if gap && !norm.is_empty() {
                if newlines >= 2 || paged {
                    block_ends.insert(norm.len());
                    block_starts.insert(norm.len() + 1);
                }
                norm.push(' ');
            }
            gap = false;
            newlines = 0;
            paged = false;
            norm.push(c);
        }
        debug_assert_eq!(norm, normalize_str(raw));
        let mut starts: BTreeSet<usize> = block_starts;
        starts.insert(0);
        let mut ends: BTreeSet<usize> = block_ends;
        ends.insert(norm.len());
        let bytes = norm.as_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            if !matches!(b, b'.' | b'?' | b'!') {
                continue;
            }
            let mut end = i + 1;
            if matches!(bytes.get(end), Some(b'"' | b')')) {
                end += 1;
            } else if norm[end..].starts_with('\u{201d}') {
                end += '\u{201d}'.len_utf8();
            }
            if end != bytes.len() && bytes[end] != b' ' {
                match footnote_marker(&norm, i, end) {
                    Some(after) => end = after,
                    None => continue,
                }
            }
            if b == b'.' && abbreviated(&norm, i) {
                continue;
            }
            ends.insert(end);
            if end < bytes.len() {
                starts.insert(end + 1);
            }
        }
        Self { norm, starts, ends }
    }

    /// Whether `span` (normalized offsets) is a run of whole sentences.
    #[must_use]
    pub fn is_aligned(&self, span: &Range<usize>) -> bool {
        span.start < span.end && self.starts.contains(&span.start) && self.ends.contains(&span.end)
    }

    /// Every run of whole sentences.
    #[must_use]
    pub fn aligned_spans(&self) -> Vec<Range<usize>> {
        let mut out = Vec::new();
        for &s in &self.starts {
            for &e in self.ends.range(s + 1..) {
                out.push(s..e);
            }
        }
        out
    }

    /// How often `quote` (normalized) occurs, overlaps included.
    #[must_use]
    pub fn occurrences(&self, quote: &str) -> usize {
        let q = normalize_str(quote);
        if q.is_empty() {
            return 0;
        }
        let mut n = 0;
        let mut from = 0;
        while let Some(at) = self.norm[from..].find(&q) {
            n += 1;
            from += at + q.chars().next().map_or(1, char::len_utf8);
        }
        n
    }

    /// The one sentence-aligned span whose SHA-256 is `quote_sha256`.
    ///
    /// # Errors
    ///
    /// `FindError` when no span or several spans match.
    pub fn find_by_hash(&self, quote_sha256: &str) -> Result<Range<usize>, FindError> {
        let matches: Vec<Range<usize>> = self
            .aligned_spans()
            .into_iter()
            .filter(|r| {
                sha256::hex(&sha256::digest(self.norm[r.clone()].as_bytes())) == quote_sha256
            })
            .collect();
        match matches.as_slice() {
            [one] => Ok(one.clone()),
            [] => Err(FindError::NotFound),
            many => Err(FindError::Several(many.len())),
        }
    }
}

/// Why a quote is not found by its hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FindError {
    NotFound,
    Several(usize),
}

impl core::fmt::Display for FindError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotFound => f.write_str("no sentence-aligned span has the quote's SHA-256"),
            Self::Several(n) => write!(f, "{n} sentence-aligned spans have the quote's SHA-256"),
        }
    }
}

impl core::error::Error for FindError {}

/// The end of a footnote marker glued to the terminator at `dot`
/// ("amounts.84 In"): 1–3 ASCII digits at `at`, after a terminator that
/// follows a letter, then a space and an upper-case ASCII letter.
fn footnote_marker(norm: &str, dot: usize, at: usize) -> Option<usize> {
    let bytes = norm.as_bytes();
    let digits = bytes[at..]
        .iter()
        .take_while(|b| b.is_ascii_digit())
        .count();
    let after = at + digits;
    ((1..=3).contains(&digits)
        && bytes.get(after) == Some(&b' ')
        && bytes.get(after + 1).is_some_and(u8::is_ascii_uppercase)
        && norm[..dot]
            .chars()
            .next_back()
            .is_some_and(char::is_alphabetic))
    .then_some(after)
}

fn abbreviated(norm: &str, dot: usize) -> bool {
    let start = norm[..dot].rfind(' ').map_or(0, |s| s + 1);
    let token = norm[start..dot].trim_start_matches(['(', '[', '"', '\'', '\u{201c}', '\u{2018}']);
    ABBREVIATIONS.contains(&token)
}

/// Every run of whole sentences of a raw text.
#[must_use]
pub fn aligned_spans(text: &str) -> Vec<Range<usize>> {
    Sentences::new(text).aligned_spans()
}

/// Whether `span` (normalized offsets) of a raw text is sentence-aligned.
#[must_use]
pub fn is_aligned(text: &str, span: &Range<usize>) -> bool {
    Sentences::new(text).is_aligned(span)
}

/// How often `quote` occurs in a raw text, both normalized.
#[must_use]
pub fn occurrences(text: &str, quote: &str) -> usize {
    Sentences::new(text).occurrences(quote)
}

/// The one sentence-aligned span of a raw text with the given hash.
///
/// # Errors
///
/// `FindError` when zero or several spans match.
pub fn find_by_hash(text: &str, quote_sha256: &str) -> Result<Range<usize>, FindError> {
    Sentences::new(text).find_by_hash(quote_sha256)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cases::normalize::quote_sha256;

    const BINDING: &str = include_str!("../../data/binding_fixtures.toml");

    #[test]
    fn sentence_alignment_matches_the_shared_fixtures() {
        let doc = fa_registry::toml::parse(BINDING).expect("binding_fixtures.toml");
        let rows = doc.arrays.get("sentence").expect("[[sentence]] rows");
        assert!(rows.len() >= 10);
        for row in rows {
            let s = |k: &str| row.get(k).and_then(|v| v.as_str()).expect(k);
            let id = s("id");
            let text = Sentences::new(s("text"));
            let quote = normalize_str(s("quote"));
            let count = row.get("count").and_then(|v| v.as_int()).expect("count");
            assert_eq!(
                i128::try_from(text.occurrences(&quote)).ok(),
                Some(count),
                "{id}"
            );
            let at = text.norm.find(&quote).expect("the quote occurs");
            let aligned = row
                .get("aligned")
                .and_then(|v| v.as_bool())
                .expect("aligned");
            assert_eq!(text.is_aligned(&(at..at + quote.len())), aligned, "{id}");
        }
    }

    #[test]
    fn find_by_hash_selects_the_one_matching_span() {
        let text = "Intro line.\n\nThe first sentence is here. The second one follows.";
        let span = find_by_hash(text, &quote_sha256("The second one follows.")).expect("one span");
        assert_eq!(&Sentences::new(text).norm[span], "The second one follows.");
        assert_eq!(
            find_by_hash(text, &quote_sha256("No such sentence.")),
            Err(FindError::NotFound)
        );
    }

    #[test]
    fn find_by_hash_with_two_matching_spans_fails() {
        let text = "One sentence. The ledger was reviewed. The ledger was reviewed.";
        assert_eq!(
            find_by_hash(text, &quote_sha256("The ledger was reviewed.")),
            Err(FindError::Several(2))
        );
        assert_eq!(occurrences(text, "The ledger was reviewed."), 2);
    }

    #[test]
    fn heading_only_line_is_one_sentence() {
        // A heading line between two blocks is one whole sentence; a word of
        // it is a fragment (A9's verify adds the anchor-lines heading rule).
        let text = "The ledger was reviewed.\n\nUNAUDITED SELECTED DATA\n\nIt balanced.";
        let s = Sentences::new(text);
        let at = s.norm.find("UNAUDITED SELECTED DATA").expect("the heading");
        assert!(s.is_aligned(&(at..at + "UNAUDITED SELECTED DATA".len())));
        assert!(!s.is_aligned(&(at..at + "UNAUDITED".len())));
    }

    #[test]
    fn the_entered_and_approved_fragment_is_not_aligned() {
        let text = "The director rarely entered and approved entries himself.";
        let s = Sentences::new(text);
        let at = s.norm.find("entered and approved").expect("occurs");
        assert!(!s.is_aligned(&(at..at + "entered and approved".len())));
        assert!(is_aligned(text, &(0..s.norm.len())));
    }
}
