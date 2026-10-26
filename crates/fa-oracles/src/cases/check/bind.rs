//! K-BIND (§2.1, §4.1, §4.4): a sourced fact is bound to its quote.
//!
//! - **Values.** Every `[[value]]` row's literal yields its value under its
//!   registered literal rule (A2's engine), and, when the quote is present,
//!   occurs in it as a whole token run (prose anchors) or is the whole quote
//!   (value-bound anchors: `table_cell`, `xbrl`).
//! - **Hash.** A present quote's `quote_sha256` is the fact's. A quote-less
//!   fact (every fact until owner decision 2a) is bound by its receipt: the
//!   receipt's `quote_sha256` is the fact's and its `quote_found_once`,
//!   `aligned` and `values_in_quote` hold.
//! - **Alignment kind.** The receipt's `alignment` is `sentence` for a prose
//!   anchor and `value` for `table_cell`, `xbrl` and `exhibit`.
//! - **Edited after `verify`.** `values_sha256` is recomputed from the
//!   fact's current values and `about_scope` and must equal the receipt's.
//! - **Whole-exhibit facts.** A committed `rows_file` fact's hash is the
//!   SHA-256 of its complaint's contiguous `[[row]]` block, from its first
//!   `[[row]]` header line through the newline ending its last field line
//!   (M2t); an uncommitted one is pending (owner decision 2b), its receipt
//!   still checked.
//!
//! With a fixture extraction at hand ([`Context::extraction`]), the quote is
//! also located in it: found exactly once, and sentence-aligned for prose.

use super::super::fact::{Sourced, Value, values_canonical};
use super::super::normalize::{normalize_str, quote_sha256};
use super::super::sentence::{FindError, Sentences};
use super::super::source::AnchorKind;
use super::{CheckReport, Context, FACTS};
use crate::sha256;

#[must_use]
pub fn check(cx: &Context<'_>) -> CheckReport {
    let case = cx.case;
    let sourced: Vec<_> = case
        .facts
        .iter()
        .filter_map(|f| Some((f, f.sourced()?)))
        .collect();
    let mut r = CheckReport::new("K-BIND", sourced.len());
    for (f, s) in sourced {
        let values: Vec<&Value> = case.values.iter().filter(|v| v.fact == f.id).collect();
        let mut problems = receipt_problems(cx, &f.id, s, &values);
        problems.extend(literal_problems(cx, &values));
        let pending = cx.pending.contains(&f.id);
        if !pending {
            if let Some(rows_file) = &s.rows_file {
                problems.extend(rows_problems(cx, s, rows_file));
            }
            if let Some(quote) = &s.quote {
                problems.extend(quote_problems(s, quote, &values));
            }
            problems.extend(extraction_problems(cx, s));
        }
        if pending {
            r.pending += 1;
        } else {
            r.examined(f.id.clone());
        }
        for p in problems {
            r.fail(FACTS, f.line, &f.id, p);
        }
    }
    r.finish()
}

/// The receipt's binding of the fact.
fn receipt_problems(cx: &Context<'_>, id: &str, s: &Sourced, values: &[&Value]) -> Vec<String> {
    let Some(rc) = cx.receipt(id) else {
        return vec!["no receipt binds the fact (run `case_fetch.py verify`)".into()];
    };
    let mut out = Vec::new();
    if rc.quote_sha256 != s.quote_sha256 {
        out.push(format!(
            "the receipt's quote_sha256 {} is not the fact's {}",
            rc.quote_sha256, s.quote_sha256
        ));
    }
    let recomputed = sha256::hex(&sha256::digest(&values_canonical(&s.about_scope, values)));
    if recomputed != rc.values_sha256 {
        out.push(format!(
            "values_sha256 mismatch: the fact's values and about_scope hash to {recomputed}, the receipt says {} (edited after verify)",
            rc.values_sha256
        ));
    }
    let prose = s.anchor_kind.is_prose();
    let want = if prose { "sentence" } else { "value" };
    if rc.alignment.as_str() != want {
        out.push(format!(
            "receipt alignment `{}` on a `{}` anchor (expected `{want}`)",
            rc.alignment.as_str(),
            s.anchor_kind.as_str()
        ));
    }
    if !rc.quote_found_once {
        out.push("the receipt records the quote not found exactly once at the anchor".into());
    }
    if !rc.aligned {
        out.push(if prose {
            "not sentence-aligned (receipt)".into()
        } else {
            "not the whole cell or value (receipt)".into()
        });
    }
    if !rc.values_in_quote {
        out.push("the receipt records a value not in the quote".into());
    }
    out
}

/// Each value's literal yields its recorded value under its rule.
fn literal_problems(cx: &Context<'_>, values: &[&Value]) -> Vec<String> {
    let rules = match &cx.rules {
        Ok(rules) => rules,
        Err(e) => return vec![format!("the derivation table does not load: {e}")],
    };
    let mut out = Vec::new();
    for v in values {
        let mut tokens = Vec::new();
        if let Some(p) = v.param {
            tokens.push(format!("k={p}"));
        }
        if v.rule.as_str() == "scale" {
            tokens.push(format!("unit={}", v.unit));
            if let Some(p) = v.precision {
                tokens.push(format!("precision={p}"));
            }
        }
        let got = rules
            .get(v.rule.as_str())
            .ok_or_else(|| format!("rule `{}` is not in the derivation table", v.rule.as_str()))
            .and_then(|rule| rules.params(rule, &tokens).map_err(|e| e.to_string()))
            .and_then(|params| {
                rules
                    .evaluate(v.rule.as_str(), &params, core::slice::from_ref(&v.literal))
                    .map_err(|e| e.to_string())
            });
        match got {
            Ok(got) if got == v.value => {}
            Ok(got) => out.push(format!(
                "value {}: `{}` under {} is {got}, not {}",
                v.ordinal,
                v.literal,
                v.rule.as_str(),
                v.value
            )),
            Err(e) => out.push(format!("value {}: `{}`: {e}", v.ordinal, v.literal)),
        }
    }
    out
}

/// A present quote: its hash, its values, and its shape.
fn quote_problems(s: &Sourced, quote: &str, values: &[&Value]) -> Vec<String> {
    let mut out = Vec::new();
    let norm = normalize_str(quote);
    let digest = quote_sha256(quote);
    if digest != s.quote_sha256 {
        out.push(format!(
            "quote_sha256 {} is not the quote's {digest}",
            s.quote_sha256
        ));
    }
    let prose = s.anchor_kind.is_prose();
    for v in values {
        let lit = normalize_str(&v.literal);
        let present = if prose {
            literal_in(&lit, &norm)
        } else {
            lit == norm
        };
        if !present {
            out.push(if prose {
                format!(
                    "value {} literal `{}` is not in the quote",
                    v.ordinal, v.literal
                )
            } else {
                format!(
                    "value {} literal `{}` is not the whole cell or value `{norm}`",
                    v.ordinal, v.literal
                )
            });
        }
    }
    if prose && !Sentences::new(quote).is_aligned(&(0..norm.len())) {
        out.push("not sentence-aligned (the quote does not end a sentence)".into());
    }
    out
}

/// The quote located in a fixture extraction of its source.
fn extraction_problems(cx: &Context<'_>, s: &Sourced) -> Vec<String> {
    let Some(text) = cx.extraction.and_then(|e| e(&s.source)) else {
        return Vec::new();
    };
    if s.anchor_kind == AnchorKind::Exhibit {
        return Vec::new();
    }
    let sentences = Sentences::new(&text);
    let mut out = Vec::new();
    match &s.quote {
        Some(quote) => {
            let q = normalize_str(quote);
            let n = sentences.occurrences(&q);
            if n != 1 {
                out.push(format!("the quote is found {n} times in the extraction"));
            } else if s.anchor_kind.is_prose() {
                let at = sentences.norm.find(&q).unwrap_or(0);
                if !sentences.is_aligned(&(at..at + q.len())) {
                    out.push("not sentence-aligned in the extraction".into());
                }
            }
        }
        None => match sentences.find_by_hash(&s.quote_sha256) {
            Ok(_) => {}
            Err(FindError::NotFound) => {
                out.push(
                    "no sentence-aligned span of the extraction has the fact's quote_sha256".into(),
                );
            }
            Err(FindError::Several(n)) => {
                out.push(format!("the quote is found {n} times in the extraction"));
            }
        },
    }
    out
}

/// A committed rows fact: its complaint's block hash is its quote_sha256.
fn rows_problems(cx: &Context<'_>, s: &Sourced, rows_file: &str) -> Vec<String> {
    let Some(text) = cx.case.rows.get(rows_file) else {
        return vec![format!(
            "rows file `{rows_file}` is committed but not loaded"
        )];
    };
    let Some(complaint) = &s.complaint else {
        return vec!["a rows fact names its `complaint`".into()];
    };
    match rows_block_sha256(text, complaint) {
        Ok(digest) if digest == s.quote_sha256 => Vec::new(),
        Ok(digest) => vec![format!(
            "rows block of `{complaint}` in {rows_file} hashes to {digest}, not the fact's quote_sha256 {}",
            s.quote_sha256
        )],
        Err(e) => vec![format!("{rows_file}: {e}")],
    }
}

/// The SHA-256 of `complaint`'s contiguous `[[row]]` block in a rows file:
/// its exact bytes from the first `[[row]]` header line through the newline
/// that ends the block's last field line (M2t's `rows_sha256`).
///
/// # Errors
///
/// When the complaint has no rows, or its rows are not contiguous.
pub fn rows_block_sha256(text: &str, complaint: &str) -> Result<String, String> {
    let want = format!("complaint = \"{complaint}\"");
    // Each row: (start byte of its header line, end byte of its last field line, its complaint matches).
    let mut rows: Vec<(usize, usize, bool)> = Vec::new();
    let mut at = 0;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_end_matches(['\n', '\r']);
        if trimmed.trim() == "[[row]]" {
            rows.push((at, at + line.len(), false));
        } else if let Some(row) = rows.last_mut() {
            let t = trimmed.trim();
            if t.starts_with('[') {
                // Another table ends the rows.
                rows.push((at, at, false));
            } else if !t.is_empty() && !t.starts_with('#') {
                row.1 = at + line.len();
                if t == want {
                    row.2 = true;
                }
            }
        }
        at += line.len();
    }
    let hits: Vec<usize> = rows
        .iter()
        .enumerate()
        .filter(|(_, r)| r.2)
        .map(|(i, _)| i)
        .collect();
    let (Some(&first), Some(&last)) = (hits.first(), hits.last()) else {
        return Err(format!("no `[[row]]` of complaint `{complaint}`"));
    };
    if last - first + 1 != hits.len() {
        return Err(format!(
            "the rows of complaint `{complaint}` are not one contiguous block"
        ));
    }
    let bytes = &text.as_bytes()[rows[first].0..rows[last].1];
    Ok(sha256::hex(&sha256::digest(bytes)))
}

/// Whether `lit` occurs in `quote` as a whole token run: never glued to a
/// letter or digit, or to a `,`/`.` digit group of a longer number (A9's
/// `literal_in`).
#[must_use]
pub fn literal_in(lit: &str, quote: &str) -> bool {
    if lit.is_empty() {
        return false;
    }
    let chars: Vec<(usize, char)> = quote.char_indices().collect();
    let lit_first_digit = lit.chars().next().is_some_and(|c| c.is_ascii_digit());
    let lit_last_digit = lit.chars().last().is_some_and(|c| c.is_ascii_digit());
    let mut from = 0;
    while let Some(off) = quote[from..].find(lit) {
        let start = from + off;
        let end = start + lit.len();
        let i = chars.partition_point(|(b, _)| *b < start);
        let j = chars.partition_point(|(b, _)| *b < end);
        let get = |k: Option<usize>| k.and_then(|k| chars.get(k)).map_or(' ', |(_, c)| *c);
        let before = get(i.checked_sub(1));
        let before2 = get(i.checked_sub(2));
        let after = get(Some(j));
        let after2 = get(Some(j + 1));
        let glued_before = before.is_alphanumeric()
            || (matches!(before, ',' | '.') && before2.is_ascii_digit() && lit_first_digit);
        let glued_after = after.is_alphanumeric()
            || (matches!(after, ',' | '.') && after2.is_ascii_digit() && lit_last_digit);
        if !glued_before && !glued_after {
            return true;
        }
        from = start + quote[start..].chars().next().map_or(1, char::len_utf8);
    }
    false
}
