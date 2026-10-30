//! The wording lint over every template text and every rendered document
//! (docs/FORENSIC_CASE_STUDIES_PLAN.md §0.3, §3.4, §12.3; bead fa-yugf.31,
//! A14).
//!
//! - **Wording.** No T, C, R, D, P or N sentence says "proves", "proven" or
//!   "proof" (reserved for registered Lean theorems); none says franken_accounting
//!   "would have caught", "stopped" or "prevented" a company; none says "fraud
//!   detected" or "matches the Big-4". Matching is case-insensitive on word
//!   boundaries.
//! - **Run invariance.** Only run-invariant fields render: a run of 32 or more
//!   hex digits (a VId, book id or digest) or a certificate id (`C:<oid>`) is
//!   refused.

/// The refused words and phrases, lower case.
pub const REFUSED: [&str; 9] = [
    "proves",
    "proven",
    "proof",
    "would have caught",
    "would have stopped",
    "would have prevented",
    "fraud detected",
    "matches the big-4",
    "big-4 auditors",
];

fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// The refused phrases `text` contains, on word boundaries.
#[must_use]
pub fn refused_words(text: &str) -> Vec<&'static str> {
    let lower = text.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    REFUSED
        .iter()
        .copied()
        .filter(|phrase| {
            lower.match_indices(phrase).any(|(at, _)| {
                let before = at.checked_sub(1).map(|i| bytes[i]);
                let after = bytes.get(at + phrase.len()).copied();
                !before.is_some_and(is_word) && !after.is_some_and(is_word)
            })
        })
        .collect()
}

/// The run-variant tokens `text` contains: hex runs of 32 or more digits and
/// certificate ids.
#[must_use]
pub fn run_variant_tokens(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for word in text.split(|c: char| !c.is_ascii_alphanumeric() && c != ':') {
        if word.starts_with("C:") && word.len() > 2 {
            out.push(word.to_string());
            continue;
        }
        let mut run = 0usize;
        for c in word.chars() {
            run = if c.is_ascii_hexdigit() { run + 1 } else { 0 };
            if run >= 32 {
                out.push(word.to_string());
                break;
            }
        }
    }
    out
}

/// Every lint problem of a rendered or template text.
#[must_use]
pub fn problems(text: &str) -> Vec<String> {
    let mut out: Vec<String> = refused_words(text)
        .into_iter()
        .map(|w| format!("refused wording `{w}`"))
        .collect();
    out.extend(
        run_variant_tokens(text)
            .into_iter()
            .map(|t| format!("run-variant token `{t}`")),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::super::templates::TEXTS;
    use super::*;

    #[test]
    fn committed_templates_pass_the_lint() {
        for (id, text) in TEXTS {
            assert!(problems(text).is_empty(), "{id}: {:?}", problems(text));
        }
    }

    #[test]
    fn template_containing_proves_is_refused() {
        for (text, word) in [
            ("The read proves the bridge.", "proves"),
            ("A proven tie-out.", "proven"),
            ("Proof of the fold.", "proof"),
            (
                "It would have prevented WorldCom's entry.",
                "would have prevented",
            ),
            ("Fraud detected on F4.", "fraud detected"),
            ("It matches the Big-4 workpapers.", "matches the big-4"),
        ] {
            assert_eq!(refused_words(text), [word], "{text}");
        }
        // Word boundaries: "proofread" and "improves" are not "proof" or "proves".
        assert!(refused_words("proofread; improves").is_empty());
    }

    #[test]
    fn run_variant_field_in_rendered_output_fails() {
        let vid = "0123456789abcdef0123456789abcdef";
        assert_eq!(run_variant_tokens(&format!("entry {vid} posted")), [vid]);
        assert_eq!(run_variant_tokens("read C:4f2a of 2000Q4"), ["C:4f2a"]);
        assert!(run_variant_tokens("value=44188000000.00 FA-REF-140 c-443").is_empty());
    }
}
