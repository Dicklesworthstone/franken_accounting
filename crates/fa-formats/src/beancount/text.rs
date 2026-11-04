//! Exact text codecs used by the plaintext ledger writers and readers.
//!
//! This module needs only `std`: source text cannot acquire ledger syntax, and
//! the codecs do not depend on a book, runtime, accounting model, or storage.

#![forbid(unsafe_code)]

// Comments and hledger header fields have no general quoted-string grammar.
// Keep ordinary exports byte-for-byte stable; only ambiguous text uses the
// versioned UTF-8 hex extension. Readers still accept the original spelling.
fn comment_text_is_lossless(text: &str) -> bool {
    text.trim() == text && !text.chars().any(char::is_control)
}

pub(crate) fn write_book_name(out: &mut String, name: &str) {
    if comment_text_is_lossless(name) {
        out.push_str(&format!("; fa_book_name: {name}\n"));
    } else {
        out.push_str(&format!(
            "; fa_book_name_hex_v1: {}\n",
            encode_text_hex(name)
        ));
    }
}

/// Complete the posting line, retaining an absent memo separately from an
/// empty one. A source newline must never become another posting.
pub(crate) fn beancount_memo_suffix(memo: Option<&str>) -> String {
    match memo {
        Some(memo) if comment_text_is_lossless(memo) => format!(" ; memo:{memo}\n"),
        Some(memo) => format!("\n    fa_memo_hex_v1: \"{}\"\n", encode_text_hex(memo)),
        None => "\n".into(),
    }
}

pub(crate) fn inline_text_metadata(key: &str, text: &str, single_token: bool) -> String {
    if comment_text_is_lossless(text) && (!single_token || !text.chars().any(char::is_whitespace)) {
        format!("{key}:{text}")
    } else {
        format!("{key}_hex_v1:{}", encode_text_hex(text))
    }
}

/// Human-readable hledger narration and the optional exact-source metadata
/// suffix. Semicolons and newlines cannot start a comment or another directive.
pub(crate) fn hledger_description(text: &str) -> (String, String) {
    if comment_text_is_lossless(text) && !text.contains(';') {
        (text.to_owned(), String::new())
    } else {
        (
            single_line_display(text),
            format!(" fa_description_hex_v1:{}", encode_text_hex(text)),
        )
    }
}

fn encode_text_hex(text: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(text.len().saturating_mul(2));
    for byte in text.bytes() {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

pub(crate) fn decode_text_hex(text: &str) -> Result<String, String> {
    if !text.len().is_multiple_of(2) {
        return Err("text hex must contain complete byte pairs".into());
    }
    let nibble = |byte| match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!("invalid hex byte 0x{byte:02x}")),
    };
    let bytes = text
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Ok((nibble(pair[0])? << 4) | nibble(pair[1])?))
        .collect::<Result<Vec<_>, String>>()?;
    String::from_utf8(bytes).map_err(|_| "text hex is not valid UTF-8".into())
}

fn single_line_display(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ';' => out.push_str("\\x3b"),
            '\\' => out.push_str("\\\\"),
            ch if ch.is_control() => out.push_str(&format!("\\u{{{:x}}}", u32::from(ch))),
            ch => out.push(ch),
        }
    }
    out
}

pub(crate) fn escape_quotes(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            ch => out.push(ch),
        }
    }
    out
}

pub(crate) fn unquote(text: &str) -> Result<String, String> {
    let text = text.trim();
    if text.len() < 2 || !text.starts_with('"') || !text.ends_with('"') {
        return Err(format!("expected quoted string, got {text:?}"));
    }
    let mut out = String::with_capacity(text.len() - 2);
    let mut chars = text[1..text.len() - 1].chars();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => out.push(match chars.next() {
                Some('\\') => '\\',
                Some('"') => '"',
                Some('n') => '\n',
                Some('r') => '\r',
                Some('t') => '\t',
                Some('b') => '\u{08}',
                Some('f') => '\u{0c}',
                other => {
                    return Err(format!(
                        "unsupported or incomplete quoted-string escape {other:?}"
                    ));
                }
            }),
            '"' => return Err("unescaped quote inside string".into()),
            ch => out.push(ch),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_text_keeps_existing_wire_spelling() {
        let mut header = String::new();
        write_book_name(&mut header, "County General Ledger");
        assert_eq!(header, "; fa_book_name: County General Ledger\n");
        assert_eq!(
            inline_text_metadata("fa_code", "1000.10", true),
            "fa_code:1000.10"
        );
        assert_eq!(
            inline_text_metadata("fa_name", "Cash fa_code:5000", false),
            "fa_name:Cash fa_code:5000"
        );
        assert_eq!(
            hledger_description("Vendor payment"),
            ("Vendor payment".into(), String::new())
        );
        assert_eq!(
            beancount_memo_suffix(Some("Vendor payment")),
            " ; memo:Vendor payment\n"
        );
    }

    #[test]
    fn absent_empty_and_whitespace_memos_are_distinct() {
        assert_eq!(beancount_memo_suffix(None), "\n");
        assert_eq!(beancount_memo_suffix(Some("")), " ; memo:\n");
        assert_eq!(
            beancount_memo_suffix(Some(" \n")),
            "\n    fa_memo_hex_v1: \"200a\"\n"
        );
        for memo in ["  ", "\t", " leading", "trailing ", "\r\n"] {
            let suffix = beancount_memo_suffix(Some(memo));
            let quoted_hex = suffix
                .strip_prefix("\n    fa_memo_hex_v1: ")
                .unwrap()
                .trim_end();
            assert_eq!(
                decode_text_hex(&unquote(quoted_hex).unwrap()).unwrap(),
                memo
            );
        }
    }

    #[test]
    fn source_memo_cannot_add_balanced_postings_or_directives() {
        let memo = "Vendor\r\n  Expenses:A5000  999999.00 USD\n  Assets:A1000  -999999.00 USD\n2026-04-01 open Assets:Injected";
        let posting = format!(
            "  Expenses:A5000  12345.67 USD{}",
            beancount_memo_suffix(Some(memo))
        );
        let lines: Vec<_> = posting.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "  Expenses:A5000  12345.67 USD");
        let quoted_hex = lines[1].strip_prefix("    fa_memo_hex_v1: ").unwrap();
        assert_eq!(
            decode_text_hex(&unquote(quoted_hex).unwrap()).unwrap(),
            memo
        );
        assert!(!posting.contains("999999.00 USD"));
        assert!(!posting.contains("open Assets:Injected"));
    }

    #[test]
    fn book_headers_keep_exact_text_on_one_physical_line() {
        for name in [
            "",
            " Book ",
            "County\r\n2026-01-01 open Assets:Injected",
            "café\t財務",
            "A\u{2028}B",
        ] {
            let mut header = String::new();
            write_book_name(&mut header, name);
            assert_eq!(header.lines().count(), 1);
            let line = header.strip_suffix('\n').unwrap();
            let restored = match line.strip_prefix("; fa_book_name_hex_v1: ") {
                Some(hex) => decode_text_hex(hex).unwrap(),
                None => line.strip_prefix("; fa_book_name: ").unwrap().to_owned(),
            };
            assert_eq!(restored, name);
        }
        let mut header = String::new();
        write_book_name(&mut header, " x ");
        assert_eq!(header, "; fa_book_name_hex_v1: 207820\n");
    }

    #[test]
    fn hledger_delimiters_keep_display_and_exact_source_separate() {
        let source = "  Invoice; vendor note\n2026-01-01 * injected\r\t\\n café  ";
        let (display, metadata) = hledger_description(source);
        assert_eq!(
            display,
            "  Invoice\\x3b vendor note\\n2026-01-01 * injected\\r\\t\\\\n café  "
        );
        assert!(!display.chars().any(char::is_control));
        assert!(!display.contains(';'));
        let hex = metadata.strip_prefix(" fa_description_hex_v1:").unwrap();
        assert_eq!(decode_text_hex(hex).unwrap(), source);
        assert_eq!(
            inline_text_metadata("fa_code", "10 00", true),
            "fa_code_hex_v1:3130203030"
        );
        for id in [
            "source id; fa_seq:999\nnew line",
            "\t",
            "café\u{2028}identifier",
        ] {
            let encoded = inline_text_metadata("fa_entry_id", id, true);
            let hex = encoded.strip_prefix("fa_entry_id_hex_v1:").unwrap();
            assert_eq!(decode_text_hex(hex).unwrap(), id);
            assert!(!encoded.chars().any(char::is_whitespace));
        }
    }

    #[test]
    fn quoted_strings_use_standard_escapes_without_double_decoding() {
        assert_eq!(
            escape_quotes("a\\b\"c\n\r\t\u{08}\u{0c}"),
            r#"a\\b\"c\n\r\t\b\f"#
        );
        assert_eq!(
            unquote(r#""a\\b\"c\n\r\t\b\f""#).unwrap(),
            "a\\b\"c\n\r\t\u{08}\u{0c}"
        );
        assert_eq!(unquote(r#""literal\\n""#).unwrap(), "literal\\n");
        assert_eq!(unquote(r#""line\nfeed""#).unwrap(), "line\nfeed");
        assert_eq!(
            unquote(" \"  quoted boundary  \"\t").unwrap(),
            "  quoted boundary  "
        );
    }

    #[test]
    fn quoted_and_hex_codecs_preserve_controls_and_unicode() {
        let mut samples = (0..=127)
            .map(|value| format!(" before{}after ", char::from(value)))
            .collect::<Vec<_>>();
        samples.extend(
            [
                "",
                "café 日本語 € 😀",
                "\u{0085}\u{2028}\u{2029}",
                "\\n\\r\\t\\b\\f\\\"",
            ]
            .map(str::to_owned),
        );
        for source in samples {
            let escaped = escape_quotes(&source);
            assert!(!escaped.contains(['\n', '\r']));
            assert_eq!(unquote(&format!("\"{escaped}\"")).unwrap(), source);
            assert_eq!(decode_text_hex(&encode_text_hex(&source)).unwrap(), source);
        }
        assert_eq!(encode_text_hex("café\n"), "636166c3a90a");
        assert_eq!(decode_text_hex("636166C3A90A").unwrap(), "café\n");
    }

    #[test]
    fn malformed_hex_and_quoted_strings_are_refused() {
        for invalid in [
            "0", "gg", "ff", "c0af", "eda080", "f4908080", "e282", "日本",
        ] {
            assert!(decode_text_hex(invalid).is_err(), "accepted {invalid:?}");
        }
        for invalid in [
            "",
            "\"",
            "unquoted",
            "\"missing",
            "missing\"",
            "\"bad\\q\"",
            "\"bad\\\"",
            "\"inner\"quote\"",
        ] {
            assert!(unquote(invalid).is_err(), "accepted {invalid:?}");
        }
    }
}
