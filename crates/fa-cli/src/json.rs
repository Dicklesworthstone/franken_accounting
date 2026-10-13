//! A minimal JSON reader and writer (closed dependency universe: no serde).
//!
//! Numbers are integers only. A JSON number with a fraction or exponent is
//! refused: amounts travel as strings like `"1500.00 USD"` so no float ever
//! touches an amount path (plan §1 constraint 4). Object keys keep insertion
//! order on read and are written sorted, so output is byte-deterministic.
//! Strings are decoded losslessly: malformed escapes, unpaired surrogates,
//! unescaped control characters and duplicate decoded keys are rejected.

use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i128),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Self::Obj(fields) => fields.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_arr(&self) -> Option<&[Json]> {
        match self {
            Self::Arr(a) => Some(a),
            _ => None,
        }
    }

    /// Render compactly with sorted object keys.
    pub fn render(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut String) {
        match self {
            Self::Null => out.push_str("null"),
            Self::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Self::Int(i) => out.push_str(&i.to_string()),
            Self::Str(s) => write_str(out, s),
            Self::Arr(a) => {
                out.push('[');
                for (i, v) in a.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    v.write(out);
                }
                out.push(']');
            }
            Self::Obj(fields) => {
                let sorted: BTreeMap<&str, &Json> =
                    fields.iter().map(|(k, v)| (k.as_str(), v)).collect();
                out.push('{');
                for (i, (k, v)) in sorted.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_str(out, k);
                    out.push(':');
                    v.write(out);
                }
                out.push('}');
            }
        }
    }
}

fn write_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// A tiny builder so call sites read like literals. Fields are kept sorted
/// by key, the order `render` writes and `parse` reads back, so a
/// constructed object equals its own rendered-and-parsed form.
pub fn obj(fields: Vec<(&str, Json)>) -> Json {
    let mut fields: Vec<(String, Json)> = fields
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
    fields.sort_by(|a, b| a.0.cmp(&b.0));
    Json::Obj(fields)
}

pub fn s(v: impl Into<String>) -> Json {
    Json::Str(v.into())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseError {
    pub offset: usize,
    pub message: String,
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "json at byte {}: {}", self.offset, self.message)
    }
}

pub fn parse(text: &str) -> Result<Json, ParseError> {
    let mut p = Parser {
        b: text.as_bytes(),
        i: 0,
    };
    p.ws();
    let v = p.value(0)?;
    p.ws();
    if p.i != p.b.len() {
        return Err(p.err("trailing characters after the value"));
    }
    Ok(v)
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

const MAX_DEPTH: usize = 64;

impl Parser<'_> {
    fn err(&self, m: &str) -> ParseError {
        ParseError {
            offset: self.i,
            message: m.to_string(),
        }
    }

    fn ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\n' | b'\r' | b'\t') {
            self.i += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn eat(&mut self, c: u8) -> bool {
        if self.peek() == Some(c) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    fn lit(&mut self, word: &str, v: Json) -> Result<Json, ParseError> {
        if self.b[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            Ok(v)
        } else {
            Err(self.err(&format!("expected `{word}`")))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Json, ParseError> {
        if depth > MAX_DEPTH {
            return Err(self.err("nesting deeper than 64"));
        }
        match self.peek() {
            None => Err(self.err("unexpected end of input")),
            Some(b'n') => self.lit("null", Json::Null),
            Some(b't') => self.lit("true", Json::Bool(true)),
            Some(b'f') => self.lit("false", Json::Bool(false)),
            Some(b'"') => self.string().map(Json::Str),
            Some(b'[') => {
                self.i += 1;
                let mut items = Vec::new();
                self.ws();
                if self.eat(b']') {
                    return Ok(Json::Arr(items));
                }
                loop {
                    self.ws();
                    items.push(self.value(depth + 1)?);
                    self.ws();
                    if self.eat(b',') {
                        continue;
                    }
                    if self.eat(b']') {
                        return Ok(Json::Arr(items));
                    }
                    return Err(self.err("expected `,` or `]`"));
                }
            }
            Some(b'{') => {
                self.i += 1;
                let mut fields = Vec::new();
                // Preserve insertion order without a quadratic duplicate scan.
                // Check decoded keys before reading their (possibly large) values.
                let mut keys = BTreeSet::new();
                self.ws();
                if self.eat(b'}') {
                    return Ok(Json::Obj(fields));
                }
                loop {
                    self.ws();
                    if self.peek() != Some(b'"') {
                        return Err(self.err("expected a string key"));
                    }
                    let k = self.string()?;
                    if !keys.insert(k.clone()) {
                        return Err(self.err(&format!("duplicate key `{k}`")));
                    }
                    self.ws();
                    if !self.eat(b':') {
                        return Err(self.err("expected `:`"));
                    }
                    self.ws();
                    let v = self.value(depth + 1)?;
                    fields.push((k, v));
                    self.ws();
                    if self.eat(b',') {
                        continue;
                    }
                    if self.eat(b'}') {
                        return Ok(Json::Obj(fields));
                    }
                    return Err(self.err("expected `,` or `}`"));
                }
            }
            Some(c) if c == b'-' || c.is_ascii_digit() => self.number(),
            Some(c) => Err(self.err(&format!("unexpected byte {c:#04x}"))),
        }
    }

    fn number(&mut self) -> Result<Json, ParseError> {
        let start = self.i;
        self.eat(b'-');
        match self.peek() {
            Some(b'0') => {
                self.i += 1;
                if matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                    return Err(self.err("leading zeros are not accepted in JSON numbers"));
                }
            }
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                    self.i += 1;
                }
            }
            _ => return Err(self.err("expected an integer digit")),
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return Err(self.err("fractional or exponent numbers are not accepted; write amounts as strings like \"12.34 USD\""));
        }
        let text =
            core::str::from_utf8(&self.b[start..self.i]).map_err(|_| self.err("bad number"))?;
        text.parse::<i128>()
            .map(Json::Int)
            .map_err(|_| self.err("integer out of range"))
    }

    /// Read exactly four ASCII hexadecimal digits, never a signed integer.
    fn hex_quad(&mut self) -> Result<u32, ParseError> {
        let mut code = 0;
        for _ in 0..4 {
            let digit = match self.peek() {
                Some(c @ b'0'..=b'9') => u32::from(c - b'0'),
                Some(c @ b'a'..=b'f') => u32::from(c - b'a' + 10),
                Some(c @ b'A'..=b'F') => u32::from(c - b'A' + 10),
                _ => return Err(self.err("expected four hexadecimal digits in \\u escape")),
            };
            self.i += 1;
            code = (code << 4) | digit;
        }
        Ok(code)
    }

    /// A UTF-16 surrogate pair encodes one scalar, not two replacements.
    fn unicode_scalar(&mut self) -> Result<char, ParseError> {
        let first = self.hex_quad()?;
        let code = match first {
            0xD800..=0xDBFF => {
                if !self.eat(b'\\') || !self.eat(b'u') {
                    return Err(
                        self.err("high surrogate must be followed by a low surrogate escape")
                    );
                }
                let low = self.hex_quad()?;
                if !(0xDC00..=0xDFFF).contains(&low) {
                    return Err(self.err("expected a low surrogate"));
                }
                0x10000 + ((first - 0xD800) << 10) + (low - 0xDC00)
            }
            0xDC00..=0xDFFF => return Err(self.err("unpaired low surrogate")),
            _ => first,
        };
        char::from_u32(code).ok_or_else(|| self.err("invalid Unicode scalar"))
    }

    fn string(&mut self) -> Result<String, ParseError> {
        self.i += 1; // opening quote
        let mut out = String::new();
        loop {
            let Some(c) = self.peek() else {
                return Err(self.err("unterminated string"));
            };
            self.i += 1;
            match c {
                b'"' => return Ok(out),
                b'\\' => {
                    let Some(e) = self.peek() else {
                        return Err(self.err("dangling escape"));
                    };
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => out.push(self.unicode_scalar()?),
                        _ => return Err(self.err("unknown escape")),
                    }
                }
                0x00..=0x1F => return Err(self.err("unescaped control character in string")),
                _ => {
                    // Copy one UTF-8 scalar.
                    let start = self.i - 1;
                    let len = utf8_len(c);
                    let end = (start + len).min(self.b.len());
                    let piece = core::str::from_utf8(&self.b[start..end])
                        .map_err(|_| self.err("invalid UTF-8"))?;
                    out.push_str(piece);
                    self.i = end;
                }
            }
        }
    }
}

fn utf8_len(first: u8) -> usize {
    match first {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        _ => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_refuses_floats() {
        let v = parse(r#"{"b":[1,-2,"x\"y\n",true,null],"a":{"k":"é"}}"#).unwrap();
        assert_eq!(
            v.render(),
            r#"{"a":{"k":"é"},"b":[1,-2,"x\"y\n",true,null]}"#
        );
        assert_eq!(parse(&v.render()).unwrap().render(), v.render());
        assert!(
            parse("1.5")
                .unwrap_err()
                .message
                .contains("amounts as strings")
        );
        assert!(parse("1e3").is_err());
        assert!(
            parse(r#"{"a":1,"a":2}"#)
                .unwrap_err()
                .message
                .contains("duplicate")
        );
        assert!(parse("[1,]").is_err());
        assert!(parse("{\"a\":1} x").is_err());
        assert_eq!(parse("\"\\u0041\"").unwrap(), Json::Str("A".into()));
    }

    #[test]
    fn integer_grammar_and_full_i128_domain() {
        for value in [i128::MIN, -10, -1, 0, 1, 10, i128::MAX] {
            assert_eq!(parse(&value.to_string()).unwrap(), Json::Int(value));
        }
        assert_eq!(parse("-0").unwrap(), Json::Int(0));
        for text in [
            "00",
            "01",
            "-00",
            "-01",
            "-",
            "- 1",
            "+1",
            "1.0",
            "1e0",
            "1E+3",
            "170141183460469231731687303715884105728",
            "-170141183460469231731687303715884105729",
        ] {
            assert!(parse(text).is_err(), "accepted {text:?}");
            assert!(
                parse(&format!("[{text}]")).is_err(),
                "accepted array {text:?}"
            );
        }
    }

    #[test]
    fn rejects_all_unescaped_controls_but_round_trips_escaped_controls() {
        for code in 0_u8..0x20 {
            let text = format!("\"{}\"", char::from(code));
            assert!(parse(&text).is_err(), "accepted raw control {code}");
            let escaped = format!(r#""\u{code:04x}""#);
            let value = Json::Str(char::from(code).to_string());
            assert_eq!(parse(&escaped).unwrap(), value);
            assert_eq!(parse(&value.render()).unwrap(), value);
        }
    }

    #[test]
    fn surrogate_pairs_preserve_non_bmp_identifiers() {
        for (text, expected) in [
            (r#""\uD834\uDD1E""#, "\u{1d11e}"),
            (r#""\ud83d\ude00""#, "\u{1f600}"),
            (r#""\uD800\uDC00""#, "\u{10000}"),
            (r#""\uDBFF\uDFFF""#, "\u{10ffff}"),
            (r#""\uFFFD""#, "\u{fffd}"),
        ] {
            let value = parse(text).unwrap();
            assert_eq!(value, Json::Str(expected.into()));
            assert_eq!(parse(&value.render()).unwrap(), value);
        }
    }

    #[test]
    fn malformed_unicode_is_never_replaced_or_accepted_as_a_signed_hex_number() {
        for text in [
            r#""\uD800""#,
            r#""\uDC00""#,
            r#""\uDFFF""#,
            r#""\uD800x""#,
            r#""\uD800\n""#,
            r#""\uD800\u0041""#,
            r#""\uD800\uD800""#,
            r#""\uDC00\uD800""#,
            r#""\u+041""#,
            r#""\u-041""#,
            r#""\u 041""#,
            r#""\u00xz""#,
            r#""\u123""#,
            r#""\uD800\u12""#,
        ] {
            assert!(parse(text).is_err(), "accepted {text:?}");
        }
    }

    #[test]
    fn duplicate_detection_uses_decoded_keys_at_every_object_depth() {
        for text in [
            r#"{"a":1,"\u0061":2}"#,
            r#"{"nested":{"a":1,"\u0061":2}}"#,
            r#"[{"a":1,"\u0061":2}]"#,
            "{\"\u{1f600}\":1,\"\\ud83d\\ude00\":2}",
        ] {
            assert!(parse(text).unwrap_err().message.contains("duplicate"));
        }
        // Reusing a key in a different object is legal.
        assert!(parse(r#"{"a":1,"nested":{"a":2}}"#).is_ok());
    }

    #[test]
    fn raw_and_escaped_identifiers_have_identical_canonical_bytes() {
        let raw = parse("{\"\u{1f600}\":\"\u{1d11e}\",\"a\":1}").unwrap();
        let escaped = parse(r#"{"a":1,"\ud83d\ude00":"\ud834\udd1e"}"#).unwrap();
        assert_eq!(raw.render(), escaped.render());
    }

    #[test]
    fn nesting_limit_and_truncated_tokens_fail_without_panicking() {
        let at_limit = format!("{}0{}", "[".repeat(MAX_DEPTH), "]".repeat(MAX_DEPTH));
        assert!(parse(&at_limit).is_ok());
        let too_deep = format!("[{at_limit}]");
        assert!(parse(&too_deep).is_err());
        for text in ["", "[", "{", "\"", "\"\\", "\"\\u", "\"\\uD800\\u", "tru"] {
            assert!(parse(text).is_err(), "accepted {text:?}");
        }
    }
}
