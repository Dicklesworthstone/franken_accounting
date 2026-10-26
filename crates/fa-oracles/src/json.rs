//! A minimal JSON reader and writer (docs/FORENSIC_CASE_STUDIES_PLAN.md
//! §3.1, "own minimal JSON reader"; bead fa-yugf.15, A7a).
//!
//! The runner reads the `fa` binary's robot lines and writes its JSONL log
//! with this module, never with the engine's serializer, so a bug shared
//! with the CLI cannot make an observation agree. The grammar is the subset
//! robot mode emits: objects, arrays, strings (with `\u` escapes and
//! surrogate pairs), integers that fit `i128`, `true`, `false` and `null`. A
//! float (a fraction or an exponent) is refused, because amounts are exact
//! strings and sequences are integers; so is a duplicate key, a leading
//! zero, a control character inside a string and anything after the value.

use core::fmt;

/// A JSON value. An object keeps its keys in document order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i128),
    Str(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    /// The member `key` of an object.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Object(members) => members.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// A path of object keys.
    #[must_use]
    pub fn at(&self, path: &[&str]) -> Option<&Self> {
        path.iter().try_fold(self, |v, k| v.get(k))
    }

    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s),
            _ => None,
        }
    }

    #[must_use]
    pub const fn as_int(&self) -> Option<i128> {
        match self {
            Self::Int(i) => Some(*i),
            _ => None,
        }
    }

    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_array(&self) -> Option<&[Self]> {
        match self {
            Self::Array(a) => Some(a),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_object(&self) -> Option<&[(String, Self)]> {
        match self {
            Self::Object(m) => Some(m),
            _ => None,
        }
    }

    #[must_use]
    pub const fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// A string value, `null` for `None`.
    #[must_use]
    pub fn opt_str(s: Option<&str>) -> Self {
        s.map_or(Self::Null, |s| Self::Str(s.to_string()))
    }
}

impl fmt::Display for Json {
    /// Compact JSON, object members in their stored order.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => f.write_str("null"),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Int(i) => write!(f, "{i}"),
            Self::Str(s) => write_string(f, s),
            Self::Array(items) => {
                f.write_str("[")?;
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        f.write_str(",")?;
                    }
                    write!(f, "{item}")?;
                }
                f.write_str("]")
            }
            Self::Object(members) => {
                f.write_str("{")?;
                for (i, (k, v)) in members.iter().enumerate() {
                    if i > 0 {
                        f.write_str(",")?;
                    }
                    write_string(f, k)?;
                    write!(f, ":{v}")?;
                }
                f.write_str("}")
            }
        }
    }
}

fn write_string(f: &mut fmt::Formatter<'_>, s: &str) -> fmt::Result {
    f.write_str("\"")?;
    for c in s.chars() {
        match c {
            '"' => f.write_str("\\\"")?,
            '\\' => f.write_str("\\\\")?,
            '\n' => f.write_str("\\n")?,
            '\r' => f.write_str("\\r")?,
            '\t' => f.write_str("\\t")?,
            c if (c as u32) < 0x20 => write!(f, "\\u{:04x}", c as u32)?,
            c => write!(f, "{c}")?,
        }
    }
    f.write_str("\"")
}

/// Why a text is not JSON of the robot subset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JsonError {
    /// The byte offset where reading stopped.
    pub offset: usize,
    pub message: String,
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "JSON at byte {}: {}", self.offset, self.message)
    }
}

impl core::error::Error for JsonError {}

/// Reads one JSON value; surrounding whitespace is allowed.
///
/// # Errors
///
/// [`JsonError`] naming the offset and why.
pub fn parse(text: &str) -> Result<Json, JsonError> {
    let mut r = Reader {
        b: text.as_bytes(),
        text,
        at: 0,
    };
    r.ws();
    let v = r.value(0)?;
    r.ws();
    if r.at != r.b.len() {
        return Err(r.err("text after the value"));
    }
    Ok(v)
}

/// The nesting a robot line never exceeds; deeper input is refused.
const MAX_DEPTH: usize = 128;

struct Reader<'t> {
    b: &'t [u8],
    text: &'t str,
    at: usize,
}

impl Reader<'_> {
    fn err(&self, message: impl Into<String>) -> JsonError {
        JsonError {
            offset: self.at,
            message: message.into(),
        }
    }

    fn ws(&mut self) {
        while self
            .b
            .get(self.at)
            .is_some_and(|c| matches!(c, b' ' | b'\t' | b'\n' | b'\r'))
        {
            self.at += 1;
        }
    }

    fn eat(&mut self, c: u8) -> Result<(), JsonError> {
        if self.b.get(self.at) == Some(&c) {
            self.at += 1;
            Ok(())
        } else {
            Err(self.err(format!("expected `{}`", c as char)))
        }
    }

    fn literal(&mut self, word: &str, v: Json) -> Result<Json, JsonError> {
        if self.b[self.at..].starts_with(word.as_bytes()) {
            self.at += word.len();
            Ok(v)
        } else {
            Err(self.err("not a JSON value"))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Json, JsonError> {
        if depth > MAX_DEPTH {
            return Err(self.err("nested too deeply"));
        }
        match self.b.get(self.at) {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => self.string().map(Json::Str),
            Some(b't') => self.literal("true", Json::Bool(true)),
            Some(b'f') => self.literal("false", Json::Bool(false)),
            Some(b'n') => self.literal("null", Json::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) => Err(self.err("not a JSON value")),
            None => Err(self.err("unexpected end of text")),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Json, JsonError> {
        self.eat(b'{')?;
        let mut members: Vec<(String, Json)> = Vec::new();
        self.ws();
        if self.b.get(self.at) == Some(&b'}') {
            self.at += 1;
            return Ok(Json::Object(members));
        }
        loop {
            self.ws();
            let key_at = self.at;
            let key = self.string()?;
            if members.iter().any(|(k, _)| *k == key) {
                return Err(JsonError {
                    offset: key_at,
                    message: format!("duplicate key `{key}`"),
                });
            }
            self.ws();
            self.eat(b':')?;
            self.ws();
            let v = self.value(depth + 1)?;
            members.push((key, v));
            self.ws();
            match self.b.get(self.at) {
                Some(b',') => self.at += 1,
                Some(b'}') => {
                    self.at += 1;
                    return Ok(Json::Object(members));
                }
                _ => return Err(self.err("expected `,` or `}`")),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Json, JsonError> {
        self.eat(b'[')?;
        let mut items = Vec::new();
        self.ws();
        if self.b.get(self.at) == Some(&b']') {
            self.at += 1;
            return Ok(Json::Array(items));
        }
        loop {
            self.ws();
            items.push(self.value(depth + 1)?);
            self.ws();
            match self.b.get(self.at) {
                Some(b',') => self.at += 1,
                Some(b']') => {
                    self.at += 1;
                    return Ok(Json::Array(items));
                }
                _ => return Err(self.err("expected `,` or `]`")),
            }
        }
    }

    fn number(&mut self) -> Result<Json, JsonError> {
        let start = self.at;
        if self.b.get(self.at) == Some(&b'-') {
            self.at += 1;
        }
        let digits_at = self.at;
        while self.b.get(self.at).is_some_and(u8::is_ascii_digit) {
            self.at += 1;
        }
        if self.at == digits_at {
            return Err(self.err("a number needs digits"));
        }
        if self.b[digits_at] == b'0' && self.at - digits_at > 1 {
            return Err(JsonError {
                offset: digits_at,
                message: "a leading zero".into(),
            });
        }
        if matches!(self.b.get(self.at), Some(b'.' | b'e' | b'E')) {
            return Err(self.err(
                "a float: robot mode carries amounts as exact strings and sequences as integers",
            ));
        }
        self.text[start..self.at]
            .parse::<i128>()
            .map(Json::Int)
            .map_err(|_| JsonError {
                offset: start,
                message: "an integer outside i128".into(),
            })
    }

    fn string(&mut self) -> Result<String, JsonError> {
        self.eat(b'"')?;
        let mut out = String::new();
        loop {
            let Some(&c) = self.b.get(self.at) else {
                return Err(self.err("an unterminated string"));
            };
            match c {
                b'"' => {
                    self.at += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.at += 1;
                    let Some(&e) = self.b.get(self.at) else {
                        return Err(self.err("an unterminated escape"));
                    };
                    self.at += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => out.push(self.unicode()?),
                        _ => return Err(self.err("an unknown escape")),
                    }
                }
                c if c < 0x20 => return Err(self.err("a control character inside a string")),
                _ => {
                    // Copy one UTF-8 character (the text is a &str).
                    let rest = &self.text[self.at..];
                    let ch = rest.chars().next().ok_or_else(|| self.err("bad UTF-8"))?;
                    out.push(ch);
                    self.at += ch.len_utf8();
                }
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, JsonError> {
        let s = self
            .text
            .get(self.at..self.at + 4)
            .filter(|s| s.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or_else(|| self.err("`\\u` takes four hex digits"))?;
        self.at += 4;
        u32::from_str_radix(s, 16).map_err(|_| self.err("bad hex"))
    }

    fn unicode(&mut self) -> Result<char, JsonError> {
        let hi = self.hex4()?;
        let code = if (0xD800..0xDC00).contains(&hi) {
            if !self.b[self.at..].starts_with(b"\\u") {
                return Err(self.err("a lone high surrogate"));
            }
            self.at += 2;
            let lo = self.hex4()?;
            if !(0xDC00..0xE000).contains(&lo) {
                return Err(self.err("a high surrogate without its low half"));
            }
            0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
        } else if (0xDC00..0xE000).contains(&hi) {
            return Err(self.err("a lone low surrogate"));
        } else {
            hi
        };
        char::from_u32(code).ok_or_else(|| self.err("not a Unicode scalar value"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_reader_round_trips_robot_lines_and_refuses_floats() {
        // Shapes copied from robot mode: the envelope, an exact amount string,
        // a sequence integer, nulls, nested objects and arrays, an escape.
        let line = r#"{"authority":{"kind":"embedded-owner","ops":null},"book":"0f3a","certificate":null,"coordinate":{"branch":"trunk","effective":null,"known_at":12},"data":{"amount":"560000000.00 USD","legs":[{"account_vid":"9a","ordinal":0},{"account_vid":"9b","ordinal":1}],"memo":"line \"costs\"é😀","ok":true},"event":"posted","next_actions":[],"v":1,"warnings":[]}"#;
        let v = parse(line).expect("a robot line");
        assert_eq!(
            v.at(&["coordinate", "known_at"]).and_then(Json::as_int),
            Some(12)
        );
        assert_eq!(
            v.at(&["data", "amount"]).and_then(Json::as_str),
            Some("560000000.00 USD")
        );
        assert_eq!(
            v.at(&["data", "memo"]).and_then(Json::as_str),
            Some("line \"costs\"\u{e9}\u{1F600}")
        );
        assert!(v.get("certificate").is_some_and(Json::is_null));
        // The writer's output reads back to the same value.
        assert_eq!(parse(&v.to_string()), Ok(v));
        for bad in [
            r#"{"amount":1.5}"#,
            r#"{"n":1e3}"#,
            r#"{"a":1,"a":2}"#,
            r#"{"n":012}"#,
            r#"{"s":"a"} x"#,
            "{\"s\":\"a\u{1}b\"}",
            r#"{"s":"\ud800"}"#,
            r#"{"n":170141183460469231731687303715884105728}"#,
        ] {
            assert!(parse(bad).is_err(), "{bad} must be refused");
        }
        assert_eq!(
            parse(r#"{"n":-170141183460469231731687303715884105728}"#)
                .ok()
                .and_then(|v| v.get("n").and_then(Json::as_int)),
            Some(i128::MIN)
        );
        let err = parse(r#"{"x":2.50}"#).expect_err("a float");
        assert!(err.message.contains("float"), "{err}");
    }
}
