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

    /// Render in TOON v3.0 format (2-space indent, comma delimiter, tabular arrays).
    #[must_use]
    pub fn render_toon(&self) -> String {
        toon::encode(self)
    }

    #[must_use]
    pub const fn is_primitive(&self) -> bool {
        matches!(
            self,
            Self::Null | Self::Bool(_) | Self::Int(_) | Self::Str(_)
        )
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

/// TOON v3.0 encoder (`--format toon`, bead `fa-1gb`).
///
/// Implements the TOON v3.0 specification over [`Json`]:
/// - 2-space indentation, comma delimiter, no trailing spaces or trailing newline;
/// - uniform arrays of primitive-valued objects encode as tabular headers
///   `key[N]{f1,f2,...}:` followed by comma-separated rows;
/// - amounts (`"1500.00 USD"`, `"-42.50 USD"`) remain strings; numeric-like or
///   negative strings are quoted so a TOON decoder never coerces them to numbers.
pub mod toon {
    use super::Json;

    const INDENT: &str = "  ";

    #[must_use]
    pub fn encode(value: &Json) -> String {
        if value.is_primitive() {
            return encode_primitive(value);
        }
        let mut writer = LineWriter::default();
        match value {
            Json::Arr(items) => encode_array_lines(None, items, &mut writer, 0),
            Json::Obj(fields) => encode_object(fields, &mut writer, 0),
            _ => {}
        }
        writer.finish()
    }

    #[derive(Default)]
    struct LineWriter {
        lines: Vec<String>,
    }

    impl LineWriter {
        fn push(&mut self, depth: usize, content: &str) {
            self.lines.push(format!("{}{content}", INDENT.repeat(depth)));
        }

        fn push_list_item(&mut self, depth: usize, content: &str) {
            if content.is_empty() {
                self.push(depth, "-");
            } else {
                self.push(depth, &format!("- {content}"));
            }
        }

        fn finish(self) -> String {
            self.lines.join("\n")
        }
    }

    fn encode_object(fields: &[(String, Json)], writer: &mut LineWriter, depth: usize) {
        for (key, value) in fields {
            encode_key_value_pair(key, value, writer, depth);
        }
    }

    fn encode_key_value_pair(key: &str, value: &Json, writer: &mut LineWriter, depth: usize) {
        let encoded_key = encode_key(key);
        match value {
            v if v.is_primitive() => {
                writer.push(depth, &format!("{encoded_key}: {}", encode_primitive(v)));
            }
            Json::Arr(items) => {
                encode_array_lines(Some(key), items, writer, depth);
            }
            Json::Obj(nested) => {
                writer.push(depth, &format!("{encoded_key}:"));
                if !nested.is_empty() {
                    encode_object(nested, writer, depth + 1);
                }
            }
            _ => {}
        }
    }

    fn encode_array_lines(
        key: Option<&str>,
        items: &[Json],
        writer: &mut LineWriter,
        depth: usize,
    ) {
        if items.is_empty() {
            writer.push(depth, &format_header(0, key, None));
            return;
        }
        if items.iter().all(Json::is_primitive) {
            let header = format_header(items.len(), key, None);
            let vals = join_primitives(items);
            writer.push(depth, &format!("{header} {vals}"));
            return;
        }
        if items
            .iter()
            .all(|v| matches!(v, Json::Arr(inner) if inner.iter().all(Json::is_primitive)))
        {
            writer.push(depth, &format_header(items.len(), key, None));
            for item in items {
                if let Json::Arr(inner) = item {
                    writer.push_list_item(depth + 1, &inline_primitive_array(None, inner));
                }
            }
            return;
        }
        if let Some(header_keys) = extract_tabular_header(items) {
            writer.push(depth, &format_header(items.len(), key, Some(&header_keys)));
            write_tabular_rows(items, &header_keys, writer, depth + 1);
            return;
        }
        writer.push(depth, &format_header(items.len(), key, None));
        write_list_items(items, writer, depth + 1);
    }

    fn write_list_items(items: &[Json], writer: &mut LineWriter, item_depth: usize) {
        for item in items {
            match item {
                v if v.is_primitive() => {
                    writer.push_list_item(item_depth, &encode_primitive(v));
                }
                Json::Arr(arr) => {
                    encode_array_on_hyphen(None, arr, writer, item_depth, item_depth + 1);
                }
                Json::Obj(fields) => {
                    encode_object_as_list_item(fields, writer, item_depth);
                }
                _ => {}
            }
        }
    }

    fn encode_array_on_hyphen(
        key: Option<&str>,
        items: &[Json],
        writer: &mut LineWriter,
        hyphen_depth: usize,
        child_depth: usize,
    ) {
        if items.is_empty() {
            writer.push_list_item(hyphen_depth, &format_header(0, key, None));
            return;
        }
        if items.iter().all(Json::is_primitive) {
            writer.push_list_item(hyphen_depth, &inline_primitive_array(key, items));
            return;
        }
        if items
            .iter()
            .all(|v| matches!(v, Json::Arr(inner) if inner.iter().all(Json::is_primitive)))
        {
            writer.push_list_item(hyphen_depth, &format_header(items.len(), key, None));
            for item in items {
                if let Json::Arr(inner) = item {
                    writer.push_list_item(child_depth, &inline_primitive_array(None, inner));
                }
            }
            return;
        }
        if let Some(header_keys) = extract_tabular_header(items) {
            writer.push_list_item(
                hyphen_depth,
                &format_header(items.len(), key, Some(&header_keys)),
            );
            write_tabular_rows(items, &header_keys, writer, child_depth);
            return;
        }
        writer.push_list_item(hyphen_depth, &format_header(items.len(), key, None));
        write_list_items(items, writer, child_depth);
    }

    fn encode_object_as_list_item(
        fields: &[(String, Json)],
        writer: &mut LineWriter,
        hyphen_depth: usize,
    ) {
        if fields.is_empty() {
            writer.push_list_item(hyphen_depth, "");
            return;
        }
        let (first_key, first_val) = &fields[0];
        let encoded_key = encode_key(first_key);
        match first_val {
            v if v.is_primitive() => {
                writer.push_list_item(
                    hyphen_depth,
                    &format!("{encoded_key}: {}", encode_primitive(v)),
                );
            }
            Json::Arr(items) => {
                encode_array_on_hyphen(
                    Some(first_key),
                    items,
                    writer,
                    hyphen_depth,
                    hyphen_depth + 2,
                );
            }
            Json::Obj(nested) => {
                writer.push_list_item(hyphen_depth, &format!("{encoded_key}:"));
                if !nested.is_empty() {
                    encode_object(nested, writer, hyphen_depth + 2);
                }
            }
            _ => {}
        }
        for (key, value) in fields.iter().skip(1) {
            encode_key_value_pair(key, value, writer, hyphen_depth + 1);
        }
    }

    fn inline_primitive_array(key: Option<&str>, items: &[Json]) -> String {
        let header = format_header(items.len(), key, None);
        if items.is_empty() {
            header
        } else {
            format!("{header} {}", join_primitives(items))
        }
    }

    fn join_primitives(items: &[Json]) -> String {
        items
            .iter()
            .map(encode_primitive)
            .collect::<Vec<_>>()
            .join(",")
    }

    fn extract_tabular_header(rows: &[Json]) -> Option<Vec<String>> {
        let Json::Obj(first_fields) = rows.first()? else {
            return None;
        };
        if first_fields.is_empty() {
            return None;
        }
        let header: Vec<String> = first_fields.iter().map(|(k, _)| k.clone()).collect();
        for row in rows {
            let Json::Obj(fields) = row else {
                return None;
            };
            if fields.len() != header.len() {
                return None;
            }
            for key in &header {
                let Some((_, val)) = fields.iter().find(|(k, _)| k == key) else {
                    return None;
                };
                if !val.is_primitive() {
                    return None;
                }
            }
        }
        Some(header)
    }

    fn write_tabular_rows(
        rows: &[Json],
        header: &[String],
        writer: &mut LineWriter,
        depth: usize,
    ) {
        for row in rows {
            if let Json::Obj(fields) = row {
                let values: Vec<String> = header
                    .iter()
                    .filter_map(|key| fields.iter().find(|(k, _)| k == key).map(|(_, v)| v))
                    .map(encode_primitive)
                    .collect();
                writer.push(depth, &values.join(","));
            }
        }
    }

    fn format_header(len: usize, key: Option<&str>, fields: Option<&[String]>) -> String {
        let mut h = String::new();
        if let Some(k) = key {
            h.push_str(&encode_key(k));
        }
        h.push_str(&format!("[{len}]"));
        if let Some(fs) = fields {
            let encoded: Vec<String> = fs.iter().map(|f| encode_key(f)).collect();
            h.push('{');
            h.push_str(&encoded.join(","));
            h.push('}');
        }
        h.push(':');
        h
    }

    fn encode_primitive(value: &Json) -> String {
        match value {
            Json::Null => "null".to_string(),
            Json::Bool(b) => if *b { "true" } else { "false" }.to_string(),
            Json::Int(n) => n.to_string(),
            Json::Str(s) => encode_string_literal(s),
            Json::Arr(_) | Json::Obj(_) => "null".to_string(),
        }
    }

    fn encode_string_literal(value: &str) -> String {
        if is_safe_unquoted(value) {
            value.to_string()
        } else {
            format!("\"{}\"", escape_string(value))
        }
    }

    fn encode_key(key: &str) -> String {
        if is_valid_unquoted_key(key) {
            key.to_string()
        } else {
            format!("\"{}\"", escape_string(key))
        }
    }

    fn is_valid_unquoted_key(key: &str) -> bool {
        let Some((&first, rest)) = key.as_bytes().split_first() else {
            return false;
        };
        (first.is_ascii_alphabetic() || first == b'_')
            && rest
                .iter()
                .all(|&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
    }

    fn is_safe_unquoted(value: &str) -> bool {
        if value.is_empty() || value.trim() != value {
            return false;
        }
        if matches!(value, "true" | "false" | "null")
            || is_numeric_like(value)
            || is_octal_like(value)
        {
            return false;
        }
        if value.starts_with('-') {
            return false;
        }
        !value.chars().any(|c| {
            matches!(
                c,
                ':' | '"' | '\\' | '[' | ']' | '{' | '}' | '\n' | '\r' | '\t' | ','
            ) || c.is_control()
        })
    }

    fn is_numeric_like(value: &str) -> bool {
        if value.is_empty() {
            return false;
        }
        let bytes = value.as_bytes();
        let mut idx = 0;
        if bytes[idx] == b'-' {
            idx += 1;
            if idx >= bytes.len() {
                return false;
            }
        }
        let digit_start = idx;
        while idx < bytes.len() && bytes[idx].is_ascii_digit() {
            idx += 1;
        }
        if idx == digit_start {
            return false;
        }
        if idx < bytes.len() && bytes[idx] == b'.' {
            idx += 1;
            let frac_start = idx;
            while idx < bytes.len() && bytes[idx].is_ascii_digit() {
                idx += 1;
            }
            if idx == frac_start {
                return false;
            }
        }
        if idx < bytes.len() && (bytes[idx] == b'e' || bytes[idx] == b'E') {
            idx += 1;
            if idx < bytes.len() && (bytes[idx] == b'+' || bytes[idx] == b'-') {
                idx += 1;
            }
            let exp_start = idx;
            while idx < bytes.len() && bytes[idx].is_ascii_digit() {
                idx += 1;
            }
            if idx == exp_start {
                return false;
            }
        }
        idx == bytes.len()
    }

    fn is_octal_like(value: &str) -> bool {
        let bytes = value.as_bytes();
        bytes.len() >= 2 && bytes[0] == b'0' && bytes[1..].iter().all(u8::is_ascii_digit)
    }

    fn escape_string(value: &str) -> String {
        let mut out = String::with_capacity(value.len());
        for c in value.chars() {
            match c {
                '\\' => out.push_str("\\\\"),
                '"' => out.push_str("\\\""),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                c => out.push(c),
            }
        }
        out
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

    #[test]
    fn toon_spec_primitives_and_accounting_amounts_golden_vectors() {
        for (input, expected) in [
            (r#""hello""#, "hello"),
            (r#""Ada_99""#, "Ada_99"),
            (r#""""#, r#""""#),
            (r#""true""#, r#""true""#),
            (r#""false""#, r#""false""#),
            (r#""null""#, r#""null""#),
            (r#""42""#, r#""42""#),
            (r#""-3.14""#, r#""-3.14""#),
            (r#""1e-6""#, r#""1e-6""#),
            (r#""05""#, r#""05""#),
            (r#""line1\nline2""#, r#""line1\nline2""#),
            (r#""tab\there""#, r#""tab\there""#),
            (r#""return\rcarriage""#, r#""return\rcarriage""#),
            (r#""C:\\Users\\path""#, r#""C:\\Users\\path""#),
            (r#""[3]: x,y""#, r#""[3]: x,y""#),
            (r#""- item""#, r#""- item""#),
            (r#""[test]""#, r#""[test]""#),
            (r#""{key}""#, r#""{key}""#),
            (r#""café""#, "café"),
            (r#""你好""#, "你好"),
            (r#""🚀""#, "🚀"),
            (r#""hello 👋 world""#, "hello 👋 world"),
            ("42", "42"),
            ("-7", "-7"),
            ("0", "0"),
            ("-0", "0"),
            ("true", "true"),
            ("false", "false"),
            ("null", "null"),
            // Accounting amounts and identifiers stay strings in TOON:
            (r#""1500.00 USD""#, "1500.00 USD"),
            (r#""0.00 USD""#, "0.00 USD"),
            (r#""-42.50 USD""#, r#""-42.50 USD""#),
            (r#""1000""#, r#""1000""#),
            (
                r#""00000000000000000000000000000001""#,
                r#""00000000000000000000000000000001""#,
            ),
        ] {
            let val = parse(input).expect(input);
            assert_eq!(val.render_toon(), expected, "input: {input}");
        }
    }

    #[test]
    fn toon_spec_objects_golden_vectors() {
        for (input, expected) in [
            (
                r#"{"id":123,"name":"Ada","active":true}"#,
                "id: 123\nname: Ada\nactive: true",
            ),
            (r#"{"id":123,"value":null}"#, "id: 123\nvalue: null"),
            (r#"{}"#, ""),
            (
                r#"{"note":"a:b"}"#,
                r#"note: "a:b""#,
            ),
            (
                r#"{"note":"a,b"}"#,
                r#"note: "a,b""#,
            ),
            (
                r#"{"text":"line1\nline2"}"#,
                r#"text: "line1\nline2""#,
            ),
            (
                r#"{"text":"say \"hello\""}"#,
                r#"text: "say \"hello\"""#,
            ),
            (
                r#"{"text":" padded "}"#,
                r#"text: " padded ""#,
            ),
            (
                r#"{"text":"  "}"#,
                r#"text: "  ""#,
            ),
            (
                r#"{"v":"true"}"#,
                r#"v: "true""#,
            ),
            (
                r#"{"v":"42"}"#,
                r#"v: "42""#,
            ),
            (
                r#"{"v":"-7.5"}"#,
                r#"v: "-7.5""#,
            ),
            (
                r#"{"order:id":7}"#,
                r#""order:id": 7"#,
            ),
            (
                r#"{"[index]":5}"#,
                r#""[index]": 5"#,
            ),
            (
                r#"{"-lead":1}"#,
                r#""-lead": 1"#,
            ),
            (
                r#"{"123":1}"#,
                r#""123": 1"#,
            ),
            (
                r#"{"":1}"#,
                r#""": 1"#,
            ),
            (
                r#"{"user_name":1,"_id":2,"a.b":3}"#,
                "user_name: 1\n_id: 2\na.b: 3",
            ),
            (
                r#"{"a":{"b":{"c":"deep"}}}"#,
                "a:\n  b:\n    c: deep",
            ),
            (
                r#"{"user":{}}"#,
                "user:",
            ),
        ] {
            let val = parse(input).expect(input);
            assert_eq!(val.render_toon(), expected, "input: {input}");
        }
    }

    #[test]
    fn toon_spec_arrays_primitive_tabular_nested_and_objects_golden_vectors() {
        for (input, expected) in [
            // arrays-primitive.json
            (
                r#"{"tags":["reading","gaming"]}"#,
                "tags[2]: reading,gaming",
            ),
            (
                r#"{"nums":[1,2,3]}"#,
                "nums[3]: 1,2,3",
            ),
            (
                r#"{"data":["x","y",true,10]}"#,
                "data[4]: x,y,true,10",
            ),
            (
                r#"{"items":[]}"#,
                "items[0]:",
            ),
            (
                r#"{"items":[""]}"#,
                r#"items[1]: """#,
            ),
            (
                r#"{"items":["a","","b"]}"#,
                r#"items[3]: a,"",b"#,
            ),
            (
                r#"{"items":[" ","  "]}"#,
                r#"items[2]: " ","  ""#,
            ),
            (
                r#"{"items":["a","b,c","d:e"]}"#,
                r#"items[3]: a,"b,c","d:e""#,
            ),
            (
                r#"{"items":["x","true","42","-3.14"]}"#,
                r#"items[4]: x,"true","42","-3.14""#,
            ),
            (
                r#"{"items":["[5]","- item","{key}"]}"#,
                r#"items[3]: "[5]","- item","{key}""#,
            ),
            // arrays-tabular.json
            (
                r#"{"items":[{"sku":"A1","qty":2,"price":"9.99 USD"},{"sku":"B2","qty":1,"price":"14.50 USD"}]}"#,
                "items[2]{sku,qty,price}:\n  A1,2,9.99 USD\n  B2,1,14.50 USD",
            ),
            (
                r#"{"items":[{"id":1,"value":null},{"id":2,"value":"test"}]}"#,
                "items[2]{id,value}:\n  1,null\n  2,test",
            ),
            (
                r#"{"items":[{"sku":"A,1","desc":"cool","qty":2},{"sku":"B2","desc":"wip: test","qty":1}]}"#,
                "items[2]{sku,desc,qty}:\n  \"A,1\",cool,2\n  B2,\"wip: test\",1",
            ),
            (
                r#"{"items":[{"id":1,"status":"true"},{"id":2,"status":"false"}]}"#,
                "items[2]{id,status}:\n  1,\"true\"\n  2,\"false\"",
            ),
            (
                r#"{"items":[{"order:id":1,"full name":"Ada"},{"order:id":2,"full name":"Bob"}]}"#,
                "items[2]{\"order:id\",\"full name\"}:\n  1,Ada\n  2,Bob",
            ),
            (
                r#"{"items":[{"a":1,"b":2,"c":3},{"c":30,"b":20,"a":10}]}"#,
                "items[2]{a,b,c}:\n  1,2,3\n  10,20,30",
            ),
            // arrays-nested.json
            (
                r#"{"pairs":[["a","b"],["c","d"]]}"#,
                "pairs[2]:\n  - [2]: a,b\n  - [2]: c,d",
            ),
            (
                r#"{"pairs":[["a","b"],["c,d","e:f","true"]]}"#,
                "pairs[2]:\n  - [2]: a,b\n  - [3]: \"c,d\",\"e:f\",\"true\"",
            ),
            (
                r#"{"pairs":[[],[]]}"#,
                "pairs[2]:\n  - [0]:\n  - [0]:",
            ),
            (
                r#"{"pairs":[[1],[2,3]]}"#,
                "pairs[2]:\n  - [1]: 1\n  - [2]: 2,3",
            ),
            (
                r#"["x","y","true",true,10]"#,
                r#"[5]: x,y,"true",true,10"#,
            ),
            (
                r#"[{"id":1},{"id":2}]"#,
                "[2]{id}:\n  1\n  2",
            ),
            (
                r#"[{"id":1},{"id":2,"name":"Ada"}]"#,
                "[2]:\n  - id: 1\n  - id: 2\n    name: Ada",
            ),
            (
                r#"["summary",{"id":1,"name":"Ada"},[{"id":2},{"status":"draft"}]]"#,
                "[3]:\n  - summary\n  - id: 1\n    name: Ada\n  - [2]:\n    - id: 2\n    - status: draft",
            ),
            (
                r#"[[1,2],[]]"#,
                "[2]:\n  - [2]: 1,2\n  - [0]:",
            ),
            (
                r#"[]"#,
                "[0]:",
            ),
            (
                r#"{"user":{"id":123,"name":"Ada","tags":["reading","gaming"],"active":true,"prefs":[]}}"#,
                "user:\n  id: 123\n  name: Ada\n  tags[2]: reading,gaming\n  active: true\n  prefs[0]:",
            ),
            (
                r#"{"items":[1,{"a":1},"text"]}"#,
                "items[3]:\n  - 1\n  - a: 1\n  - text",
            ),
            (
                r#"{"items":[{"a":1},[1,2]]}"#,
                "items[2]:\n  - a: 1\n  - [2]: 1,2",
            ),
            // arrays-objects.json
            (
                r#"{"items":[{"id":1,"name":"First"},{"id":2,"name":"Second","extra":true}]}"#,
                "items[2]:\n  - id: 1\n    name: First\n  - id: 2\n    name: Second\n    extra: true",
            ),
            (
                r#"{"items":[{"id":1,"nested":{"x":1}}]}"#,
                "items[1]:\n  - id: 1\n    nested:\n      x: 1",
            ),
            (
                r#"{"items":[{"nums":[1,2,3],"name":"Ada"}]}"#,
                "items[1]:\n  - nums[3]: 1,2,3\n    name: Ada",
            ),
            (
                r#"{"items":[{"name":"Ada","nums":[1,2,3]}]}"#,
                "items[1]:\n  - name: Ada\n    nums[3]: 1,2,3",
            ),
            (
                r#"{"items":[{"matrix":[[1,2],[3,4]],"name":"grid"}]}"#,
                "items[1]:\n  - matrix[2]:\n      - [2]: 1,2\n      - [2]: 3,4\n    name: grid",
            ),
            (
                r#"{"items":[{"users":[{"id":1,"name":"Ada"},{"id":2,"name":"Bob"}],"status":"active"}]}"#,
                "items[1]:\n  - users[2]{id,name}:\n      1,Ada\n      2,Bob\n    status: active",
            ),
            (
                r#"{"items":[{"users":[{"id":1,"name":"Ada"},{"id":2}],"status":"active"}]}"#,
                "items[1]:\n  - users[2]:\n      - id: 1\n        name: Ada\n      - id: 2\n    status: active",
            ),
            (
                r#"{"items":[{"nums":[1,2],"tags":["a","b"],"name":"test"}]}"#,
                "items[1]:\n  - nums[2]: 1,2\n    tags[2]: a,b\n    name: test",
            ),
            (
                r#"{"items":[{"nums":[1,2,3],"tags":["a","b"]}]}"#,
                "items[1]:\n  - nums[3]: 1,2,3\n    tags[2]: a,b",
            ),
            (
                r#"{"items":[{"name":"Ada","data":[]}]}"#,
                "items[1]:\n  - name: Ada\n    data[0]:",
            ),
            (
                r#"{"items":[{"users":[{"id":1},{"id":2}],"note":"x"}]}"#,
                "items[1]:\n  - users[2]{id}:\n      1\n      2\n    note: x",
            ),
            (
                r#"{"items":[{"users":[{"id":1,"name":"Ada"},{"id":2,"name":"Bob"}]}]}"#,
                "items[1]:\n  - users[2]{id,name}:\n      1,Ada\n      2,Bob",
            ),
            (
                r#"{"items":[{"data":[],"name":"x"}]}"#,
                "items[1]:\n  - data[0]:\n    name: x",
            ),
            (
                r#"{"items":["first","second",{}]}"#,
                "items[3]:\n  - first\n  - second\n  -",
            ),
            (
                r#"{"items":[{"id":1,"data":"string"},{"id":2,"data":{"nested":true}}]}"#,
                "items[2]:\n  - id: 1\n    data: string\n  - id: 2\n    data:\n      nested: true",
            ),
        ] {
            let val = parse(input).expect(input);
            let encoded = val.render_toon();
            assert_eq!(encoded, expected, "input: {input}");
            assert!(!encoded.ends_with('\n'), "no trailing newline: {input}");
            for line in encoded.lines() {
                assert!(!line.ends_with(' '), "no trailing space on line {line:?}");
            }
        }
    }
}
