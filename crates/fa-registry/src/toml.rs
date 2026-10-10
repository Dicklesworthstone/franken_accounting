//! A deliberately small TOML reader: exactly the subset the registries use.
//!
//! Supported: comments, `key = value` with basic strings (`"..."` with the
//! common escapes), integers (optional sign, `_` separators), booleans, and
//! flat arrays of those scalars; `[table]` headers; `[[array.of.tables]]`
//! headers. Not supported (and refused with a line number): dotted keys,
//! inline tables, multi-line strings, floats (no float has a place in a
//! registry), dates. The parser is total: every input yields a document or a
//! `TomlError` naming the line.

use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Str(String),
    Int(i128),
    Bool(bool),
    Array(Vec<Value>),
}

impl Value {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i128> {
        match self {
            Self::Int(i) => Some(*i),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Self::Array(a) => Some(a),
            _ => None,
        }
    }
}

/// One table: ordered keys.
pub type Table = BTreeMap<String, Value>;

/// A parsed document: root scalars, named tables, and arrays of tables.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Document {
    pub root: Table,
    pub tables: BTreeMap<String, Table>,
    pub arrays: BTreeMap<String, Vec<Table>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TomlError {
    pub line: usize,
    pub message: String,
}

impl core::fmt::Display for TomlError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "toml line {}: {}", self.line, self.message)
    }
}

impl core::error::Error for TomlError {}

enum Target {
    Root,
    Table(String),
    ArrayItem(String),
}

pub fn parse(text: &str) -> Result<Document, TomlError> {
    let mut doc = Document::default();
    let mut target = Target::Root;
    for (idx, raw) in text.lines().enumerate() {
        let line_no = idx + 1;
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if let Some(inner) = line.strip_prefix("[[").and_then(|l| l.strip_suffix("]]")) {
            let name = inner.trim();
            if name.is_empty() {
                return Err(err(line_no, "empty array-of-tables name"));
            }
            doc.arrays
                .entry(name.to_string())
                .or_default()
                .push(Table::new());
            target = Target::ArrayItem(name.to_string());
            continue;
        }
        if let Some(inner) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            let name = inner.trim();
            if name.is_empty() {
                return Err(err(line_no, "empty table name"));
            }
            doc.tables.entry(name.to_string()).or_default();
            target = Target::Table(name.to_string());
            continue;
        }
        let (key, value_text) = line
            .split_once('=')
            .ok_or_else(|| err(line_no, "expected `key = value`"))?;
        let key = key.trim();
        if key.is_empty() || key.contains('.') || key.contains(' ') {
            return Err(err(
                line_no,
                "unsupported key (dotted or quoted keys are not allowed)",
            ));
        }
        let value = parse_value(value_text.trim(), line_no)?;
        let table = match &target {
            Target::Root => &mut doc.root,
            Target::Table(name) => doc.tables.get_mut(name).expect("table exists"),
            Target::ArrayItem(name) => doc
                .arrays
                .get_mut(name)
                .and_then(|v| v.last_mut())
                .expect("array item exists"),
        };
        if table.insert(key.to_string(), value).is_some() {
            return Err(err(line_no, &format!("duplicate key `{key}`")));
        }
    }
    Ok(doc)
}

fn err(line: usize, message: &str) -> TomlError {
    TomlError {
        line,
        message: message.to_string(),
    }
}

/// Remove a trailing `# comment`, honouring `#` inside strings.
fn strip_comment(line: &str) -> &str {
    let mut in_str = false;
    let mut escaped = false;
    for (i, c) in line.char_indices() {
        match c {
            '\\' if in_str => escaped = !escaped,
            '"' if !escaped => in_str = !in_str,
            '#' if !in_str => return &line[..i],
            _ => escaped = false,
        }
    }
    line
}

fn parse_value(text: &str, line: usize) -> Result<Value, TomlError> {
    if let Some(rest) = text.strip_prefix('"') {
        let (s, remainder) = parse_string(rest, line)?;
        if !remainder.trim().is_empty() {
            return Err(err(line, "trailing characters after string"));
        }
        return Ok(Value::Str(s));
    }
    if text == "true" {
        return Ok(Value::Bool(true));
    }
    if text == "false" {
        return Ok(Value::Bool(false));
    }
    if let Some(inner) = text.strip_prefix('[').and_then(|t| t.strip_suffix(']')) {
        return parse_array(inner, line);
    }
    parse_int(text, line).map(Value::Int)
}

fn parse_int(text: &str, line: usize) -> Result<i128, TomlError> {
    let cleaned: String = text.chars().filter(|c| *c != '_').collect();
    if cleaned.is_empty() || cleaned.contains('.') {
        return Err(err(
            line,
            &format!("unsupported value `{text}` (floats and dates are not allowed)"),
        ));
    }
    cleaned
        .parse::<i128>()
        .map_err(|_| err(line, &format!("unsupported value `{text}`")))
}

fn parse_string(rest: &str, line: usize) -> Result<(String, &str), TomlError> {
    let mut out = String::new();
    let mut chars = rest.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '"' => return Ok((out, &rest[i + 1..])),
            '\\' => {
                let (_, e) = chars.next().ok_or_else(|| err(line, "dangling escape"))?;
                out.push(match e {
                    'n' => '\n',
                    't' => '\t',
                    '"' => '"',
                    '\\' => '\\',
                    other => return Err(err(line, &format!("unsupported escape \\{other}"))),
                });
            }
            c => out.push(c),
        }
    }
    Err(err(line, "unterminated string"))
}

fn parse_array(inner: &str, line: usize) -> Result<Value, TomlError> {
    let mut items = Vec::new();
    let mut rest = inner.trim();
    while !rest.is_empty() {
        if let Some(after_quote) = rest.strip_prefix('"') {
            let (s, remainder) = parse_string(after_quote, line)?;
            items.push(Value::Str(s));
            rest = remainder.trim_start();
        } else {
            let end = rest.find(',').unwrap_or(rest.len());
            let token = rest[..end].trim();
            if token.is_empty() {
                return Err(err(line, "empty array element"));
            }
            items.push(parse_value(token, line)?);
            rest = &rest[end..];
        }
        rest = rest.trim_start();
        if let Some(r) = rest.strip_prefix(',') {
            rest = r.trim_start();
        } else if !rest.is_empty() {
            return Err(err(line, "expected `,` between array elements"));
        }
    }
    Ok(Value::Array(items))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_registry_subset() {
        let doc = parse(
            r#"
# comment
schema_version = 1
[registry]
name = "exit codes"   # trailing comment
flags = [1, 2, 3]
words = ["a", "b # not a comment", "c"]
ok = true
[[row]]
code = 0
name = "success"
[[row]]
code = -2_000
name = "neg"
"#,
        )
        .unwrap();
        assert_eq!(doc.root["schema_version"], Value::Int(1));
        assert_eq!(doc.tables["registry"]["name"].as_str(), Some("exit codes"));
        assert_eq!(doc.tables["registry"]["flags"].as_array().unwrap().len(), 3);
        assert_eq!(
            doc.tables["registry"]["words"].as_array().unwrap()[1].as_str(),
            Some("b # not a comment")
        );
        assert_eq!(doc.tables["registry"]["ok"].as_bool(), Some(true));
        assert_eq!(doc.arrays["row"].len(), 2);
        assert_eq!(doc.arrays["row"][1]["code"].as_int(), Some(-2000));
    }

    #[test]
    fn refuses_what_it_does_not_support_with_a_line_number() {
        assert_eq!(parse("x = 1.5").unwrap_err().line, 1);
        assert_eq!(parse("a.b = 1").unwrap_err().line, 1);
        assert_eq!(parse("ok = 1\nx = \"unterminated").unwrap_err().line, 2);
        assert_eq!(parse("k = 1\nk = 2").unwrap_err().line, 2);
        assert!(parse("k = [1,]").is_ok(), "a trailing comma is legal TOML");
        assert!(parse("k = [1,,2]").is_err());
        assert!(parse("k = [,1]").is_err());
        assert!(parse("[t]\n[[t]]\n").is_ok());
    }
}
