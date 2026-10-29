//! Typed reads of one TOML table, tracking which keys were read so that an
//! unread key is refused as `UnknownField` (a misspelled field is never
//! silently ignored).

use std::collections::BTreeSet;

use fa_registry::toml::{Table, Value};

use super::error::{LoadError, LoadErrorKind};

pub(crate) struct Row<'a> {
    file: &'a str,
    line: Option<usize>,
    id: Option<String>,
    table: &'a Table,
    used: BTreeSet<String>,
}

impl<'a> Row<'a> {
    pub(crate) fn new(file: &'a str, line: Option<usize>, table: &'a Table) -> Self {
        let id = table.get("id").and_then(Value::as_str).map(str::to_string);
        Self {
            file,
            line,
            id,
            table,
            used: BTreeSet::new(),
        }
    }

    pub(crate) fn with_id(mut self, id: Option<String>) -> Self {
        if id.is_some() {
            self.id = id;
        }
        self
    }

    pub(crate) fn line(&self) -> Option<usize> {
        self.line
    }

    pub(crate) fn err(&self, kind: LoadErrorKind, detail: impl Into<String>) -> LoadError {
        LoadError {
            file: self.file.to_string(),
            line: self.line,
            kind,
            row: self.id.clone(),
            detail: detail.into(),
        }
    }

    pub(crate) fn has(&self, key: &str) -> bool {
        self.table.contains_key(key)
    }

    fn take(&mut self, key: &str) -> Option<&'a Value> {
        self.used.insert(key.to_string());
        let table: &'a Table = self.table;
        table.get(key)
    }

    fn missing(&mut self, key: &str, errs: &mut Vec<LoadError>) {
        self.used.insert(key.to_string());
        errs.push(self.err(LoadErrorKind::MissingField, format!("`{key}` is required")));
    }

    pub(crate) fn opt_str(&mut self, key: &str, errs: &mut Vec<LoadError>) -> Option<String> {
        match self.take(key) {
            None => None,
            Some(Value::Str(s)) => Some(s.clone()),
            Some(_) => {
                errs.push(self.err(
                    LoadErrorKind::WrongType,
                    format!("`{key}` must be a string"),
                ));
                None
            }
        }
    }

    pub(crate) fn req_str(&mut self, key: &str, errs: &mut Vec<LoadError>) -> String {
        if !self.has(key) {
            self.missing(key, errs);
            return String::new();
        }
        self.opt_str(key, errs).unwrap_or_default()
    }

    pub(crate) fn opt_bool(&mut self, key: &str, errs: &mut Vec<LoadError>) -> Option<bool> {
        match self.take(key) {
            None => None,
            Some(Value::Bool(b)) => Some(*b),
            Some(_) => {
                errs.push(self.err(
                    LoadErrorKind::WrongType,
                    format!("`{key}` must be a boolean"),
                ));
                None
            }
        }
    }

    pub(crate) fn req_bool(&mut self, key: &str, errs: &mut Vec<LoadError>) -> bool {
        if !self.has(key) {
            self.missing(key, errs);
            return false;
        }
        self.opt_bool(key, errs).unwrap_or_default()
    }

    pub(crate) fn opt_int(&mut self, key: &str, errs: &mut Vec<LoadError>) -> Option<i128> {
        match self.take(key) {
            None => None,
            Some(Value::Int(i)) => Some(*i),
            Some(_) => {
                errs.push(self.err(
                    LoadErrorKind::WrongType,
                    format!("`{key}` must be an integer"),
                ));
                None
            }
        }
    }

    pub(crate) fn req_int(&mut self, key: &str, errs: &mut Vec<LoadError>) -> i128 {
        if !self.has(key) {
            self.missing(key, errs);
            return 0;
        }
        self.opt_int(key, errs).unwrap_or_default()
    }

    /// A one-line array of strings.
    pub(crate) fn opt_strs(&mut self, key: &str, errs: &mut Vec<LoadError>) -> Option<Vec<String>> {
        match self.take(key) {
            None => None,
            Some(Value::Array(items)) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    match item {
                        Value::Str(s) => out.push(s.clone()),
                        _ => {
                            errs.push(self.err(
                                LoadErrorKind::WrongType,
                                format!("`{key}` must be an array of strings"),
                            ));
                            return None;
                        }
                    }
                }
                Some(out)
            }
            Some(_) => {
                errs.push(self.err(
                    LoadErrorKind::WrongType,
                    format!("`{key}` must be an array"),
                ));
                None
            }
        }
    }

    pub(crate) fn req_strs(&mut self, key: &str, errs: &mut Vec<LoadError>) -> Vec<String> {
        if !self.has(key) {
            self.missing(key, errs);
            return Vec::new();
        }
        self.opt_strs(key, errs).unwrap_or_default()
    }

    /// A one-line array of scalars, each rendered as text (`params`).
    pub(crate) fn opt_scalars(
        &mut self,
        key: &str,
        errs: &mut Vec<LoadError>,
    ) -> Option<Vec<Value>> {
        match self.take(key) {
            None => None,
            Some(Value::Array(items)) => {
                if items.iter().any(|v| matches!(v, Value::Array(_))) {
                    errs.push(self.err(LoadErrorKind::WrongType, format!("`{key}` must be flat")));
                    return None;
                }
                Some(items.clone())
            }
            Some(_) => {
                errs.push(self.err(
                    LoadErrorKind::WrongType,
                    format!("`{key}` must be an array"),
                ));
                None
            }
        }
    }

    /// Refuses every key the reader never asked for, unless `allowed`.
    pub(crate) fn finish(&self, allowed: &[&str], context: &str, errs: &mut Vec<LoadError>) {
        for key in self.table.keys() {
            if !self.used.contains(key) && !allowed.contains(&key.as_str()) {
                errs.push(self.err(
                    LoadErrorKind::UnknownField,
                    format!("unknown field `{key}`{context}"),
                ));
            }
        }
    }
}

/// Whether `s` is 64 lower-case hex characters.
#[must_use]
pub(crate) fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Whether `s` is a `YYYY-MM-DD` calendar date (proleptic Gregorian, years
/// 1000–9999).
#[must_use]
pub(crate) fn is_date(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return false;
    }
    let digits = |r: core::ops::Range<usize>| -> Option<u32> {
        let part = s.get(r)?;
        if part.bytes().all(|c| c.is_ascii_digit()) {
            part.parse().ok()
        } else {
            None
        }
    };
    let (Some(y), Some(m), Some(d)) = (digits(0..4), digits(5..7), digits(8..10)) else {
        return false;
    };
    if y < 1000 || !(1..=12).contains(&m) || d == 0 {
        return false;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let days = match m {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    d <= days
}

/// Whether `s` is a `month_day_literal` result: ISO 8601's year-less
/// `--MM-DD` (a day of some year, so `--02-29` is one), then optionally one
/// space and a weekday name.
#[must_use]
pub(crate) fn is_month_day(s: &str) -> bool {
    let (md, weekday) = s.split_once(' ').map_or((s, None), |(md, w)| (md, Some(w)));
    md.len() == 7
        && md.starts_with("--")
        && is_date(&format!("2000{}", &md[1..]))
        && weekday.is_none_or(|w| super::date::WEEKDAYS.contains(&w))
}

/// Whether `s` is an integer string (optional leading `-`, digits only).
#[must_use]
pub(crate) fn is_integer(s: &str) -> bool {
    let digits = s.strip_prefix('-').unwrap_or(s);
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_hex_and_integers() {
        assert!(is_date("2000-02-29"));
        assert!(!is_date("1900-02-29"), "1900 is not a leap year");
        assert!(!is_date("2001-13-01"));
        assert!(!is_date("2001-1-01"));
        assert!(is_sha256_hex(&"a".repeat(64)));
        assert!(!is_sha256_hex(&"A".repeat(64)), "upper case is refused");
        assert!(is_integer("-139"));
        assert!(!is_integer("13.9"));
        assert!(!is_integer("-"));
    }
}
