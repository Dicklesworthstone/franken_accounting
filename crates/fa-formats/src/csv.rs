//! Lossless comma-separated logical records shared by GL readers.
//!
//! A record is consumed on demand, so a multiline field is never mistaken for
//! another posting and parsing does not retain a second copy of every row.

use crate::FormatError;

pub(crate) enum CsvRecord<'a> {
    Comment(&'a str),
    Row { line: usize, fields: Vec<String> },
}

pub(crate) struct CsvRecords<'a> {
    source: &'a str,
    offset: usize,
    line: usize,
    format: &'static str,
    failed: bool,
    legacy: bool,
    preamble: bool,
}

impl<'a> CsvRecords<'a> {
    pub(crate) fn new(source: &'a str, format: &'static str) -> Self {
        Self {
            source: source.strip_prefix('\u{feff}').unwrap_or(source),
            offset: 0,
            line: 1,
            format,
            failed: false,
            legacy: false,
            preamble: true,
        }
    }

    /// Vendor/generic sources recognize comments only before their header.
    /// After it, an unquoted `#` belongs to the original source identity.
    /// Keep historical vendor tolerance of padding outside quoted fields.
    pub(crate) fn legacy(source: &'a str, format: &'static str) -> Self {
        Self {
            legacy: true,
            ..Self::new(source, format)
        }
    }

    fn newline(&mut self, ch: char) {
        if ch == '\r' && self.source[self.offset..].starts_with('\n') {
            self.offset += 1;
        }
        self.line += 1;
    }

    fn refuse(&mut self, line: usize, detail: &str) -> FormatError {
        self.failed = true;
        FormatError::Parse {
            format: self.format,
            detail: format!("line {line}: {detail}"),
        }
    }
}

impl<'a> Iterator for CsvRecords<'a> {
    type Item = Result<CsvRecord<'a>, FormatError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        // Comments are recognized only between records, never inside a quoted
        // field. A quoted first field beginning with '#' is ordinary data.
        while self.offset < self.source.len() {
            let rest = &self.source[self.offset..];
            let end = rest.find(['\r', '\n']).unwrap_or(rest.len());
            let first_line = &rest[..end];
            let comment =
                first_line.trim_start().starts_with('#') && (!self.legacy || self.preamble);
            if !first_line.trim().is_empty() && !comment {
                break;
            }
            self.offset += end;
            if let Some(ch) = self.source[self.offset..].chars().next() {
                self.offset += ch.len_utf8();
                self.newline(ch);
            }
            if !first_line.trim().is_empty() {
                return Some(Ok(CsvRecord::Comment(first_line.trim())));
            }
        }
        if self.offset == self.source.len() {
            return None;
        }

        let start_line = self.line;
        self.preamble = false;
        let mut fields = Vec::new();
        let mut field = String::new();
        let mut quoted = false;
        let mut closed_quote = false;
        while let Some(ch) = self.source[self.offset..].chars().next() {
            self.offset += ch.len_utf8();
            if quoted {
                if ch == '"' {
                    if self.source[self.offset..].starts_with('"') {
                        self.offset += 1;
                        field.push('"');
                    } else {
                        quoted = false;
                        closed_quote = true;
                    }
                } else {
                    field.push(ch);
                    if ch == '\r' {
                        if self.source[self.offset..].starts_with('\n') {
                            self.offset += 1;
                            field.push('\n');
                        }
                        self.line += 1;
                    } else if ch == '\n' {
                        self.line += 1;
                    }
                }
                continue;
            }
            match ch {
                '"' if (field.is_empty() || self.legacy && field.trim().is_empty())
                    && !closed_quote =>
                {
                    field.clear();
                    quoted = true;
                }
                ',' => {
                    fields.push(core::mem::take(&mut field));
                    closed_quote = false;
                }
                '\r' | '\n' => {
                    self.newline(ch);
                    fields.push(field);
                    return Some(Ok(CsvRecord::Row {
                        line: start_line,
                        fields,
                    }));
                }
                '"' => {
                    return Some(Err(
                        self.refuse(start_line, "unexpected quote in an unquoted CSV field")
                    ));
                }
                ' ' | '\t' if closed_quote && self.legacy => {}
                _ if closed_quote => {
                    return Some(Err(
                        self.refuse(start_line, "unexpected text after a quoted CSV field")
                    ));
                }
                _ => field.push(ch),
            }
        }
        if quoted {
            return Some(Err(self.refuse(start_line, "unterminated quoted CSV field")));
        }
        fields.push(field);
        Some(Ok(CsvRecord::Row {
            line: start_line,
            fields,
        }))
    }
}

pub(crate) fn quote_field(value: &str) -> String {
    if value.contains([',', '"', '\r', '\n']) || value.starts_with('#') || value.trim() != value {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::{CsvRecord, CsvRecords, quote_field};

    #[test]
    fn logical_records_keep_multiline_text_quotes_and_physical_line_numbers() {
        let source = "\u{feff}# source\r\n\r\nid,memo,tail\r\nA,\"one, \"\"two\"\"\r\n# still the memo\",\r\nB,plain,x";
        let records = CsvRecords::new(source, "test")
            .map(|record| record.expect("well-formed CSV"))
            .filter_map(|record| match record {
                CsvRecord::Comment(_) => None,
                CsvRecord::Row { line, fields } => Some((line, fields)),
            })
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].0, 3);
        assert_eq!(records[1].0, 4);
        assert_eq!(records[2].0, 6);
        assert_eq!(records[1].1, ["A", "one, \"two\"\r\n# still the memo", ""]);
    }

    #[test]
    fn malformed_quotes_are_refused_and_the_iterator_stops() {
        for source in ["a,\"unclosed", "a,b\"c", "a,\"b\"trailing", "a,\"b\" \n"] {
            let mut records = CsvRecords::new(source, "test");
            assert!(records.next().unwrap().is_err(), "{source:?}");
            assert!(records.next().is_none());
        }
    }

    #[test]
    fn quoted_fields_round_trip_without_text_sanitization() {
        for text in [
            "",
            "  text  ",
            "a,b",
            "\"quoted\"",
            "\r\n",
            "# data",
            "café",
        ] {
            let encoded = format!("{},end\n", quote_field(text));
            let CsvRecord::Row { fields, .. } =
                CsvRecords::new(&encoded, "test").next().unwrap().unwrap()
            else {
                panic!("quoted data cannot become a comment");
            };
            assert_eq!(fields, [text, "end"]);
        }
    }

    #[test]
    fn legacy_comments_end_at_the_header_and_quote_padding_does_not_trim_text() {
        let source = "  # preamble, unmatched \"\r\nid,memo\r\n#OTHER,  \"  retained  \" \t\r\n \" A\" ,\"second\"";
        let rows = CsvRecords::legacy(source, "test")
            .filter_map(|record| match record.unwrap() {
                CsvRecord::Comment(_) => None,
                CsvRecord::Row { fields, .. } => Some(fields),
            })
            .collect::<Vec<_>>();
        assert_eq!(
            rows,
            [
                vec!["id", "memo"],
                vec!["#OTHER", "  retained  "],
                vec![" A", "second"],
            ]
        );
    }
}
