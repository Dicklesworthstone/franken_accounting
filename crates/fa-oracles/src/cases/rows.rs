//! Line numbers for semantic errors.
//!
//! `fa_registry::toml::Document` keeps no line numbers
//! (`crates/fa-registry/src/toml.rs:56-60`): the parser's own `TomlError`
//! covers syntax errors, and every semantic error (a dangling key, two
//! provenance kinds) takes its line from these helpers.

/// The 1-based line of the `index`-th (0-based) `[[array]]` header in
/// `text`, if there is one.
#[must_use]
pub fn row_line(text: &str, array: &str, index: usize) -> Option<usize> {
    let header = format!("[[{array}]]");
    text.lines()
        .enumerate()
        .filter(|(_, l)| strip_comment(l).trim() == header)
        .nth(index)
        .map(|(n, _)| n + 1)
}

/// The 1-based line of a root key (`key = …` before the first table or
/// array header), if present.
#[must_use]
pub fn root_key_line(text: &str, key: &str) -> Option<usize> {
    for (n, raw) in text.lines().enumerate() {
        let line = strip_comment(raw).trim();
        if line.starts_with('[') {
            return None;
        }
        if let Some((k, _)) = line.split_once('=')
            && k.trim() == key
        {
            return Some(n + 1);
        }
    }
    None
}

/// The 1-based line of a key inside the `index`-th `[[array]]` row, or the
/// row's header line when the key is not there.
#[must_use]
pub fn row_key_line(text: &str, array: &str, index: usize, key: &str) -> Option<usize> {
    let start = row_line(text, array, index)?;
    for (n, raw) in text.lines().enumerate().skip(start) {
        let line = strip_comment(raw).trim();
        if line.starts_with('[') {
            break;
        }
        if let Some((k, _)) = line.split_once('=')
            && k.trim() == key
        {
            return Some(n + 1);
        }
    }
    Some(start)
}

/// The text before an unquoted `#`.
fn strip_comment(line: &str) -> &str {
    let mut in_string = false;
    let mut after_backslash = false;
    for (i, c) in line.char_indices() {
        if in_string {
            if c == '"' && !after_backslash {
                in_string = false;
            }
            after_backslash = c == '\\' && !after_backslash;
        } else if c == '"' {
            in_string = true;
            after_backslash = false;
        } else if c == '#' {
            return &line[..i];
        }
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEXT: &str = "# header\nschema = 1\n\n[[fact]] # first\nid = \"F1\"\n\n[[fact]]\nid = \"F2\"\nnote = \"a # in a string\"\n";

    #[test]
    fn row_line_finds_each_header() {
        assert_eq!(row_line(TEXT, "fact", 0), Some(4));
        assert_eq!(row_line(TEXT, "fact", 1), Some(7));
        assert_eq!(row_line(TEXT, "fact", 2), None);
        assert_eq!(row_line(TEXT, "value", 0), None);
    }

    #[test]
    fn root_and_row_keys_have_lines() {
        assert_eq!(root_key_line(TEXT, "schema"), Some(2));
        assert_eq!(root_key_line(TEXT, "id"), None, "id is not a root key");
        assert_eq!(row_key_line(TEXT, "fact", 1, "note"), Some(9));
        assert_eq!(
            row_key_line(TEXT, "fact", 1, "missing"),
            Some(7),
            "falls back to the header"
        );
    }
}
