//! Tokens of a rule's source text, each with the line and column it starts at.

use crate::CanonError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Token {
    Ident(String),
    Str(String),
    Int(u64),
    Symbol(char),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Spanned {
    pub token: Token,
    pub line: u32,
    pub column: u32,
}

/// Rule sources are small; this bounds the work a hostile one can ask for.
pub const MAX_SOURCE_BYTES: usize = 64 * 1024;

pub(crate) fn tokens(source: &str) -> Result<Vec<Spanned>, CanonError> {
    if source.len() > MAX_SOURCE_BYTES {
        return Err(CanonError::new(
            1,
            1,
            format!("a rule source is at most {MAX_SOURCE_BYTES} bytes"),
        ));
    }
    let chars: Vec<char> = source.chars().collect();
    let mut out = Vec::new();
    let (mut i, mut line, mut column) = (0usize, 1u32, 1u32);
    while i < chars.len() {
        let c = chars[i];
        let (start_line, start_column) = (line, column);
        let advance = |i: &mut usize, line: &mut u32, column: &mut u32| {
            if chars[*i] == '\n' {
                *line += 1;
                *column = 1;
            } else {
                *column += 1;
            }
            *i += 1;
        };
        if c.is_whitespace() {
            advance(&mut i, &mut line, &mut column);
            continue;
        }
        if c == '#' || (c == '/' && chars.get(i + 1) == Some(&'/')) {
            while i < chars.len() && chars[i] != '\n' {
                advance(&mut i, &mut line, &mut column);
            }
            continue;
        }
        let token = if c.is_ascii_alphabetic() || c == '_' {
            let mut text = String::new();
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                text.push(chars[i]);
                advance(&mut i, &mut line, &mut column);
            }
            Token::Ident(text)
        } else if c.is_ascii_digit() {
            let mut value: u64 = 0;
            while i < chars.len() && chars[i].is_ascii_digit() {
                let digit = u64::from(chars[i] as u8 - b'0');
                value = value
                    .checked_mul(10)
                    .and_then(|v| v.checked_add(digit))
                    .ok_or_else(|| {
                        CanonError::new(start_line, start_column, "integer literal overflows u64")
                    })?;
                advance(&mut i, &mut line, &mut column);
            }
            Token::Int(value)
        } else if c == '"' {
            advance(&mut i, &mut line, &mut column);
            let mut text = String::new();
            loop {
                match chars.get(i) {
                    None | Some('\n') => {
                        return Err(CanonError::new(
                            start_line,
                            start_column,
                            "unterminated string literal",
                        ));
                    }
                    Some('"') => {
                        advance(&mut i, &mut line, &mut column);
                        break;
                    }
                    Some('\\') => {
                        return Err(CanonError::new(
                            line,
                            column,
                            "string literals take no escapes",
                        ));
                    }
                    Some(ch) => {
                        text.push(*ch);
                        advance(&mut i, &mut line, &mut column);
                    }
                }
            }
            Token::Str(text)
        } else if "{}(),.:=+-*/".contains(c) {
            advance(&mut i, &mut line, &mut column);
            Token::Symbol(c)
        } else {
            return Err(CanonError::new(
                line,
                column,
                format!("unexpected character `{c}`"),
            ));
        };
        out.push(Spanned {
            token,
            line: start_line,
            column: start_column,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_carry_positions_and_comments_vanish() {
        let toks = tokens("rule a v1 # note\n  debit \"1200\" x * 7/100").unwrap();
        let kinds: Vec<&Token> = toks.iter().map(|t| &t.token).collect();
        assert_eq!(
            kinds,
            [
                &Token::Ident("rule".into()),
                &Token::Ident("a".into()),
                &Token::Ident("v1".into()),
                &Token::Ident("debit".into()),
                &Token::Str("1200".into()),
                &Token::Ident("x".into()),
                &Token::Symbol('*'),
                &Token::Int(7),
                &Token::Symbol('/'),
                &Token::Int(100),
            ]
        );
        assert_eq!((toks[3].line, toks[3].column), (2, 3));
    }

    #[test]
    fn malformed_text_is_refused_with_its_position() {
        for (source, line, column) in [
            ("\"open", 1, 1),
            ("x\n  @", 2, 3),
            ("99999999999999999999", 1, 1),
            ("\"a\\b\"", 1, 3),
        ] {
            let error = tokens(source).unwrap_err();
            assert_eq!(
                (error.line, error.column),
                (line, column),
                "{source}: {error}"
            );
        }
    }
}
