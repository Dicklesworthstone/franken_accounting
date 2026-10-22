//! The profile's lexer. It mirrors the substrate's lexical rules exactly
//! (fgdb-gql `graph_text::literal`): `'`, `"` and backtick spans close on
//! their delimiter and double it to escape, `//` and `/* */` are comments,
//! and words are `[A-Za-z_][A-Za-z0-9_]*`. A token records its bracket depth
//! and its innermost enclosing open bracket, so clause analysis can tell the
//! statement's root from a pattern, a map or a call's arguments.

use crate::{Law, Refusal};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Word,
    /// A whole quoted span, delimiters included.
    Quoted,
    Param,
    Digits,
    /// Digits with a fraction or an exponent: the native grammar reads it
    /// as a float.
    Float,
    Punct,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Token {
    pub kind: Kind,
    pub start: usize,
    pub end: usize,
    /// Open brackets enclosing the token; a bracket itself counts the level
    /// it opens or closes from.
    pub depth: u32,
    /// The innermost enclosing open bracket, as a token index.
    pub parent: Option<usize>,
}

pub(crate) struct Lexed<'a> {
    pub text: &'a str,
    pub tokens: Vec<Token>,
}

impl Lexed<'_> {
    pub fn str(&self, i: usize) -> &str {
        self.tokens
            .get(i)
            .map_or("", |t| &self.text[t.start..t.end])
    }

    pub fn kind(&self, i: usize) -> Option<Kind> {
        self.tokens.get(i).map(|t| t.kind)
    }

    pub fn word(&self, i: usize, expected: &str) -> bool {
        self.kind(i) == Some(Kind::Word) && self.str(i).eq_ignore_ascii_case(expected)
    }

    pub fn punct(&self, i: usize, expected: char) -> bool {
        self.kind(i) == Some(Kind::Punct) && self.str(i).starts_with(expected)
    }

    pub fn root(&self, i: usize) -> bool {
        self.tokens.get(i).is_some_and(|t| t.depth == 0)
    }

    /// Token `j` starts where token `i` ends: no whitespace or comment
    /// between them.
    pub fn adjacent(&self, i: usize, j: usize) -> bool {
        match (self.tokens.get(i), self.tokens.get(j)) {
            (Some(a), Some(b)) => a.end == b.start,
            _ => false,
        }
    }

    /// A quoted span's text with its doubled delimiters decoded.
    pub fn unquoted(&self, i: usize) -> String {
        let raw = self.str(i);
        let Some(delimiter) = raw.chars().next() else {
            return String::new();
        };
        let body = raw.get(1..raw.len().saturating_sub(1)).unwrap_or_default();
        let doubled: String = [delimiter, delimiter].iter().collect();
        body.replace(&doubled, &delimiter.to_string())
    }
}

fn refused(at: usize, message: &str) -> Refusal {
    Refusal::new(
        Law::Profile,
        at,
        message,
        "close the span; a quote inside a literal is written twice ('it''s')",
    )
}

pub(crate) fn lex(text: &str) -> Result<Lexed<'_>, Refusal> {
    let bytes = text.as_bytes();
    let mut tokens: Vec<Token> = Vec::new();
    let mut open: Vec<usize> = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let ch = text[at..].chars().next().unwrap_or(' ');
        if ch.is_whitespace() {
            at += ch.len_utf8();
            continue;
        }
        let rest = &bytes[at..];
        if rest.starts_with(b"//") {
            at = text[at..].find('\n').map_or(text.len(), |line| at + line);
            continue;
        }
        if rest.starts_with(b"/*") {
            at = text[at + 2..]
                .find("*/")
                .map(|close| at + 2 + close + 2)
                .ok_or_else(|| refused(at, "a block comment is never closed"))?;
            continue;
        }
        let start = at;
        let kind = match bytes[at] {
            b'\'' | b'"' | b'`' => {
                let delimiter = bytes[at];
                let mut end = at + 1;
                loop {
                    match bytes.get(end) {
                        None => return Err(refused(at, "a quoted span is never closed")),
                        Some(&b) if b == delimiter => {
                            end += 1;
                            if bytes.get(end) != Some(&delimiter) {
                                break;
                            }
                            end += 1;
                        }
                        Some(_) => end += 1,
                    }
                }
                at = end;
                Kind::Quoted
            }
            b if b.is_ascii_alphabetic() || b == b'_' => {
                at = word_end(bytes, at + 1);
                Kind::Word
            }
            b'$' if bytes
                .get(at + 1)
                .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_') =>
            {
                at = word_end(bytes, at + 2);
                Kind::Param
            }
            b if b.is_ascii_digit() => {
                at = digits_end(bytes, at);
                let fraction = bytes.get(at) == Some(&b'.')
                    && bytes.get(at + 1).is_some_and(u8::is_ascii_digit);
                if fraction {
                    at = digits_end(bytes, at + 1);
                }
                let exponent = matches!(bytes.get(at), Some(b'e' | b'E'))
                    && match bytes.get(at + 1) {
                        Some(b'+' | b'-') => bytes.get(at + 2).is_some_and(u8::is_ascii_digit),
                        Some(b) => b.is_ascii_digit(),
                        None => false,
                    };
                if exponent {
                    let sign = usize::from(matches!(bytes.get(at + 1), Some(b'+' | b'-')));
                    at = digits_end(bytes, at + 1 + sign);
                }
                if fraction || exponent {
                    Kind::Float
                } else {
                    Kind::Digits
                }
            }
            _ => {
                at += ch.len_utf8();
                Kind::Punct
            }
        };
        let index = tokens.len();
        let token = match (kind, &text[start..at]) {
            (Kind::Punct, "(" | "[" | "{") => {
                let token = Token {
                    kind,
                    start,
                    end: at,
                    depth: u32::try_from(open.len()).unwrap_or(u32::MAX),
                    parent: open.last().copied(),
                };
                open.push(index);
                token
            }
            (Kind::Punct, ")" | "]" | "}") => {
                open.pop();
                Token {
                    kind,
                    start,
                    end: at,
                    depth: u32::try_from(open.len()).unwrap_or(u32::MAX),
                    parent: open.last().copied(),
                }
            }
            _ => Token {
                kind,
                start,
                end: at,
                depth: u32::try_from(open.len()).unwrap_or(u32::MAX),
                parent: open.last().copied(),
            },
        };
        tokens.push(token);
    }
    Ok(Lexed { text, tokens })
}

fn word_end(bytes: &[u8], mut at: usize) -> usize {
    while bytes
        .get(at)
        .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
    {
        at += 1;
    }
    at
}

fn digits_end(bytes: &[u8], mut at: usize) -> usize {
    while bytes.get(at).is_some_and(u8::is_ascii_digit) {
        at += 1;
    }
    at
}
