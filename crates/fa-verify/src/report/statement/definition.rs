//! Closed definition language: account partitions and acyclic exact formulas.
use super::super::{ReportError, failed, text};
use crate::codec::Reader;
use std::collections::BTreeSet;

pub(super) const MAX_BYTES: usize = 64 * 1024;
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Source {
    Accounts {
        types: Vec<u8>,
        credit: bool,
    },
    Formula {
        add: Vec<String>,
        subtract: Vec<String>,
    },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Line {
    pub code: String,
    pub label: String,
    pub source: Source,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Definition {
    pub bytes: Vec<u8>,
    pub name: String,
    pub version: u32,
    pub activity: bool,
    pub lines: Vec<Line>,
    pub checks: Vec<String>,
}
fn invalid(s: impl Into<String>) -> ReportError {
    failed("statement_definition", s)
}
fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}
fn label(s: &str) -> bool {
    !s.trim().is_empty() && s.len() <= 256
}
fn names(r: &mut Reader<'_>) -> Result<Vec<String>, ReportError> {
    let n = r.count(64, 4, "definition.names")?;
    let mut names = Vec::with_capacity(n);
    for _ in 0..n {
        let name = text(r, 64, "definition.name")?.to_string();
        if !identifier(&name) {
            return Err(invalid("invalid definition operand identifier"));
        }
        names.push(name);
    }
    if !names.windows(2).all(|p| p[0] < p[1]) {
        return Err(invalid("definition operands must be sorted and unique"));
    }
    Ok(names)
}
impl Definition {
    pub fn covered(&self, tag: u8) -> bool {
        if self.activity {
            matches!(tag, 4 | 5)
        } else {
            (1..=5).contains(&tag)
        }
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, ReportError> {
        if bytes.len() > MAX_BYTES {
            return Err(invalid("definition exceeds 64 KiB"));
        }
        let mut r = Reader::new(bytes);
        if &r.fixed::<17>("definition.magic")? != b"FA-STATEMENT-DEF\0"
            || r.u16("definition.major")? != 1
            || r.u16("definition.minor")? != 0
        {
            return Err(invalid("unsupported statement definition format"));
        }
        let name = text(&mut r, 64, "definition.name")?.to_string();
        let title = text(&mut r, 256, "definition.title")?;
        let version = r.u32("definition.version")?;
        let activity = match r.u8("definition.kind")? {
            0 => false,
            1 => true,
            _ => return Err(invalid("unknown statement accounting basis")),
        };
        if !identifier(&name) || !label(title) || version == 0 {
            return Err(invalid("definition name, title or version is invalid"));
        }
        let n = r.count(64, 10, "definition.lines")?;
        if n == 0 {
            return Err(invalid("a statement requires at least one line"));
        }
        let mut earlier = BTreeSet::new();
        let mut lines = Vec::with_capacity(n);
        for _ in 0..n {
            let code = text(&mut r, 64, "line.code")?.to_string();
            let name = text(&mut r, 256, "line.label")?.to_string();
            if !identifier(&code) || !label(&name) || earlier.contains(&code) {
                return Err(invalid("line code or label is invalid or repeated"));
            }
            let source = match r.u8("line.source")? {
                0 => {
                    let count = r.count(5, 1, "line.types")?;
                    let mut types = Vec::with_capacity(count);
                    for _ in 0..count {
                        types.push(r.u8("line.type")?);
                    }
                    if types.is_empty()
                        || !types.windows(2).all(|p| p[0] < p[1])
                        || types.iter().any(|tag| {
                            if activity {
                                !matches!(tag, 4 | 5)
                            } else {
                                !(1..=5).contains(tag)
                            }
                        })
                    {
                        return Err(invalid(
                            "account line must map sorted, unique, covered types",
                        ));
                    }
                    let credit = match r.u8("line.sign")? {
                        0 => false,
                        1 => true,
                        _ => return Err(invalid("unknown account-line sign")),
                    };
                    Source::Accounts { types, credit }
                }
                1 => {
                    let add = names(&mut r)?;
                    let subtract = names(&mut r)?;
                    let mut used = BTreeSet::new();
                    if add.is_empty() && subtract.is_empty() {
                        return Err(invalid("formula has no operands"));
                    }
                    for operand in add.iter().chain(&subtract) {
                        if !earlier.contains(operand) || !used.insert(operand) {
                            return Err(invalid(
                                "formula repeats an operand or names a forward/cyclic input",
                            ));
                        }
                    }
                    Source::Formula { add, subtract }
                }
                _ => return Err(invalid("unknown statement line source")),
            };
            earlier.insert(code.clone());
            lines.push(Line {
                code,
                label: name,
                source,
            });
        }
        let checks = names(&mut r)?;
        if (!activity && checks.is_empty())
            || checks.iter().any(|code| {
                !lines
                    .iter()
                    .any(|line| line.code == *code && matches!(line.source, Source::Formula { .. }))
            })
        {
            return Err(invalid(
                "statement identities must name formulas; stock requires an identity",
            ));
        }
        r.finish("statement definition")?;
        Ok(Self {
            bytes: bytes.to_vec(),
            name,
            version,
            activity,
            lines,
            checks,
        })
    }
}
