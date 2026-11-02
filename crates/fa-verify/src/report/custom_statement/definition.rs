//! Independent bounded decoder for company-defined account sets and formulas.

use super::super::{ReportError, failed, metadata, statement, text};
use crate::codec::Reader;
use statement::definition::{Definition, Line, MAX_BYTES, Source};
use std::collections::{BTreeMap, BTreeSet};

pub(in crate::report) const FORMAT: &[u8] = b"fa:custom-statement-def:v1";
const MAX_MATCH_WORK: usize = 32 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::report) enum AccountSet {
    Types(Vec<u8>),
    Codes(Vec<String>),
    Prefixes(Vec<String>),
    Union(Vec<Self>),
    Difference(Box<Self>, Box<Self>),
}

fn invalid(detail: impl Into<String>) -> ReportError {
    failed("custom_statement_definition", detail)
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

fn names(
    r: &mut Reader<'_>,
    limit: usize,
    field: &'static str,
) -> Result<Vec<String>, ReportError> {
    let count = r.count(limit, 4, field)?;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        let value = text(r, 64, field)?.to_string();
        if value.is_empty() {
            return Err(invalid(
                "account names and formula operands must be nonempty",
            ));
        }
        values.push(value);
    }
    if !values.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(invalid(
            "account sets and formula operands must be sorted and unique",
        ));
    }
    Ok(values)
}

fn covered(activity: bool, typ: u8) -> bool {
    if activity {
        matches!(typ, 4 | 5)
    } else {
        (1..=5).contains(&typ)
    }
}

impl AccountSet {
    fn read(r: &mut Reader<'_>, activity: bool, depth: usize) -> Result<Self, ReportError> {
        if depth > 8 {
            return Err(invalid("account-set nesting exceeds eight"));
        }
        Ok(match r.u8("custom.account_set")? {
            1 => {
                let count = r.count(8, 1, "custom.account_types")?;
                let mut types = Vec::with_capacity(count);
                for _ in 0..count {
                    types.push(r.u8("custom.account_type")?);
                }
                if types.is_empty()
                    || !types.windows(2).all(|pair| pair[0] < pair[1])
                    || types.iter().any(|typ| !covered(activity, *typ))
                {
                    return Err(invalid("account types must be a sorted unique covered set"));
                }
                Self::Types(types)
            }
            tag @ (2 | 3) => {
                let names = names(r, 1024, "custom.account_codes")?;
                if names.is_empty() {
                    return Err(invalid("account codes and prefixes require a nonempty set"));
                }
                if tag == 2 {
                    Self::Codes(names)
                } else {
                    Self::Prefixes(names)
                }
            }
            4 => {
                let count = r.count(32, 1, "custom.union")?;
                if count < 2 {
                    return Err(invalid(
                        "an account-set union requires two through 32 children",
                    ));
                }
                let mut children = Vec::with_capacity(count);
                for _ in 0..count {
                    children.push(Self::read(r, activity, depth + 1)?);
                }
                Self::Union(children)
            }
            5 => Self::Difference(
                Box::new(Self::read(r, activity, depth + 1)?),
                Box::new(Self::read(r, activity, depth + 1)?),
            ),
            _ => return Err(invalid("unknown account-set expression")),
        })
    }

    fn explicit_codes<'a>(&'a self, out: &mut BTreeSet<&'a str>) {
        match self {
            Self::Codes(codes) => out.extend(codes.iter().map(String::as_str)),
            Self::Union(children) => {
                for child in children {
                    child.explicit_codes(out);
                }
            }
            Self::Difference(include, exclude) => {
                include.explicit_codes(out);
                exclude.explicit_codes(out);
            }
            Self::Types(_) | Self::Prefixes(_) => {}
        }
    }

    fn matches(
        &self,
        account: &metadata::Account,
        remaining: &mut usize,
    ) -> Result<bool, ReportError> {
        fn spend(remaining: &mut usize, work: usize) -> Result<(), ReportError> {
            *remaining = remaining.checked_sub(work).ok_or_else(|| {
                failed(
                    "bounded_input",
                    "custom account-set matching exceeds its work budget",
                )
            })?;
            Ok(())
        }
        spend(remaining, 1)?;
        Ok(match self {
            Self::Types(types) => types.binary_search(&account.account_type).is_ok(),
            Self::Codes(codes) => {
                // Code lengths are bounded. Charge a conservative comparison
                // budget while using logarithmic lookup rather than a scan.
                spend(remaining, 64 * (codes.len().ilog2() as usize + 1))?;
                codes.binary_search(&account.code).is_ok()
            }
            Self::Prefixes(prefixes) => {
                let mut matched = false;
                for prefix in prefixes {
                    spend(remaining, prefix.len())?;
                    if account.code.starts_with(prefix) {
                        matched = true;
                        break;
                    }
                }
                matched
            }
            Self::Union(children) => {
                let mut matched = false;
                for child in children {
                    if child.matches(account, remaining)? {
                        matched = true;
                        break;
                    }
                }
                matched
            }
            Self::Difference(include, exclude) => {
                include.matches(account, remaining)? && !exclude.matches(account, remaining)?
            }
        })
    }
}

pub(super) fn decode(bytes: &[u8]) -> Result<Definition, ReportError> {
    if bytes.len() > MAX_BYTES {
        return Err(invalid("custom definition exceeds 64 KiB"));
    }
    let mut r = Reader::new(bytes);
    if r.fixed::<{ FORMAT.len() }>("custom.definition.format")? != FORMAT {
        return Err(invalid("unsupported custom definition format"));
    }
    let name = text(&mut r, 64, "custom.definition.name")?.to_string();
    let title = text(&mut r, 256, "custom.definition.title")?;
    let version = r.u32("custom.definition.version")?;
    let activity = match r.u8("custom.definition.kind")? {
        0 => false,
        1 => true,
        _ => return Err(invalid("unknown custom statement accounting basis")),
    };
    if !identifier(&name) || title.trim().is_empty() || version == 0 {
        return Err(invalid(
            "custom definition name, title or version is invalid",
        ));
    }
    let count = r.count(128, 10, "custom.definition.lines")?;
    if count == 0 {
        return Err(invalid("a custom definition requires at least one line"));
    }
    let mut lines = Vec::with_capacity(count);
    let mut earlier = BTreeSet::new();
    for _ in 0..count {
        let code = text(&mut r, 64, "custom.line.code")?.to_string();
        let label = text(&mut r, 256, "custom.line.label")?.to_string();
        if !identifier(&code) || label.trim().is_empty() || earlier.contains(&code) {
            return Err(invalid(
                "custom line identifiers or labels are invalid or repeated",
            ));
        }
        let source = match r.u8("custom.line.source")? {
            0 => {
                let set = AccountSet::read(&mut r, activity, 0)?;
                let credit = match r.u8("custom.line.sign")? {
                    0 => false,
                    1 => true,
                    _ => return Err(invalid("unknown custom account-line sign")),
                };
                Source::CustomAccounts { set, credit }
            }
            1 => {
                let add = names(&mut r, 128, "custom.formula.add")?;
                let subtract = names(&mut r, 128, "custom.formula.subtract")?;
                let mut operands = BTreeSet::new();
                if add.is_empty() && subtract.is_empty() {
                    return Err(invalid("custom formula has no operands"));
                }
                for operand in add.iter().chain(&subtract) {
                    if !earlier.contains(operand) || !operands.insert(operand) {
                        return Err(invalid(
                            "custom formula repeats an operand or names a forward/cyclic input",
                        ));
                    }
                }
                Source::Formula { add, subtract }
            }
            _ => return Err(invalid("unknown custom line source")),
        };
        earlier.insert(code.clone());
        lines.push(Line {
            code,
            label,
            source,
        });
    }
    let checks = names(&mut r, 128, "custom.definition.checks")?;
    if (!activity && checks.is_empty())
        || checks.iter().any(|check| {
            !lines
                .iter()
                .any(|line| line.code == *check && matches!(line.source, Source::Formula { .. }))
        })
    {
        return Err(invalid(
            "custom statement checks must name formulas; stock requires an identity",
        ));
    }
    r.finish("custom definition")?;
    Ok(Definition {
        bytes: bytes.to_vec(),
        digest_domain: FORMAT,
        name,
        version,
        activity,
        lines,
        checks,
    })
}

pub(in crate::report) fn mappings(
    definition: &Definition,
    schema: &metadata::Schema,
) -> Result<Vec<statement::StatementMapping>, ReportError> {
    if schema.accounts.len() > 1_000_000 {
        return Err(failed(
            "bounded_input",
            "custom statement chart exceeds one million accounts",
        ));
    }
    let mut by_code = BTreeMap::new();
    for (id, account) in &schema.accounts {
        if account.code.is_empty()
            || account.code.len() > 64
            || account.name.len() > 1024 * 1024
            || !(1..=8).contains(&account.account_type)
            || by_code
                .insert(account.code.as_str(), (*id, account))
                .is_some()
        {
            return Err(failed(
                "statement_partition",
                "custom chart account identities, codes or metadata are invalid",
            ));
        }
    }
    let mut explicit = BTreeSet::new();
    for line in &definition.lines {
        if let Source::CustomAccounts { set, .. } = &line.source {
            set.explicit_codes(&mut explicit);
        }
    }
    for code in explicit {
        let Some((_, account)) = by_code.get(code) else {
            return Err(failed(
                "statement_partition",
                format!("custom definition names unknown account {code}"),
            ));
        };
        if !account.is_leaf || !definition.covered(account.account_type) {
            return Err(failed(
                "statement_partition",
                format!("custom definition explicitly names summary or uncovered account {code}"),
            ));
        }
    }
    let mut remaining = MAX_MATCH_WORK;
    let mut output_bytes = 0usize;
    let mut mappings = Vec::new();
    for (code, (id, account)) in by_code {
        if !account.is_leaf || !definition.covered(account.account_type) {
            continue;
        }
        let mut mapped = None;
        for line in &definition.lines {
            if let Source::CustomAccounts { set, .. } = &line.source
                && set.matches(account, &mut remaining)?
                && mapped.replace(line).is_some()
            {
                return Err(failed(
                    "statement_partition",
                    format!("custom account {code} maps to multiple lines"),
                ));
            }
        }
        let line = mapped.ok_or_else(|| {
            failed(
                "statement_partition",
                format!("custom account {code} has no mapping, including zero balances"),
            )
        })?;
        output_bytes = output_bytes
            .checked_add(16 + 4 + code.len() + 4 + account.name.len() + 2 + 4 + line.code.len())
            .ok_or_else(|| failed("bounded_input", "custom account mapping size overflow"))?;
        if output_bytes > super::super::MAX_REPORT_BUNDLE_BYTES {
            return Err(failed(
                "bounded_input",
                "custom account mappings exceed 64 MiB",
            ));
        }
        mappings.push(statement::StatementMapping {
            account: id,
            code: code.to_string(),
            name: account.name.clone(),
            account_type: account.account_type,
            is_leaf: true,
            line_code: line.code.clone(),
        });
    }
    Ok(mappings)
}
