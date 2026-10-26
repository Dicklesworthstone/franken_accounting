//! Strict, editable custom-definition data for the public statement workflow.
//!
//! `[[mapping]]` rows name typed account-set expressions. Composite rows may
//! reference only earlier mappings; `[[line]]` selects one mapping and sign or
//! a formula over earlier lines. Mapping names are source aliases, not durable
//! identities: canonical definition bytes contain the expanded expression.

use std::collections::{BTreeMap, BTreeSet};

use fa_model::{AccountType, Writer};
use fa_registry::toml::{Table, Value};

use super::{
    AccountSetExpr, CustomLineDefinition, CustomLineSource, CustomStatementDefinition,
    MAX_CUSTOM_LINES, MAX_EXPR_DEPTH, MAX_EXPR_ITEMS,
};
use crate::{MAX_DEFINITION_BYTES, Sign, StatementError, StatementKind};

enum MappingSource {
    Leaf(AccountSetExpr),
    Union(Vec<usize>),
    Difference { include: usize, exclude: usize },
}

struct Mapping<'a> {
    name: &'a str,
    source: MappingSource,
    depth: usize,
    encoded_bytes: usize,
}

fn invalid(message: impl Into<String>) -> StatementError {
    StatementError::Definition(message.into())
}

fn keys(table: &Table, allowed: &[&str]) -> Result<(), StatementError> {
    if let Some(key) = table.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(invalid(format!(
            "unsupported custom-definition field `{key}`"
        )));
    }
    Ok(())
}

fn string<'a>(table: &'a Table, key: &str) -> Result<&'a str, StatementError> {
    let text = table
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("`{key}` must be a string")))?;
    if text
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\t'))
    {
        return Err(invalid(format!(
            "`{key}` contains an unsupported control character"
        )));
    }
    Ok(text)
}

fn integer(table: &Table, key: &str) -> Result<i128, StatementError> {
    table
        .get(key)
        .and_then(Value::as_int)
        .ok_or_else(|| invalid(format!("`{key}` must be an integer")))
}

fn strings(table: &Table, key: &str, max: usize) -> Result<Vec<String>, StatementError> {
    let array = table
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(format!("`{key}` must be a string array")))?;
    if array.len() > max {
        return Err(invalid(format!("`{key}` exceeds its {max}-item bound")));
    }
    array
        .iter()
        .map(|value| {
            let text = value
                .as_str()
                .ok_or_else(|| invalid(format!("`{key}` must contain only strings")))?;
            if text.len() > 64
                || text
                    .chars()
                    .any(|c| c.is_control() && !matches!(c, '\n' | '\t'))
            {
                return Err(invalid(format!(
                    "`{key}` contains an unbounded or unsupported string"
                )));
            }
            Ok(text.to_string())
        })
        .collect()
}

fn identifier(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 64
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The registry parser intentionally accepts only scalar arrays. Reject nested
/// array syntax before calling it, so adversarial nesting cannot recurse there.
fn scalar_arrays(text: &str) -> Result<(), StatementError> {
    for line in text.lines() {
        if line.trim_start().starts_with('[') {
            continue;
        }
        let mut quoted = false;
        let mut escaped = false;
        let mut depth = 0usize;
        for c in line.chars() {
            if quoted {
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == '"' {
                    quoted = false;
                }
            } else {
                match c {
                    '#' => break,
                    '"' => quoted = true,
                    '[' => {
                        depth += 1;
                        if depth > 1 {
                            return Err(invalid(
                                "custom-definition TOML admits only flat scalar arrays",
                            ));
                        }
                    }
                    ']' => depth = depth.saturating_sub(1),
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

fn reference(names: &BTreeMap<&str, usize>, name: &str) -> Result<usize, StatementError> {
    names.get(name).copied().ok_or_else(|| {
        invalid(format!(
            "mapping `{name}` is unknown, forward-referenced or cyclic"
        ))
    })
}

fn parse_mapping<'a>(
    row: &'a Table,
    names: &BTreeMap<&str, usize>,
    mappings: &[Mapping<'_>],
    covered: &[u8],
) -> Result<Mapping<'a>, StatementError> {
    let name = string(row, "name")?;
    if !identifier(name) || names.contains_key(name) {
        return Err(invalid(
            "mapping names must be unique bounded ASCII identifiers",
        ));
    }
    let source = match string(row, "kind")? {
        "AccountTypes" => {
            keys(row, &["name", "kind", "types"])?;
            let mut tags = strings(row, "types", 8)?
                .iter()
                .map(|name| {
                    AccountType::ALL
                        .iter()
                        .find(|row| row.1 == name)
                        .map(|row| row.0)
                        .ok_or_else(|| invalid(format!("unknown account type `{name}`")))
                })
                .collect::<Result<Vec<_>, _>>()?;
            tags.sort_unstable();
            MappingSource::Leaf(AccountSetExpr::AccountTypes(tags))
        }
        "AccountCodes" => {
            keys(row, &["name", "kind", "codes"])?;
            MappingSource::Leaf(AccountSetExpr::AccountCodes(strings(
                row,
                "codes",
                MAX_EXPR_ITEMS,
            )?))
        }
        "AccountCodePrefixes" => {
            keys(row, &["name", "kind", "prefixes"])?;
            MappingSource::Leaf(AccountSetExpr::AccountCodePrefixes(strings(
                row,
                "prefixes",
                MAX_EXPR_ITEMS,
            )?))
        }
        "Union" => {
            keys(row, &["name", "kind", "children"])?;
            let children = strings(row, "children", 32)?;
            if children.len() < 2
                || children.iter().collect::<BTreeSet<_>>().len() != children.len()
            {
                return Err(invalid(
                    "Union requires 2..=32 distinct earlier mapping names",
                ));
            }
            MappingSource::Union(
                children
                    .iter()
                    .map(|name| reference(names, name))
                    .collect::<Result<_, _>>()?,
            )
        }
        "Difference" => {
            keys(row, &["name", "kind", "include", "exclude"])?;
            MappingSource::Difference {
                include: reference(names, string(row, "include")?)?,
                exclude: reference(names, string(row, "exclude")?)?,
            }
        }
        other => return Err(invalid(format!("unsupported account-set kind `{other}`"))),
    };
    let (depth, encoded_bytes) = match &source {
        MappingSource::Leaf(expr) => {
            expr.validate(covered, 0)?;
            let mut writer = Writer::new();
            expr.encode(&mut writer);
            (0, writer.finish()?.len())
        }
        MappingSource::Union(children) => (
            children
                .iter()
                .map(|i| mappings[*i].depth)
                .max()
                .unwrap_or(0)
                + 1,
            5 + children
                .iter()
                .map(|i| mappings[*i].encoded_bytes)
                .sum::<usize>(),
        ),
        MappingSource::Difference { include, exclude } => (
            1 + mappings[*include].depth.max(mappings[*exclude].depth),
            1 + mappings[*include].encoded_bytes + mappings[*exclude].encoded_bytes,
        ),
    };
    if depth > MAX_EXPR_DEPTH {
        return Err(invalid("AccountSetExpr nesting exceeds maximum depth 8"));
    }
    if encoded_bytes > MAX_DEFINITION_BYTES {
        return Err(invalid(
            "expanded account-set expression exceeds the 64 KiB byte bound",
        ));
    }
    Ok(Mapping {
        name,
        source,
        depth,
        encoded_bytes,
    })
}

/// Expansion is reached only after checking its complete encoded size. A small
/// source DAG therefore cannot turn repeated references into an unbounded tree.
fn expand(index: usize, mappings: &[Mapping<'_>], used: &mut BTreeSet<usize>) -> AccountSetExpr {
    used.insert(index);
    match &mappings[index].source {
        MappingSource::Leaf(expr) => expr.clone(),
        MappingSource::Union(children) => AccountSetExpr::Union(
            children
                .iter()
                .map(|i| expand(*i, mappings, used))
                .collect(),
        ),
        MappingSource::Difference { include, exclude } => AccountSetExpr::Difference {
            include: Box::new(expand(*include, mappings, used)),
            exclude: Box::new(expand(*exclude, mappings, used)),
        },
    }
}

impl CustomStatementDefinition {
    /// Read strict version-1 TOML: root metadata, typed `[[mapping]]` rows,
    /// then `[[line]]` rows with either `mapping`/`sign` or `add`/`subtract`.
    /// Mapping references must point backward; formula inputs must name earlier
    /// lines. Unknown fields and unused mapping declarations are refused.
    pub fn from_toml(text: &str) -> Result<Self, StatementError> {
        if text.len() > MAX_DEFINITION_BYTES {
            return Err(invalid(
                "custom-definition TOML exceeds the 64 KiB byte bound",
            ));
        }
        scalar_arrays(text)?;
        let doc = fa_registry::toml::parse(text).map_err(|e| invalid(e.to_string()))?;
        if !doc.tables.is_empty()
            || doc
                .arrays
                .keys()
                .any(|k| !matches!(k.as_str(), "mapping" | "line"))
        {
            return Err(invalid(
                "only the root, [[mapping]] and [[line]] tables are admitted",
            ));
        }
        keys(
            &doc.root,
            &[
                "schema_version",
                "name",
                "title",
                "version",
                "kind",
                "check_lines",
            ],
        )?;
        if integer(&doc.root, "schema_version")? != 1 {
            return Err(invalid("custom-definition schema_version must be 1"));
        }
        let kind = match string(&doc.root, "kind")? {
            "BalanceSheet" => StatementKind::BalanceSheet,
            "IncomeStatement" => StatementKind::IncomeStatement,
            other => return Err(invalid(format!("unsupported statement kind `{other}`"))),
        };
        let rows = doc
            .arrays
            .get("mapping")
            .map(Vec::as_slice)
            .unwrap_or_default();
        if rows.len() > MAX_EXPR_ITEMS {
            return Err(invalid("custom definition exceeds 1024 named mappings"));
        }
        let mut mappings = Vec::with_capacity(rows.len());
        let mut names = BTreeMap::new();
        for row in rows {
            let mapping = parse_mapping(row, &names, &mappings, kind.covered_types())?;
            names.insert(mapping.name, mappings.len());
            mappings.push(mapping);
        }
        let rows = doc
            .arrays
            .get("line")
            .map(Vec::as_slice)
            .unwrap_or_default();
        if rows.is_empty() || rows.len() > MAX_CUSTOM_LINES {
            return Err(invalid("custom definition requires 1..=128 lines"));
        }
        let mut lines = Vec::with_capacity(rows.len());
        let mut used = BTreeSet::new();
        let mut expanded_bytes = 0usize;
        for row in rows {
            let source = if row.contains_key("mapping") {
                keys(row, &["code", "label", "mapping", "sign"])?;
                let index = reference(&names, string(row, "mapping")?)?;
                expanded_bytes += mappings[index].encoded_bytes;
                if expanded_bytes > MAX_DEFINITION_BYTES {
                    return Err(invalid("expanded definition exceeds the 64 KiB byte bound"));
                }
                CustomLineSource::AccountSet {
                    expr: expand(index, &mappings, &mut used),
                    sign: match string(row, "sign")? {
                        "debit" => Sign::Debit,
                        "credit" => Sign::Credit,
                        other => return Err(invalid(format!("unknown account sign `{other}`"))),
                    },
                }
            } else {
                keys(row, &["code", "label", "add", "subtract"])?;
                CustomLineSource::Formula {
                    add: strings(row, "add", MAX_CUSTOM_LINES)?,
                    subtract: strings(row, "subtract", MAX_CUSTOM_LINES)?,
                }
            };
            lines.push(CustomLineDefinition {
                code: string(row, "code")?.to_string(),
                label: string(row, "label")?.to_string(),
                source,
            });
        }
        if let Some((_, unused)) = mappings.iter().enumerate().find(|(i, _)| !used.contains(i)) {
            return Err(invalid(format!(
                "mapping `{}` is not used by any line",
                unused.name
            )));
        }
        let definition = Self {
            name: string(&doc.root, "name")?.to_string(),
            title: string(&doc.root, "title")?.to_string(),
            version: u32::try_from(integer(&doc.root, "version")?)
                .map_err(|_| invalid("version must fit a positive u32"))?,
            kind,
            lines,
            check_lines: strings(&doc.root, "check_lines", MAX_CUSTOM_LINES)?,
        };
        definition.validate()?;
        definition.canonical_bytes()?;
        Ok(definition)
    }

    /// Export a deterministic editable seed, preserving the existing canonical
    /// definition and digest. Source aliases are assigned in traversal order.
    pub fn to_toml(&self) -> Result<String, StatementError> {
        self.validate()?;
        self.canonical_bytes()?;
        let mut out = format!(
            "schema_version = 1\nname = {}\ntitle = {}\nversion = {}\nkind = {}\ncheck_lines = {}\n",
            quoted(&self.name)?,
            quoted(&self.title)?,
            self.version,
            quoted(self.kind.name())?,
            array(&self.check_lines)?,
        );
        let mut next = 0usize;
        let mut line_mappings = Vec::with_capacity(self.lines.len());
        for line in &self.lines {
            line_mappings.push(match &line.source {
                CustomLineSource::AccountSet { expr, .. } => {
                    Some(write_mapping(expr, &mut out, &mut next)?)
                }
                CustomLineSource::Formula { .. } => None,
            });
        }
        for (line, mapping) in self.lines.iter().zip(line_mappings) {
            append(
                &mut out,
                &format!(
                    "\n[[line]]\ncode = {}\nlabel = {}\n",
                    quoted(&line.code)?,
                    quoted(&line.label)?
                ),
            )?;
            match (&line.source, mapping) {
                (CustomLineSource::AccountSet { sign, .. }, Some(name)) => {
                    append(
                        &mut out,
                        &format!(
                            "mapping = {}\nsign = {}\n",
                            quoted(&name)?,
                            quoted(match sign {
                                Sign::Debit => "debit",
                                Sign::Credit => "credit",
                            })?
                        ),
                    )?;
                }
                (CustomLineSource::Formula { add, subtract }, None) => {
                    append(
                        &mut out,
                        &format!("add = {}\nsubtract = {}\n", array(add)?, array(subtract)?),
                    )?;
                }
                _ => return Err(invalid("custom-definition source and mapping disagree")),
            }
        }
        Ok(out)
    }
}

fn quoted(text: &str) -> Result<String, StatementError> {
    let mut out = String::from("\"");
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                return Err(invalid(
                    "a string contains an unsupported TOML control character",
                ));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    Ok(out)
}

fn array(values: &[String]) -> Result<String, StatementError> {
    let values = values
        .iter()
        .map(|s| quoted(s))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(format!("[{}]", values.join(", ")))
}

fn append(out: &mut String, text: &str) -> Result<(), StatementError> {
    if out.len() + text.len() > MAX_DEFINITION_BYTES {
        return Err(invalid(
            "editable definition TOML exceeds the 64 KiB byte bound",
        ));
    }
    out.push_str(text);
    Ok(())
}

fn write_mapping(
    expr: &AccountSetExpr,
    out: &mut String,
    next: &mut usize,
) -> Result<String, StatementError> {
    let fields = match expr {
        AccountSetExpr::AccountTypes(types) => {
            let names = types
                .iter()
                .map(|tag| {
                    AccountType::ALL
                        .iter()
                        .find(|row| row.0 == *tag)
                        .map(|row| row.1.to_string())
                        .ok_or_else(|| invalid("unknown account type in mapping"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            format!("kind = \"AccountTypes\"\ntypes = {}\n", array(&names)?)
        }
        AccountSetExpr::AccountCodes(codes) => {
            format!("kind = \"AccountCodes\"\ncodes = {}\n", array(codes)?)
        }
        AccountSetExpr::AccountCodePrefixes(prefixes) => format!(
            "kind = \"AccountCodePrefixes\"\nprefixes = {}\n",
            array(prefixes)?
        ),
        AccountSetExpr::Union(children) => {
            let names = children
                .iter()
                .map(|child| write_mapping(child, out, next))
                .collect::<Result<Vec<_>, _>>()?;
            format!("kind = \"Union\"\nchildren = {}\n", array(&names)?)
        }
        AccountSetExpr::Difference { include, exclude } => {
            let include = write_mapping(include, out, next)?;
            let exclude = write_mapping(exclude, out, next)?;
            format!(
                "kind = \"Difference\"\ninclude = {}\nexclude = {}\n",
                quoted(&include)?,
                quoted(&exclude)?
            )
        }
    };
    if *next == MAX_EXPR_ITEMS {
        return Err(invalid("editable definition exceeds 1024 named mappings"));
    }
    *next += 1;
    let name = format!("mapping_{next}");
    append(
        out,
        &format!("\n[[mapping]]\nname = {}\n{fields}", quoted(&name)?),
    )?;
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::custom::{
        PRESENTATION_ROUNDING_SPEC_FORMAT, PresentationRoundingSpec, evaluate_custom,
        lint_custom_statement_definition,
    };
    use crate::{Account, AccountBalance, ColumnInput, StatementDefinition, StatementInput};
    use fa_model::Id128;
    use fa_money::rounding::RoundingLaw;
    use fa_time::DateDay;

    const DEFINITION: &str = r#"
schema_version = 1
name = "example-income"
title = "Example income statement"
version = 1
kind = "IncomeStatement"
check_lines = []

[[mapping]]
name = "revenue"
kind = "AccountTypes"
types = ["Revenue"]

[[mapping]]
name = "expenses"
kind = "AccountTypes"
types = ["Expense"]

[[mapping]]
name = "rent"
kind = "AccountCodes"
codes = ["5000"]

[[mapping]]
name = "payroll"
kind = "AccountCodePrefixes"
prefixes = ["51"]

[[mapping]]
name = "selected"
kind = "Union"
children = ["rent", "payroll"]

[[mapping]]
name = "other"
kind = "Difference"
include = "expenses"
exclude = "selected"

[[line]]
code = "revenue"
label = "Revenue"
mapping = "revenue"
sign = "credit"

[[line]]
code = "selected"
label = "Rent and payroll"
mapping = "selected"
sign = "debit"

[[line]]
code = "other"
label = "Other expenses"
mapping = "other"
sign = "debit"

[[line]]
code = "net"
label = "Net income"
add = ["revenue"]
subtract = ["other", "selected"]
"#;

    fn chart() -> Vec<Account> {
        [
            (1, "4000", 4),
            (2, "5000", 5),
            (3, "5100", 5),
            (4, "5990", 5),
        ]
        .into_iter()
        .map(|(id, code, account_type)| Account {
            id,
            code: code.into(),
            name: code.into(),
            account_type,
            is_leaf: true,
        })
        .collect()
    }

    #[test]
    fn custom_toml_all_mapping_kinds_evaluate_the_complete_chart() {
        let definition = CustomStatementDefinition::from_toml(DEFINITION).unwrap();
        let accounts = chart();
        let lint = lint_custom_statement_definition(&definition, &accounts).unwrap();
        assert!(lint.is_clean());
        assert_eq!(lint.covered_leaf_count, 4);
        let input = StatementInput {
            book_id: Id128([1; 16]),
            branch_id: Id128::TRUNK,
            known_at: 9,
            accounts,
            units: vec![1],
            columns: vec![ColumnInput {
                label: "FY2026-P01".into(),
                periods: vec!["FY2026-P01".into()],
                effective_from: Some(DateDay(1)),
                effective_through: DateDay(31),
                balances: vec![
                    AccountBalance {
                        account_id: 1,
                        unit_id: 1,
                        debits: 0,
                        credits: 1000,
                    },
                    AccountBalance {
                        account_id: 2,
                        unit_id: 1,
                        debits: 200,
                        credits: 0,
                    },
                    AccountBalance {
                        account_id: 3,
                        unit_id: 1,
                        debits: 300,
                        credits: 0,
                    },
                    AccountBalance {
                        account_id: 4,
                        unit_id: 1,
                        debits: 400,
                        credits: 0,
                    },
                ],
            }],
        };
        let report = evaluate_custom(&definition, &input).unwrap();
        let values: Vec<_> = report
            .lines
            .iter()
            .map(|l| (l.code.as_str(), l.amounts[0]))
            .collect();
        assert_eq!(
            values,
            [
                ("revenue", 1000),
                ("selected", 500),
                ("other", 400),
                ("net", 100)
            ]
        );
        let bytes = definition.canonical_bytes().unwrap();
        assert_eq!(
            CustomStatementDefinition::decode(&bytes).unwrap(),
            definition
        );

        // Parsing does not hide a double mapping; the chart admission still refuses it.
        let doubled = CustomStatementDefinition::from_toml(
            &DEFINITION.replace("mapping = \"other\"", "mapping = \"expenses\"")
                .replace("[[mapping]]\nname = \"other\"\nkind = \"Difference\"\ninclude = \"expenses\"\nexclude = \"selected\"\n", ""),
        ).unwrap();
        let lint = lint_custom_statement_definition(&doubled, &chart()).unwrap();
        assert!(!lint.is_clean());
        assert_eq!(lint.multiply_mapped_leaves.len(), 2);
        assert!(evaluate_custom(&doubled, &input).is_err());
    }

    #[test]
    fn custom_toml_editable_seeds_preserve_existing_canonical_definitions() {
        let mut definitions = vec![
            CustomStatementDefinition::from_toml(DEFINITION).unwrap(),
            CustomStatementDefinition::us_gaap_small_company_balance_sheet(),
            CustomStatementDefinition::us_gaap_small_company_income_statement(),
        ];
        for name in ["balance-sheet", "income-statement"] {
            definitions.push(CustomStatementDefinition::from_builtin(
                &StatementDefinition::embedded(name).unwrap(),
            ));
        }
        for definition in definitions {
            let text = definition.to_toml().unwrap();
            let loaded = CustomStatementDefinition::from_toml(&text).unwrap();
            assert_eq!(loaded, definition);
            assert_eq!(loaded.digest().unwrap(), definition.digest().unwrap());
            assert_eq!(loaded.to_toml().unwrap(), text);
            let commented = format!(
                "# review copy\n{}",
                text.replace("schema_version = 1", "schema_version   = 1 # cosmetic")
            );
            assert_eq!(
                CustomStatementDefinition::from_toml(&commented).unwrap(),
                definition
            );
        }
        let mut escaped = CustomStatementDefinition::from_toml(DEFINITION).unwrap();
        escaped.title = "Quoted \"statement\" \\ title\nwith a tab\tand brackets [x]".into();
        assert_eq!(
            CustomStatementDefinition::from_toml(&escaped.to_toml().unwrap()).unwrap(),
            escaped
        );
    }

    #[test]
    fn custom_toml_refuses_unknown_ambiguous_and_cyclic_definitions() {
        for text in [
            DEFINITION.replacen("schema_version = 1", "schema_version = 2", 1),
            DEFINITION.replacen(
                "schema_version = 1",
                "schema_version = 1\nignored = true",
                1,
            ),
            DEFINITION.replacen("kind = \"AccountCodes\"", "kind = \"AnyCode\"", 1),
            DEFINITION.replacen(
                "codes = [\"5000\"]",
                "codes = [\"5000\"]\nprefixes = [\"5\"]",
                1,
            ),
            DEFINITION.replacen("codes = [\"5000\"]", "codes = [\"5000\", \"5000\"]", 1),
            DEFINITION.replacen("types = [\"Revenue\"]", "types = [\"Asset\"]", 1),
            DEFINITION.replacen("name = \"rent\"", "name = \"revenue\"", 1),
            DEFINITION.replacen(
                "children = [\"rent\", \"payroll\"]",
                "children = [\"rent\", \"selected\"]",
                1,
            ),
            DEFINITION.replacen("exclude = \"selected\"", "exclude = \"absent\"", 1),
            DEFINITION.replacen("sign = \"credit\"", "sign = \"credit\"\nadd = []", 1),
            DEFINITION.replacen("sign = \"credit\"", "sign = \"Credit\"", 1),
            DEFINITION.replacen("add = [\"revenue\"]", "add = [\"net\"]", 1),
            DEFINITION.replacen("add = [\"revenue\"]", "add = [\"absent\"]", 1),
            DEFINITION.replacen(
                "subtract = [\"other\", \"selected\"]",
                "subtract = [\"other\", \"revenue\"]",
                1,
            ),
            DEFINITION.replacen(
                "subtract = [\"other\", \"selected\"]",
                "subtract = [\"selected\", \"other\"]",
                1,
            ),
            format!(
                "{DEFINITION}\n[[mapping]]\nname = \"unused\"\nkind = \"AccountTypes\"\ntypes = [\"Revenue\"]\n"
            ),
            format!("{DEFINITION}\n[unexpected]\nx = true\n"),
        ] {
            assert!(
                CustomStatementDefinition::from_toml(&text).is_err(),
                "accepted {text}"
            );
        }
    }

    #[test]
    fn custom_toml_bounds_text_arrays_lines_and_expression_expansion() {
        let large = " ".repeat(MAX_DEFINITION_BYTES + 1);
        assert!(CustomStatementDefinition::from_toml(&large).is_err());
        assert!(CustomStatementDefinition::decode(&vec![0; MAX_DEFINITION_BYTES + 1]).is_err());
        let nested = format!("schema_version = {}0{}", "[".repeat(4000), "]".repeat(4000));
        let error = CustomStatementDefinition::from_toml(&nested)
            .unwrap_err()
            .to_string();
        assert!(error.contains("flat scalar arrays"), "{error}");
        let mut many_lines = DEFINITION.to_string();
        for i in 0..MAX_CUSTOM_LINES {
            many_lines.push_str(&format!("\n[[line]]\ncode = \"extra_{i}\"\nlabel = \"Extra\"\nadd = [\"net\"]\nsubtract = []\n"));
        }
        assert!(
            CustomStatementDefinition::from_toml(&many_lines)
                .unwrap_err()
                .to_string()
                .contains("1..=128")
        );

        // A short source DAG doubles a 1 KiB leaf at each level. Reject the
        // encoded size before ever cloning its exponentially expanded tree.
        let codes: Vec<String> = (0..128).map(|n| format!("{n:04}")).collect();
        let mut bomb = format!(
            "schema_version = 1\nname = \"bounded\"\ntitle = \"Bounded\"\nversion = 1\nkind = \"IncomeStatement\"\ncheck_lines = []\n\n[[mapping]]\nname = \"m0\"\nkind = \"AccountCodes\"\ncodes = {}\n",
            array(&codes).unwrap(),
        );
        for i in 1..=8 {
            bomb.push_str(&format!("\n[[mapping]]\nname = \"m{i}\"\nkind = \"Difference\"\ninclude = \"m{}\"\nexclude = \"m{}\"\n", i - 1, i - 1));
        }
        bomb.push_str(
            "\n[[line]]\ncode = \"r\"\nlabel = \"R\"\nmapping = \"m8\"\nsign = \"credit\"\n",
        );
        assert!(bomb.len() < MAX_DEFINITION_BYTES);
        let error = CustomStatementDefinition::from_toml(&bomb)
            .unwrap_err()
            .to_string();
        assert!(error.contains("expanded account-set expression"), "{error}");

        let mut deep = DEFINITION.to_string();
        for i in 0..9 {
            let previous = if i == 0 {
                "other".to_string()
            } else {
                format!("deep_{}", i - 1)
            };
            deep.push_str(&format!("\n[[mapping]]\nname = \"deep_{i}\"\nkind = \"Difference\"\ninclude = \"{previous}\"\nexclude = \"rent\"\n"));
        }
        let error = CustomStatementDefinition::from_toml(&deep)
            .unwrap_err()
            .to_string();
        assert!(error.contains("depth 8"), "{error}");
    }

    fn rounding() -> PresentationRoundingSpec {
        PresentationRoundingSpec {
            rounding_law: RoundingLaw::HalfEven,
            scale_reduction_digits: 2,
            residual_line_code: "rounding".into(),
            residual_line_label: "Presentation rounding".into(),
        }
    }

    #[test]
    fn presentation_rounding_parameters_bind_every_choice_and_round_trip() {
        let base = rounding();
        let original = base.canonical_bytes().unwrap();
        assert_eq!(PresentationRoundingSpec::decode(&original).unwrap(), base);
        for law in RoundingLaw::ALL {
            for digits in [0, 2, 38] {
                let spec = PresentationRoundingSpec {
                    rounding_law: law,
                    scale_reduction_digits: digits,
                    ..base.clone()
                };
                spec.validate().unwrap();
                assert_eq!(
                    PresentationRoundingSpec::decode(&spec.canonical_bytes().unwrap()).unwrap(),
                    spec
                );
            }
        }
        for spec in [
            PresentationRoundingSpec {
                rounding_law: RoundingLaw::HalfUp,
                ..base.clone()
            },
            PresentationRoundingSpec {
                scale_reduction_digits: 3,
                ..base.clone()
            },
            PresentationRoundingSpec {
                residual_line_code: "residual".into(),
                ..base.clone()
            },
            PresentationRoundingSpec {
                residual_line_label: "Declared residual".into(),
                ..base.clone()
            },
        ] {
            assert_ne!(spec.canonical_bytes().unwrap(), original);
        }
    }

    #[test]
    fn presentation_rounding_parameters_refuse_invalid_or_unbounded_encodings() {
        let original = rounding().canonical_bytes().unwrap();
        let mut unknown_law = original.clone();
        let offset = PRESENTATION_ROUNDING_SPEC_FORMAT.len();
        unknown_law[offset..offset + 2].copy_from_slice(&u16::MAX.to_le_bytes());
        let mut unknown_format = original.clone();
        unknown_format[0] ^= 1;
        let mut trailing = original.clone();
        trailing.push(0);
        for bytes in [
            unknown_law,
            unknown_format,
            trailing,
            original[..original.len() - 1].to_vec(),
        ] {
            assert!(PresentationRoundingSpec::decode(&bytes).is_err());
        }
        for spec in [
            PresentationRoundingSpec {
                scale_reduction_digits: 39,
                ..rounding()
            },
            PresentationRoundingSpec {
                residual_line_code: String::new(),
                ..rounding()
            },
            PresentationRoundingSpec {
                residual_line_code: "ambiguous code".into(),
                ..rounding()
            },
            PresentationRoundingSpec {
                residual_line_label: "  ".into(),
                ..rounding()
            },
        ] {
            assert!(spec.validate().is_err());
            assert!(PresentationRoundingSpec::decode(&spec.canonical_bytes().unwrap()).is_err());
        }
        let oversized = PresentationRoundingSpec {
            residual_line_code: "r".repeat(65),
            ..rounding()
        };
        assert!(oversized.validate().is_err());
        assert!(oversized.canonical_bytes().is_err());
    }
}
