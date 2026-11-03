//! One pure procedure between two ordinary native reads. This module only
//! splits and rewrites GQL; predicates, projections, ordering and limits
//! remain the substrate's, and open-item accounting remains the journal fold.

use std::collections::BTreeSet;

use fa_time::{DateDay, EffectiveSelector};

use crate::lex::{Kind, Lexed};
use crate::{Law, Native, Refusal, Selectors, aggregate, clause_word, law, lex, native};

const FIX: &str = "MATCH (l:Leg)-[:IN_UNIT]->(u:Unit) CALL fa.open_amount(l) YIELD open, age_days WHERE age_days > 90 RETURN u.code, SUM(open) AS exposure EFFECTIVE AT '2026-03-31'";

/// A bounded `fa.open_amount` stage. Source column zero is the Leg vertex;
/// the other source columns are the original pipeline's carried values.
/// Every value read from a graph property is projected at the source prefix,
/// so resuming the pipeline never substitutes a current property value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenAmount {
    effective_through: DateDay,
    input_columns: usize,
    continuation: String,
    columns: Vec<String>,
}

impl OpenAmount {
    #[must_use]
    pub const fn effective_through(&self) -> DateDay {
        self.effective_through
    }

    /// Source columns, including column zero (the procedure's leg).
    #[must_use]
    pub const fn input_columns(&self) -> usize {
        self.input_columns
    }

    /// The one bounded list parameter the caller supplies. Each row is a
    /// map with `c0..cN`, `open` and `age_days` fields.
    #[must_use]
    pub const fn parameter(&self) -> &'static str {
        "__fa_rows"
    }

    /// Native continuation at the same recorded prefix as the source read.
    #[must_use]
    pub fn statement(&self, known_at: u64) -> String {
        let mut carried = (0..self.input_columns)
            .map(|i| format!("__fa_row.c{i} AS __fa_c{i}"))
            .collect::<Vec<_>>();
        carried.push("__fa_row.open AS open".into());
        carried.push("__fa_row.age_days AS age_days".into());
        format!(
            "UNWIND $__fa_rows AS __fa_row FOR SYSTEM_TIME AS OF SEQ {known_at} WITH {} {}",
            carried.join(", "),
            self.continuation
        )
    }

    /// Names as written by the caller, before internal carried-column names
    /// replaced their expressions. An amount aggregation carries its own
    /// output column names instead.
    #[must_use]
    pub fn columns(&self) -> &[String] {
        &self.columns
    }
}

fn refused(lexed: &Lexed<'_>, at: usize, message: &str) -> Refusal {
    Refusal::new(
        Law::Profile,
        lexed.tokens.get(at).map_or(lexed.text.len(), |t| t.start),
        message,
        FIX,
    )
}

pub(crate) fn compile(
    lexed: &Lexed<'_>,
    selectors: &Selectors,
    call: usize,
) -> Result<Native, Refusal> {
    if !(lexed.word(call + 1, "fa")
        && lexed.punct(call + 2, '.')
        && lexed.word(call + 3, "open_amount")
        && lexed.punct(call + 4, '(')
        && lexed.kind(call + 5) == Some(Kind::Word)
        && lexed.punct(call + 6, ')')
        && lexed.word(call + 7, "YIELD")
        && lexed.str(call + 8) == "open"
        && lexed.punct(call + 9, ',')
        && lexed.str(call + 10) == "age_days")
    {
        return Err(refused(
            lexed,
            call,
            "a pipeline CALL is exactly CALL fa.open_amount(<leg>) YIELD open, age_days",
        ));
    }
    let after = call + 11;
    if !(lexed.word(after, "WHERE") || lexed.word(after, "RETURN")) {
        return Err(refused(
            lexed,
            after,
            "open_amount is followed by WHERE and RETURN, or RETURN",
        ));
    }
    let effective_through = match selectors.effective {
        Some(EffectiveSelector::AsOf(day)) => day,
        _ => {
            return Err(refused(
                lexed,
                call,
                "open_amount needs one explicit EFFECTIVE AT civil date for its open balance and age",
            ));
        }
    };
    if selectors.certify {
        return Err(refused(
            lexed,
            call,
            "a per-row procedure has two native stages and is not a v1 query certificate",
        ));
    }
    for i in 1..call {
        if clause_word(lexed, i) && !(lexed.word(i, "MATCH") || lexed.word(i, "WHERE")) {
            return Err(refused(
                lexed,
                i,
                "before open_amount this build accepts MATCH patterns and WHERE filters",
            ));
        }
    }
    let mut returned = None;
    for i in after..lexed.tokens.len() {
        // A nested graph read after the fold would need a separate reach and
        // binding analysis. Keep this continuation purely row relational.
        if lexed.word(i, "MATCH") || lexed.word(i, "CALL") || lexed.word(i, "EXISTS") {
            return Err(refused(
                lexed,
                i,
                "one open_amount CALL is followed only by row filters and a final projection",
            ));
        }
        if !clause_word(lexed, i) {
            continue;
        }
        if lexed.word(i, "RETURN") {
            if returned.replace(i).is_some() {
                return Err(refused(lexed, i, "a pipeline has one final RETURN"));
            }
        } else if !(lexed.word(i, "WHERE") && returned.is_none()
            || returned.is_some() && ["ORDER", "SKIP", "LIMIT"].iter().any(|w| lexed.word(i, w)))
        {
            return Err(refused(
                lexed,
                i,
                "after open_amount this build accepts WHERE, RETURN, ORDER BY, SKIP and LIMIT",
            ));
        }
    }
    let returned = returned.ok_or_else(|| refused(lexed, after, "the pipeline returns nothing"))?;
    let leg = lexed.str(call + 5);
    let nodes = law::nodes(lexed, 0, call);
    if !nodes
        .iter()
        .any(|n| n.var.as_deref() == Some(leg) && n.labels.iter().any(|label| label == "Leg"))
    {
        return Err(refused(
            lexed,
            call + 5,
            "open_amount takes a Leg variable bound by the preceding MATCH",
        ));
    }
    let mut bindings = nodes
        .into_iter()
        .filter_map(|n| n.var)
        .collect::<BTreeSet<_>>();
    for i in 1..call {
        if lexed.root(i)
            && lexed.punct(i, '[')
            && lexed.kind(i + 1) == Some(Kind::Word)
            && (lexed.punct(i + 2, ':') || lexed.punct(i + 2, ']'))
        {
            bindings.insert(lexed.str(i + 1).to_string());
        }
    }
    if bindings.contains("open") || bindings.contains("age_days") {
        return Err(refused(
            lexed,
            call,
            "the yielded names open and age_days must be new bindings",
        ));
    }
    for i in returned + 1..lexed.tokens.len() {
        if !lexed.root(i) || !lexed.word(i, "AS") {
            continue;
        }
        if lexed.kind(i + 1) != Some(Kind::Word) {
            return Err(refused(
                lexed,
                i + 1,
                "a pipeline RETURN alias must be an unquoted name",
            ));
        }
        if bindings.contains(lexed.str(i + 1)) || matches!(lexed.str(i + 1), "open" | "age_days") {
            return Err(refused(
                lexed,
                i + 1,
                "a RETURN alias must not shadow a carried MATCH binding or procedure yield",
            ));
        }
    }
    let call_start = lexed.tokens[call].start;
    let after_start = lexed.tokens[after].start;
    let mut analyzed = lexed.text.to_string();
    analyzed.replace_range(
        call_start..after_start,
        &" ".repeat(after_start - call_start),
    );
    let analyzed = lex::lex(&analyzed)?;
    let amounts = law::check_with_amount_aliases(&analyzed, &[("open", leg)])?;
    let (continuation, aggregation) = if amounts.aggregated {
        let mut names = vec!["open"];
        names.extend(amounts.aliases.iter().map(String::as_str));
        let (cut, returned, plan) = aggregate::plan_with_amount_aliases(&analyzed, &[], &names)?;
        (
            format!("{} {returned}", lexed.text[after_start..cut].trim()),
            Some(plan),
        )
    } else {
        (lexed.text[after_start..].trim().to_string(), None)
    };
    let columns = output_columns(lexed, returned)?;
    let mut inputs = vec![leg.to_string()];
    let continuation = carry(&continuation, &bindings, &mut inputs)?;
    let source = format!(
        "{} RETURN {}",
        lexed.text[..call_start].trim(),
        inputs
            .iter()
            .enumerate()
            .map(|(i, expression)| format!("{expression} AS __fa_c{i}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    // The original selectors were already blanked. The new source has new
    // offsets, so only their semantic values, never their old spans, apply.
    let source_selectors = Selectors {
        period: selectors.period.clone(),
        effective: selectors.effective.clone(),
        ..Selectors::default()
    };
    let mut source = native(&lex::lex(&source)?, &source_selectors)?;
    source.aggregation = aggregation;
    source.open_amount = Some(OpenAmount {
        effective_through,
        input_columns: inputs.len(),
        continuation,
        columns,
    });
    Ok(source)
}

fn output_columns(lexed: &Lexed<'_>, returned: usize) -> Result<Vec<String>, Refusal> {
    let end = (returned + 1..lexed.tokens.len())
        .find(|&i| clause_word(lexed, i))
        .unwrap_or(lexed.tokens.len());
    let mut first = returned + 1;
    if lexed.word(first, "DISTINCT") {
        first += 1;
    }
    let mut ranges = Vec::new();
    let mut from = first;
    for i in first..end {
        if lexed.root(i) && lexed.punct(i, ',') {
            ranges.push(from..i);
            from = i + 1;
        }
    }
    ranges.push(from..end);
    ranges
        .into_iter()
        .map(|r| {
            if r.is_empty() || (r.len() == 1 && lexed.punct(r.start, '*')) {
                return Err(refused(
                    lexed,
                    r.start,
                    "name the pipeline's RETURN expressions explicitly",
                ));
            }
            if r.len() >= 3
                && lexed.word(r.end - 2, "AS")
                && lexed.kind(r.end - 1) == Some(Kind::Word)
            {
                Ok(lexed.str(r.end - 1).to_string())
            } else {
                Ok(
                    lexed.text[lexed.tokens[r.start].start..lexed.tokens[r.end - 1].end]
                        .trim()
                        .to_string(),
                )
            }
        })
        .collect()
}

fn carry(
    text: &str,
    bindings: &BTreeSet<String>,
    inputs: &mut Vec<String>,
) -> Result<String, Refusal> {
    let lexed = lex::lex(text)?;
    let mut rewritten = String::new();
    let mut copied = 0;
    let mut i = 0;
    while i < lexed.tokens.len() {
        let name = lexed.str(i);
        if lexed.kind(i) != Some(Kind::Word)
            || !bindings.contains(name)
            || i > 0 && (lexed.punct(i - 1, '.') || lexed.word(i - 1, "AS"))
            || lexed.punct(i + 1, ':')
            || lexed.punct(i + 1, '(')
        {
            i += 1;
            continue;
        }
        let (expression, last) = if lexed.punct(i + 1, '.') {
            if lexed.kind(i + 2) != Some(Kind::Word) || lexed.punct(i + 3, '.') {
                return Err(refused(
                    &lexed,
                    i,
                    "a carried property is one binding.property",
                ));
            }
            (format!("{name}.{}", lexed.str(i + 2)), i + 2)
        } else {
            (name.to_string(), i)
        };
        let column = match inputs.iter().position(|input| input == &expression) {
            Some(column) => column,
            None => {
                inputs.push(expression);
                inputs.len() - 1
            }
        };
        rewritten.push_str(&text[copied..lexed.tokens[i].start]);
        rewritten.push_str(&format!("__fa_c{column}"));
        copied = lexed.tokens[last].end;
        i = last + 1;
    }
    rewritten.push_str(&text[copied..]);
    Ok(rewritten)
}
