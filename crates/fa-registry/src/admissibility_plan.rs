//! Std-only parser of plan Appendix C (`COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENACCOUNTING.md`)
//! for the exhaustive admissibility cross-check (`fa-nfq`).
//!
//! Parses the Markdown table under `## Appendix C — Entry-Class × Period-State Admissibility Matrix`
//! plus the `**Period kinds.**` and `§7.3` rules into `(class, state, disposition_family)` decisions,
//! cell qualifiers, kind rules, special-period class lists, and pre-opening rules.

use std::collections::{BTreeMap, BTreeSet};

use fa_time::{PeriodKind, PeriodState};

use crate::{ALL_STATES, Decision};

/// Disposition family within a posting class cell (plan §5.4, Appendix C).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DispositionFamily {
    /// Standard posting (`Posts` for `Resolution`, or the single family for all other classes).
    Standard,
    /// Explicit release (`Voids` for `Resolution`).
    Voids,
    /// Expiry sweep release (`Expires` for `Resolution`).
    Expires,
}

impl DispositionFamily {
    pub const ALL: [Self; 3] = [Self::Standard, Self::Voids, Self::Expires];
}

pub const ALL_KINDS: [PeriodKind; 5] = [
    PeriodKind::Normal,
    PeriodKind::Opening,
    PeriodKind::Adjustment,
    PeriodKind::Closing,
    PeriodKind::Historical,
];

/// Parsed representation of plan Appendix C from markdown text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanAdmissibility {
    pub cells: BTreeMap<(String, PeriodState, DispositionFamily), Decision>,
    pub qualifiers: BTreeMap<(String, PeriodState), String>,
    pub historical_admits: BTreeSet<String>,
    pub pre_opening_kinds: Vec<PeriodKind>,
    pub pre_opening_admits: BTreeSet<String>,
    pub special_period_admits: Vec<(PeriodKind, BTreeSet<String>)>,
}

impl PlanAdmissibility {
    /// Parse `COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENACCOUNTING.md` Appendix C.
    pub fn parse(markdown: &str) -> Result<Self, String> {
        let appendix_start = markdown
            .find("## Appendix C — Entry-Class × Period-State Admissibility Matrix")
            .ok_or_else(|| "missing `## Appendix C` heading in plan markdown".to_string())?;
        let after_heading = &markdown[appendix_start..];
        let appendix_end = after_heading[3..]
            .find("\n## Appendix ")
            .map_or(after_heading.len(), |idx| idx + 3);
        let section = &after_heading[..appendix_end];

        let mut table_lines = Vec::new();
        let mut in_table = false;
        for line in section.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("| Class \\ State |") {
                in_table = true;
                table_lines.push(trimmed);
                continue;
            }
            if in_table {
                if trimmed.starts_with('|') {
                    table_lines.push(trimmed);
                } else {
                    break;
                }
            }
        }
        if table_lines.len() < 3 {
            return Err("Appendix C markdown table has fewer than 3 rows".to_string());
        }

        // Verify header columns match ALL_STATES
        let header_cols = split_md_row(table_lines[0]);
        if header_cols.len() != 6 {
            return Err(format!(
                "expected 6 columns in Appendix C header, found {}",
                header_cols.len()
            ));
        }
        for (idx, state) in ALL_STATES.iter().enumerate() {
            let col = header_cols[idx + 1].trim_matches('`');
            if col != state.name() {
                return Err(format!(
                    "header column {} is `{col}`, expected `{}`",
                    idx + 1,
                    state.name()
                ));
            }
        }

        let mut cells = BTreeMap::new();
        let mut qualifiers = BTreeMap::new();

        for &row_line in &table_lines[2..] {
            let cols = split_md_row(row_line);
            if cols.len() != 6 {
                return Err(format!("malformed row in Appendix C: `{row_line}`"));
            }
            let class_col = cols[0];
            let classes = extract_backticked_tokens(class_col);
            if classes.is_empty() {
                continue;
            }
            // Control rows (PeriodControl, SchemaControl, PolicyControl) are not posting classes
            if classes.iter().any(|c| {
                matches!(
                    c.as_str(),
                    "PeriodControl" | "SchemaControl" | "PolicyControl"
                )
            }) {
                continue;
            }
            for class in classes {
                for (state_idx, &state) in ALL_STATES.iter().enumerate() {
                    let raw_cell = cols[state_idx + 1];
                    let (std_dec, voids_dec, expires_dec, qual) =
                        parse_plan_cell(&class, state, raw_cell)?;
                    if let Some(q) = qual {
                        qualifiers.insert((class.clone(), state), q);
                    }
                    cells.insert((class.clone(), state, DispositionFamily::Standard), std_dec);
                    cells.insert((class.clone(), state, DispositionFamily::Voids), voids_dec);
                    cells.insert(
                        (class.clone(), state, DispositionFamily::Expires),
                        expires_dec,
                    );
                }
            }
        }

        // Parse Period kinds prose in Appendix C
        let kinds_line = section
            .lines()
            .find(|l| l.trim().starts_with("**Period kinds.**"))
            .ok_or_else(|| "missing `**Period kinds.**` paragraph in Appendix C".to_string())?;
        if !kinds_line.contains("a `Historical` period (§7.2) admits only `Migration`") {
            return Err(
                "Appendix C `**Period kinds.**` does not state Historical admits only Migration"
                    .to_string(),
            );
        }
        let mut historical_admits = BTreeSet::new();
        historical_admits.insert("Migration".to_string());

        if !kinds_line.contains(
            "A special period (`Opening`, `Adjustment`, `Closing`) ending on or before the book's opening date is born `Locked`, keeps its kind, admits only `Migration`",
        ) {
            return Err("Appendix C `**Period kinds.**` does not state pre_opening rule".to_string());
        }
        let pre_opening_kinds = vec![
            PeriodKind::Opening,
            PeriodKind::Adjustment,
            PeriodKind::Closing,
        ];
        let mut pre_opening_admits = BTreeSet::new();
        pre_opening_admits.insert("Migration".to_string());

        // Parse §7.3 special-period class list from the plan
        let special_marker = "only `Adjusting`, `Closing`, `Elimination`, `Revision`, `Restatement`, and `Migration` classes may target a special period";
        let special_classes: BTreeSet<String> = if markdown.contains(special_marker) {
            [
                "Adjusting",
                "Closing",
                "Elimination",
                "Revision",
                "Restatement",
                "Migration",
            ]
            .into_iter()
            .map(str::to_string)
            .collect()
        } else {
            return Err("plan §7.3 special-period class list not found in markdown".to_string());
        };
        let mut special_period_admits = Vec::new();
        for kind in [
            PeriodKind::Opening,
            PeriodKind::Adjustment,
            PeriodKind::Closing,
        ] {
            special_period_admits.push((kind, special_classes.clone()));
        }

        Ok(Self {
            cells,
            qualifiers,
            historical_admits,
            pre_opening_kinds,
            pre_opening_admits,
            special_period_admits,
        })
    }

    /// Evaluate the plan's admissibility decision for `(class, state, family, kind, pre_opening)`.
    #[must_use]
    pub fn decide_cell(
        &self,
        class: &str,
        state: PeriodState,
        family: DispositionFamily,
        kind: PeriodKind,
        pre_opening: bool,
    ) -> Option<Decision> {
        if kind == PeriodKind::Historical && !self.historical_admits.contains(class) {
            return Some(Decision::Refuse);
        }
        if pre_opening
            && self.pre_opening_kinds.contains(&kind)
            && !self.pre_opening_admits.contains(class)
        {
            return Some(Decision::Refuse);
        }
        if let Some((_, allowed)) = self.special_period_admits.iter().find(|(k, _)| *k == kind)
            && !allowed.contains(class)
        {
            return Some(Decision::Refuse);
        }
        let effective_family = if class == "Resolution" {
            family
        } else {
            match family {
                DispositionFamily::Standard
                | DispositionFamily::Voids
                | DispositionFamily::Expires => DispositionFamily::Standard,
            }
        };
        self.cells
            .get(&(class.to_string(), state, effective_family))
            .cloned()
    }
}

fn split_md_row(line: &str) -> Vec<&str> {
    let trimmed = line.trim().trim_start_matches('|').trim_end_matches('|');
    let mut cols = Vec::new();
    let mut start = 0usize;
    let mut paren_depth = 0usize;
    let mut in_backticks = false;
    for (idx, ch) in trimmed.char_indices() {
        match ch {
            '`' => in_backticks = !in_backticks,
            '(' if !in_backticks => paren_depth = paren_depth.saturating_add(1),
            ')' if !in_backticks => paren_depth = paren_depth.saturating_sub(1),
            '|' if !in_backticks && paren_depth == 0 => {
                cols.push(trimmed[start..idx].trim());
                start = idx + 1;
            }
            _ => {}
        }
    }
    cols.push(trimmed[start..].trim());
    cols
}

fn extract_backticked_tokens(text: &str) -> Vec<String> {
    // Only extract backticked tokens before any parenthetical note `(...)`
    let prefix = text.split('(').next().unwrap_or(text);
    let mut out = Vec::new();
    let mut rest = prefix;
    while let Some(start) = rest.find('`') {
        let after = &rest[start + 1..];
        let Some(end) = after.find('`') else {
            break;
        };
        out.push(after[..end].to_string());
        rest = &after[end + 1..];
    }
    out
}

fn parse_plan_cell(
    class: &str,
    state: PeriodState,
    raw: &str,
) -> Result<(Decision, Decision, Decision, Option<String>), String> {
    if raw.contains(';') && class == "Resolution" {
        // Compound Resolution cell, e.g.:
        // "`Posts` W(`post_closed`); `Voids`/`Expires` Admit (the sweep's intrinsic `post_closed`)"
        // or "`Voids`/`Expires` Admit; `Posts` Refuse"
        let mut posts_dec = None;
        let mut releases_dec = None;
        for part in raw.split(';') {
            let p = part.trim();
            if p.starts_with("`Posts`") {
                let spec = p.trim_start_matches("`Posts`").trim();
                posts_dec = Some(parse_single_decision(class, state, spec)?.0);
            } else if p.starts_with("`Voids`/`Expires`") {
                let spec = p.trim_start_matches("`Voids`/`Expires`").trim();
                releases_dec = Some(parse_single_decision(class, state, spec)?.0);
            } else {
                return Err(format!(
                    "unrecognized compound Resolution clause `{p}` in ({class}, {})",
                    state.name()
                ));
            }
        }
        let p_dec =
            posts_dec.ok_or_else(|| format!("missing `Posts` in ({class}, {})", state.name()))?;
        let r_dec = releases_dec
            .ok_or_else(|| format!("missing `Voids`/`Expires` in ({class}, {})", state.name()))?;
        let qual = match (&p_dec, &r_dec) {
            (Decision::With { .. }, Decision::Admit) => Some("posts_only_with".to_string()),
            (Decision::Refuse, Decision::Admit) => Some("voids_expires".to_string()),
            _ => None,
        };
        return Ok((p_dec, r_dec.clone(), r_dec, qual));
    }

    let (dec, qual) = parse_single_decision(class, state, raw)?;
    Ok((dec.clone(), dec.clone(), dec, qual))
}

fn parse_single_decision(
    class: &str,
    state: PeriodState,
    raw: &str,
) -> Result<(Decision, Option<String>), String> {
    let trimmed = raw.trim();
    if trimmed == "Refuse" || trimmed.starts_with("Refuse ") {
        return Ok((Decision::Refuse, None));
    }
    if trimmed == "Admit" || trimmed.starts_with("Admit ") {
        return Ok((Decision::Admit, None));
    }
    if let Some(after_w) = trimmed.strip_prefix("W(") {
        let Some(close_idx) = after_w.find(')') else {
            return Err(format!(
                "unclosed W(...) in ({class}, {}): `{raw}`",
                state.name()
            ));
        };
        let inside = &after_w[..close_idx];
        let rest = after_w[close_idx + 1..].trim();
        let mut parts = inside.split(',');
        let op_raw = parts
            .next()
            .ok_or_else(|| format!("empty W() in ({class}, {})", state.name()))?
            .trim()
            .trim_matches('`');
        let approvals = match parts.next() {
            Some(n_str) => n_str.trim().parse::<u8>().map_err(|_| {
                format!(
                    "invalid approval count `{n_str}` in ({class}, {})",
                    state.name()
                )
            })?,
            None => 0,
        };
        let qual = if rest.contains("inside an `Approved` case")
            || rest.contains("inside a `Revision` case")
        {
            Some("case".to_string())
        } else if rest.contains("inside an open `MigrationRun`") {
            Some("run".to_string())
        } else {
            None
        };
        return Ok((
            Decision::With {
                op: op_raw.to_string(),
                approvals,
            },
            qual,
        ));
    }
    Err(format!(
        "unrecognized Appendix C decision `{raw}` in ({class}, {})",
        state.name()
    ))
}
