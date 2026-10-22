//! The amount law (plan §15.5): native GQL knows an amount only as a decimal
//! at its unit's scale, so the profile proves at rewrite time that a
//! statement never mixes units.
//!
//! - An aggregate over amounts (`SUM`, `AVG`, `MIN`, `MAX`, `COLLECT`) is
//!   confined to one unit: the statement pins the unit, or the same
//!   `RETURN`/`WITH` groups by it.
//! - An amount compared, ordered or filtered (`WHERE`, `ORDER BY`, a
//!   pattern's map) is pinned to one unit, every amount in that clause to
//!   the same one, and never compared with a literal: the native grammar has
//!   no exact decimal literal, and an integer is a different type.
//! - One expression that combines amounts of two bindings needs both pinned
//!   to the same unit.
//!
//! A unit is pinned by `x.unit_id = <literal>` on the amount's own binding,
//! or by its `IN_UNIT` unit `u` with `u.code = '<code>'` or
//! `u.unit_id = <literal>`, as a top-level conjunct of a `WHERE` with no
//! root `OR`, or in the pattern's own map (`(u:Unit {code: 'USD'})`). It is
//! grouped by a non-aggregate item naming `x.unit_id`, `u.code`, `u.unit_id`
//! or `u`. Anything the analysis cannot prove is refused, never admitted.

use std::collections::BTreeMap;

use crate::lex::{Kind, Lexed};
use crate::{Law, Refusal, clause_word};

/// The properties that hold an amount, in any label.
pub(crate) const AMOUNTS: &[&str] = &[
    "amount",
    "amount_bytes",
    "applied",
    "debits_posted",
    "credits_posted",
    "debits_pending",
    "credits_pending",
    "lower_bound",
    "upper_bound",
];

const AGGREGATES: &[&str] = &["SUM", "SUM_INT", "AVG", "AVG_INT", "MIN", "MAX", "COLLECT"];

const GROUP_FIX: &str = "aggregate per unit: RETURN u.code, SUM(l.amount) with (l)-[:IN_UNIT]->(u:Unit), or pin one unit with WHERE u.code = 'USD'";
const PIN_FIX: &str = "pin one unit: (l)-[:IN_UNIT]->(u:Unit {code: 'USD'}) or WHERE l.unit_id = <id>; an amount compares only with an amount of that unit";

/// A node pattern `(v:Label {key: literal})`.
pub(crate) struct Node {
    pub var: Option<String>,
    pub labels: Vec<String>,
    /// Map entries: key and the value's token index.
    map: Vec<(String, usize)>,
    open: usize,
    close: usize,
}

/// The node patterns among tokens `[from, to)` at the root.
pub(crate) fn nodes(lexed: &Lexed<'_>, from: usize, to: usize) -> Vec<Node> {
    let mut found = Vec::new();
    let mut i = from;
    while i < to {
        if !(lexed.root(i) && lexed.punct(i, '(')) {
            i += 1;
            continue;
        }
        let Some(close) = (i + 1..to).find(|&k| lexed.root(k) && lexed.punct(k, ')')) else {
            break;
        };
        let mut j = i + 1;
        let mut var = None;
        if lexed.kind(j) == Some(Kind::Word)
            && (lexed.punct(j + 1, ':') || lexed.punct(j + 1, ')') || lexed.punct(j + 1, '{'))
        {
            var = Some(lexed.str(j).to_string());
            j += 1;
        }
        let mut labels = Vec::new();
        while (lexed.punct(j, ':') || lexed.punct(j, '|') || lexed.punct(j, '&'))
            && lexed.kind(j + 1) == Some(Kind::Word)
        {
            labels.push(lexed.str(j + 1).to_string());
            j += 2;
        }
        let mut map = Vec::new();
        if lexed.punct(j, '{') {
            for k in j + 1..close {
                if lexed.tokens[k].parent == Some(j)
                    && lexed.kind(k) == Some(Kind::Word)
                    && lexed.punct(k + 1, ':')
                {
                    map.push((lexed.str(k).to_string(), k + 2));
                }
            }
        }
        found.push(Node {
            var,
            labels,
            map,
            open: i,
            close,
        });
        i = close + 1;
    }
    found
}

/// `(x)-[:IN_UNIT]->(u)` edges between consecutive nodes of one path, as
/// (amount binding, unit binding).
fn unit_edges(lexed: &Lexed<'_>, nodes: &[Node]) -> Vec<(String, String)> {
    let mut edges = Vec::new();
    for pair in nodes.windows(2) {
        let (a, b) = (&pair[0], &pair[1]);
        let between = a.close + 1..b.open;
        if between.is_empty()
            || between
                .clone()
                .any(|k| lexed.root(k) && lexed.punct(k, ','))
        {
            continue;
        }
        let in_unit = between.clone().any(|k| {
            lexed.word(k, "IN_UNIT") && (lexed.punct(k - 1, ':') || lexed.punct(k - 1, '|'))
        });
        if !in_unit {
            continue;
        }
        let left = lexed.punct(between.start, '<');
        let right = lexed.punct(between.end - 1, '>');
        match (&a.var, &b.var, left, right) {
            (Some(x), Some(u), false, true) => edges.push((x.clone(), u.clone())),
            (Some(u), Some(x), true, false) => edges.push((x.clone(), u.clone())),
            _ => {}
        }
    }
    edges
}

/// How a binding's unit is fixed: the property and the literal's text.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Pin {
    key: String,
    value: String,
}

struct Facts {
    labels: BTreeMap<String, Vec<String>>,
    /// amount binding → its IN_UNIT units.
    units: BTreeMap<String, Vec<String>>,
    pins: BTreeMap<String, Pin>,
}

impl Facts {
    fn pinned(&self, var: &str) -> Option<&Pin> {
        if let Some(pin) = self.pins.get(var).filter(|p| p.key == "unit_id") {
            return Some(pin);
        }
        self.units
            .get(var)
            .into_iter()
            .flatten()
            .find_map(|u| self.pins.get(u))
    }

    fn is_unit(&self, var: &str) -> bool {
        self.labels
            .get(var)
            .is_some_and(|labels| labels.iter().any(|l| l == "Unit"))
    }

    /// Tokens `[from, to)` name a unit key of `var`.
    fn groups(&self, lexed: &Lexed<'_>, var: &str, from: usize, to: usize) -> bool {
        let partners = self.units.get(var);
        (from..to).any(|k| {
            if lexed.kind(k) != Some(Kind::Word) || (k > 0 && lexed.punct(k - 1, '.')) {
                return false;
            }
            let name = lexed.str(k);
            let property = if lexed.punct(k + 1, '.') {
                Some(lexed.str(k + 2))
            } else {
                None
            };
            if name == var {
                return property == Some("unit_id");
            }
            partners.is_some_and(|units| units.iter().any(|u| u == name))
                && matches!(property, None | Some("code" | "unit_id"))
        })
    }
}

fn literal(lexed: &Lexed<'_>, i: usize) -> bool {
    matches!(
        lexed.kind(i),
        Some(Kind::Digits | Kind::Quoted | Kind::Float)
    )
}

fn operator(lexed: &Lexed<'_>, i: usize) -> bool {
    lexed.punct(i, '=') || lexed.punct(i, '<') || lexed.punct(i, '>') || lexed.punct(i, '!')
}

/// The reference at tokens `[start, end)` is compared with a literal.
fn compared_with_literal(lexed: &Lexed<'_>, start: usize, end: usize) -> bool {
    let mut k = end;
    let mut saw = false;
    while operator(lexed, k) {
        saw = true;
        k += 1;
    }
    if lexed.punct(k, '-') {
        k += 1;
    }
    if saw && literal(lexed, k) {
        return true;
    }
    let mut k = start;
    let mut saw = false;
    while k > 0 && operator(lexed, k - 1) {
        saw = true;
        k -= 1;
    }
    saw && k > 0 && literal(lexed, k - 1)
}

pub(crate) fn aggregated(lexed: &Lexed<'_>, i: usize) -> bool {
    let mut parent = lexed.tokens[i].parent;
    while let Some(p) = parent {
        if lexed.punct(p, '(')
            && p > 0
            && lexed.kind(p - 1) == Some(Kind::Word)
            && AGGREGATES.iter().any(|a| lexed.word(p - 1, a))
        {
            return true;
        }
        parent = lexed.tokens[p].parent;
    }
    false
}

/// Root clause regions: (keyword token, end token).
fn clauses(lexed: &Lexed<'_>) -> Vec<(usize, usize)> {
    let starts: Vec<usize> = (0..lexed.tokens.len())
        .filter(|&i| clause_word(lexed, i))
        .collect();
    starts
        .iter()
        .enumerate()
        .map(|(n, &start)| {
            (
                start,
                starts.get(n + 1).copied().unwrap_or(lexed.tokens.len()),
            )
        })
        .collect()
}

fn facts(lexed: &Lexed<'_>, regions: &[(usize, usize)]) -> Facts {
    let mut facts = Facts {
        labels: BTreeMap::new(),
        units: BTreeMap::new(),
        pins: BTreeMap::new(),
    };
    for &(start, end) in regions {
        if !(lexed.word(start, "MATCH") || lexed.word(start, "OPTIONAL")) {
            continue;
        }
        let found = nodes(lexed, start, end);
        for node in &found {
            if let Some(var) = &node.var {
                facts
                    .labels
                    .entry(var.clone())
                    .or_default()
                    .extend(node.labels.iter().cloned());
            }
        }
        for (x, u) in unit_edges(lexed, &found) {
            facts.units.entry(x).or_default().push(u);
        }
        for node in &found {
            let Some(var) = &node.var else { continue };
            for (key, value) in &node.map {
                let unit_key =
                    key == "unit_id" || (key == "code" && node.labels.iter().any(|l| l == "Unit"));
                if unit_key && matches!(lexed.kind(*value), Some(Kind::Digits | Kind::Quoted)) {
                    facts.pins.insert(
                        var.clone(),
                        Pin {
                            key: key.clone(),
                            value: lexed.str(*value).to_string(),
                        },
                    );
                }
            }
        }
    }
    for &(start, end) in regions {
        if !lexed.word(start, "WHERE") {
            continue;
        }
        let body = start + 1..end;
        if body
            .clone()
            .any(|k| lexed.root(k) && (lexed.word(k, "OR") || lexed.word(k, "XOR")))
        {
            continue;
        }
        let mut conjuncts = Vec::new();
        let mut from = body.start;
        for k in body.clone() {
            if lexed.root(k) && lexed.word(k, "AND") {
                conjuncts.push(from..k);
                from = k + 1;
            }
        }
        conjuncts.push(from..body.end);
        for c in conjuncts {
            if c.len() != 5 {
                continue;
            }
            let s = c.start;
            let (var, property, value) = if lexed.kind(s) == Some(Kind::Word)
                && lexed.punct(s + 1, '.')
                && lexed.punct(s + 3, '=')
                && matches!(lexed.kind(s + 4), Some(Kind::Digits | Kind::Quoted))
            {
                (s, s + 2, s + 4)
            } else if matches!(lexed.kind(s), Some(Kind::Digits | Kind::Quoted))
                && lexed.punct(s + 1, '=')
                && lexed.kind(s + 2) == Some(Kind::Word)
                && lexed.punct(s + 3, '.')
            {
                (s + 2, s + 4, s)
            } else {
                continue;
            };
            let name = lexed.str(var).to_string();
            let key = lexed.str(property).to_string();
            if key == "unit_id" || (key == "code" && facts.is_unit(&name)) {
                facts.pins.insert(
                    name,
                    Pin {
                        key,
                        value: lexed.str(value).to_string(),
                    },
                );
            }
        }
    }
    facts
}

/// One amount reference: the binding (None for an alias), the tokens it
/// spans and its property.
struct Reference {
    var: Option<String>,
    pin: Option<Pin>,
    start: usize,
    end: usize,
}

fn refused(lexed: &Lexed<'_>, i: usize, message: String, fix: &str) -> Refusal {
    let at = lexed.tokens.get(i).map_or(0, |t| t.start);
    Refusal::new(Law::Amount, at, &message, fix)
}

/// Check the amount law. `Ok(true)`: the statement aggregates an amount,
/// which the profile computes itself ([`crate::aggregate`]).
pub(crate) fn check(lexed: &Lexed<'_>) -> Result<bool, Refusal> {
    let regions = clauses(lexed);
    let facts = facts(lexed, &regions);
    let mut sums_amounts = false;
    // Amount-valued aliases a RETURN or WITH item defines, with the unit
    // pin its source carries.
    let mut aliases: BTreeMap<String, Option<Pin>> = BTreeMap::new();
    for &(start, end) in &regions {
        let projection = lexed.word(start, "RETURN") || lexed.word(start, "WITH");
        let pattern = lexed.word(start, "MATCH") || lexed.word(start, "OPTIONAL");
        if pattern {
            for node in nodes(lexed, start, end) {
                if let Some((key, value)) = node
                    .map
                    .iter()
                    .find(|(key, _)| AMOUNTS.contains(&key.as_str()))
                {
                    return Err(refused(
                        lexed,
                        *value,
                        format!("`{key}` in a pattern's map compares an amount with a literal"),
                        PIN_FIX,
                    ));
                }
            }
        }
        let mut items = Vec::new();
        if projection {
            let mut from = start + 1;
            for k in start + 1..end {
                if lexed.root(k) && lexed.punct(k, ',') {
                    items.push(from..k);
                    from = k + 1;
                }
            }
            items.push(from..end);
        } else {
            items.push(start + 1..end);
        }
        let mut clause_pins: Vec<(usize, Option<Pin>)> = Vec::new();
        for item in &items {
            let mut references = Vec::new();
            for k in item.clone() {
                if lexed.kind(k) != Some(Kind::Word) || (k > 0 && lexed.punct(k - 1, '.')) {
                    continue;
                }
                let name = lexed.str(k);
                if lexed.punct(k + 1, '.') && AMOUNTS.contains(&lexed.str(k + 2)) {
                    if lexed.word(k + 3, "IS") {
                        continue;
                    }
                    if aggregated(lexed, k) {
                        sums_amounts = true;
                    }
                    references.push(Reference {
                        var: Some(name.to_string()),
                        pin: facts.pinned(name).cloned(),
                        start: k,
                        end: k + 3,
                    });
                } else if let Some(pin) = aliases.get(name)
                    && !lexed.punct(k + 1, '.')
                    && !lexed.punct(k + 1, '(')
                    && !(k > 0 && lexed.word(k - 1, "AS"))
                {
                    references.push(Reference {
                        var: None,
                        pin: pin.clone(),
                        start: k,
                        end: k + 1,
                    });
                }
            }
            if references.is_empty() {
                continue;
            }
            let mut distinct: Vec<&Reference> = Vec::new();
            for r in &references {
                if !distinct.iter().any(|d| d.var == r.var && d.var.is_some()) {
                    distinct.push(r);
                }
            }
            if distinct.len() > 1
                && !distinct
                    .windows(2)
                    .all(|w| w[0].pin.is_some() && w[0].pin == w[1].pin)
            {
                let pinned = distinct.iter().all(|d| d.pin.is_some());
                return Err(refused(
                    lexed,
                    references[0].start,
                    format!(
                        "`{}` combines amounts of {} bindings {}",
                        lexed.text[lexed.tokens[item.start].start..lexed.tokens[item.end - 1].end]
                            .trim(),
                        distinct.len(),
                        if pinned {
                            "pinned to different units"
                        } else {
                            "not pinned to one unit"
                        }
                    ),
                    PIN_FIX,
                ));
            }
            for r in &references {
                let shown = &lexed.text[lexed.tokens[r.start].start..lexed.tokens[r.end - 1].end];
                if projection && aggregated(lexed, r.start) {
                    let grouped = r.var.as_deref().is_some_and(|var| {
                        items.iter().any(|other| {
                            !other.clone().any(|k| {
                                AGGREGATES.iter().any(|a| lexed.word(k, a))
                                    && lexed.punct(k + 1, '(')
                            }) && facts.groups(lexed, var, other.start, other.end)
                        })
                    });
                    if r.pin.is_none() && !grouped {
                        return Err(refused(
                            lexed,
                            r.start,
                            format!("aggregating `{shown}` adds amounts of every unit"),
                            GROUP_FIX,
                        ));
                    }
                } else if !projection {
                    if compared_with_literal(lexed, r.start, r.end) {
                        return Err(refused(
                            lexed,
                            r.start,
                            format!(
                                "`{shown}` is compared with a literal; the native grammar has no exact decimal literal"
                            ),
                            PIN_FIX,
                        ));
                    }
                    if r.pin.is_none() {
                        return Err(refused(
                            lexed,
                            r.start,
                            format!("`{shown}` is compared or ordered across units"),
                            PIN_FIX,
                        ));
                    }
                    clause_pins.push((r.start, r.pin.clone()));
                }
            }
            if projection
                && item.len() >= 2
                && lexed.word(item.end - 2, "AS")
                && lexed.kind(item.end - 1) == Some(Kind::Word)
            {
                // Two or more bindings in one item were proved pinned alike.
                aliases.insert(lexed.str(item.end - 1).to_string(), distinct[0].pin.clone());
            }
        }
        if let Some((first, pin)) = clause_pins.first()
            && clause_pins.iter().any(|(_, other)| other != pin)
        {
            return Err(refused(
                lexed,
                *first,
                "one clause compares amounts pinned to different units".to_string(),
                PIN_FIX,
            ));
        }
    }
    Ok(sums_amounts)
}
