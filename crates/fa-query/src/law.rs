//! The amount law (plan §15.5): native GQL knows an amount only as a decimal
//! at its unit's scale, so the profile proves at rewrite time that a
//! statement never mixes units.
//!
//! - An aggregate over amounts (`SUM`, `AVG`, `MIN`, `MAX`, `COLLECT`,
//!   `COUNT(DISTINCT ...)`) is
//!   confined to one unit: the statement pins the unit, or the same
//!   `RETURN`/`WITH` groups by it.
//! - An amount compared, ordered or filtered (including predicates in
//!   `RETURN`, `WITH` and `CASE`) is pinned to one unit. Compared amounts
//!   share that unit and are never compared with a literal: the native grammar has
//!   no exact decimal literal, and an integer is a different type.
//! - One expression that combines amounts of two bindings needs both pinned
//!   to the same unit.
//!
//! A unit is pinned by `x.unit_id = <literal>` on the amount's own binding,
//! or by its `IN_UNIT` unit `u` with `u.code = '<code>'` or
//! `u.unit_id = <literal>`, as a top-level conjunct of a `WHERE` with no
//! root `OR`, or in the pattern's own map (`(u:Unit {code: 'USD'})`). It is
//! linked by exactly one directed `IN_UNIT` hop: zero-hop/longer walks and
//! relationship alternatives do not establish the endpoint's unit identity.
//! A map pin is one complete scalar literal, never the prefix of an expression.
//! A unit is grouped by a non-aggregate item that is exactly `x.unit_id`, `u.code`,
//! `u.unit_id` or `u` (an expression that only mentions one, such as
//! `x.unit_id * 0`, groups nothing). A pin holds in its scope: a `WITH`
//! passes on only the bindings it projects unchanged, a `UNION` arm starts
//! afresh, and an `OPTIONAL MATCH` (its map or its `WHERE`) pins nothing,
//! since an unmatched row is null-extended, not dropped. Anything the
//! analysis cannot prove is refused, never admitted.

use std::collections::BTreeMap;
use std::ops::Range;

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
    /// Map entries: key and the complete value's token range.
    map: Vec<(String, std::ops::Range<usize>)>,
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
                    let end = (k + 2..close)
                        .find(|&at| {
                            (lexed.tokens[at].parent == Some(j) && lexed.punct(at, ','))
                                || (lexed.tokens[at].parent == Some(i) && lexed.punct(at, '}'))
                        })
                        .unwrap_or(close);
                    map.push((lexed.str(k).to_string(), k + 2..end));
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

/// Whether the complete relationship between two nodes proves a single
/// directed IN_UNIT hop, and if so whether its direction is reversed.
/// Keywords are case-insensitive in GQL; relation names are not.
fn single_unit_hop(lexed: &Lexed<'_>, from: usize, to: usize) -> Option<bool> {
    let mut at = from;
    let reversed = lexed.punct(at, '<');
    at += usize::from(reversed);
    if !lexed.punct(at, '-') || !lexed.punct(at + 1, '[') {
        return None;
    }
    at += 2;
    if lexed.kind(at) == Some(Kind::Word) && lexed.punct(at + 1, ':') {
        at += 1; // Optional relationship binding, as in [r:IN_UNIT].
    }
    if !lexed.punct(at, ':') || lexed.str(at + 1) != "IN_UNIT" {
        return None;
    }
    at += 2;
    let one =
        |index| lexed.kind(index) == Some(Kind::Digits) && lexed.str(index).parse::<u16>() == Ok(1);
    let inner_bounds = lexed.punct(at, '*');
    if inner_bounds {
        at += 1;
        if one(at) {
            at += 1;
            if lexed.punct(at, '.') && lexed.punct(at + 1, '.') {
                at += 2;
                if !one(at) {
                    return None;
                }
                at += 1;
            }
        } else if lexed.punct(at, '.') && lexed.punct(at + 1, '.') && one(at + 2) {
            // The native Cypher spelling *..1 has an implicit lower bound of 1.
            at += 3;
        } else {
            return None;
        }
    }
    if !lexed.punct(at, ']') || !lexed.punct(at + 1, '-') {
        return None;
    }
    at += 2;
    if !reversed {
        if !lexed.punct(at, '>') {
            return None;
        }
        at += 1;
    }
    if lexed.punct(at, '{') {
        // Native GQL postfix {,1} starts at zero, so only {1} or {1,1}
        // proves one hop. Native syntax also rejects two quantifiers.
        if inner_bounds || !one(at + 1) {
            return None;
        }
        at += 2;
        if lexed.punct(at, ',') {
            if !one(at + 1) {
                return None;
            }
            at += 2;
        }
        if !lexed.punct(at, '}') {
            return None;
        }
        at += 1;
    }
    (at == to).then_some(reversed)
}

/// Exact `(x)-[:IN_UNIT]->(u)` edges between consecutive nodes of one path,
/// as (amount binding, unit binding). A mention of IN_UNIT inside a broader
/// walk or an alternative relation is not a unit witness.
fn unit_edges(lexed: &Lexed<'_>, nodes: &[Node]) -> Vec<(String, String)> {
    let mut edges = Vec::new();
    for pair in nodes.windows(2) {
        let (a, b) = (&pair[0], &pair[1]);
        let Some(reversed) = single_unit_hop(lexed, a.close + 1, b.open) else {
            continue;
        };
        match (&a.var, &b.var, reversed) {
            (Some(x), Some(u), false) => edges.push((x.clone(), u.clone())),
            (Some(u), Some(x), true) => edges.push((x.clone(), u.clone())),
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

/// What one scope proves about its bindings.
#[derive(Default)]
struct Facts {
    labels: BTreeMap<String, Vec<String>>,
    /// amount binding → its IN_UNIT units.
    units: BTreeMap<String, Vec<String>>,
    pins: BTreeMap<String, Pin>,
    /// A binding a `WITH` passed on with the unit it was pinned to before.
    carried: BTreeMap<String, Pin>,
}

impl Facts {
    fn pinned(&self, var: &str) -> Option<&Pin> {
        if let Some(pin) = self.carried.get(var) {
            return Some(pin);
        }
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

    /// The item at tokens `[from, to)` is a unit key of `var` and nothing
    /// else: `var.unit_id`, or its IN_UNIT unit `u`, `u.code` or
    /// `u.unit_id`, optionally named with `AS` (and after the `DISTINCT` of
    /// a first item). An expression that only mentions one, such as
    /// `var.unit_id * 0` or `size(u.code)`, has one value for every unit.
    fn groups(&self, lexed: &Lexed<'_>, var: &str, from: usize, to: usize) -> bool {
        let from = if lexed.word(from, "DISTINCT") {
            from + 1
        } else {
            from
        };
        let to =
            if to >= from + 3 && lexed.word(to - 2, "AS") && lexed.kind(to - 1) == Some(Kind::Word)
            {
                to - 2
            } else {
                to
            };
        let partner = |name: &str| {
            self.units
                .get(var)
                .is_some_and(|units| units.iter().any(|u| u == name))
        };
        if lexed.kind(from) != Some(Kind::Word) {
            return false;
        }
        let name = lexed.str(from);
        match to.saturating_sub(from) {
            1 => partner(name),
            3 if lexed.punct(from + 1, '.') && lexed.kind(from + 2) == Some(Kind::Word) => {
                let property = lexed.str(from + 2);
                (name == var && property == "unit_id")
                    || (partner(name) && matches!(property, "code" | "unit_id"))
            }
            _ => false,
        }
    }

    /// Every binding this scope knows.
    fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .labels
            .keys()
            .chain(self.units.keys())
            .chain(self.pins.keys())
            .chain(self.carried.keys())
            .cloned()
            .collect();
        names.sort();
        names.dedup();
        names
    }

    /// The facts a `WITH` at tokens `[start, end)` passes on to the scope
    /// after it. Only a binding it projects unchanged (`v`, `v AS w` or `*`)
    /// keeps its labels, its own pin, the unit it is pinned to here, and its
    /// unit edges to units projected with it; every other name is new.
    fn carry(&self, lexed: &Lexed<'_>, start: usize, end: usize) -> Facts {
        let first = if lexed.word(start + 1, "DISTINCT") {
            start + 2
        } else {
            start + 1
        };
        let mut from = first;
        let mut items = Vec::new();
        for k in first..end {
            if lexed.root(k) && lexed.punct(k, ',') {
                items.push(from..k);
                from = k + 1;
            }
        }
        items.push(from..end);
        let mut renamed: Vec<(String, String)> = Vec::new();
        for item in items {
            if item.len() == 1 && lexed.punct(item.start, '*') {
                renamed.extend(self.names().into_iter().map(|n| (n.clone(), n)));
            } else if lexed.kind(item.start) == Some(Kind::Word)
                && (item.len() == 1
                    || (item.len() == 3
                        && lexed.word(item.start + 1, "AS")
                        && lexed.kind(item.start + 2) == Some(Kind::Word)))
            {
                renamed.push((
                    lexed.str(item.start).to_string(),
                    lexed.str(item.end - 1).to_string(),
                ));
            }
        }
        let new_names = |old: &str| -> Vec<String> {
            renamed
                .iter()
                .filter(|(o, _)| o == old)
                .map(|(_, n)| n.clone())
                .collect()
        };
        let mut next = Facts::default();
        for (old, new) in &renamed {
            if let Some(labels) = self.labels.get(old) {
                next.labels.insert(new.clone(), labels.clone());
            }
            if let Some(pin) = self.pins.get(old) {
                next.pins.insert(new.clone(), pin.clone());
            }
            if let Some(pin) = self.pinned(old) {
                next.carried.insert(new.clone(), pin.clone());
            }
            let units: Vec<String> = self
                .units
                .get(old)
                .into_iter()
                .flatten()
                .flat_map(|u| new_names(u))
                .collect();
            if !units.is_empty() {
                next.units.entry(new.clone()).or_default().extend(units);
            }
        }
        next
    }

    /// A `MATCH` at tokens `[start, end)`: its labels, and unless it is
    /// optional (where an unmatched row is null-extended, not dropped) its
    /// IN_UNIT edges and the unit keys its maps fix.
    fn pattern(&mut self, lexed: &Lexed<'_>, start: usize, end: usize, optional: bool) {
        let found = nodes(lexed, start, end);
        for node in &found {
            if let Some(var) = &node.var {
                self.labels
                    .entry(var.clone())
                    .or_default()
                    .extend(node.labels.iter().cloned());
            }
        }
        if optional {
            return;
        }
        for (x, u) in unit_edges(lexed, &found) {
            self.units.entry(x).or_default().push(u);
        }
        for node in &found {
            let Some(var) = &node.var else { continue };
            for (key, value) in &node.map {
                let unit_key =
                    key == "unit_id" || (key == "code" && node.labels.iter().any(|l| l == "Unit"));
                if unit_key
                    && value.len() == 1
                    && matches!(lexed.kind(value.start), Some(Kind::Digits | Kind::Quoted))
                    && node.map.iter().filter(|(other, _)| other == key).count() == 1
                {
                    self.pins.insert(
                        var.clone(),
                        Pin {
                            key: key.clone(),
                            value: lexed.str(value.start).to_string(),
                        },
                    );
                }
            }
        }
    }

    /// A `WHERE` at tokens `[start, end)`: the unit keys its top-level
    /// equality conjuncts fix, when it has no root `OR`.
    fn where_pins(&mut self, lexed: &Lexed<'_>, start: usize, end: usize) {
        let body = start + 1..end;
        if body
            .clone()
            .any(|k| lexed.root(k) && (lexed.word(k, "OR") || lexed.word(k, "XOR")))
        {
            return;
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
            if key == "unit_id" || (key == "code" && self.is_unit(&name)) {
                self.pins.insert(
                    name,
                    Pin {
                        key,
                        value: lexed.str(value).to_string(),
                    },
                );
            }
        }
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

/// A grouping parenthesis is transparent to an operand's type; a function
/// call is not. In particular, COUNT(amount) is a scalar, not an amount.
fn grouping_parenthesis(lexed: &Lexed<'_>, at: usize) -> bool {
    lexed.punct(at, '(')
        && (at == 0
            || lexed.kind(at - 1) != Some(Kind::Word)
            || clause_word(lexed, at - 1)
            || [
                "WHEN", "THEN", "ELSE", "CASE", "AND", "OR", "XOR", "NOT", "IN", "DISTINCT", "BY",
            ]
            .iter()
            .any(|word| lexed.word(at - 1, word)))
}

/// Widen one reference only through parentheses that enclose exactly it.
/// Parent/depth checks prevent crossing an expression or function argument.
fn grouped_reference(lexed: &Lexed<'_>, start: usize, end: usize) -> (usize, usize) {
    let (mut start, mut end) = (start, end);
    while start > 0 && grouping_parenthesis(lexed, start - 1) && lexed.punct(end, ')') {
        let open = start - 1;
        if lexed.tokens[start].parent != Some(open)
            || lexed.tokens[end].parent != lexed.tokens[open].parent
            || lexed.tokens[end].depth != lexed.tokens[open].depth
        {
            break;
        }
        start = open;
        end += 1;
    }
    (start, end)
}

fn null_test(lexed: &Lexed<'_>, start: usize, end: usize) -> bool {
    let (_, end) = grouped_reference(lexed, start, end);
    lexed.word(end, "IS")
        && (lexed.word(end + 1, "NULL")
            || (lexed.word(end + 1, "NOT") && lexed.word(end + 2, "NULL")))
}

fn simple_case_subject(lexed: &Lexed<'_>, start: usize, end: usize) -> bool {
    start > 0 && lexed.word(start - 1, "CASE") && lexed.word(end, "WHEN")
}

/// The simple CASE subject compared with this complete WHEN operand, if
/// any. Search outwards across preceding completed nested CASE expressions.
/// A searched CASE has no subject and therefore supplies no implicit operand.
fn case_subject_for_when(lexed: &Lexed<'_>, start: usize, end: usize) -> Option<usize> {
    if start == 0 || !lexed.word(start - 1, "WHEN") || !lexed.word(end, "THEN") {
        return None;
    }
    let mut nested = 0_usize;
    for k in (0..start - 1).rev() {
        if k > 0 && lexed.punct(k - 1, '.') {
            continue;
        }
        if lexed.word(k, "END") {
            nested += 1;
        } else if lexed.word(k, "CASE") {
            if nested == 0 {
                return (!lexed.word(k + 1, "WHEN")).then_some(k + 1);
            }
            nested -= 1;
        }
    }
    None
}

fn compared(lexed: &Lexed<'_>, start: usize, end: usize) -> bool {
    let (start, end) = grouped_reference(lexed, start, end);
    operator(lexed, end)
        || (start > 0 && operator(lexed, start - 1))
        || simple_case_subject(lexed, start, end)
        || case_subject_for_when(lexed, start, end).is_some()
}

fn starts_literal(lexed: &Lexed<'_>, mut at: usize) -> bool {
    while grouping_parenthesis(lexed, at) || lexed.punct(at, '-') || lexed.punct(at, '+') {
        at += 1;
    }
    literal(lexed, at)
}

/// The reference is compared with a literal, including grouping parentheses
/// on either operand and a literal's unary sign. The check is independent of
/// whether the containing predicate filters rows or projects a result.
fn compared_with_literal(lexed: &Lexed<'_>, start: usize, end: usize) -> bool {
    let (start, end) = grouped_reference(lexed, start, end);
    if case_subject_for_when(lexed, start, end).is_some_and(|at| starts_literal(lexed, at)) {
        return true;
    }
    // A simple CASE compares its subject with every WHEN operand, not just
    // the first one. Nested CASE arms belong to their own subject.
    if simple_case_subject(lexed, start, end) {
        let mut nested = 0_usize;
        for k in end..lexed.tokens.len() {
            if k > 0 && lexed.punct(k - 1, '.') {
                continue;
            }
            if lexed.word(k, "CASE") {
                nested += 1;
            } else if lexed.word(k, "END") {
                if nested == 0 {
                    break;
                }
                nested -= 1;
            } else if nested == 0 && lexed.word(k, "WHEN") && starts_literal(lexed, k + 1) {
                return true;
            }
        }
    }
    let mut k = end;
    let mut saw = false;
    while operator(lexed, k) {
        saw = true;
        k += 1;
    }
    if saw && starts_literal(lexed, k) {
        return true;
    }
    let mut k = start;
    let mut saw = false;
    while k > 0 && operator(lexed, k - 1) {
        saw = true;
        k -= 1;
    }
    while k > 0 && lexed.punct(k - 1, ')') {
        k -= 1;
    }
    saw && k > 0 && literal(lexed, k - 1)
}

/// A direct COUNT(amount) observes presence, not the amount's value. DISTINCT
/// compares values and is not exempt. A COUNT of an expression still evaluates
/// that expression: its comparisons and arithmetic must pass the amount law.
fn counted(lexed: &Lexed<'_>, i: usize) -> bool {
    let mut end = i + 1;
    while lexed.punct(end, '.') && lexed.kind(end + 1) == Some(Kind::Word) {
        end += 2;
    }
    let (start, end) = grouped_reference(lexed, i, end);
    let Some(parent) = lexed.tokens[start].parent else {
        return false;
    };
    parent > 0
        && lexed.punct(parent, '(')
        && lexed.word(parent - 1, "COUNT")
        && start == parent + 1
        && lexed.punct(end, ')')
        && lexed.tokens[end].depth == lexed.tokens[parent].depth
        && lexed.tokens[end].parent == lexed.tokens[parent].parent
}

/// COUNT(DISTINCT amount) compares amount values while removing duplicates.
/// It needs exact distinct aggregation, even though its output is an integer.
fn distinctly_counted(lexed: &Lexed<'_>, i: usize) -> bool {
    let mut parent = lexed.tokens[i].parent;
    while let Some(p) = parent {
        if p > 0
            && lexed.punct(p, '(')
            && lexed.word(p - 1, "COUNT")
            && lexed.word(p + 1, "DISTINCT")
        {
            return true;
        }
        parent = lexed.tokens[p].parent;
    }
    false
}

/// The bounds of one value beside IN or BETWEEN. Grouping, list literals and
/// function calls are complete operands; a property chain keeps its root.
/// More elaborate operands are refused below instead of guessed at.
fn operand_end(lexed: &Lexed<'_>, start: usize) -> usize {
    let mut at = start;
    while lexed.punct(at, '-') || lexed.punct(at, '+') {
        at += 1;
    }
    if at >= lexed.tokens.len() {
        return at;
    }
    if lexed.kind(at) == Some(Kind::Word) && lexed.punct(at + 1, '(') {
        at += 1;
    }
    let close = if lexed.punct(at, '(') {
        Some(')')
    } else if lexed.punct(at, '[') {
        Some(']')
    } else if lexed.punct(at, '{') {
        Some('}')
    } else {
        None
    };
    if let Some(close) = close {
        let depth = lexed.tokens[at].depth;
        at = (at + 1..lexed.tokens.len())
            .find(|&k| lexed.tokens[k].depth == depth && lexed.punct(k, close))
            .map_or(lexed.tokens.len(), |k| k + 1);
    } else {
        at += 1;
    }
    while lexed.punct(at, '.') && lexed.kind(at + 1) == Some(Kind::Word) {
        at += 2;
    }
    at
}

fn operand_start(lexed: &Lexed<'_>, end: usize) -> usize {
    let Some(mut at) = end.checked_sub(1) else {
        return 0;
    };
    let open = if lexed.punct(at, ')') {
        Some('(')
    } else if lexed.punct(at, ']') {
        Some('[')
    } else if lexed.punct(at, '}') {
        Some('{')
    } else {
        None
    };
    if let Some(open) = open {
        let depth = lexed.tokens[at].depth;
        at = (0..at)
            .rev()
            .find(|&k| lexed.tokens[k].depth == depth && lexed.punct(k, open))
            .unwrap_or(at);
        if open == '(' && !grouping_parenthesis(lexed, at) {
            at = at.saturating_sub(1);
        }
    }
    while at >= 2 && lexed.punct(at - 1, '.') && lexed.kind(at - 2) == Some(Kind::Word) {
        at -= 2;
    }
    if at > 0 && (lexed.punct(at - 1, '-') || lexed.punct(at - 1, '+')) {
        at -= 1;
    }
    at
}

fn compares_container(lexed: &Lexed<'_>, expression: Range<usize>) -> bool {
    let mut at = expression.start;
    while at < expression.end {
        if !operator(lexed, at) {
            at += 1;
            continue;
        }
        let start = operand_start(lexed, at).max(expression.start);
        let mut right = at + 1;
        while operator(lexed, right) {
            right += 1;
        }
        let end = operand_end(lexed, right).min(expression.end);
        if (start..end).any(|k| lexed.punct(k, '{') || lexed.punct(k, '[')) {
            return true;
        }
        at = right;
    }
    false
}

struct WordComparison {
    span: Range<usize>,
    has_literal: bool,
    complete: bool,
}

fn word_comparison_keyword(lexed: &Lexed<'_>, i: usize) -> bool {
    (lexed.word(i, "IN") || lexed.word(i, "BETWEEN"))
        && !(i > 0
            && (lexed.punct(i - 1, '.') || lexed.punct(i - 1, ':') || lexed.word(i - 1, "AS")))
        && !lexed.punct(i + 1, ':')
}

/// Membership and range predicates compare their operands just as = and <
/// do. Inspect both the subject and every list/range operand, so putting the
/// amount on the right cannot turn a literal into an exact decimal.
fn word_comparisons(lexed: &Lexed<'_>, item: Range<usize>) -> Vec<WordComparison> {
    let mut found = Vec::new();
    for k in item.clone() {
        if !word_comparison_keyword(lexed, k) {
            continue;
        }
        let left_end = if k > 0 && lexed.word(k - 1, "NOT") {
            k - 1
        } else {
            k
        };
        let start = operand_start(lexed, left_end).max(item.start);
        let mut end = operand_end(lexed, k + 1).min(item.end);
        let mut complete = start < left_end && k + 1 < end;
        if lexed.word(k, "BETWEEN") {
            if lexed.word(end, "AND") && end < item.end {
                let upper = end + 1;
                end = operand_end(lexed, upper).min(item.end);
                complete &= upper < end;
            } else {
                complete = false;
            }
        }
        found.push(WordComparison {
            span: start..end,
            has_literal: (start..end).any(|at| literal(lexed, at)),
            complete,
        });
    }
    found
}

/// A complete COUNT or an explicit top-level predicate produces a scalar.
/// Do not carry the units of its inputs onto its output alias. CASE and
/// other functions remain conservative: an inner predicate does not establish
/// the type of their result.
fn scalar_projection(lexed: &Lexed<'_>, mut start: usize, mut end: usize) -> bool {
    while grouping_parenthesis(lexed, start) && end > start + 1 && lexed.punct(end - 1, ')') {
        let depth = lexed.tokens[start].depth;
        if (start + 1..end - 1).any(|k| lexed.tokens[k].depth <= depth) {
            break;
        }
        start += 1;
        end -= 1;
    }
    if start >= end {
        return false;
    }
    let depth = lexed.tokens[start].depth;
    if lexed.word(start, "COUNT")
        && lexed.punct(start + 1, '(')
        && lexed.punct(end - 1, ')')
        && (start + 2..end - 1).all(|k| lexed.tokens[k].depth > depth)
    {
        return true;
    }
    if (start..end).any(|k| lexed.tokens[k].depth == depth && lexed.word(k, "CASE")) {
        return false;
    }
    (start..end).any(|k| {
        lexed.tokens[k].depth == depth
            && (operator(lexed, k)
                || word_comparison_keyword(lexed, k)
                || (lexed.word(k, "IS")
                    && (lexed.word(k + 1, "NULL")
                        || (lexed.word(k + 1, "NOT") && lexed.word(k + 2, "NULL")))))
    })
}

pub(crate) fn aggregated(lexed: &Lexed<'_>, i: usize) -> bool {
    if distinctly_counted(lexed, i) {
        return true;
    }
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

/// The facts of each scope, and the scope of each region. A `WITH` closes
/// a scope (its own items still read the scope before it) and a `UNION`
/// arm opens a new one with nothing carried over.
fn scopes(lexed: &Lexed<'_>, regions: &[(usize, usize)]) -> (Vec<Facts>, Vec<usize>) {
    let mut scopes = vec![Facts::default()];
    let mut scope_of = Vec::with_capacity(regions.len());
    for (n, &(start, end)) in regions.iter().enumerate() {
        let current = scopes.len() - 1;
        scope_of.push(current);
        let optional = |at: usize| at > 0 && lexed.word(at - 1, "OPTIONAL");
        if lexed.word(start, "UNION") {
            scopes.push(Facts::default());
        } else if lexed.word(start, "WITH") {
            let next = scopes[current].carry(lexed, start, end);
            scopes.push(next);
        } else if lexed.word(start, "MATCH") {
            scopes[current].pattern(lexed, start, end, optional(start));
        } else if lexed.word(start, "WHERE") {
            // An OPTIONAL MATCH's WHERE decides which rows are
            // null-extended; it keeps every row of the bindings before it.
            let after_optional = n > 0 && {
                let before = regions[n - 1].0;
                lexed.word(before, "MATCH") && optional(before)
            };
            if !after_optional {
                scopes[current].where_pins(lexed, start, end);
            }
        }
    }
    (scopes, scope_of)
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

/// What the amount law found in an admitted statement.
pub(crate) struct Amounts {
    /// The statement aggregates an amount, which the profile computes
    /// itself ([`crate::aggregate`]).
    pub aggregated: bool,
    /// The names a `RETURN` or `WITH` item gives an amount: aggregating one
    /// is aggregating an amount, so a null in it is refused, never skipped.
    pub aliases: Vec<String>,
}

/// Check the amount law.
pub(crate) fn check(lexed: &Lexed<'_>) -> Result<Amounts, Refusal> {
    check_with_amount_aliases(lexed, &[])
}

/// Procedure yields retain the unit provenance of their source leg. The
/// alias is an amount even though its spelling has no `.amount` property.
pub(crate) fn check_with_amount_aliases(
    lexed: &Lexed<'_>,
    amounts: &[(&str, &str)],
) -> Result<Amounts, Refusal> {
    let regions = clauses(lexed);
    let (scopes, scope_of) = scopes(lexed, &regions);
    let mut sums_amounts = false;
    // Amount-valued aliases a RETURN or WITH item defines, with the unit
    // pin its source carries.
    let mut aliases: BTreeMap<String, Option<Pin>> = BTreeMap::new();
    for (n, &(start, end)) in regions.iter().enumerate() {
        let facts = &scopes[scope_of[n]];
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
                        value.start,
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
            let expression_end = if item.len() >= 3
                && lexed.word(item.end - 2, "AS")
                && lexed.kind(item.end - 1) == Some(Kind::Word)
            {
                item.end - 2
            } else {
                item.end
            };
            if item.clone().any(|k| {
                lexed.punct(k, '.')
                    && lexed.punct(k + 1, '*')
                    && lexed.tokens[k].parent.is_some_and(|p| lexed.punct(p, '{'))
            }) {
                // A complete raw RETURN n{.*} only renders properties. Keep
                // a named result conservative so a later ORDER BY row.field
                // cannot use it as an untyped amount carrier.
                if lexed.word(start, "RETURN")
                    && expression_end == item.start + 5
                    && lexed.kind(item.start) == Some(Kind::Word)
                    && lexed.punct(item.start + 1, '{')
                    && lexed.punct(item.start + 2, '.')
                    && lexed.punct(item.start + 3, '*')
                    && lexed.punct(item.start + 4, '}')
                {
                    if expression_end < item.end {
                        aliases.insert(lexed.str(item.end - 1).to_string(), None);
                    }
                    continue;
                }
                return Err(refused(
                    lexed,
                    item.start,
                    "a wildcard map projection does not establish amount provenance".to_string(),
                    "name the required scalar properties explicitly; keep amounts and their unit keys as separate columns",
                ));
            }
            let mut references = Vec::new();
            for k in item.clone() {
                if lexed.kind(k) != Some(Kind::Word) || counted(lexed, k) {
                    continue;
                }
                let name = lexed.str(k);
                if k > 0 && lexed.punct(k - 1, '.') {
                    // `l{.amount}` is the same value as an explicit map field,
                    // though no binding immediately precedes its dot.
                    if AMOUNTS.contains(&name)
                        && lexed.tokens[k].parent.is_some_and(|p| {
                            lexed.punct(p, '{')
                                && (k == p + 2 || (k >= 2 && lexed.punct(k - 2, ',')))
                        })
                    {
                        sums_amounts |= aggregated(lexed, k);
                        references.push(Reference {
                            var: None,
                            pin: None,
                            start: k - 1,
                            end: k + 1,
                        });
                    }
                    continue;
                }
                let mut end = k + 1;
                while lexed.punct(end, '.') && lexed.kind(end + 1) == Some(Kind::Word) {
                    end += 2;
                }
                if aliases.contains_key(name) && (end > k + 1 || lexed.punct(end, '[')) {
                    return Err(refused(
                        lexed,
                        k,
                        format!(
                            "extracting from amount alias `{name}` loses its scalar unit provenance"
                        ),
                        "project the amount directly as a scalar WITH alias, retain its unit pin, then aggregate that scalar",
                    ));
                }
                if end > k + 1 && AMOUNTS.contains(&lexed.str(end - 1)) {
                    if null_test(lexed, k, end) {
                        continue;
                    }
                    if aggregated(lexed, k) {
                        sums_amounts = true;
                    }
                    references.push(Reference {
                        var: (end == k + 3).then(|| name.to_string()),
                        pin: (end == k + 3)
                            .then(|| facts.pinned(name).cloned())
                            .flatten(),
                        start: k,
                        end,
                    });
                } else if let Some((_, source)) = amounts.iter().find(|(alias, _)| *alias == name)
                    && !lexed.punct(k + 1, '.')
                    && !lexed.punct(k + 1, '(')
                    && !(k > 0 && lexed.word(k - 1, "AS"))
                {
                    if null_test(lexed, k, k + 1) {
                        continue;
                    }
                    sums_amounts |= aggregated(lexed, k);
                    references.push(Reference {
                        var: Some((*source).to_string()),
                        pin: facts.pinned(source).cloned(),
                        start: k,
                        end: k + 1,
                    });
                } else if let Some(pin) = aliases.get(name)
                    && !lexed.punct(k + 1, '.')
                    && !lexed.punct(k + 1, '(')
                    && !(k > 0 && lexed.word(k - 1, "AS"))
                {
                    if null_test(lexed, k, k + 1) {
                        continue;
                    }
                    // `WITH l.amount AS x ... MAX(x)` aggregates an amount
                    // as `MAX(l.amount)` does.
                    sums_amounts |= aggregated(lexed, k);
                    references.push(Reference {
                        var: None,
                        pin: pin.clone(),
                        start: k,
                        end: k + 1,
                    });
                }
            }
            if references.is_empty() {
                // Rebinding an amount alias to a count or another scalar
                // ends the old provenance; do not retain a stale unit pin.
                if projection
                    && item.len() >= 3
                    && lexed.word(item.end - 2, "AS")
                    && lexed.kind(item.end - 1) == Some(Kind::Word)
                {
                    aliases.remove(lexed.str(item.end - 1));
                }
                continue;
            }
            let word_predicates = word_comparisons(lexed, item.clone());
            let has_map = (item.start..expression_end).any(|k| lexed.punct(k, '{'));
            let has_list = (item.start..expression_end).any(|k| lexed.punct(k, '['));
            if (has_map || has_list)
                && (compares_container(lexed, item.start..expression_end)
                    || (has_map && !word_predicates.is_empty()))
            {
                return Err(refused(
                    lexed,
                    references[0].start,
                    "a container comparison does not establish scalar amount operands or exact literals".to_string(),
                    "compare the scalar amounts directly after pinning their units; construct output maps and lists after the comparisons",
                ));
            }
            // A list in a complete IN predicate produces a Boolean. An
            // arbitrary container, map comparison or alias named IN does not.
            let scalar_membership = !has_map
                && !word_predicates.is_empty()
                && scalar_projection(lexed, item.start, expression_end)
                && references.iter().all(|r| {
                    word_predicates
                        .iter()
                        .any(|p| p.complete && p.span.start <= r.start && r.end <= p.span.end)
                });
            if lexed.word(start, "WITH") && (has_map || has_list) && !scalar_membership {
                return Err(refused(
                    lexed,
                    references[0].start,
                    "an intermediate amount container does not preserve scalar unit provenance"
                        .to_string(),
                    "project the amount directly: WITH l.amount AS value after pinning l's unit; render containers only in the final RETURN",
                ));
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
                if distinctly_counted(lexed, r.start)
                    && !(r.end == r.start + 3 && lexed.str(r.end - 1) == "amount")
                {
                    return Err(refused(
                        lexed,
                        r.start,
                        format!(
                            "COUNT(DISTINCT `{shown}`) has no retained exact leg amount representation"
                        ),
                        "retain the leg binding and count COUNT(DISTINCT l.amount), grouped by its unit or pinned to one unit; amount aliases do not retain the byte fallback",
                    ));
                }
                let word_predicate = word_predicates
                    .iter()
                    .find(|p| p.span.start <= r.start && r.end <= p.span.end);
                if compared_with_literal(lexed, r.start, r.end)
                    || word_predicate.is_some_and(|p| p.has_literal)
                {
                    return Err(refused(
                        lexed,
                        r.start,
                        format!(
                            "`{shown}` is compared with a literal; the native grammar has no exact decimal literal"
                        ),
                        PIN_FIX,
                    ));
                }
                if !word_predicates.is_empty()
                    && (word_predicate.is_some_and(|p| !p.complete)
                        || (word_predicate.is_none() && !compared(lexed, r.start, r.end)))
                {
                    return Err(refused(
                        lexed,
                        r.start,
                        format!(
                            "the IN/BETWEEN expression does not establish `{shown}`'s comparison operands"
                        ),
                        "compare scalar amounts with explicit =, < or > predicates after pinning their units; literals are not exact decimal amounts",
                    ));
                }
                if projection
                    && (compared(lexed, r.start, r.end) || word_predicate.is_some())
                    && r.pin.is_none()
                {
                    return Err(refused(
                        lexed,
                        r.start,
                        format!("`{shown}` is compared across units"),
                        PIN_FIX,
                    ));
                }
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
                            format!(
                                "aggregating `{shown}` {} amounts of every unit",
                                if distinctly_counted(lexed, r.start) {
                                    "compares"
                                } else {
                                    "adds"
                                }
                            ),
                            GROUP_FIX,
                        ));
                    }
                } else if !projection {
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
                let alias = lexed.str(item.end - 1).to_string();
                if scalar_projection(lexed, item.start, item.end - 2) {
                    aliases.remove(&alias);
                } else {
                    aliases.insert(alias, distinct[0].pin.clone());
                }
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
    Ok(Amounts {
        aggregated: sums_amounts,
        aliases: aliases.into_keys().collect(),
    })
}
