//! `registries/sod_policy.toml` — segregation of duties as data (plan §14.3,
//! Appendix C universal rules, FA-INV-10 clause `sod`).
//!
//! This module only parses and cross-checks the rows; the predicate itself
//! is `fa-policy`'s (the laws layer), and `fa-reference` carries an
//! independent oracle of it. Profiles and ops stay strings here: the
//! registry is pure data and names no type from a crate above it. The
//! `fa-policy` parity test proves every string resolves in its closed
//! vocabularies.

use std::collections::BTreeSet;

use fa_time::PeriodState;

use crate::toml::{Table, Value};
use crate::{Admissibility, ClassKind, Decision, EntryClasses, RegistryError, invalid, load};

const SOD_POLICY: &str = include_str!("../../../registries/sod_policy.toml");
const R: &str = "sod_policy.toml";

/// The profile names a rule may cite (plan §14.4 base profiles).
pub const PROFILES: &[&str] = &["Human", "Agent", "System"];

/// The exclusion vocabulary. `preparer` and `duplicate` are universal: every
/// rule (and the default) must carry both.
pub const EXCLUSIONS: &[&str] = &["preparer", "duplicate", "case_preparer", "session_lineage"];

/// Transitions a control rule may key on, per control class.
/// Every PeriodControl transition has a row (`transition_period` refuses
/// one that does not), so the vocabulary is the state machine's.
const PERIOD_TRANSITIONS: &[&str] = &["Open", "SoftClose", "Close", "Lock", "Reopen"];
const POLICY_TRANSITIONS: &[&str] = &["Activate"];
/// A TimeEvidence tick (plan §7.1a).
const TIME_TRANSITIONS: &[&str] = &["Tick"];
/// One sweep batch and its SweepCursor: the expiry sweep's Expires (§5.4) or
/// the scheduled-reversal sweep's Reversals (§7.6).
const SWEEP_TRANSITIONS: &[&str] = &["Expire", "Reverse"];
/// A scheduled reversal cancelled by lineage (§7.6).
const SCHEDULE_TRANSITIONS: &[&str] = &["Cancel"];
/// The control classes with no period state (book-scoped, plan §7.1).
const IMPORT_TRANSITIONS: &[&str] = &["Import"];
/// A legal hold's placement and release (plan §8.5).
const HOLD_TRANSITIONS: &[&str] = &["Place", "Release"];
/// A DraftSet's lifecycle (plan §15.2; fa-s7x).
const DRAFT_TRANSITIONS: &[&str] = &["Open", "Plan", "Promote", "Discard"];
/// A Scenario's lifecycle (plan §15.2; fa-k07b): never promoted.
const SCENARIO_TRANSITIONS: &[&str] = &["Open", "Plan", "Discard"];
const BOOK_SCOPED_CONTROLS: &[&str] = &[
    "PolicyControl",
    "TimeControl",
    "SweepControl",
    "ScheduleControl",
    "MigrationControl",
    "ImportControl",
    "HoldControl",
    "DraftControl",
    "ScenarioControl",
];
/// A MigrationRun's lifecycle (plan §8.6).
const MIGRATION_TRANSITIONS: &[&str] = &["Open", "Finalize", "Abandon"];

/// Which entry a rule governs. `state` is the period state the entry
/// resolves to (for `PeriodControl`, the transition's from-state); `None`
/// for a book-scoped control.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SodKey {
    pub class: String,
    pub state: Option<PeriodState>,
    /// `Some("Posts")` on a `Resolution` rule; `None` otherwise.
    pub disposition: Option<String>,
    /// `Some(..)` on control rules (`Lock`, `Reopen`, `Activate`).
    pub transition: Option<String>,
}

/// What a governed entry's approvals must satisfy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SodRequirement {
    /// The SoD minimum; the kernel requires `max(matrix approvals, approvers)`.
    pub approvers: u8,
    /// The op every approver's capability held when the approval was recorded.
    pub approver_op: String,
    /// Profiles that may approve, ascending, unique, non-empty.
    pub approver_profiles: Vec<String>,
    /// Human approvers required when the preparer holds an Agent-profile capability.
    pub agent_prepared_human_approvers: u8,
    /// Exclusions, ascending, unique; always ⊇ {duplicate, preparer}.
    pub exclusions: Vec<String>,
    pub cite: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SodRule {
    pub name: String,
    pub key: SodKey,
    /// The op the preparer needs: control rows only (the matrix owns it for
    /// posting classes, so it is `None` there).
    pub preparer_op: Option<String>,
    pub requirement: SodRequirement,
}

/// The parsed policy: the default requirement and the rules, sorted by key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SodPolicy {
    pub default: SodRequirement,
    pub rules: Vec<SodRule>,
}

fn str_list(t: &Table, key: &str) -> Result<Vec<String>, RegistryError> {
    let items = t
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(R, format!("missing array `{key}`")))?;
    let mut out = Vec::with_capacity(items.len());
    for v in items {
        let s = v
            .as_str()
            .ok_or_else(|| invalid(R, format!("`{key}` holds a non-string")))?;
        out.push(s.to_string());
    }
    Ok(out)
}

fn small(t: &Table, key: &str) -> Result<u8, RegistryError> {
    let v = t
        .get(key)
        .and_then(Value::as_int)
        .ok_or_else(|| invalid(R, format!("missing integer `{key}`")))?;
    u8::try_from(v).map_err(|_| invalid(R, format!("`{key}` = {v} is outside 0..=255")))
}

fn text(t: &Table, key: &str) -> Result<String, RegistryError> {
    t.get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| invalid(R, format!("missing string `{key}`")))
}

fn opt_text(t: &Table, key: &str) -> Result<Option<String>, RegistryError> {
    match t.get(key) {
        None => Ok(None),
        Some(v) => v
            .as_str()
            .map(|s| Some(s.to_string()))
            .ok_or_else(|| invalid(R, format!("`{key}` is not a string"))),
    }
}

/// A sorted, duplicate-free list drawn from `vocabulary`.
fn vocabulary_set(
    what: &str,
    mut items: Vec<String>,
    vocabulary: &[&str],
) -> Result<Vec<String>, RegistryError> {
    for i in &items {
        if !vocabulary.contains(&i.as_str()) {
            return Err(invalid(
                R,
                format!("unknown {what} `{i}` (registered: {vocabulary:?})"),
            ));
        }
    }
    let n = items.len();
    items.sort();
    items.dedup();
    if items.len() != n {
        return Err(invalid(R, format!("{what} listed twice")));
    }
    Ok(items)
}

fn requirement(t: &Table, scope: &str) -> Result<SodRequirement, RegistryError> {
    let approver_profiles = vocabulary_set("profile", str_list(t, "approver_profiles")?, PROFILES)?;
    if approver_profiles.is_empty() {
        return Err(invalid(R, format!("{scope}: no profile may approve")));
    }
    let exclusions = vocabulary_set("exclusion", str_list(t, "exclusions")?, EXCLUSIONS)?;
    for universal in ["preparer", "duplicate"] {
        if !exclusions.iter().any(|e| e == universal) {
            return Err(invalid(
                R,
                format!("{scope}: the universal exclusion `{universal}` is missing"),
            ));
        }
    }
    let approver_op = text(t, "approver_op")?;
    if approver_op.is_empty() {
        return Err(invalid(R, format!("{scope}: empty approver_op")));
    }
    Ok(SodRequirement {
        approvers: small(t, "approvers")?,
        approver_op,
        approver_profiles,
        agent_prepared_human_approvers: small(t, "agent_prepared_human_approvers")?,
        exclusions,
        cite: text(t, "cite")?,
    })
}

impl SodPolicy {
    /// Parse and cross-check `sod_policy.toml` against the class registry
    /// and the admissibility matrix: every class is registered; a posting
    /// rule names a period state, is not on a `refuse` cell, never loosens
    /// the cell's approval count, and leaves the preparer's op to the
    /// matrix; a control rule names its transition and preparer op; keys are
    /// unique.
    pub fn embedded(classes: &EntryClasses, matrix: &Admissibility) -> Result<Self, RegistryError> {
        Self::parse(SOD_POLICY, classes, matrix)
    }

    /// [`Self::embedded`] over arbitrary text (the negative tests feed it
    /// broken policies).
    pub fn parse(
        text_in: &str,
        classes: &EntryClasses,
        matrix: &Admissibility,
    ) -> Result<Self, RegistryError> {
        let doc = load(R, text_in)?;
        if doc.root.get("schema_version").and_then(Value::as_int) != Some(1) {
            return Err(invalid(R, "schema_version must be 1"));
        }
        let default = requirement(
            doc.tables
                .get("default")
                .ok_or_else(|| invalid(R, "missing [default]"))?,
            "[default]",
        )?;
        let mut rules: Vec<SodRule> = Vec::new();
        let mut names = BTreeSet::new();
        for t in doc.arrays.get("rule").unwrap_or(&Vec::new()) {
            let name = text(t, "name")?;
            if !names.insert(name.clone()) {
                return Err(invalid(R, format!("rule `{name}` defined twice")));
            }
            let class = text(t, "class")?;
            let registered = classes.by_name(&class).ok_or_else(|| {
                invalid(R, format!("{name}: `{class}` is not a registered class"))
            })?;
            let state = match opt_text(t, "state")? {
                None => None,
                Some(s) => Some(
                    PeriodState::from_name(&s)
                        .ok_or_else(|| invalid(R, format!("{name}: unknown state `{s}`")))?,
                ),
            };
            let disposition = opt_text(t, "disposition")?;
            let transition = opt_text(t, "transition")?;
            let preparer_op = opt_text(t, "preparer_op")?;
            let requirement = requirement(t, &name)?;
            match registered.kind {
                ClassKind::Posting => {
                    let state = state.ok_or_else(|| {
                        invalid(R, format!("{name}: a posting rule names its period state"))
                    })?;
                    if transition.is_some() || preparer_op.is_some() {
                        return Err(invalid(
                            R,
                            format!(
                                "{name}: transition/preparer_op are control-row keys; the matrix owns a posting class's op"
                            ),
                        ));
                    }
                    let release = match disposition.as_deref() {
                        None => false,
                        Some("Posts") if class == "Resolution" => false,
                        Some(d) => {
                            return Err(invalid(
                                R,
                                format!(
                                    "{name}: disposition `{d}` (only Resolution keys on Posts)"
                                ),
                            ));
                        }
                    };
                    if class == "Resolution" && disposition.is_none() {
                        return Err(invalid(
                            R,
                            format!("{name}: a Resolution rule names its disposition (Posts)"),
                        ));
                    }
                    match matrix.decide_disposition(&class, state, release) {
                        Some(Decision::Refuse) | None => {
                            return Err(invalid(
                                R,
                                format!(
                                    "{name}: ({class}, {}) is refused by the matrix; a rule there is dead",
                                    state.name()
                                ),
                            ));
                        }
                        Some(Decision::With { approvals, .. })
                            if requirement.approvers < approvals =>
                        {
                            return Err(invalid(
                                R,
                                format!(
                                    "{name}: {} approver(s) loosens the matrix's {approvals} for ({class}, {})",
                                    requirement.approvers,
                                    state.name()
                                ),
                            ));
                        }
                        Some(_) => {}
                    }
                }
                ClassKind::Control => {
                    if disposition.is_some() {
                        return Err(invalid(R, format!("{name}: a control has no disposition")));
                    }
                    let allowed: &[&str] = match class.as_str() {
                        "PeriodControl" => PERIOD_TRANSITIONS,
                        "PolicyControl" => POLICY_TRANSITIONS,
                        "TimeControl" => TIME_TRANSITIONS,
                        "SweepControl" => SWEEP_TRANSITIONS,
                        "ScheduleControl" => SCHEDULE_TRANSITIONS,
                        "MigrationControl" => MIGRATION_TRANSITIONS,
                        "ImportControl" => IMPORT_TRANSITIONS,
                        "HoldControl" => HOLD_TRANSITIONS,
                        "DraftControl" => DRAFT_TRANSITIONS,
                        "ScenarioControl" => SCENARIO_TRANSITIONS,
                        other => {
                            return Err(invalid(
                                R,
                                format!("{name}: no transitions are registered for `{other}`"),
                            ));
                        }
                    };
                    let tr = transition.as_deref().ok_or_else(|| {
                        invalid(R, format!("{name}: a control rule names its transition"))
                    })?;
                    if !allowed.contains(&tr) {
                        return Err(invalid(
                            R,
                            format!("{name}: `{tr}` is not a {class} transition ({allowed:?})"),
                        ));
                    }
                    match (class.as_str(), state) {
                        ("PeriodControl", None) => {
                            return Err(invalid(
                                R,
                                format!("{name}: a PeriodControl rule names the from-state"),
                            ));
                        }
                        (book_scoped, Some(_)) if BOOK_SCOPED_CONTROLS.contains(&book_scoped) => {
                            return Err(invalid(
                                R,
                                format!(
                                    "{name}: {book_scoped} is book-scoped; it has no period state"
                                ),
                            ));
                        }
                        _ => {}
                    }
                    if preparer_op.as_deref().is_none_or(str::is_empty) {
                        return Err(invalid(
                            R,
                            format!("{name}: a control rule names the preparer's op"),
                        ));
                    }
                }
            }
            rules.push(SodRule {
                name,
                key: SodKey {
                    class,
                    state,
                    disposition,
                    transition,
                },
                preparer_op,
                requirement,
            });
        }
        rules.sort_by(|a, b| a.key.cmp(&b.key));
        for w in rules.windows(2) {
            if w[0].key == w[1].key {
                return Err(invalid(
                    R,
                    format!(
                        "rules `{}` and `{}` govern the same entry",
                        w[0].name, w[1].name
                    ),
                ));
            }
        }
        // Admission picks a control's op from the transition alone, before
        // the from-state is read; so every row of one transition agrees on it.
        let mut ops: std::collections::BTreeMap<(&str, &str), (&str, &str)> =
            std::collections::BTreeMap::new();
        for r in &rules {
            let (Some(t), Some(op)) = (r.key.transition.as_deref(), r.preparer_op.as_deref())
            else {
                continue;
            };
            match ops.insert((r.key.class.as_str(), t), (op, r.name.as_str())) {
                Some((other, name)) if other != op => {
                    return Err(invalid(
                        R,
                        format!(
                            "rules `{name}` and `{}` name different preparer ops (`{other}`, `{op}`) for {} {t}",
                            r.name, r.key.class
                        ),
                    ));
                }
                _ => {}
            }
        }
        Ok(Self { default, rules })
    }

    /// The preparer op every rule of `class`'s `transition` names, when one
    /// is registered (the parser guarantees they agree).
    pub fn transition_op(&self, class: &str, transition: &str) -> Option<&str> {
        self.rules
            .iter()
            .find(|r| r.key.class == class && r.key.transition.as_deref() == Some(transition))
            .and_then(|r| r.preparer_op.as_deref())
    }

    /// The rule for exactly this key, if one is registered.
    pub fn rule(&self, key: &SodKey) -> Option<&SodRule> {
        self.rules
            .binary_search_by(|r| r.key.cmp(key))
            .ok()
            .map(|i| &self.rules[i])
    }

    /// The requirement governing `key`: its rule's, else the default.
    /// Returns the rule name (`"default"` for the default) for citation.
    pub fn requirement(&self, key: &SodKey) -> (&str, &SodRequirement) {
        match self.rule(key) {
            Some(r) => (r.name.as_str(), &r.requirement),
            None => ("default", &self.default),
        }
    }

    /// Canonical bytes of the policy (sorted rules, `key=value` lines), the
    /// input to the digest a `PolicyActivation` journals as its policy oid.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        fn requirement_lines(out: &mut String, scope: &str, r: &SodRequirement) {
            out.push_str(&format!(
                "{scope}|approvers={}|approver_op={}|approver_profiles={}|agent_prepared_human_approvers={}|exclusions={}\n",
                r.approvers,
                r.approver_op,
                r.approver_profiles.join(","),
                r.agent_prepared_human_approvers,
                r.exclusions.join(","),
            ));
        }
        let mut out = String::from("fa:sod-policy:v1\n");
        requirement_lines(&mut out, "default", &self.default);
        for r in &self.rules {
            let scope = format!(
                "rule:{}|class={}|state={}|disposition={}|transition={}|preparer_op={}",
                r.name,
                r.key.class,
                r.key.state.map_or("-", PeriodState::name),
                r.key.disposition.as_deref().unwrap_or("-"),
                r.key.transition.as_deref().unwrap_or("-"),
                r.preparer_op.as_deref().unwrap_or("-"),
            );
            requirement_lines(&mut out, &scope, &r.requirement);
        }
        out.into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deps() -> (EntryClasses, Admissibility) {
        let classes = EntryClasses::embedded().expect("classes");
        let matrix = Admissibility::embedded(&classes).expect("matrix");
        (classes, matrix)
    }

    fn rule_text(body: &str) -> String {
        format!(
            "schema_version = 1\n[default]\napprovers = 0\napprover_op = \"approve\"\napprover_profiles = [\"Human\"]\nagent_prepared_human_approvers = 0\nexclusions = [\"preparer\", \"duplicate\"]\ncite = \"c\"\n{body}"
        )
    }

    const OK_REQ: &str = "approver_op = \"approve\"\napprover_profiles = [\"Human\"]\nagent_prepared_human_approvers = 0\nexclusions = [\"preparer\", \"duplicate\"]\ncite = \"c\"\n";

    fn refused(body: &str) -> String {
        let (classes, matrix) = deps();
        match SodPolicy::parse(&rule_text(body), &classes, &matrix) {
            Ok(_) => format!("ADMITTED: {body}"),
            Err(e) => e.to_string(),
        }
    }

    /// The registry gate: the embedded policy loads, every rule is
    /// reachable by its key, and the dangerous classes the plan names are
    /// governed by rules rather than the default.
    #[test]
    fn embedded_sod_policy_loads_and_governs_the_dangerous_classes() {
        let (classes, matrix) = deps();
        let p = SodPolicy::embedded(&classes, &matrix).expect("sod policy");
        assert!(p.default.exclusions.iter().any(|e| e == "preparer"));
        for r in &p.rules {
            assert_eq!(
                p.rule(&r.key).map(|x| x.name.as_str()),
                Some(r.name.as_str())
            );
            assert!(r.requirement.exclusions.iter().any(|e| e == "duplicate"));
        }
        let key =
            |class: &str, state: Option<PeriodState>, d: Option<&str>, t: Option<&str>| SodKey {
                class: class.into(),
                state,
                disposition: d.map(str::to_string),
                transition: t.map(str::to_string),
            };
        for (k, approvers) in [
            (key("Reversal", Some(PeriodState::Closed), None, None), 0),
            (
                key("Resolution", Some(PeriodState::Closed), Some("Posts"), None),
                0,
            ),
            (key("Restatement", Some(PeriodState::Locked), None, None), 2),
            (key("Migration", Some(PeriodState::Locked), None, None), 2),
            (
                key(
                    "PeriodControl",
                    Some(PeriodState::Closed),
                    None,
                    Some("Reopen"),
                ),
                2,
            ),
            (
                key(
                    "PeriodControl",
                    Some(PeriodState::Closed),
                    None,
                    Some("Lock"),
                ),
                1,
            ),
            (key("PolicyControl", None, None, Some("Activate")), 2),
            (key("TimeControl", None, None, Some("Tick")), 0),
            (key("SweepControl", None, None, Some("Expire")), 0),
            (key("ScheduleControl", None, None, Some("Cancel")), 0),
            (key("SweepControl", None, None, Some("Reverse")), 0),
            (
                key(
                    "PeriodControl",
                    Some(PeriodState::Future),
                    None,
                    Some("Open"),
                ),
                0,
            ),
            (
                key(
                    "PeriodControl",
                    Some(PeriodState::Open),
                    None,
                    Some("SoftClose"),
                ),
                0,
            ),
            (
                key(
                    "PeriodControl",
                    Some(PeriodState::Open),
                    None,
                    Some("Close"),
                ),
                0,
            ),
            (
                key(
                    "PeriodControl",
                    Some(PeriodState::SoftClosed),
                    None,
                    Some("Close"),
                ),
                0,
            ),
            (key("MigrationControl", None, None, Some("Open")), 0),
            (key("MigrationControl", None, None, Some("Finalize")), 2),
            (key("MigrationControl", None, None, Some("Abandon")), 0),
        ] {
            let (name, req) = p.requirement(&k);
            assert_ne!(name, "default", "{k:?} must be governed by a rule");
            assert_eq!(req.approvers, approvers, "{name}");
        }
        for (t, op) in [
            ("Open", "close"),
            ("SoftClose", "close"),
            ("Close", "close"),
            ("Lock", "close"),
            ("Reopen", "reopen"),
        ] {
            assert_eq!(p.transition_op("PeriodControl", t), Some(op), "{t}");
        }
        assert_eq!(
            p.transition_op("PolicyControl", "Activate"),
            Some("rule_change")
        );
        // An Open-period Original falls to the default.
        assert_eq!(
            p.requirement(&key("Original", Some(PeriodState::Open), None, None))
                .0,
            "default"
        );
        // Every posting rule's count is at least its matrix cell's.
        for r in p.rules.iter().filter(|r| r.preparer_op.is_none()) {
            let state = r.key.state.expect("posting rules have states");
            if let Some(Decision::With { approvals, .. }) =
                matrix.decide_disposition(&r.key.class, state, false)
            {
                assert!(r.requirement.approvers >= approvals, "{}", r.name);
            }
        }
        // Canonical bytes are stable and cover every rule.
        let a = p.canonical_bytes();
        assert_eq!(
            a,
            SodPolicy::embedded(&classes, &matrix)
                .unwrap()
                .canonical_bytes()
        );
        let text = String::from_utf8(a).unwrap();
        for r in &p.rules {
            assert!(text.contains(&format!("rule:{}|", r.name)), "{}", r.name);
        }
    }

    #[test]
    fn broken_policies_are_refused_with_the_reason() {
        let cases: Vec<(String, &str)> = vec![
            (
                format!("[[rule]]\nname = \"x\"\nclass = \"Nope\"\nstate = \"Closed\"\napprovers = 0\n{OK_REQ}"),
                "not a registered class",
            ),
            (
                format!("[[rule]]\nname = \"x\"\nclass = \"Adjusting\"\nstate = \"Closed\"\napprovers = 0\n{OK_REQ}"),
                "loosens the matrix",
            ),
            (
                format!("[[rule]]\nname = \"x\"\nclass = \"Original\"\nstate = \"Closed\"\napprovers = 1\n{OK_REQ}"),
                "refused by the matrix",
            ),
            (
                format!("[[rule]]\nname = \"x\"\nclass = \"Reversal\"\napprovers = 0\n{OK_REQ}"),
                "names its period state",
            ),
            (
                format!("[[rule]]\nname = \"x\"\nclass = \"Reversal\"\nstate = \"Closed\"\npreparer_op = \"close\"\napprovers = 0\n{OK_REQ}"),
                "control-row keys",
            ),
            (
                format!("[[rule]]\nname = \"x\"\nclass = \"Resolution\"\nstate = \"Closed\"\napprovers = 0\n{OK_REQ}"),
                "names its disposition",
            ),
            (
                format!("[[rule]]\nname = \"x\"\nclass = \"PeriodControl\"\nstate = \"Closed\"\ntransition = \"Explode\"\npreparer_op = \"close\"\napprovers = 1\n{OK_REQ}"),
                "not a PeriodControl transition",
            ),
            (
                format!("[[rule]]\nname = \"x\"\nclass = \"PolicyControl\"\nstate = \"Open\"\ntransition = \"Activate\"\npreparer_op = \"rule_change\"\napprovers = 2\n{OK_REQ}"),
                "book-scoped",
            ),
            (
                format!("[[rule]]\nname = \"x\"\nclass = \"MigrationControl\"\nstate = \"Locked\"\ntransition = \"Finalize\"\npreparer_op = \"migrate\"\napprovers = 2\n{OK_REQ}"),
                "book-scoped",
            ),
            (
                format!("[[rule]]\nname = \"x\"\nclass = \"MigrationControl\"\ntransition = \"Activate\"\npreparer_op = \"migrate\"\napprovers = 2\n{OK_REQ}"),
                "not a MigrationControl transition",
            ),
            (
                format!("[[rule]]\nname = \"x\"\nclass = \"PolicyControl\"\ntransition = \"Activate\"\napprovers = 2\n{OK_REQ}"),
                "preparer's op",
            ),
            (
                format!("[[rule]]\nname = \"x\"\nclass = \"TimeControl\"\nstate = \"Open\"\ntransition = \"Tick\"\npreparer_op = \"witness\"\napprovers = 0\n{OK_REQ}"),
                "TimeControl is book-scoped",
            ),
            (
                format!("[[rule]]\nname = \"x\"\nclass = \"SweepControl\"\ntransition = \"Tick\"\npreparer_op = \"post\"\napprovers = 0\n{OK_REQ}"),
                "not a SweepControl transition",
            ),
            (
                "[[rule]]\nname = \"x\"\nclass = \"Reversal\"\nstate = \"Closed\"\napprovers = 0\napprover_op = \"approve\"\napprover_profiles = [\"Human\"]\nagent_prepared_human_approvers = 0\nexclusions = [\"duplicate\"]\ncite = \"c\"\n".to_string(),
                "universal exclusion `preparer`",
            ),
            (
                "[[rule]]\nname = \"x\"\nclass = \"Reversal\"\nstate = \"Closed\"\napprovers = 0\napprover_op = \"approve\"\napprover_profiles = [\"Robot\"]\nagent_prepared_human_approvers = 0\nexclusions = [\"preparer\", \"duplicate\"]\ncite = \"c\"\n".to_string(),
                "unknown profile",
            ),
            (
                "[[rule]]\nname = \"x\"\nclass = \"Reversal\"\nstate = \"Closed\"\napprovers = 0\napprover_op = \"approve\"\napprover_profiles = []\nagent_prepared_human_approvers = 0\nexclusions = [\"preparer\", \"duplicate\"]\ncite = \"c\"\n".to_string(),
                "no profile may approve",
            ),
            (
                format!("[[rule]]\nname = \"x\"\nclass = \"Reversal\"\nstate = \"Closed\"\napprovers = 0\n{OK_REQ}[[rule]]\nname = \"y\"\nclass = \"Reversal\"\nstate = \"Closed\"\napprovers = 1\n{OK_REQ}"),
                "govern the same entry",
            ),
            (
                format!("[[rule]]\nname = \"x\"\nclass = \"Reversal\"\nstate = \"Closed\"\napprovers = 300\n{OK_REQ}"),
                "outside 0..=255",
            ),
            (
                format!("[[rule]]\nname = \"x\"\nclass = \"PeriodControl\"\nstate = \"Open\"\ntransition = \"Close\"\npreparer_op = \"close\"\napprovers = 0\n{OK_REQ}[[rule]]\nname = \"y\"\nclass = \"PeriodControl\"\nstate = \"SoftClosed\"\ntransition = \"Close\"\npreparer_op = \"reopen\"\napprovers = 0\n{OK_REQ}"),
                "different preparer ops",
            ),
        ];
        for (body, want) in cases {
            let got = refused(&body);
            assert!(got.contains(want), "want `{want}`, got `{got}`");
        }
        let (classes, matrix) = deps();
        assert!(
            SodPolicy::parse("schema_version = 1\n", &classes, &matrix)
                .unwrap_err()
                .to_string()
                .contains("missing [default]")
        );
    }
}
