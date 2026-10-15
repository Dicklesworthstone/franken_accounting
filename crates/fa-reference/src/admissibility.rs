//! Independent hand-transcribed Appendix C admissibility matrix for the
//! reference oracle (`fa-nfq`).
//!
//! Does NOT read `registries/admissibility.toml`. By encoding the matrix
//! literally in the oracle, any wrong or drifted row in `admissibility.toml`
//! is caught immediately by the four-way cell comparison (`plan == toml ==
//! oracle == kernel`) and by differential walks.

use fa_registry::{Decision, DispositionFamily};
use fa_time::{DateDay, PeriodKind, PeriodState, PeriodTransition};

fn with(op: &str, approvals: u8) -> Decision {
    Decision::With {
        op: op.to_string(),
        approvals,
    }
}

/// Hand-transcribed plan §7.3 / Appendix C `PeriodControl` state machine (`fa-vfu`).
///
/// Does NOT call `fa_time::period::transition`.
#[allow(clippy::result_unit_err)]
pub fn oracle_transition(from: PeriodState, t: PeriodTransition) -> Result<PeriodState, ()> {
    use PeriodState::{Closed, Future, Locked, Open, SoftClosed};
    match (from, t) {
        (Future, PeriodTransition::Open) => Ok(Open),
        (Open, PeriodTransition::SoftClose) => Ok(SoftClosed),
        (Open | SoftClosed, PeriodTransition::Close) => Ok(Closed),
        (Closed, PeriodTransition::Lock) => Ok(Locked),
        (SoftClosed, PeriodTransition::Reopen { to: Open }) => Ok(Open),
        (
            Closed | Locked,
            PeriodTransition::Reopen {
                to: to @ (Open | SoftClosed),
            },
        ) => Ok(to),
        _ => Err(()),
    }
}

/// Hand-transcribed Appendix C cell decision for `(class, state)` and disposition `release`
/// (`false` = Standard / `Posts`, `true` = `Voids`).
#[must_use]
pub fn decide_disposition(class: &str, state: PeriodState, release: bool) -> Option<Decision> {
    use PeriodState::{Closed, Future, Locked, Open, SoftClosed};
    Some(match class {
        "Original" | "Pending" => match state {
            Future | Closed | Locked => Decision::Refuse,
            Open => Decision::Admit,
            SoftClosed => with("post_softclosed", 0),
        },
        "Resolution" => match (state, release) {
            (Future, _) => Decision::Refuse,
            (Open | SoftClosed, _) => Decision::Admit,
            (Closed, false) => with("post_closed", 0),
            (Closed, true) => Decision::Admit,
            (Locked, false) => Decision::Refuse,
            (Locked, true) => Decision::Admit,
        },
        "Reversal" => match state {
            Future | Locked => Decision::Refuse,
            Open | SoftClosed => Decision::Admit,
            Closed => with("post_closed", 0),
        },
        "Replacement" | "Reclassification" | "Adjusting" | "Allocation" | "Revaluation"
        | "Elimination" => match state {
            Future | Locked => Decision::Refuse,
            Open | SoftClosed => Decision::Admit,
            Closed => with("post_closed", 1),
        },
        "Closing" => match state {
            Future => Decision::Refuse,
            Open | SoftClosed => with("close", 0),
            Closed => with("close", 1),
            Locked => with("restate", 2),
        },
        "Migration" => match state {
            Future | Open | SoftClosed | Closed => Decision::Refuse,
            Locked => with("migrate", 2),
        },
        "Revision" => match state {
            Future | Open | SoftClosed => Decision::Refuse,
            Closed => with("restate", 1),
            Locked => with("restate", 2),
        },
        "Restatement" => match state {
            Future | Open | SoftClosed => Decision::Refuse,
            Closed | Locked => with("restate", 2),
        },
        "PriorPeriodAdjustment" => match state {
            Future | Closed | Locked => Decision::Refuse,
            Open | SoftClosed => with("restate", 2),
        },
        _ => return None,
    })
}

/// Hand-transcribed Appendix C decision for `Resolution(Expires)` (the expiry sweep).
#[must_use]
pub fn decide_expires(state: PeriodState) -> Decision {
    match state {
        PeriodState::Future => Decision::Refuse,
        PeriodState::Open | PeriodState::SoftClosed | PeriodState::Closed | PeriodState::Locked => {
            Decision::Admit
        }
    }
}

/// Hand-transcribed Appendix C qualifier tag (`case`, `run`, `posts_only_with`, `voids_expires`) on `(class, state)`.
#[must_use]
pub fn qualifier_tag(class: &str, state: PeriodState) -> Option<&'static str> {
    use PeriodState::{Closed, Locked, Open, SoftClosed};
    match (class, state) {
        ("Resolution", Closed) => Some("posts_only_with"),
        ("Resolution", Locked) => Some("voids_expires"),
        ("Closing", Locked) => Some("case"),
        ("Migration", Locked) => Some("run"),
        ("Revision", Closed | Locked) => Some("case"),
        ("Restatement", Closed | Locked) => Some("case"),
        ("PriorPeriodAdjustment", Open | SoftClosed) => Some("case"),
        _ => None,
    }
}

/// Whether `kind` has a period-kind restriction (`Historical` only).
#[must_use]
pub fn kind_has_restriction(kind: PeriodKind) -> bool {
    matches!(kind, PeriodKind::Historical)
}

/// Whether `kind`'s period-kind rule admits `class`.
#[must_use]
pub fn kind_admits(kind: PeriodKind, class: &str) -> bool {
    match kind {
        PeriodKind::Historical => class == "Migration",
        PeriodKind::Normal | PeriodKind::Opening | PeriodKind::Adjustment | PeriodKind::Closing => {
            true
        }
    }
}

/// Whether the pre-opening special-period rule governs `(kind, end, opening_date)`.
#[must_use]
pub fn pre_opening_governs(kind: PeriodKind, end: DateDay, opening_date: Option<DateDay>) -> bool {
    matches!(
        kind,
        PeriodKind::Opening | PeriodKind::Adjustment | PeriodKind::Closing
    ) && opening_date.is_some_and(|day| end <= day)
}

/// Birth state of a pre-opening special period (`Locked`).
pub const PRE_OPENING_BORN: PeriodState = PeriodState::Locked;

/// Whether a pre-opening special period admits `class` (`Migration` only).
#[must_use]
pub fn pre_opening_admits(class: &str) -> bool {
    class == "Migration"
}

/// Whether a live special period (`Opening`, `Adjustment`, `Closing`) admits `class` (plan §7.3).
#[must_use]
pub fn special_period_admits(kind: PeriodKind, class: &str) -> bool {
    match kind {
        PeriodKind::Opening | PeriodKind::Adjustment | PeriodKind::Closing => matches!(
            class,
            "Adjusting" | "Closing" | "Elimination" | "Revision" | "Restatement" | "Migration"
        ),
        PeriodKind::Normal | PeriodKind::Historical => true,
    }
}

/// Evaluate the complete oracle admissibility cell `(class, state, family, kind, pre_opening)`.
#[must_use]
pub fn decide_cell(
    class: &str,
    state: PeriodState,
    family: DispositionFamily,
    kind: PeriodKind,
    pre_opening: bool,
) -> Option<Decision> {
    if !kind_admits(kind, class) {
        return Some(Decision::Refuse);
    }
    if pre_opening
        && matches!(
            kind,
            PeriodKind::Opening | PeriodKind::Adjustment | PeriodKind::Closing
        )
        && !pre_opening_admits(class)
    {
        return Some(Decision::Refuse);
    }
    if !special_period_admits(kind, class) {
        return Some(Decision::Refuse);
    }
    match family {
        DispositionFamily::Expires if class == "Resolution" => Some(decide_expires(state)),
        DispositionFamily::Expires | DispositionFamily::Voids => {
            decide_disposition(class, state, true)
        }
        DispositionFamily::Standard => decide_disposition(class, state, false),
    }
}
