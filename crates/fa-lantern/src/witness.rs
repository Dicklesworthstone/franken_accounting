//! Determinism witnesses (plan §11.1; CGSE). A ranking must not depend on
//! how the stream was iterated: the witness runs a procedure twice over the
//! same snapshot, once over the snapshot with its entries reversed, and once
//! with every entry's legs reversed, and reports which comparisons held.
//! The first two must give the same findings digest; the leg probe moves
//! ordinals, so only the multiset of (severity, statistic) is compared.

use fa_journal::genesis::BookContext;

use crate::{LanternError, Procedure, ProcedureRun, Snapshot, run_over};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Witness {
    pub procedure: String,
    pub digest: [u8; 32],
    /// Two runs over the same snapshot gave the same digest.
    pub repeated: bool,
    /// Reversing the entry order gave the same digest.
    pub entry_order: bool,
    /// Reversing every entry's legs gave the same statistics.
    pub leg_order_statistics: bool,
}

impl Witness {
    #[must_use]
    pub fn deterministic(&self) -> bool {
        self.repeated && self.entry_order && self.leg_order_statistics
    }
}

fn statistics(run: &ProcedureRun) -> Vec<(u8, String, i128, u8, u64)> {
    let mut v: Vec<_> = run
        .findings
        .iter()
        .map(|f| {
            (
                f.severity.tag(),
                f.statistic.name.clone(),
                f.statistic.value,
                f.statistic.scale,
                f.statistic.population,
            )
        })
        .collect();
    v.sort();
    v
}

/// Witness `procedure` over `snapshot`.
pub fn determinism(
    snapshot: &Snapshot,
    book: &BookContext,
    procedure: &dyn Procedure,
) -> Result<Witness, LanternError> {
    let a = run_over(snapshot, book, procedure)?;
    let b = run_over(snapshot, book, procedure)?;
    let c = run_over(&snapshot.with_entries_reversed(), book, procedure)?;
    let d = run_over(&snapshot.with_legs_reversed(), book, procedure)?;
    Ok(Witness {
        procedure: a.procedure.clone(),
        digest: a.findings_digest,
        repeated: a.findings_digest == b.findings_digest,
        entry_order: a.findings_digest == c.findings_digest,
        leg_order_statistics: statistics(&a) == statistics(&d),
    })
}
