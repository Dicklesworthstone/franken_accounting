//! The v5 `posted_principal_transfer_v1` rule. These are posted principal
//! movements, not cash or an independent legal determination of transfer credit.

use std::collections::{BTreeMap, BTreeSet};

use fa_money::Side;
use fgdb_types::VId;

use super::attribution::{Leg, Named};
use crate::amount::amount_sum;
use crate::{LanternError, Meter};

pub(super) const RULE: &str = "posted_principal_transfer_v1";

/// One exact (unit, legal entity) partition. No party or amount is inferred
/// from the other partition, a name, an entry description or an earlier balance.
#[derive(Default)]
pub(super) struct Partition {
    pub cash: bool,
    pub other: bool,
    pub investors: Vec<(Side, Leg)>,
    pub clearing: Vec<(Side, Leg)>,
}

fn refuse(procedure: &str, entry: VId, unit: u32, why: &str) -> LanternError {
    LanternError::Parameter {
        procedure: procedure.into(),
        name: RULE.into(),
        message: format!(
            "entry {:032x}, unit {unit}: {why}; principal transfers require either one named investor leg against only unnamed investor_transfer clearing legs, or balanced investor legs naming exactly two parties, within one unit/legal entity and with no cash or other accounts",
            entry.0
        ),
    }
}

impl Partition {
    /// Per party (principal in, principal out), at the exact amounts posted.
    /// Clearing transfers admit one investor leg; direct transfers admit two
    /// distinct parties, with every investor leg explicitly naming its owner.
    pub(super) fn movements(
        &self,
        procedure: &str,
        entry: VId,
        unit: u32,
        work: &mut Meter<'_>,
    ) -> Result<BTreeMap<VId, (i128, i128)>, LanternError> {
        let mut moved = BTreeMap::new();
        if !self.clearing.is_empty() && (self.investors.is_empty() || self.cash || self.other) {
            return Err(refuse(
                procedure,
                entry,
                unit,
                "marked clearing transfer has cash, other accounts or no investor leg",
            ));
        }
        if self.clearing.is_empty() && (self.cash || self.other) {
            let mut debit = false;
            let mut credit = false;
            for (side, _) in &self.investors {
                work.compare(1)?;
                match side {
                    Side::Debit => debit = true,
                    Side::Credit => credit = true,
                }
            }
            if debit && credit {
                return Err(refuse(
                    procedure,
                    entry,
                    unit,
                    "a direct investor movement is mixed with cash or other accounts",
                ));
            }
        }
        if self.investors.is_empty() || (self.clearing.is_empty() && (self.cash || self.other)) {
            // Cash attribution owns ordinary cash entries. An unmarked fee,
            // reclassification or other contra account never implies transfer.
            return Ok(moved);
        }
        let mut parties = BTreeSet::new();
        let mut debit = 0i128;
        let mut credit = 0i128;
        for (side, leg) in &self.investors {
            work.compare(1)?;
            let Named::One(party) = leg.named else {
                return Err(refuse(
                    procedure,
                    entry,
                    unit,
                    "an investor leg has no unique party",
                ));
            };
            if leg.amount <= 0 {
                return Err(refuse(
                    procedure,
                    entry,
                    unit,
                    "an investor leg is not positive",
                ));
            }
            parties.insert(party);
            let margin = moved.entry(party).or_insert((0, 0));
            match side {
                Side::Debit => {
                    debit = amount_sum(debit, leg.amount, "principal transfer debit total")?;
                    margin.1 = amount_sum(margin.1, leg.amount, "principal transfer out")?;
                }
                Side::Credit => {
                    credit = amount_sum(credit, leg.amount, "principal transfer credit total")?;
                    margin.0 = amount_sum(margin.0, leg.amount, "principal transfer in")?;
                }
            }
        }
        if self.clearing.is_empty() {
            if parties.len() == 1 && debit == credit {
                // A balanced reclassification of one investor's own capital
                // changes no principal owner. It is not an inter-party flow.
                return Ok(BTreeMap::new());
            }
            if parties.len() != 2 {
                return Err(refuse(
                    procedure,
                    entry,
                    unit,
                    "a direct transfer does not name exactly two parties",
                ));
            }
        } else if self.investors.len() != 1 {
            return Err(refuse(
                procedure,
                entry,
                unit,
                "a clearing transfer has more than one investor leg",
            ));
        }
        for (side, leg) in &self.clearing {
            work.compare(1)?;
            if leg.named != Named::None || leg.amount <= 0 {
                return Err(refuse(
                    procedure,
                    entry,
                    unit,
                    "a clearing leg is named or not positive",
                ));
            }
            match side {
                Side::Debit => debit = amount_sum(debit, leg.amount, "principal clearing debit")?,
                Side::Credit => {
                    credit = amount_sum(credit, leg.amount, "principal clearing credit")?
                }
            }
        }
        if debit != credit {
            return Err(refuse(
                procedure,
                entry,
                unit,
                "the transfer partition does not balance",
            ));
        }
        Ok(moved)
    }
}
