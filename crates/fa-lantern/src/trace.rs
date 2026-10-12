//! Tracing laws (plan §11.5): the traceable share of one deposit through a
//! commingled account up to the coordinate's effective date, under a
//! registered law. `trace.libr` is the lowest intermediate balance rule
//! (the claimant's traceable amount never exceeds the lowest balance between
//! the deposit and the claim; no replenishment); `trace.fifo` is Clayton's
//! rule (withdrawals draw the oldest money first); `trace.lifo` draws the
//! newest first; `trace.pro_rata` lets every withdrawal carry tainted and
//! clean value in proportion to their shares of the balance, split under
//! the registered largest-remainder law. One account, one hop; the claim
//! date is the coordinate's `effective_through`, the source is an entry,
//! and the result is an exact computation whose evidentiary weight is the
//! law's, never a finding of fact.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use fa_journal::genesis::BookContext;
use fa_money::allocation::largest_remainder;
use fa_money::{Amount, Side, UnitId};
use fa_time::DateDay;
use fgdb_types::VId;

use crate::jet::finding;
use crate::{
    Cite, Finding, LanternError, MAX_CITES, Params, Procedure, Severity, Snapshot, Statistic, Work,
};

/// A registered tracing law.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Law {
    Libr,
    Fifo,
    Lifo,
    ProRata,
}

impl Law {
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::Libr => "trace.libr",
            Self::Fifo => "trace.fifo",
            Self::Lifo => "trace.lifo",
            Self::ProRata => "trace.pro_rata",
        }
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Libr => "LIBR",
            Self::Fifo => "FIFO (Clayton)",
            Self::Lifo => "LIFO",
            Self::ProRata => "pro rata",
        }
    }
}

/// `intraday_order`: how same-day movements are sequenced.
const STATEMENT_ORDINAL: i128 = 0;
const VALUE_DATE: i128 = 1;
const WITHDRAWALS_FIRST: i128 = 2;
const DEPOSITS_FIRST: i128 = 3;

/// One tracing run: `law` applied to the deposit `source` made into
/// `account`.
pub struct Trace {
    law: Law,
    params: Params,
    account: VId,
    source: VId,
}

impl Trace {
    /// With the registry's pinned parameters for `law`.
    pub fn new(law: Law, account: VId, source: VId) -> Result<Self, LanternError> {
        Ok(Self {
            law,
            params: Params::defaults(law.id())?,
            account,
            source,
        })
    }

    #[must_use]
    pub fn with(law: Law, params: Params, account: VId, source: VId) -> Self {
        Self {
            law,
            params,
            account,
            source,
        }
    }

    fn refuse(&self, name: &str, message: &str) -> LanternError {
        LanternError::Parameter {
            procedure: self.law.id().into(),
            name: name.into(),
            message: message.into(),
        }
    }
}

/// One entry's net movement on one side of the traced account.
#[derive(Clone, Debug)]
struct Movement {
    entry: VId,
    date: DateDay,
    inflow: bool,
    magnitude: i128,
}

/// The account's movements in the deposit's unit, ordered under the
/// intraday rule, with the position of the source deposit.
struct Stream {
    unit: UnitId,
    moves: Vec<Movement>,
    source_at: usize,
}

fn hex(v: VId) -> String {
    format!("{:032x}", v.0)
}

impl Trace {
    fn stream(
        &self,
        snapshot: &Snapshot,
        claim: DateDay,
        intraday: i128,
    ) -> Result<Stream, LanternError> {
        let account = snapshot
            .accounts
            .get(&self.account)
            .ok_or_else(|| self.refuse("account", "not an account of this book"))?;
        let inflow_side = if account.normal_balance == 0 {
            Side::Debit
        } else {
            Side::Credit
        };
        // The deposit's unit comes from the source entry's inflow leg(s).
        let mut unit: Option<UnitId> = None;
        for e in snapshot.entries.iter().filter(|e| e.vid == self.source) {
            if e.entry.proposal.effective_date > claim {
                return Err(self.refuse(
                    "source",
                    "the source deposit is effective after the coordinate's effective date",
                ));
            }
            for leg in &e.entry.proposal.legs {
                if leg.account_ref == self.account && leg.side == inflow_side {
                    match unit {
                        None => unit = Some(leg.amount.unit),
                        Some(u) if u == leg.amount.unit => {}
                        Some(_) => {
                            return Err(self.refuse(
                                "source",
                                "the source deposit carries more than one unit into the account",
                            ));
                        }
                    }
                }
            }
        }
        let Some(unit) = unit else {
            return Err(self.refuse(
                "source",
                "the source entry has no inflow leg on the account (an entry of the book that deposits into it is required)",
            ));
        };
        // Net each entry's legs on the account, per side, in that unit.
        let mut per_entry: BTreeMap<(VId, bool), (DateDay, i128)> = BTreeMap::new();
        for e in snapshot.entries.iter().filter(|e| e.posts()) {
            if e.entry.proposal.effective_date > claim {
                continue;
            }
            for leg in &e.entry.proposal.legs {
                if leg.account_ref != self.account || leg.amount.unit != unit {
                    continue;
                }
                let magnitude = leg
                    .amount
                    .mantissa
                    .checked_abs()
                    .ok_or(LanternError::Overflow("trace magnitude"))?;
                let slot = per_entry
                    .entry((e.vid, leg.side == inflow_side))
                    .or_insert((e.entry.proposal.effective_date, 0));
                slot.1 = slot
                    .1
                    .checked_add(magnitude)
                    .ok_or(LanternError::Overflow("trace movement"))?;
            }
        }
        let mut moves: Vec<Movement> = per_entry
            .into_iter()
            .filter(|(_, (_, m))| *m != 0)
            .map(|((entry, inflow), (date, magnitude))| Movement {
                entry,
                date,
                inflow,
                magnitude,
            })
            .collect();
        let rank = |m: &Movement| match intraday {
            WITHDRAWALS_FIRST => u8::from(m.inflow),
            DEPOSITS_FIRST => u8::from(!m.inflow),
            _ => 0,
        };
        moves.sort_by(|a, b| {
            (a.date, rank(a), a.entry, a.inflow).cmp(&(b.date, rank(b), b.entry, b.inflow))
        });
        let source_at = moves
            .iter()
            .position(|m| m.entry == self.source && m.inflow)
            .ok_or_else(|| {
                self.refuse("source", "the source deposit nets to zero on the account")
            })?;
        Ok(Stream {
            unit,
            moves,
            source_at,
        })
    }
}

/// What a law computed over the stream.
struct Traced {
    deposit: i128,
    traced: i128,
    /// Balance after the deposit and its lowest later value, with the entry
    /// at which the lowest was reached.
    lowest: (i128, Option<VId>),
    /// Outflow entries that carried tainted value, with the amount carried.
    carriers: BTreeMap<VId, i128>,
}

fn add(a: i128, b: i128, what: &'static str) -> Result<i128, LanternError> {
    a.checked_add(b).ok_or(LanternError::Overflow(what))
}

fn sub(a: i128, b: i128, what: &'static str) -> Result<i128, LanternError> {
    a.checked_sub(b).ok_or(LanternError::Overflow(what))
}

fn run_law(law: Law, stream: &Stream, work: &mut Work) -> Result<Traced, LanternError> {
    // The opening balance before the deposit is clean money.
    let mut opening = 0i128;
    for m in &stream.moves[..stream.source_at] {
        work.leg();
        opening = if m.inflow {
            add(opening, m.magnitude, "opening balance")?
        } else {
            sub(opening, m.magnitude, "opening balance")?
        };
    }
    let deposit = stream.moves[stream.source_at].magnitude;
    let mut balance = add(opening, deposit, "balance")?;
    let mut lowest = (balance, None);
    let mut carriers: BTreeMap<VId, i128> = BTreeMap::new();
    // Layered money for FIFO/LIFO: `(tainted, amount)`, oldest first.
    let mut layers: VecDeque<(bool, i128)> = VecDeque::new();
    if opening > 0 {
        layers.push_back((false, opening));
    }
    layers.push_back((true, deposit));
    // Pooled money for pro rata and LIBR.
    let mut tainted = deposit;
    let mut clean = opening.max(0);
    for m in &stream.moves[stream.source_at + 1..] {
        work.leg();
        if m.inflow {
            balance = add(balance, m.magnitude, "balance")?;
            layers.push_back((false, m.magnitude));
            clean = add(clean, m.magnitude, "clean pool")?;
            continue;
        }
        balance = sub(balance, m.magnitude, "balance")?;
        if balance < lowest.0 {
            lowest = (balance, Some(m.entry));
        }
        match law {
            Law::Libr => {
                // No replenishment: a later deposit never restores the share.
                tainted = tainted.min(balance.max(0));
            }
            Law::Fifo | Law::Lifo => {
                let mut remaining = m.magnitude;
                while remaining > 0 {
                    let Some(front) = (if law == Law::Fifo {
                        layers.front_mut()
                    } else {
                        layers.back_mut()
                    }) else {
                        break;
                    };
                    let take = remaining.min(front.1);
                    if front.0 {
                        let carried = carriers.entry(m.entry).or_insert(0);
                        *carried = add(*carried, take, "carried")?;
                    }
                    front.1 = sub(front.1, take, "layer")?;
                    remaining = sub(remaining, take, "withdrawal")?;
                    if front.1 == 0 {
                        if law == Law::Fifo {
                            layers.pop_front();
                        } else {
                            layers.pop_back();
                        }
                    }
                }
            }
            Law::ProRata => {
                let pool = add(tainted, clean, "pool")?;
                if pool <= 0 {
                    continue;
                }
                let drawn = m.magnitude.min(pool);
                let weights = [tainted.unsigned_abs(), clean.unsigned_abs()];
                let shares = largest_remainder(Amount::new(stream.unit, drawn), &weights)?;
                let (Some(t), Some(c)) = (shares.first(), shares.get(1)) else {
                    return Err(LanternError::Overflow("pro-rata shares"));
                };
                if t.mantissa > 0 {
                    carriers.insert(m.entry, t.mantissa);
                }
                tainted = sub(tainted, t.mantissa, "tainted pool")?;
                clean = sub(clean, c.mantissa, "clean pool")?;
            }
        }
    }
    let traced = match law {
        Law::Libr | Law::ProRata => tainted,
        Law::Fifo | Law::Lifo => layers
            .iter()
            .filter(|(t, _)| *t)
            .try_fold(0i128, |acc, (_, a)| acc.checked_add(*a))
            .ok_or(LanternError::Overflow("traced"))?,
    };
    Ok(Traced {
        deposit,
        traced,
        lowest,
        carriers,
    })
}

impl Procedure for Trace {
    fn id(&self) -> &'static str {
        self.law.id()
    }
    fn version(&self) -> u16 {
        1
    }
    fn params(&self) -> &Params {
        &self.params
    }
    fn inputs(&self) -> Vec<(String, String)> {
        vec![
            ("account".into(), hex(self.account)),
            ("source".into(), hex(self.source)),
        ]
    }
    fn run(
        &self,
        snapshot: &Snapshot,
        _book: &BookContext,
        work: &mut Work,
    ) -> Result<Vec<Finding>, LanternError> {
        let Some(claim) = snapshot.coordinate.effective_through else {
            return Err(self.refuse(
                "effective_through",
                "tracing runs up to a declared effective date (the coordinate's effective_through)",
            ));
        };
        let intraday = self.params.get("intraday_order")?;
        match intraday {
            STATEMENT_ORDINAL | WITHDRAWALS_FIRST | DEPOSITS_FIRST => {}
            VALUE_DATE => {
                return Err(self.refuse(
                    "intraday_order",
                    "ValueDate ordering needs retained value dates; a later slice",
                ));
            }
            _ => {
                return Err(self.refuse(
                    "intraday_order",
                    "0 StatementOrdinal, 2 WithdrawalsFirst or 3 DepositsFirst",
                ));
            }
        }
        if self.law == Law::Libr && self.params.get("replenishment")? != 0 {
            return Err(self.refuse(
                "replenishment",
                "only 0 (Never) is registered; OnEvidence replenishment is a later slice",
            ));
        }
        let stream = self.stream(snapshot, claim, intraday)?;
        let t = run_law(self.law, &stream, work)?;
        let movements = stream.moves.len() as u64;
        let mut cites = vec![Cite::Account(self.account), Cite::Entry(self.source)];
        let mut cited: BTreeSet<VId> = t.carriers.keys().copied().collect();
        if let Some(at) = t.lowest.1 {
            cited.insert(at);
        }
        cites.extend(
            cited
                .into_iter()
                .filter(|v| *v != self.source)
                .take(MAX_CITES - 2)
                .map(Cite::Entry),
        );
        let carried: i128 = t
            .carriers
            .values()
            .try_fold(0i128, |acc, v| acc.checked_add(*v))
            .ok_or(LanternError::Overflow("carried"))?;
        let source_date = stream.moves[stream.source_at].date;
        Ok(vec![finding(
            self.law.id(),
            Severity::Info,
            Statistic {
                name: "traced_mantissa".into(),
                value: t.traced,
                scale: 0,
                population: movements,
            },
            cites,
            format!(
                "{}: {} (mantissa) deposited {:04}-{:02}-{:02}; {} later movement(s) through {:04}-{:02}-{:02}; lowest balance after the deposit {}; {} withdrawal(s) carried {} tainted; traced {}",
                self.law.name(),
                t.deposit,
                source_date.year(),
                source_date.month(),
                source_date.day(),
                movements.saturating_sub(stream.source_at as u64 + 1),
                claim.year(),
                claim.month(),
                claim.day(),
                t.lowest.0,
                t.carriers.len(),
                carried,
                t.traced
            ),
        )])
    }
}
