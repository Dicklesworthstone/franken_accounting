//! Tracing laws (plan §11.5): the traceable share of one deposit through a
//! commingled account up to the coordinate's effective date, under a
//! registered law. `trace.libr` is the lowest intermediate balance rule
//! (the claimant's traceable amount never exceeds the lowest balance between
//! the deposit and the claim; no replenishment); `trace.fifo` is Clayton's
//! rule (withdrawals draw the oldest money first); `trace.lifo` draws the
//! newest first; `trace.pro_rata` lets every withdrawal carry tainted and
//! clean value in proportion to their shares of the balance, split under
//! the registered largest-remainder law. One account, one hop, one source
//! legal entity; the claim date is the coordinate's `effective_through`,
//! the source is an entry, and the result is an exact computation whose
//! evidentiary weight is the law's, never a finding of fact.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use fa_journal::genesis::BookContext;
use fa_money::allocation::largest_remainder;
use fa_money::{Amount, Side, UnitId};
use fa_time::DateDay;
use fgdb_types::VId;

use crate::jet::finding;
use crate::projection::{entity, entity_scope, scoped_entity};
use crate::{
    Cite, Finding, LanternError, MAX_CITES, Meter, Params, Procedure, Severity, Snapshot, Statistic,
};

#[cfg(test)]
mod tests;

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
/// `account`. A source spanning entities is ambiguous and is refused.
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

/// One entry's net movement on one side of the traced account and entity.
#[derive(Clone, Debug)]
struct Movement {
    entry: VId,
    date: DateDay,
    /// The entry's recorded commit sequence: the statement order of
    /// movements on one effective day (`StatementOrdinal`). Entry VIds are
    /// identity hashes and carry no order.
    recorded: u64,
    inflow: bool,
    magnitude: i128,
    replenishes: bool,
}

impl Movement {
    #[cfg(test)]
    fn from_net(entry: VId, date: DateDay, recorded: u64, net: i128) -> Result<Self, LanternError> {
        Self::from_net_with_replenish(entry, date, recorded, net, false)
    }

    fn from_net_with_replenish(
        entry: VId,
        date: DateDay,
        recorded: u64,
        net: i128,
        replenishes: bool,
    ) -> Result<Self, LanternError> {
        Ok(Self {
            entry,
            date,
            recorded,
            inflow: net > 0,
            magnitude: net
                .checked_abs()
                .ok_or(LanternError::Overflow("trace movement magnitude"))?,
            replenishes,
        })
    }
}

/// The account's movements in the deposit's unit and entity, ordered under
/// the intraday rule, with the position of the source deposit.
struct Stream {
    unit: UnitId,
    entity: Option<VId>,
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
        work: &mut Meter<'_>,
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
        for e in snapshot.entries.iter().filter(|e| e.vid == self.source) {
            if e.entry.proposal.effective_date > claim {
                return Err(self.refuse(
                    "source",
                    "the source deposit is effective after the coordinate's effective date",
                ));
            }
        }
        let live = snapshot.live_postings_through(Some(claim))?;
        let scope = entity_scope(live.iter().flat_map(|entry| &entry.entry.proposal.legs))?;
        // Select BOTH the source's unit and legal entity. A shared chart
        // account is not authority to spend another entity's clean balance.
        let mut source_scope = entity::Source::default();
        let mut source_docs = BTreeSet::new();
        for e in live.iter().filter(|e| e.vid == self.source) {
            for ev in &e.entry.proposal.evidence {
                source_docs.insert(ev.document_oid);
            }
            for leg in &e.entry.proposal.legs {
                if leg.account_ref == self.account && leg.side == inflow_side {
                    source_scope
                        .observe(leg.amount.unit.0, scoped_entity(&scope, leg)?.map(|value| value.0))
                        .map_err(|error| self.refuse("source", match error {
                            entity::AmbiguousSource::Unit => "the source deposit carries more than one unit into the account",
                            entity::AmbiguousSource::Entity => "the source deposit spans legal entities; an unambiguous source entity is required",
                        }))?;
                }
            }
        }
        let Some((unit, entity)) = source_scope.selected() else {
            return Err(self.refuse(
                "source",
                "the source entry has no live inflow leg on the account (an unreversed entry of the book that deposits into it is required)",
            ));
        };
        let unit = UnitId(unit);
        let entity = entity.map(VId);
        // Net only this account, unit AND entity, retaining recorded order.
        let mut per_entry: BTreeMap<VId, (DateDay, u64, i128, bool)> = BTreeMap::new();
        for e in live {
            work.entry()?;
            let replenishes = e.vid != self.source
                && ((!source_docs.is_empty()
                    && e.entry
                        .proposal
                        .evidence
                        .iter()
                        .any(|ev| source_docs.contains(&ev.document_oid)))
                    || e.entry
                        .proposal
                        .supersession
                        .iter()
                        .any(|s| s.target.vid == self.source));
            for leg in &e.entry.proposal.legs {
                if leg.account_ref != self.account
                    || leg.amount.unit != unit
                    || scoped_entity(&scope, leg)? != entity
                {
                    continue;
                }
                let magnitude = leg
                    .amount
                    .mantissa
                    .checked_abs()
                    .ok_or(LanternError::Overflow("trace magnitude"))?;
                let signed = if leg.side == inflow_side {
                    magnitude
                } else {
                    magnitude
                        .checked_neg()
                        .ok_or(LanternError::Overflow("trace magnitude"))?
                };
                let slot = per_entry.entry(e.vid).or_insert((
                    e.entry.proposal.effective_date,
                    e.recorded_at.0,
                    0,
                    replenishes,
                ));
                slot.2 = slot
                    .2
                    .checked_add(signed)
                    .ok_or(LanternError::Overflow("trace movement"))?;
            }
        }
        let mut moves: Vec<Movement> = per_entry
            .into_iter()
            .filter(|(_, (_, _, net, _))| *net != 0)
            .map(|(entry, (date, recorded, net, replenishes))| {
                Movement::from_net_with_replenish(entry, date, recorded, net, replenishes)
            })
            .collect::<Result<_, LanternError>>()?;
        let rank = |m: &Movement| match intraday {
            WITHDRAWALS_FIRST => u8::from(m.inflow),
            DEPOSITS_FIRST => u8::from(!m.inflow),
            _ => 0,
        };
        // Same-day movements follow the statement (recorded) order; the
        // entry identity only breaks ties inside one commit, deterministically.
        let move_count = moves.len() as u64;
        work.compare(move_count.saturating_mul(move_count.max(1).ilog2().into()))?;
        moves.sort_by(|a, b| {
            (a.date, rank(a), a.recorded, a.entry, a.inflow).cmp(&(
                b.date,
                rank(b),
                b.recorded,
                b.entry,
                b.inflow,
            ))
        });
        let source_at = moves
            .iter()
            .position(|m| m.entry == self.source && m.inflow)
            .ok_or_else(|| {
                self.refuse("source", "the source deposit nets to zero on the account")
            })?;
        Ok(Stream {
            unit,
            entity,
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
    /// Inflow entries that replenished tainted value under `OnEvidence`.
    replenishers: BTreeSet<VId>,
}

fn add(a: i128, b: i128, what: &'static str) -> Result<i128, LanternError> {
    a.checked_add(b).ok_or(LanternError::Overflow(what))
}

fn sub(a: i128, b: i128, what: &'static str) -> Result<i128, LanternError> {
    a.checked_sub(b).ok_or(LanternError::Overflow(what))
}

#[cfg(test)]
fn run_law(law: Law, stream: &Stream, work: &mut Meter<'_>) -> Result<Traced, LanternError> {
    run_law_with_replenishment(law, stream, false, work)
}

fn run_law_with_replenishment(
    law: Law,
    stream: &Stream,
    replenish_on_evidence: bool,
    work: &mut Meter<'_>,
) -> Result<Traced, LanternError> {
    // The opening balance before the deposit is clean money.
    let mut opening = 0i128;
    for m in &stream.moves[..stream.source_at] {
        work.leg()?;
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
    let mut replenishers: BTreeSet<VId> = BTreeSet::new();
    // An account owes before it holds: only the increase in max(balance, 0)
    // becomes held money. Keep overdrafts in the signed balance, not a
    // second magnitude accumulator: negating i128::MIN would falsely refuse
    // an otherwise representable opening balance and its repayment.
    let traceable = deposit.min(balance.max(0));
    // Only the selected law's state is maintained. In particular, FIFO/LIFO
    // withdrawals do not reduce a pro-rata clean pool, so updating that
    // unused pool on deposits would accumulate turnover and overflow even
    // while the actual account balance remained bounded.
    let layered = matches!(law, Law::Fifo | Law::Lifo);
    let mut layers: VecDeque<(bool, i128)> = VecDeque::new();
    if layered {
        if opening > 0 {
            layers.push_back((false, opening));
        }
        if traceable > 0 {
            layers.push_back((true, traceable));
        }
    }
    let mut tainted = traceable;
    let mut clean = if law == Law::ProRata {
        opening.max(0)
    } else {
        0
    };
    for m in &stream.moves[stream.source_at + 1..] {
        work.leg()?;
        if m.inflow {
            let before = balance.max(0);
            balance = add(balance, m.magnitude, "balance")?;
            let held = sub(balance.max(0), before, "inflow")?;
            if held > 0 {
                match law {
                    Law::Fifo | Law::Lifo => layers.push_back((false, held)),
                    Law::ProRata => clean = add(clean, held, "clean pool")?,
                    Law::Libr => {
                        if replenish_on_evidence && m.replenishes && tainted < traceable {
                            let deficit = sub(traceable, tainted, "replenish cap")?;
                            let avail = sub(balance.max(0), tainted, "replenish avail")?.max(0);
                            let restored = held.min(deficit).min(avail);
                            if restored > 0 {
                                tainted = add(tainted, restored, "replenished taint")?;
                                replenishers.insert(m.entry);
                            }
                        }
                    }
                }
            }
            continue;
        }
        balance = sub(balance, m.magnitude, "balance")?;
        if balance < lowest.0 {
            lowest = (balance, Some(m.entry));
        }
        match law {
            Law::Libr => {
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
                        // The signed balance already records any overdraft.
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
                let drawn = m.magnitude.min(pool.max(0));
                if drawn == 0 {
                    continue;
                }
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
        replenishers,
    })
}

impl Trace {
    pub(crate) fn run_as(
        &self,
        procedure_id: &str,
        version: u16,
        snapshot: &Snapshot,
        book: &BookContext,
        work: &mut Meter<'_>,
    ) -> Result<Vec<Finding>, LanternError> {
        let refuse = |name: &str, message: &str| LanternError::Parameter {
            procedure: procedure_id.into(),
            name: name.into(),
            message: message.into(),
        };
        let Some(claim) = snapshot.coordinate.effective_through else {
            return Err(refuse(
                "effective_through",
                "tracing runs up to a declared effective date (the coordinate's effective_through)",
            ));
        };
        let intraday = self.params.get("intraday_order")?;
        match intraday {
            STATEMENT_ORDINAL | WITHDRAWALS_FIRST | DEPOSITS_FIRST => {}
            VALUE_DATE => {
                return Err(refuse(
                    "intraday_order",
                    "ValueDate ordering needs retained value dates; a later slice",
                ));
            }
            _ => {
                return Err(refuse(
                    "intraday_order",
                    "0 StatementOrdinal, 2 WithdrawalsFirst or 3 DepositsFirst",
                ));
            }
        }
        let replenish_on_evidence = if self.law == Law::Libr {
            match self.params.get("replenishment")? {
                0 => false,
                1 => true,
                _ => {
                    return Err(refuse("replenishment", "0 Never or 1 OnEvidence"));
                }
            }
        } else {
            false
        };
        let stream = self
            .stream(snapshot, claim, intraday, work)
            .map_err(|err| match err {
                LanternError::Parameter { name, message, .. } => refuse(&name, &message),
                other => other,
            })?;
        let t = run_law_with_replenishment(self.law, &stream, replenish_on_evidence, work)?;
        let movements = stream.moves.len() as u64;
        let mut cites = vec![Cite::Account(self.account), Cite::Entry(self.source)];
        let mut cited: BTreeSet<VId> = t.carriers.keys().copied().collect();
        cited.extend(t.replenishers.iter().copied());
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
        let entity_text = stream.entity.map_or_else(
            || "implicit book entity".into(),
            |entity| format!("entity {}", hex(entity)),
        );
        let mut f = finding(
            procedure_id,
            Severity::Info,
            Statistic {
                name: "traced_mantissa".into(),
                value: t.traced,
                scale: crate::unit_scale(book, stream.unit.0)?,
                population: movements,
            },
            cites,
            format!(
                "{}: {} (mantissa) deposited {:04}-{:02}-{:02}; {} later movement(s) through {:04}-{:02}-{:02}; lowest balance after the deposit {}; {} withdrawal(s) carried {} tainted; traced {}; {entity_text}",
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
        );
        f.version = version;
        Ok(vec![f])
    }
}

impl Procedure for Trace {
    fn id(&self) -> &'static str {
        self.law.id()
    }
    fn version(&self) -> u16 {
        2
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
        book: &BookContext,
        work: &mut Meter<'_>,
    ) -> Result<Vec<Finding>, LanternError> {
        self.run_as(self.id(), self.version(), snapshot, book, work)
    }
}
