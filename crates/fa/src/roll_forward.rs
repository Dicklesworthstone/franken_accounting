//! Historical lead schedules from native journal payloads (plan §12.1).
//!
//! Opening stock, posted movements and closing stock share one recorded
//! prefix. The register fold's migration visibility predicate is reused;
//! current chart and mutable leg/register mirrors are not source authority.
//! The plain read returns exact arithmetic and entry citations. Certification
//! additionally binds native history for replay, not outsider authorization.

mod certificate;

pub use certificate::{
    CertifiedRollForward, MAX_ROLL_FORWARD_CERTIFICATE_BYTES, MAX_ROLL_FORWARD_WORKPAPER_BYTES,
    ROLL_FORWARD_CERTIFICATE_FORMAT, RollForwardCertificate,
};

use std::collections::{BTreeMap, BTreeSet};

use asupersync::fs::Vfs;
use fa_journal::rows::{AccountRow, bytes};
use fa_journal::{KernelError, Refusal, exit};
use fa_model::symbols::{label, property};
use fa_model::{AccountType, Entry, EntryClass, EntryOrigin, Id128};
use fa_money::{Side, UnitId};
use fa_policy::Capability;
use fa_registers::{RegisterError, TrialBalance};
use fa_statements::cash_flow::{
    EquityActivityKind, EquityMovement, EquityRollForward, EquityRollForwardInput,
};
use fa_statements::roll_forward::{Bucket, Movement, RollForwardInput};
use fa_statements::{Account, AccountBalance};
use fa_time::DateDay;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::{AsyncBook, BookError, Outcome};
pub use fa_statements::roll_forward::RollForward;

/// Explicit monetary leaf/unit selection, not an access-control scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RollForwardRequest {
    pub accounts: Vec<VId>,
    pub units: Vec<u32>,
    pub label: String,
    pub effective_from: DateDay,
    pub effective_through: DateDay,
    /// None resolves the current head exactly once, before any source reads.
    pub known_at: Option<CommitSeq>,
}

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        fa_journal::refusal::code::STRUCTURE,
        exit::USAGE,
        message,
        "plan §12.1 (opening + posted activity = closing at one coordinate)",
        "select distinct existing monetary leaves and native units, ordered inclusive dates and a retained known-at sequence; do not add a balancing entry",
    )
}

fn corrupt(message: impl Into<String>) -> BookError {
    KernelError::Corrupt(message.into()).into()
}

fn scope(request: &RollForwardRequest) -> Result<(BTreeSet<VId>, BTreeSet<u32>), Refusal> {
    if request.accounts.is_empty()
        || request.accounts.len() > 4096
        || request.units.is_empty()
        || request.units.len() > 4096
        || request.label.trim().is_empty()
        || request.label.len() > 256
        || request.effective_from > request.effective_through
    {
        return Err(invalid(
            "invalid or excessive roll-forward scope, label or dates",
        ));
    }
    let accounts: BTreeSet<_> = request.accounts.iter().copied().collect();
    let units: BTreeSet<_> = request.units.iter().copied().collect();
    if accounts.len() != request.accounts.len() || units.len() != request.units.len() {
        return Err(invalid("roll-forward accounts and units must not repeat"));
    }
    if accounts
        .len()
        .checked_mul(units.len())
        .is_none_or(|cells| cells > 666_666)
    {
        return Err(invalid(
            "roll-forward scope would exceed the output amount bound",
        ));
    }
    Ok((accounts, units))
}

fn balances(
    fold: TrialBalance,
    at: CommitSeq,
    through: DateDay,
    accounts: &BTreeSet<VId>,
    units: &BTreeSet<u32>,
) -> Result<Vec<AccountBalance>, BookError> {
    if fold.known_at != at || fold.effective_through != Some(through) || fold.activity {
        return Err(corrupt(
            "roll-forward stock fold has a different coordinate",
        ));
    }
    Ok(fold
        .rows
        .into_iter()
        .filter(|row| accounts.contains(&row.account) && units.contains(&row.unit_id))
        .map(|row| AccountBalance {
            account_id: row.account.0,
            unit_id: row.unit_id,
            debits: row.debits,
            credits: row.credits,
        })
        .collect())
}

/// The model records reason codes on supersession links, not on an entry's
/// free-text description. Preserve the exact distinct code set; an empty
/// string means no recorded supersession reason. No text is decrypted and
/// no accountant's classification is inferred. Rule origins retain the
/// recorded version OID; other origins have no rule version.
fn bucket(entry: &Entry) -> Bucket {
    let reasons: BTreeSet<_> = entry
        .proposal
        .supersession
        .iter()
        .map(|link| link.reason_code)
        .collect();
    let reason_code = if reasons.is_empty() {
        String::new()
    } else {
        format!(
            "supersession:{}",
            reasons
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(",")
        )
    };
    Bucket {
        class: entry.proposal.class,
        reason_code,
        rule_digest: match &entry.proposal.origin {
            EntryOrigin::Rule {
                rule_version_oid, ..
            } => Some(rule_version_oid.0),
            _ => None,
        },
    }
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Produce a historical account lead schedule under CURRENT authority to
    /// read the whole book at the selected recorded prefix. A known-at caveat
    /// permits an explicit prefix within its bound; account, period and
    /// effective caveats are refused because the native source reads the whole
    /// prefix before projecting the requested monetary leaves and date window.
    /// Every financial read is pinned to the same prefix.
    /// Posted reversals and Closing entries are real movements, Pending
    /// reservations are not. Zero legs have no movement and are omitted.
    /// Current expiry/revocation apply even when selecting an older prefix.
    /// No document is opened, runtime spawned, checkpoint minted or write made.
    pub fn roll_forward(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        request: &RollForwardRequest,
    ) -> Outcome<RollForward> {
        if let Err(denial) = fa_policy::admit_read(capability, principal, self.context().book_id)
            .and_then(|()| {
                fa_policy::reach(
                    capability,
                    &fa_policy::Reach {
                        observes: request
                            .known_at
                            .map_or(fa_policy::Observes::Head, fa_policy::Observes::At),
                        ..fa_policy::Reach::whole_book(true)
                    },
                    None,
                )
            })
        {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        let query = cx.query();
        query.checkpoint().map_err(BookError::Context)?;
        query.with_restriction(|| {
            let head = self.db.frontier().map_err(KernelError::from)?;
            if let Err(denial) = fa_policy::current(capability, head) {
                return Ok(Err(fa_journal::policy::refusal(&denial)));
            }
            if let Err(refusal) =
                fa_journal::policy::capability_admitted(&self.db, self.context(), capability)?
            {
                return Ok(Err(refusal));
            }
            let (account_ids, units) = match scope(request) {
                Ok(scope) => scope,
                Err(refusal) => return Ok(Err(refusal)),
            };
            let at = request.known_at.unwrap_or(head);
            if at > head {
                return Ok(Err(invalid(
                    "roll-forward known-at is beyond the book head",
                )));
            }
            crate::certificate::context_at(&self.db, self.context(), at)?;
            let chart = fa_journal::chart::read_at(&self.db, self.context(), at)?;
            let mut accounts = Vec::new();
            for id in &account_ids {
                let Some(account) = chart.accounts().get(id) else {
                    return Ok(Err(invalid(
                        "roll-forward account is absent at the selected prefix",
                    )));
                };
                if !account.is_leaf || !(1..=5).contains(&account.account_type) {
                    return Ok(Err(invalid(
                        "roll-forward requires monetary posting leaves",
                    )));
                }
                accounts.push(as_account(account));
            }
            for unit in &units {
                if self.context().units.get(UnitId(*unit)).is_none() {
                    return Ok(Err(invalid("roll-forward unit is not registered")));
                }
            }
            let stock = |through| -> Result<Vec<AccountBalance>, BookError> {
                balances(
                    fa_registers::balance_as_of(&self.db, self.context(), through, Some(at))?,
                    at,
                    through,
                    &account_ids,
                    &units,
                )
            };
            let opening = match request.effective_from.0.checked_sub(1) {
                Some(before) => stock(DateDay(before)),
                None => Ok(Vec::new()), // no representable earlier civil day
            };
            let opening = match opening {
                Ok(rows) => rows,
                Err(BookError::Registers(RegisterError::InvalidSelection(message))) => {
                    return Ok(Err(invalid(message)));
                }
                Err(error) => return Err(error),
            };
            query.checkpoint().map_err(BookError::Context)?;
            let closing = match stock(request.effective_through) {
                Ok(rows) => rows,
                Err(BookError::Registers(RegisterError::InvalidSelection(message))) => {
                    return Ok(Err(invalid(message)));
                }
                Err(error) => return Err(error),
            };
            let mut movements = Vec::new();
            let mut runs = BTreeMap::new();
            for (index, row) in self
                .db
                .vertices_at(at)
                .map_err(KernelError::from)?
                .into_iter()
                .enumerate()
            {
                if index % 256 == 0 {
                    query.checkpoint().map_err(BookError::Context)?;
                }
                if !row.labels.contains(&label::ENTRY) {
                    continue;
                }
                let entry = Entry::decode(&bytes(
                    &row,
                    property::FA_PAYLOAD,
                    "roll-forward entry payload",
                )?)
                .map_err(KernelError::from)?;
                let p = &entry.proposal;
                if p.book_id != self.context().book_id
                    || p.branch_id != Id128::TRUNK
                    || row.created_at.0 == 0
                    || row.created_at > at
                {
                    return Err(corrupt(
                        "roll-forward source entry has a different coordinate",
                    ));
                }
                if !fa_journal::migration::visible_at(&self.db, &entry, at, &mut runs)?
                    || p.class.is_control()
                    || p.class == EntryClass::PENDING
                    || p.effective_date < request.effective_from
                    || p.effective_date > request.effective_through
                {
                    continue;
                }
                let bucket = bucket(&entry);
                for (ordinal, leg) in p.legs.iter().enumerate() {
                    if !account_ids.contains(&leg.account_ref)
                        || !units.contains(&leg.amount.unit.0)
                        || leg.amount.mantissa == 0
                    {
                        continue;
                    }
                    if movements.len() == 2_000_000 {
                        return Ok(Err(invalid(
                            "roll-forward exceeds two million selected movements",
                        )));
                    }
                    let (debits, credits) = match leg.side {
                        Side::Debit => (leg.amount.mantissa, 0),
                        Side::Credit => (0, leg.amount.mantissa),
                    };
                    movements.push(Movement {
                        entry_digest: entry.entry_digest,
                        leg_index: u32::try_from(ordinal)
                            .map_err(|_| corrupt("roll-forward leg ordinal overflow"))?,
                        recorded_seq: row.created_at.0,
                        effective_day: p.effective_date,
                        account_id: leg.account_ref.0,
                        unit_id: leg.amount.unit.0,
                        bucket: bucket.clone(),
                        debits,
                        credits,
                    });
                }
            }
            query.checkpoint().map_err(BookError::Context)?;
            let source = RollForwardInput {
                book_id: self.context().book_id,
                branch_id: Id128::TRUNK,
                known_at: at.0,
                label: request.label.clone(),
                effective_from: request.effective_from,
                effective_through: request.effective_through,
                accounts,
                units: units.into_iter().collect(),
                opening,
                closing,
                movements,
            };
            let result = fa_statements::roll_forward::evaluate(&source)
                .map_err(|error| invalid(error.to_string()));
            query.checkpoint().map_err(BookError::Context)?;
            Ok(result)
        })
    }

    /// The Statement of Changes in Equity (plan §12.1, `EquityRollForward`)
    /// over the lead schedule of every equity, revenue and expense leaf at
    /// one recorded prefix, under the same CURRENT whole-book read authority
    /// as [`Self::roll_forward`], which supplies its stocks and movements.
    /// Net income is revenue and expense activity outside `Closing` entries;
    /// a `Closing` entry's legs are the closing transfer, which must move
    /// nothing in total. Opening equity plus net income, issuances,
    /// distributions and other equity movements ties to closing equity per
    /// unit, or the statement is refused. Units are never converted, and no
    /// account's role is inferred: the request names the issuance and
    /// distribution leaves.
    pub fn equity_roll_forward(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        request: &EquityRollForwardRequest,
    ) -> Outcome<EquityRollForwardReport> {
        // Authorization precedes the chart read that selects the leaves;
        // roll_forward repeats both checks at the same prefix.
        if let Err(denial) = fa_policy::admit_read(capability, principal, self.context().book_id)
            .and_then(|()| {
                fa_policy::reach(
                    capability,
                    &fa_policy::Reach {
                        observes: request
                            .known_at
                            .map_or(fa_policy::Observes::Head, fa_policy::Observes::At),
                        ..fa_policy::Reach::whole_book(true)
                    },
                    None,
                )
            })
        {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        let query = cx.query();
        query.checkpoint().map_err(BookError::Context)?;
        let selected = query.with_restriction(|| -> Outcome<(CommitSeq, Vec<VId>)> {
            let head = self.db.frontier().map_err(KernelError::from)?;
            if let Err(denial) = fa_policy::current(capability, head) {
                return Ok(Err(fa_journal::policy::refusal(&denial)));
            }
            if let Err(refusal) =
                fa_journal::policy::capability_admitted(&self.db, self.context(), capability)?
            {
                return Ok(Err(refusal));
            }
            let at = request.known_at.unwrap_or(head);
            if at > head {
                return Ok(Err(invalid_equity(
                    "equity roll-forward known-at is beyond the book head",
                )));
            }
            crate::certificate::context_at(&self.db, self.context(), at)?;
            let chart = fa_journal::chart::read_at(&self.db, self.context(), at)?;
            let mut named = BTreeSet::new();
            for (role, ids) in [
                ("issuance", &request.issuance_accounts),
                ("distribution", &request.distribution_accounts),
            ] {
                for id in ids {
                    let Some(account) = chart.accounts().get(id) else {
                        return Ok(Err(invalid_equity(format!(
                            "{role} account {:032x} is absent from the chart at the selected prefix",
                            id.0
                        ))));
                    };
                    if !account.is_leaf || account.account_type != AccountType::EQUITY.0 {
                        return Ok(Err(invalid_equity(format!(
                            "{role} account `{}` is not an equity posting leaf",
                            account.code
                        ))));
                    }
                    if !named.insert(*id) {
                        return Ok(Err(invalid_equity(format!(
                            "equity account `{}` is named more than once",
                            account.code
                        ))));
                    }
                }
            }
            let accounts = chart
                .accounts()
                .values()
                .filter(|a| {
                    a.is_leaf
                        && [
                            AccountType::EQUITY,
                            AccountType::REVENUE,
                            AccountType::EXPENSE,
                        ]
                        .contains(&AccountType(a.account_type))
                })
                .map(|a| a.vid)
                .collect();
            Ok(Ok((at, accounts)))
        })?;
        let (at, accounts) = match selected {
            Ok(selected) => selected,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let source = match self.roll_forward(
            cx,
            principal,
            capability,
            &RollForwardRequest {
                accounts,
                units: request.units.clone(),
                label: request.label.clone(),
                effective_from: request.effective_from,
                effective_through: request.effective_through,
                known_at: Some(at),
            },
        )? {
            Ok(source) => source,
            Err(refusal) => return Ok(Err(refusal)),
        };
        Ok(equity_from_lead_schedule(source, request))
    }
}

/// The Statement of Changes in Equity's question (plan §12.1,
/// `EquityRollForward`): native units, an inclusive effective window, one
/// recorded prefix, and which equity leaves carry owner issuances and which
/// distributions. Every other posted leg on an equity leaf is another equity
/// movement, and a `Closing` entry's legs are the closing transfer; no
/// account's role is inferred from its name or code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EquityRollForwardRequest {
    pub units: Vec<u32>,
    pub label: String,
    pub effective_from: DateDay,
    pub effective_through: DateDay,
    /// None resolves the current head exactly once, before any source reads.
    pub known_at: Option<CommitSeq>,
    pub issuance_accounts: Vec<VId>,
    pub distribution_accounts: Vec<VId>,
}

/// A reconciled Statement of Changes in Equity with its exact inputs: the
/// equity, revenue and expense leaves at the prefix, and every classified
/// equity leg (direct movements and closing transfers) it folded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EquityRollForwardReport {
    pub statement: EquityRollForward,
    pub accounts: Vec<Account>,
    pub movements: Vec<EquityMovement>,
}

/// Classify the lead schedule's legs and fold the statement. Stocks are
/// the schedule's own opening and closing (debit minus credit, as one
/// positive side); nothing is read again.
fn equity_from_lead_schedule(
    source: RollForward,
    request: &EquityRollForwardRequest,
) -> Result<EquityRollForwardReport, Refusal> {
    let types: BTreeMap<u128, u8> = source
        .accounts
        .iter()
        .map(|a| (a.id, a.account_type))
        .collect();
    let issuance: BTreeSet<u128> = request.issuance_accounts.iter().map(|v| v.0).collect();
    let distribution: BTreeSet<u128> = request.distribution_accounts.iter().map(|v| v.0).collect();
    let overflow = || invalid_equity("equity roll-forward net income overflows");
    let mut net_income: BTreeMap<u32, i128> = source.units.iter().map(|u| (*u, 0)).collect();
    let mut movements = Vec::new();
    for m in &source.movements {
        let Some(&account_type) = types.get(&m.account_id) else {
            return Err(invalid_equity(
                "a lead-schedule movement names an account outside its selection",
            ));
        };
        let kind = if m.bucket.class == EntryClass::CLOSING {
            EquityActivityKind::ClosingTransfer
        } else if account_type == AccountType::EQUITY.0 {
            if issuance.contains(&m.account_id) {
                EquityActivityKind::Issuance
            } else if distribution.contains(&m.account_id) {
                EquityActivityKind::Distribution
            } else {
                EquityActivityKind::OtherEquity
            }
        } else {
            let slot = net_income.get_mut(&m.unit_id).ok_or_else(|| {
                invalid_equity("a lead-schedule movement names a unit outside its selection")
            })?;
            *slot = slot
                .checked_add(m.credits)
                .and_then(|v| v.checked_sub(m.debits))
                .ok_or_else(overflow)?;
            continue;
        };
        movements.push(EquityMovement {
            entry_digest: m.entry_digest,
            leg_index: m.leg_index,
            recorded_seq: m.recorded_seq,
            effective_day: m.effective_day,
            class: m.bucket.class,
            kind,
            account_id: m.account_id,
            unit_id: m.unit_id,
            debits: m.debits,
            credits: m.credits,
        });
    }
    let stock = |account_id: u128, unit_id: u32, net: i128| -> Result<AccountBalance, Refusal> {
        let (debits, credits) = if net >= 0 {
            (net, 0)
        } else {
            (
                0,
                net.checked_neg()
                    .ok_or_else(|| invalid_equity("an equity stock overflows"))?,
            )
        };
        Ok(AccountBalance {
            account_id,
            unit_id,
            debits,
            credits,
        })
    };
    let mut opening_balances = Vec::with_capacity(source.rows.len());
    let mut closing_balances = Vec::with_capacity(source.rows.len());
    for row in &source.rows {
        opening_balances.push(stock(row.account_id, row.unit_id, row.opening)?);
        closing_balances.push(stock(row.account_id, row.unit_id, row.closing)?);
    }
    let input = EquityRollForwardInput {
        book_id: source.book_id,
        branch_id: source.branch_id,
        known_at: source.known_at,
        label: source.label.clone(),
        effective_from: source.effective_from,
        effective_through: source.effective_through,
        accounts: source.accounts.clone(),
        units: source.units.clone(),
        opening_balances,
        closing_balances,
        net_income_by_unit: net_income,
        equity_movements: movements.clone(),
    };
    let statement = fa_statements::cash_flow::evaluate_equity_roll_forward(&input)
        .map_err(|error| invalid_equity(error.to_string()))?;
    Ok(EquityRollForwardReport {
        statement,
        accounts: source.accounts,
        movements,
    })
}

fn invalid_equity(message: impl Into<String>) -> Refusal {
    Refusal::new(
        fa_journal::refusal::code::STRUCTURE,
        exit::USAGE,
        message,
        "plan §12.1 (EquityRollForward: opening equity + net income + issuances + distributions + other equity movements = closing equity, at one coordinate)",
        "name each issuance and distribution account once, as an equity posting leaf of the chart at the selected known-at; select native units and ordered inclusive dates; do not add a balancing entry",
    )
}

fn as_account(account: &AccountRow) -> Account {
    Account {
        id: account.vid.0,
        code: account.code.clone(),
        name: account.name.clone(),
        account_type: account.account_type,
        is_leaf: account.is_leaf,
    }
}

#[cfg(test)]
mod tests {
    mod certification;
    mod workpaper;

    use super::*;
    use crate::{BookKeys, Entropy};
    use asupersync::runtime::{Runtime, RuntimeBuilder};
    use asupersync::{Budget, Cx};
    use fa_journal::{AccountSpec, BookSpec, Document, PostRequest, UnitPolicy};
    use fa_model::{AccountType, EntryPayload, EvidenceRef, LegPayload, Oid, account_vid};
    use fa_money::{Amount, UnitRegistry};
    use fa_time::{FiscalCalendar, PeriodTransition};
    use fgdb::MemVfs;
    use std::path::Path;

    const PRINCIPAL: VId = VId(1);
    fn day(d: u8) -> DateDay {
        DateDay::from_ymd(2026, 1, d).unwrap()
    }
    fn cap(ops: &[&str]) -> Capability {
        Capability::embedded(PRINCIPAL, ops).unwrap()
    }

    struct Harness {
        runtime: Runtime,
        root: Cx,
        book: AsyncBook<MemVfs>,
        vfs: MemVfs,
        usd: UnitId,
        jpy: UnitId,
        evidence: Vec<EvidenceRef>,
    }

    impl Harness {
        fn new() -> Self {
            let runtime = RuntimeBuilder::new().build().unwrap();
            let root = runtime.request_cx_with_budget(Budget::INFINITE);
            let cx = PurposeContexts::narrow_runtime_root(&root);
            let units = UnitRegistry::embedded().unwrap();
            let usd = units.lookup("USD").unwrap();
            let jpy = units.lookup("JPY").unwrap();
            let book_id = Id128([113; 16]);
            let spec = BookSpec {
                book_id,
                name: "Roll-forward integration".into(),
                base_unit: usd,
                calendar: FiscalCalendar::monthly("roll-forward", 1, 1).unwrap(),
                time_zone_policy: None,
                entities: Vec::new(),
                opening_date: None,
            };
            let vfs = cx.commit().with_restriction(MemVfs::new).unwrap();
            let mut book = runtime
                .block_on(AsyncBook::create_with_vfs(
                    &cx,
                    vfs.clone(),
                    Path::new("roll-forward-book"),
                    BookKeys::for_development(113),
                    spec,
                    Entropy::deterministic(113),
                ))
                .unwrap();
            let accounts: Vec<_> = [
                ("1000", AccountType::ASSET),
                ("3000", AccountType::EQUITY),
                ("6100", AccountType::EXPENSE),
            ]
            .into_iter()
            .map(|(code, kind)| AccountSpec {
                code: code.into(),
                name: code.into(),
                account_type: kind.0,
                normal_balance: u8::from(kind == AccountType::EQUITY),
                is_leaf: true,
                unit_policy: UnitPolicy::AnyCurrency,
                parent_code: None,
                limit: None,
            })
            .collect();
            runtime
                .block_on(book.install_chart(
                    &cx,
                    &accounts,
                    PRINCIPAL,
                    day(1),
                    b"roll-chart",
                    &fa_journal::Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
                ))
                .unwrap()
                .unwrap();
            runtime
                .block_on(
                    book.create_periods(
                        &cx,
                        2026,
                        fgdb_types::VId(1),
                        &fa_journal::Capability::embedded(fgdb_types::VId(1), &["schema_change"])
                            .unwrap(),
                    ),
                )
                .unwrap()
                .unwrap();
            runtime
                .block_on(book.transition_period(
                    &cx,
                    "FY2026-P01",
                    PeriodTransition::Open,
                    PRINCIPAL,
                    1,
                    b"roll-open",
                    &cap(&["close"]),
                ))
                .unwrap()
                .unwrap();
            let doc = Document {
                book_id,
                kind: 1,
                mime: "text/plain".into(),
                grade: 3,
                retrieved_by: PRINCIPAL,
                bytes: b"Admitted lead schedule evidence".to_vec(),
            };
            runtime
                .block_on(book.add_document(&cx, &doc))
                .unwrap()
                .unwrap();
            Self {
                runtime,
                root,
                book,
                vfs,
                usd,
                jpy,
                evidence: vec![doc.evidence_ref(1)],
            }
        }
        fn cx(&self) -> PurposeContexts {
            PurposeContexts::narrow_runtime_root(&self.root)
        }
        fn id(&self, code: &str) -> VId {
            account_vid(self.book.context().book_id, code)
        }
        fn head(&self) -> CommitSeq {
            self.book.head(&self.cx()).unwrap()
        }
        fn request(&self) -> RollForwardRequest {
            RollForwardRequest {
                accounts: vec![self.id("1000"), self.id("3000"), self.id("6100")],
                units: vec![self.usd.0],
                label: "January 10 through 20".into(),
                effective_from: day(10),
                effective_through: day(20),
                known_at: None,
            }
        }
        fn post(&mut self, date: u8, key: &[u8], unit: UnitId, net: i128) {
            let cx = self.cx();
            let (debit, credit) = if net >= 0 {
                ("1000", "3000")
            } else {
                ("3000", "1000")
            };
            let amount = Amount::new(unit, net.abs());
            let legs = vec![
                LegPayload::simple(Side::Debit, self.id(debit), amount),
                LegPayload::simple(Side::Credit, self.id(credit), amount),
            ];
            let proposal = EntryPayload {
                schema_minor: 0,
                book_id: self.book.context().book_id,
                branch_id: Id128::TRUNK,
                class: EntryClass::ORIGINAL,
                effective_date: day(date),
                document_date: None,
                description: self.book.seal_text(&cx, "Lead schedule posting").unwrap(),
                effective_period: None,
                unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
                legs,
                control: None,
                base_totals: None,
                idempotency_key: key.to_vec(),
                origin: EntryOrigin::Intent {
                    intent_oid: Oid([53; 32]),
                    intent_kind: 1,
                },
                principal_ref: PRINCIPAL,
                session_ref: None,
                evidence: self.evidence.clone(),
                supersession: Vec::new(),
                pending: None,
                external_ids: Vec::new(),
                tags: Vec::new(),
                extensions: Vec::new(),
            };
            self.runtime
                .block_on(self.book.post(
                    &cx,
                    PostRequest {
                        proposal,
                        approvals: Vec::new(),
                        plan_certificate: None,
                        capability: cap(&["post"]),
                    },
                ))
                .unwrap()
                .unwrap();
        }
        fn read(&self, request: &RollForwardRequest) -> RollForward {
            self.book
                .roll_forward(&self.cx(), PRINCIPAL, &cap(&["read"]), request)
                .unwrap()
                .unwrap()
        }
    }

    fn row(report: &RollForward, account: VId, unit: UnitId) -> &fa_statements::roll_forward::Row {
        report
            .rows
            .iter()
            .find(|row| row.account_id == account.0 && row.unit_id == unit.0)
            .unwrap()
    }

    #[test]
    fn real_postings_respect_both_inclusive_boundaries_and_read_without_writing() {
        let mut h = Harness::new();
        h.post(1, b"opening", h.usd, 100);
        h.post(10, b"first", h.usd, 50);
        h.post(20, b"last", h.usd, -20);
        h.post(21, b"outside", h.usd, 7);
        let head = h.head();
        let report = h.read(&h.request());
        let cash = row(&report, h.id("1000"), h.usd);
        assert_eq!(
            (cash.opening, cash.net_change, cash.closing),
            (100, 30, 130)
        );
        assert_eq!(cash.activity, [30]);
        assert_eq!(report.movements.len(), 4);
        let capital = row(&report, h.id("3000"), h.usd);
        assert_eq!((capital.opening, capital.closing), (-100, -130));
        assert_eq!(row(&report, h.id("6100"), h.usd).closing, 0);
        assert_eq!(h.head(), head);
    }

    #[test]
    fn late_effective_postings_change_current_but_not_pinned_historical_bytes() {
        let mut h = Harness::new();
        h.post(1, b"opening", h.usd, 100);
        h.post(10, b"first", h.usd, 50);
        let mut request = h.request();
        request.known_at = Some(h.head());
        let original = h.read(&request).canonical_bytes().unwrap();
        h.post(11, b"late", h.usd, 9);
        assert_eq!(h.read(&request).canonical_bytes().unwrap(), original);
        assert_eq!(row(&h.read(&h.request()), h.id("1000"), h.usd).closing, 159);
    }

    #[test]
    fn native_units_stay_separate_and_selection_order_is_not_semantic() {
        let mut h = Harness::new();
        h.post(10, b"dollars", h.usd, 50);
        h.post(10, b"yen", h.jpy, -50);
        let mut request = h.request();
        request.units.push(h.jpy.0);
        let report = h.read(&request);
        assert_eq!(row(&report, h.id("1000"), h.usd).closing, 50);
        assert_eq!(row(&report, h.id("1000"), h.jpy).closing, -50);
        let bytes = report.canonical_bytes().unwrap();
        request.accounts.reverse();
        request.units.reverse();
        assert_eq!(h.read(&request).canonical_bytes().unwrap(), bytes);
    }

    #[test]
    fn current_authority_and_explicit_scope_are_required_for_historical_reads() {
        let h = Harness::new();
        let request = h.request();
        assert!(
            h.book
                .roll_forward(&h.cx(), PRINCIPAL, &cap(&["post"]), &request)
                .unwrap()
                .is_err()
        );
        assert!(
            h.book
                .roll_forward(&h.cx(), VId(99), &cap(&["read"]), &request)
                .unwrap()
                .is_err()
        );
        for bad in [
            RollForwardRequest {
                accounts: vec![VId(u128::MAX)],
                ..request.clone()
            },
            RollForwardRequest {
                accounts: vec![h.id("1000"), h.id("1000")],
                ..request.clone()
            },
            RollForwardRequest {
                units: vec![u32::MAX],
                ..request.clone()
            },
            RollForwardRequest {
                known_at: Some(CommitSeq(h.head().0 + 1)),
                ..request.clone()
            },
            RollForwardRequest {
                effective_through: day(9),
                ..request.clone()
            },
        ] {
            assert!(
                h.book
                    .roll_forward(&h.cx(), PRINCIPAL, &cap(&["read"]), &bad)
                    .unwrap()
                    .is_err()
            );
        }
    }

    #[test]
    fn native_ledger_reads_enforce_caveats_and_preserve_authorized_historical_bytes() {
        let mut h = Harness::new();
        h.post(10, b"before-pin", h.usd, 50);
        let pin = h.head();
        let request = RollForwardRequest {
            known_at: Some(pin),
            ..h.request()
        };
        let expected = h.read(&request).canonical_bytes().unwrap();
        let expected_gl = h
            .book
            .general_ledger(&h.cx(), PRINCIPAL, &cap(&["read"]), &request)
            .unwrap()
            .unwrap()
            .canonical_bytes()
            .unwrap();
        let source = h
            .book
            .certify_roll_forward(&h.cx(), PRINCIPAL, &cap(&["read", "produce"]), &request)
            .unwrap()
            .unwrap();
        h.post(15, b"after-pin", h.usd, 70);
        let head = h.head();
        let pinned = cap(&["read", "produce"]).known_at_most(pin);
        assert_eq!(
            h.book
                .roll_forward(&h.cx(), PRINCIPAL, &pinned, &request)
                .unwrap()
                .unwrap()
                .canonical_bytes()
                .unwrap(),
            expected
        );
        assert_eq!(
            h.book
                .general_ledger(&h.cx(), PRINCIPAL, &pinned, &request)
                .unwrap()
                .unwrap()
                .canonical_bytes()
                .unwrap(),
            expected_gl
        );
        assert_ne!(h.read(&h.request()).canonical_bytes().unwrap(), expected);
        let cx = h.cx();
        h.runtime
            .block_on(
                h.book
                    .prepare_report_history(&cx, PRINCIPAL, &pinned, Some(pin)),
            )
            .unwrap()
            .unwrap();

        for known_at in [None, Some(head)] {
            let outside = RollForwardRequest {
                known_at,
                ..request.clone()
            };
            let denial = h
                .book
                .roll_forward(&cx, PRINCIPAL, &pinned, &outside)
                .unwrap()
                .unwrap_err();
            assert_eq!((denial.code, denial.exit), ("FA-REF-011", 7));
            assert!(denial.message.contains("known_at"));
            let denial = h
                .runtime
                .block_on(
                    h.book
                        .prepare_report_history(&cx, PRINCIPAL, &pinned, known_at),
                )
                .unwrap()
                .unwrap_err();
            assert_eq!((denial.code, denial.exit), ("FA-REF-011", 7));
        }

        // Account/date selectors are report projections, not permission to
        // load a wider source. Even a caveat containing every requested leaf
        // or the report's last day cannot authorize that whole-prefix read.
        for (restricted, caveat) in [
            (
                cap(&["read", "produce"])
                    .for_accounts(&["1000", "3000", "6100"])
                    .unwrap(),
                "accounts",
            ),
            (
                cap(&["read", "produce"])
                    .for_periods(&["FY2026-P01"])
                    .unwrap(),
                "periods",
            ),
            (
                cap(&["read", "produce"]).effective_through(day(20)),
                "effective",
            ),
            (
                cap(&["read", "produce"]).on_branch(Id128([9; 16])).unwrap(),
                "branch",
            ),
            (
                cap(&["read", "produce"]).known_at_most(CommitSeq(pin.0 - 1)),
                "known_at",
            ),
        ] {
            for denial in [
                h.book
                    .roll_forward(&cx, PRINCIPAL, &restricted, &request)
                    .unwrap()
                    .unwrap_err(),
                h.book
                    .general_ledger(&cx, PRINCIPAL, &restricted, &request)
                    .unwrap()
                    .unwrap_err(),
                h.book
                    .certify_roll_forward(&cx, PRINCIPAL, &restricted, &request)
                    .unwrap()
                    .unwrap_err(),
                h.book
                    .replay_roll_forward(&cx, PRINCIPAL, &restricted, &source.certificate)
                    .unwrap()
                    .unwrap_err(),
            ] {
                assert_eq!((denial.code, denial.exit), ("FA-REF-011", 7));
                assert!(denial.message.contains(caveat), "{denial:?}");
            }
        }
        // The certificate itself contains a complete native closure. Its
        // conservative head admission is distinct from the plain read above.
        let denial = h
            .book
            .certify_roll_forward(&cx, PRINCIPAL, &pinned, &request)
            .unwrap()
            .unwrap_err();
        assert_eq!((denial.code, denial.exit), ("FA-REF-011", 7));
        assert_eq!(h.head(), head);

        let expired = pinned.clone().expiring_at(head);
        let denial = h
            .book
            .general_ledger(&cx, PRINCIPAL, &expired, &request)
            .unwrap()
            .unwrap_err();
        assert_eq!((denial.code, denial.exit), ("FA-REF-014", 7));
        h.runtime
            .block_on(h.book.revoke_capability(
                &cx,
                cap(&["issue_capability"]),
                pinned.commitment().unwrap(),
                day(20),
                b"revoke-pinned-ledger",
                "Revoke the pinned ledger reader",
            ))
            .unwrap()
            .unwrap();
        let revoked_head = h.head();
        let denial = h
            .book
            .general_ledger(&cx, PRINCIPAL, &pinned, &request)
            .unwrap()
            .unwrap_err();
        assert_eq!((denial.code, denial.exit), ("FA-REF-023", 7));
        assert_eq!(h.head(), revoked_head);
    }

    #[test]
    fn native_ledger_scope_refusal_precedes_poisoned_source_reads() {
        let mut h = Harness::new();
        h.post(10, b"visible-before-poison", h.usd, 50);
        let pin = h.head();
        let pinned = cap(&["read"]).known_at_most(pin);
        let request = RollForwardRequest {
            known_at: Some(pin),
            ..h.request()
        };
        let expected = h.read(&request).canonical_bytes().unwrap();
        let mut damage = fgdb::WriteBatch::new(fa_model::symbols::relation::CHILD_OF);
        damage.set_vertex_property(
            h.id("1000"),
            property::ACCOUNT_TYPE,
            Some(fgdb_types::CanonicalScalar::bytes(vec![0xff]).unwrap()),
        );
        let cx = h.cx();
        h.runtime
            .block_on(h.book.db.write(&cx.commit(), damage))
            .unwrap();
        assert!(
            h.book
                .roll_forward(&cx, PRINCIPAL, &cap(&["read"]), &h.request())
                .is_err(),
            "the poisoned head must be reached by an unrestricted read"
        );
        let head = h.head();
        for restricted in [
            pinned.clone(),
            cap(&["read"]).for_accounts(&["1000"]).unwrap(),
            cap(&["read"]).for_periods(&["FY2026-P01"]).unwrap(),
            cap(&["read"]).effective_through(day(20)),
        ] {
            let denial = h
                .book
                .roll_forward(&cx, PRINCIPAL, &restricted, &h.request())
                .unwrap()
                .unwrap_err();
            assert_eq!((denial.code, denial.exit), ("FA-REF-011", 7));
        }
        assert_eq!(
            h.book
                .roll_forward(&cx, PRINCIPAL, &pinned, &request)
                .unwrap()
                .unwrap()
                .canonical_bytes()
                .unwrap(),
            expected,
            "an authorized old prefix never decodes a poisoned later chart"
        );
        assert_eq!(h.head(), head);
    }

    #[test]
    fn valid_empty_scope_cells_have_zero_stock_and_no_invented_activity() {
        let h = Harness::new();
        let report = h.read(&h.request());
        assert_eq!(report.rows.len(), 3);
        assert!(report.buckets.is_empty());
        assert!(report.movements.is_empty());
        assert!(
            report
                .rows
                .iter()
                .all(|row| row.opening == 0 && row.closing == 0 && row.net_change == 0)
        );
    }
}
