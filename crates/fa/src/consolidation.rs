//! Consolidation of a multi-entity book (plan §12.3, FA-INV-13).
//!
//! A book that declares several legal entities sharing its functional unit
//! is a group: every leg names its entity and the balance law holds per
//! `(unit, legal_entity)`. Its members are those entities, its ownership
//! graph is the journaled `OWNS` edges between them active on the period's
//! last day, and the accounts consolidation reads are named by account role
//! (`registries/account_roles.toml` rows that list `consolidate`), never by
//! code or name. Each member's posted stock through that day is the input to
//! fa-statements' Concordat, which derives every elimination, the
//! noncontrolling interest and the consolidated statements, and proves
//! consolidated equity against the members' equity, the eliminations and the
//! NCI. Nothing is posted: the run is a deterministic read whose digest is a
//! function of the journal prefix, so the same prefix reruns to the same
//! bytes. Single-parent ownership forests include partly owned intermediates:
//! only each child's controlling earnings and reserves flow up to its parent,
//! with exact minority residuals at every registered rounding boundary.
//! Consolidation across books (an entity per book, translation and
//! CTA) and posting the eliminations on a consolidation branch stay with
//! fa-76hy.

use std::collections::{BTreeMap, BTreeSet};

use asupersync::fs::Vfs;
use fa_journal::KernelError;
use fa_journal::genesis::BookContext;
use fa_journal::refusal::{Refusal, exit};
use fa_journal::rows::{AccountRow, PeriodRow, bytes};
use fa_model::symbols::{label, property};
use fa_model::{Id128, RelationshipKind, Writer, legal_entity_vid, period_vid};
use fa_money::UnitId;
use fa_money::rounding::RoundingLaw;
use fa_policy::Capability;
pub use fa_statements::concordat::{
    AdjustmentLayerLeg, BOOK_TO_BOOK_BRIDGE_FORMAT, BookKind, BookToBookBridge,
    BookToBookBridgeRow, BookToBookInput, BookToBookReasonCode, BridgeExplanation,
    ConsolidatedEquityReconciliation, ConsolidationRun, EliminationEntry, EliminationLeg,
    reconcile_book_to_book,
};
use fa_statements::concordat::{
    ConcordatError, ConsolidationInput, EntityMemberInput, IncomeInput, OwnershipSpec, consolidate,
};
use fa_statements::{Account, AccountBalance};
use fa_time::DateDay;
use fgdb::Database;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::{AsyncBook, BookError, Outcome};

pub const CONSOLIDATION_REFUSED: &str = "FA-REF-194";

/// The account roles a consolidation reads. fa-cli holds this list to the
/// role registry rows that name the `consolidate` verb.
pub const CONSOLIDATION_ROLES: &[&str] = &[
    "contributed_capital",
    "intercompany",
    "intercompany_activity",
    "investment_in_subsidiary",
    "noncontrolling_interest",
    "noncontrolling_interest_income",
];

/// The registered law that splits a subsidiary's capital and post-acquisition
/// equity between the controlling and the noncontrolling interest.
pub const CONSOLIDATION_ROUNDING: RoundingLaw = RoundingLaw::HalfEven;

const CITE: &str = "plan §12.3, FA-INV-13 (consolidation: eliminations from the ownership graph and intercompany accounts, NCI, consolidated equity reconciliation)";

/// One legal entity of the group and how it is owned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupMember {
    pub code: String,
    pub name: String,
    /// The group entity owning it on the period's last day, if any.
    pub parent: Option<String>,
    /// That parent's stake in basis points.
    pub ownership_bps: Option<u16>,
}

/// A consolidation run over one period of a multi-entity book.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Consolidation {
    pub period: String,
    pub known_at: CommitSeq,
    pub effective_through: DateDay,
    /// Ordered by code.
    pub members: Vec<GroupMember>,
    pub rounding_law: RoundingLaw,
    pub run: ConsolidationRun,
    /// `ConsolidationRun::digest`: equal prefixes give equal digests.
    pub run_digest: [u8; 32],
    /// Concordat's entity ids by member code, to render legs.
    pub entity_codes: BTreeMap<Id128, String>,
    /// Every account of the chart at `known_at`: id → (code, name).
    pub accounts: BTreeMap<u128, (String, String)>,
}

/// A group report in the historical book's shared functional currency.
/// Amounts are the journal's independently verified retained valuations;
/// this report neither selects new rates nor translates another book.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FunctionalConsolidation {
    pub base_unit: UnitId,
    pub group: Consolidation,
}

impl FunctionalConsolidation {
    /// Bind the valuation posture and functional unit separately from the
    /// native consolidation output, whose existing encoding is unchanged.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, fa_model::EncodeError> {
        let mut w = Writer::new();
        w.fixed(crate::certificate::FUNCTIONAL_CONSOLIDATION_OUTPUT_FORMAT.as_bytes())
            .u32(self.base_unit.0)
            .str("retained-base-amounts")
            .bytes(&self.group.canonical_bytes()?);
        w.finish()
    }

    pub(crate) fn set_known_at(&mut self, known_at: CommitSeq) {
        self.group.set_known_at(known_at);
    }
}

fn refusal(why: impl Into<String>, fix: impl Into<String>) -> Refusal {
    Refusal::new(CONSOLIDATION_REFUSED, exit::REFUSAL, why, CITE, fix)
}

fn entity_id(book: &BookContext, code: &str) -> Id128 {
    Id128(legal_entity_vid(book.book_id, code).0.to_be_bytes())
}

fn assign_fix(role: &str) -> String {
    format!(
        "assign the role to its account (fa chart role <account> {role}); fa chart roles shows what each role means and which accounts hold it"
    )
}

/// Concordat's refusal in the book's words: entity and account ids become
/// their codes, and the fix names what to check.
fn concordat_refusal(
    error: &ConcordatError,
    entities: &BTreeMap<Id128, String>,
    accounts: &BTreeMap<u128, (String, String)>,
    units: &fa_money::UnitRegistry,
) -> Refusal {
    let entity = |id: &Id128| entities.get(id).cloned().unwrap_or_else(|| id.to_hex());
    let account = |id: u128| {
        accounts
            .get(&id)
            .map_or_else(|| format!("{id:032x}"), |(code, _)| code.clone())
    };
    let money = |unit: u32, mantissa: i128| {
        fa_money::Amount::new(fa_money::UnitId(unit), mantissa).render(units)
    };
    let why = match error {
        ConcordatError::UnmatchedIntercompanyGroup {
            unit_id,
            residual,
            nets,
        } => format!(
            "the group's intercompany accounts are {} out of balance (debits minus credits): {}",
            money(*unit_id, *residual),
            nets.iter()
                .map(|(e, a, net)| format!(
                    "{} carries {} on {}",
                    entity(e),
                    money(*unit_id, *net),
                    account(*a)
                ))
                .collect::<Vec<_>>()
                .join("; ")
        ),
        ConcordatError::InvestmentEquityMismatch {
            parent_entity,
            investment_account_id,
            subsidiaries,
            unit_id,
            investment_balance,
            expected_controlling_equity,
        } => format!(
            "{} carries {} on investment account {}, but its share of the contributed capital of {} is {}",
            entity(parent_entity),
            money(*unit_id, *investment_balance),
            account(*investment_account_id),
            subsidiaries
                .iter()
                .map(&entity)
                .collect::<Vec<_>>()
                .join(", "),
            money(*unit_id, *expected_controlling_equity)
        ),
        other => {
            let mut why = other.to_string();
            for (id, code) in entities {
                why = why.replace(&id.to_hex(), code);
            }
            for (id, (code, _)) in accounts {
                why = why.replace(&format!("{id:032x}"), code);
            }
            why
        }
    };
    let fix = match error {
        ConcordatError::UnmatchedIntercompanyGroup { .. } => {
            "every intercompany balance and charge needs its counterparty's side in the same unit: post the missing side under the counterparty's legal_entity, or correct the one recorded on the wrong account (fa tb shows each account); a sale into inventory leaves unrealized profit, which consolidation does not eliminate yet (fa-76hy)"
        }
        ConcordatError::InvestmentEquityMismatch { .. } => {
            "a parent's investment at cost equals its share of each subsidiary's contributed capital: check the OWNS stake (fa party ownership) and the investment_in_subsidiary and contributed_capital roles; goodwill and pre-acquisition retained earnings are not modeled yet (fa-76hy)"
        }
        _ => {
            "correct the named roles, ownership or balances and run the consolidation again; nothing is posted to balance it"
        }
    };
    refusal(why, fix)
}

/// The OWNS stake as whole basis points, refusing one that is not.
fn stake_bps(num: i128, den: u128, owner: &str, owned: &str) -> Result<u16, Refusal> {
    let bps = u128::try_from(num)
        .ok()
        .and_then(|n| n.checked_mul(10_000))
        .filter(|scaled| scaled % den == 0)
        .map(|scaled| scaled / den)
        .and_then(|bps| u16::try_from(bps).ok())
        .filter(|bps| (1..=10_000).contains(bps));
    bps.ok_or_else(|| {
        refusal(
            format!(
                "{owner} owns {num}/{den} of {owned}, which is not a whole number of basis points"
            ),
            "record the stake as a fraction of 10000 (fa party relate <owner> <owned> --kind owns --pct <bps>/10000); NCI is computed in basis points",
        )
    })
}

pub(crate) fn consolidate_at<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    period: &str,
    at: CommitSeq,
) -> Outcome<Consolidation> {
    Ok(consolidate_at_basis(db, book, period, at, false)?.map(|(_, group)| group))
}

pub(crate) fn consolidate_functional_at<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    period: &str,
    at: CommitSeq,
) -> Outcome<FunctionalConsolidation> {
    Ok(consolidate_at_basis(db, book, period, at, true)?
        .map(|(base_unit, group)| FunctionalConsolidation { base_unit, group }))
}

fn consolidate_at_basis<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    period: &str,
    at: CommitSeq,
    functional: bool,
) -> Outcome<(UnitId, Consolidation)> {
    crate::certificate::context_at(db, book, at)?;
    let spec = fa_journal::genesis::read_book_spec_at(db, at)?.ok_or(BookError::NoBook)?;
    if functional && let Err(refusal) = spec.validate_functional_units(&book.units) {
        return Ok(Err(refusal));
    }
    if spec.entities.len() < 2 {
        return Ok(Err(refusal(
            format!(
                "this book declares {} legal entit{}; a consolidation needs a group of two or more",
                spec.entities.len(),
                if spec.entities.len() == 1 { "y" } else { "ies" }
            ),
            "consolidate a book created with one --entity per group member (fa book create --entity CODE:Name ...); consolidation across books is not available yet (fa-76hy)",
        )));
    }
    let Some(period_row) = db
        .vertex_at(period_vid(&book.calendar.id, period), at)
        .map_err(KernelError::from)?
        .filter(|row| row.labels.contains(&label::PERIOD))
    else {
        return Ok(Err(refusal(
            format!("unknown period `{period}` at sequence {}", at.0),
            "name a period of the book's calendar (fa period list)",
        )));
    };
    let period_row = PeriodRow::decode(&period_row)?;
    let through = DateDay(
        period_row
            .end
            .0
            .checked_sub(1)
            .ok_or_else(|| KernelError::Corrupt("period end underflow".into()))?,
    );

    // The chart at the prefix.
    let mut chart = Vec::new();
    let mut accounts = BTreeMap::new();
    for row in db.vertices_at(at).map_err(KernelError::from)? {
        if !row.labels.contains(&label::ACCOUNT) {
            continue;
        }
        if bytes(&row, property::BOOK_ID, "consolidation account book")? != book.book_id.0 {
            return Err(KernelError::Corrupt(
                "consolidation account belongs to another book".into(),
            )
            .into());
        }
        let account = AccountRow::decode(&row)?;
        accounts.insert(account.vid.0, (account.code.clone(), account.name.clone()));
        chart.push(Account {
            id: account.vid.0,
            code: account.code,
            name: account.name,
            account_type: account.account_type,
            is_leaf: account.is_leaf,
        });
    }
    chart.sort_by(|a, b| a.code.cmp(&b.code).then(a.id.cmp(&b.id)));

    // The ownership graph on the period's last day, between group entities.
    let codes: BTreeMap<VId, String> = spec
        .entities
        .iter()
        .map(|e| (legal_entity_vid(book.book_id, &e.code), e.code.clone()))
        .collect();
    let rea = fa_journal::rea::read_rea_at(db, book, at)?;
    let mut owners: BTreeMap<String, Vec<(String, u16)>> = BTreeMap::new();
    for edge in &rea.relationships {
        let RelationshipKind::Owns { pct } = edge.spec.kind else {
            continue;
        };
        if !edge.spec.is_active_on(through) {
            continue;
        }
        let (Some(owner), Some(owned)) = (codes.get(&edge.spec.from), codes.get(&edge.spec.to))
        else {
            continue;
        };
        let bps = match stake_bps(pct.num(), pct.den(), owner, owned) {
            Ok(bps) => bps,
            Err(refusal) => return Ok(Err(refusal)),
        };
        owners
            .entry(owned.clone())
            .or_default()
            .push((owner.clone(), bps));
    }
    let mut parent_of: BTreeMap<String, (String, u16)> = BTreeMap::new();
    for (owned, list) in &owners {
        match list.as_slice() {
            [(owner, bps)] => {
                parent_of.insert(owned.clone(), (owner.clone(), *bps));
            }
            _ => {
                return Ok(Err(refusal(
                    format!(
                        "{owned} is owned by several group entities on {}: {}",
                        through.render(),
                        list.iter()
                            .map(|(o, bps)| format!("{o} ({bps} bps)"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    "consolidation follows one group parent per subsidiary; end the other OWNS edges (fa party relate ... --valid-to) or consolidate them separately (fa-76hy)",
                )));
            }
        }
    }
    for start in parent_of.keys() {
        let mut seen = BTreeSet::from([start.as_str()]);
        let mut cursor = start.as_str();
        while let Some((parent, _)) = parent_of.get(cursor) {
            if !seen.insert(parent.as_str()) {
                return Ok(Err(refusal(
                    format!("the group's OWNS edges form a cycle through {start}"),
                    "end the OWNS edge that closes the cycle (fa party ownership shows each stake)",
                )));
            }
            cursor = parent.as_str();
        }
    }
    // The accounts each role names.
    let roles = fa_journal::account_roles_at(db, book, at)?;
    let role = |name: &str| -> Vec<u128> {
        roles
            .accounts_with(name)
            .into_iter()
            .map(|vid| vid.0)
            .collect()
    };
    let capital = role("contributed_capital");
    let investments = role("investment_in_subsidiary");
    let single = |name: &str, needed: bool| -> Result<Option<u128>, Refusal> {
        match role(name).as_slice() {
            [] if needed => Err(refusal(
                format!(
                    "a partly owned subsidiary needs a `{name}` account, and none holds the role"
                ),
                assign_fix(name),
            )),
            [] => Ok(None),
            [only] => Ok(Some(*only)),
            many => Err(refusal(
                format!(
                    "{} accounts hold the `{name}` role ({}); consolidation reads one",
                    many.len(),
                    many.iter()
                        .map(|id| accounts.get(id).map_or("?", |(code, _)| code.as_str()))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                format!(
                    "remove the role from all but one (fa chart role <account> {name} --remove); fa chart roles lists the holders"
                ),
            )),
        }
    };
    let partial = parent_of.values().any(|(_, bps)| *bps < 10_000);
    let (nci, nci_income) = match (
        single("noncontrolling_interest", partial),
        single("noncontrolling_interest_income", partial),
    ) {
        (Ok(nci), Ok(income)) => (nci, income),
        (Err(refusal), _) | (_, Err(refusal)) => return Ok(Err(refusal)),
    };
    if !parent_of.is_empty() {
        for (needed, name) in [
            (&capital, "contributed_capital"),
            (&investments, "investment_in_subsidiary"),
        ] {
            if needed.is_empty() {
                return Ok(Err(refusal(
                    format!("the group has subsidiaries, and no account holds the `{name}` role"),
                    assign_fix(name),
                )));
            }
        }
    }
    let mut intercompany = role("intercompany");
    intercompany.extend(role("intercompany_activity"));

    // Each member's posted stock through the period's last day.
    let stock = if functional {
        let stock = fa_registers::fold_functional_stock(db, book, through, Some(at))
            .map_err(BookError::from)?;
        if stock.base_unit != spec.base_unit {
            return Err(KernelError::Corrupt(
                "functional group stock differs from the historical book's base unit".into(),
            )
            .into());
        }
        fa_registers::entity::EntityStock {
            known_at: stock.known_at,
            through: stock.effective_through,
            cells: stock
                .cells
                .into_iter()
                .map(|cell| fa_registers::entity::EntityBalance {
                    entity: cell.key.entity,
                    account: cell.key.account,
                    unit_id: cell.key.unit_id,
                    debits: cell.debits,
                    credits: cell.credits,
                })
                .collect(),
        }
    } else {
        fa_registers::stock_by_entity(db, book, through, Some(at)).map_err(BookError::from)?
    };
    let mut balances: BTreeMap<String, Vec<AccountBalance>> = spec
        .entities
        .iter()
        .map(|e| (e.code.clone(), Vec::new()))
        .collect();
    let mut summed: BTreeMap<(u128, u32), (i128, i128)> = BTreeMap::new();
    for cell in &stock.cells {
        let Some(list) = cell.entity.as_ref().and_then(|code| balances.get_mut(code)) else {
            return Err(KernelError::Corrupt(format!(
                "a posted leg on account {:032x} names no declared legal entity in a multi-entity book",
                cell.account.0
            ))
            .into());
        };
        list.push(AccountBalance {
            account_id: cell.account.0,
            unit_id: cell.unit_id,
            debits: cell.debits,
            credits: cell.credits,
        });
        let slot = summed.entry((cell.account.0, cell.unit_id)).or_default();
        slot.0 = slot
            .0
            .checked_add(cell.debits)
            .ok_or(fa_registers::RegisterError::Overflow)
            .map_err(BookError::from)?;
        slot.1 = slot
            .1
            .checked_add(cell.credits)
            .ok_or(fa_registers::RegisterError::Overflow)
            .map_err(BookError::from)?;
    }
    // Native entity stock is checked against the independent native book
    // fold. Functional stock already checks each entry's balance by entity;
    // every one of its posted cells is assigned to exactly one member above.
    if !functional {
        let whole =
            fa_registers::balance_as_of(db, book, through, Some(at)).map_err(BookError::from)?;
        let plain: BTreeMap<(u128, u32), (i128, i128)> = whole
            .rows
            .iter()
            .filter(|r| r.debits != 0 || r.credits != 0)
            .map(|r| ((r.account.0, r.unit_id), (r.debits, r.credits)))
            .collect();
        summed.retain(|_, (d, c)| *d != 0 || *c != 0);
        if summed != plain {
            return Err(KernelError::Corrupt(
                "the members' stock does not sum to the book's posted stock".into(),
            )
            .into());
        }
    }

    // Each member's activity in the period, outside the classes the income
    // statement excludes (Closing entries and their reversals), as `fa
    // statement income-statement` folds it.
    let income_definition = fa_statements::StatementDefinition::embedded("income-statement")
        .map_err(|e| KernelError::Corrupt(format!("embedded income statement: {e}")))?;
    let excluded = income_definition.excluded_classes();
    let periods = [period.to_string()];
    let activity = if functional {
        let activity = fa_registers::fold_period_functional_excluding_classes(
            db,
            book,
            period,
            Some(at),
            excluded,
        )
        .map_err(BookError::from)?;
        if activity.base_unit != spec.base_unit {
            return Err(KernelError::Corrupt(
                "functional group activity differs from the historical book's base unit".into(),
            )
            .into());
        }
        fa_registers::entity::EntityActivity {
            known_at: activity.known_at,
            periods: vec![activity.period],
            cells: activity
                .cells
                .into_iter()
                .map(|cell| fa_registers::entity::EntityBalance {
                    entity: cell.key.entity,
                    account: cell.key.account,
                    unit_id: cell.key.unit_id,
                    debits: cell.debits,
                    credits: cell.credits,
                })
                .collect(),
        }
    } else {
        fa_registers::period_activity_by_entity(db, book, &periods, Some(at), excluded)
            .map_err(BookError::from)?
    };
    let mut activity_of: BTreeMap<String, Vec<AccountBalance>> = spec
        .entities
        .iter()
        .map(|e| (e.code.clone(), Vec::new()))
        .collect();
    let mut summed: BTreeMap<(u128, u32), (i128, i128)> = BTreeMap::new();
    for cell in &activity.cells {
        let Some(list) = cell
            .entity
            .as_ref()
            .and_then(|code| activity_of.get_mut(code))
        else {
            return Err(KernelError::Corrupt(format!(
                "a posted leg on account {:032x} names no declared legal entity in a multi-entity book",
                cell.account.0
            ))
            .into());
        };
        list.push(AccountBalance {
            account_id: cell.account.0,
            unit_id: cell.unit_id,
            debits: cell.debits,
            credits: cell.credits,
        });
        let slot = summed.entry((cell.account.0, cell.unit_id)).or_default();
        slot.0 = slot
            .0
            .checked_add(cell.debits)
            .ok_or(fa_registers::RegisterError::Overflow)
            .map_err(BookError::from)?;
        slot.1 = slot
            .1
            .checked_add(cell.credits)
            .ok_or(fa_registers::RegisterError::Overflow)
            .map_err(BookError::from)?;
    }
    if !functional {
        let whole =
            fa_registers::period_activity_excluding_classes(db, book, &periods, Some(at), excluded)
                .map_err(BookError::from)?;
        let plain: BTreeMap<(u128, u32), (i128, i128)> = whole
            .rows
            .iter()
            .filter(|r| r.debits != 0 || r.credits != 0)
            .map(|r| ((r.account.0, r.unit_id), (r.debits, r.credits)))
            .collect();
        summed.retain(|_, (d, c)| *d != 0 || *c != 0);
        if summed != plain {
            return Err(KernelError::Corrupt(
                "the members' activity does not sum to the book's posted activity".into(),
            )
            .into());
        }
    }

    let entity_codes: BTreeMap<Id128, String> = spec
        .entities
        .iter()
        .map(|e| (entity_id(book, &e.code), e.code.clone()))
        .collect();
    let mut ownership = Vec::new();
    for (owned, (parent, bps)) in &parent_of {
        let parent_net = |account: u128| {
            balances[parent]
                .iter()
                .filter(|b| b.account_id == account)
                .any(|b| b.debits != b.credits)
        };
        let carried: Vec<u128> = investments
            .iter()
            .copied()
            .filter(|a| parent_net(*a))
            .collect();
        let investment = match carried.as_slice() {
            [] | [_] => carried.first().copied().unwrap_or(investments[0]),
            many => {
                return Ok(Err(refusal(
                    format!(
                        "{parent} carries investments on {} investment_in_subsidiary accounts ({}); consolidation reads one per parent",
                        many.len(),
                        many.iter()
                            .map(|id| accounts.get(id).map_or("?", |(code, _)| code.as_str()))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    "carry a parent's investments in its subsidiaries on one investment_in_subsidiary account (fa-76hy)",
                )));
            }
        };
        ownership.push(OwnershipSpec {
            parent_entity: entity_id(book, parent),
            subsidiary_entity: entity_id(book, owned),
            ownership_bps: *bps,
            investment_account_id: investment,
            subsidiary_equity_account_ids: capital.clone(),
            nci_equity_account_id: nci,
            nci_income_account_id: nci_income,
            rounding_law: CONSOLIDATION_ROUNDING,
        });
    }
    let input = ConsolidationInput {
        consolidation_book_id: book.book_id,
        branch_id: Id128::TRUNK,
        known_at: at.0,
        period: period.to_string(),
        effective_through: through,
        accounts: chart,
        units: if functional {
            vec![spec.base_unit.0]
        } else {
            book.units.iter().map(|(id, _)| id.0).collect()
        },
        members: spec
            .entities
            .iter()
            .map(|e| EntityMemberInput {
                entity_id: entity_id(book, &e.code),
                book_id: book.book_id,
                known_at: at.0,
                balances: balances.remove(&e.code).unwrap_or_default(),
            })
            .collect(),
        intercompany_pairs: Vec::new(),
        intercompany_accounts: intercompany,
        ownership,
        income: IncomeInput {
            periods: activity.periods,
            effective_from: period_row.start,
            members: spec
                .entities
                .iter()
                .map(|e| EntityMemberInput {
                    entity_id: entity_id(book, &e.code),
                    book_id: book.book_id,
                    known_at: at.0,
                    balances: activity_of.remove(&e.code).unwrap_or_default(),
                })
                .collect(),
        },
    };
    let run = match consolidate(&input) {
        Ok(run) => run,
        Err(error) => {
            return Ok(Err(concordat_refusal(
                &error,
                &entity_codes,
                &accounts,
                &book.units,
            )));
        }
    };
    let run_digest = run
        .digest()
        .map_err(|e| KernelError::Corrupt(format!("consolidation run encoding: {e}")))?
        .0;
    let mut members: Vec<GroupMember> = spec
        .entities
        .iter()
        .map(|e| GroupMember {
            code: e.code.clone(),
            name: e.name.clone(),
            parent: parent_of.get(&e.code).map(|(p, _)| p.clone()),
            ownership_bps: parent_of.get(&e.code).map(|(_, bps)| *bps),
        })
        .collect();
    members.sort_by(|a, b| a.code.cmp(&b.code));
    Ok(Ok((
        spec.base_unit,
        Consolidation {
            period: period.to_string(),
            known_at: at,
            effective_through: through,
            members,
            rounding_law: CONSOLIDATION_ROUNDING,
            run,
            run_digest,
            entity_codes,
            accounts,
        },
    )))
}

impl Consolidation {
    /// The certified output (`fa:consolidation:v1`): the period, the prefix,
    /// the members and how each is owned, the rounding law, and the run's own
    /// canonical bytes. `run_digest` is a digest of the latter, not a part.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, fa_model::EncodeError> {
        let mut w = Writer::new();
        w.fixed(crate::certificate::CONSOLIDATION_OUTPUT_FORMAT.as_bytes())
            .str(&self.period)
            .u64(self.known_at.0)
            .i32(self.effective_through.0)
            .list(&self.members, |w, member| {
                w.str(&member.code)
                    .str(&member.name)
                    .opt(member.parent.as_ref(), |w, parent| {
                        w.str(parent);
                    })
                    .opt(member.ownership_bps.as_ref(), |w, bps| {
                        w.u16(*bps);
                    });
            })
            .str(self.rounding_law.name())
            .bytes(&self.run.canonical_bytes()?);
        w.finish()
    }

    /// Restamp the prefix the run was read at, so that certificate status can
    /// compare a run recomputed at the head with the certified one.
    pub(crate) fn set_known_at(&mut self, known_at: CommitSeq) {
        self.known_at = known_at;
        self.run.known_at = known_at.0;
        self.run.balance_sheet.known_at = known_at.0;
        self.run.income_statement.known_at = known_at.0;
    }
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Consolidate the book's legal entities for `period` at `known_at` (the
    /// head when `None`), under current whole-book read authority: a token
    /// carrying any scope caveat is refused before anything is read.
    pub fn consolidation(
        &self,
        cx: &PurposeContexts,
        period: &str,
        known_at: Option<CommitSeq>,
        capability: &Capability,
    ) -> Outcome<Consolidation> {
        self.query(cx, |db, book| {
            let at = match crate::subledger::admitted_at(db, book, capability, known_at)? {
                Ok(at) => at,
                Err(refusal) => return Ok(Err(refusal)),
            };
            consolidate_at(db, book, period, at)
        })
    }

    /// Consolidate the group's retained functional carrying values after
    /// verifying their rate documents and registered valuation laws. Current
    /// whole-book Read authority is checked before history is loaded and again
    /// before returning the report. No posting or rate selection occurs.
    pub async fn functional_consolidation(
        &mut self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        period: &str,
        known_at: Option<CommitSeq>,
    ) -> Outcome<FunctionalConsolidation> {
        let at = match self
            .prepare_functional_report(cx, principal, capability, known_at, false)
            .await?
        {
            Ok(at) => at,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let result = self.query(cx, |db, book| {
            crate::certificate::context_at(db, book, at)?;
            if let Err(refusal) = crate::certificate::verify_functional_sources(db, cx, book, at)? {
                return Ok(Err(refusal));
            }
            consolidate_functional_at(db, book, period, at)
        })?;
        if let Err(refusal) =
            self.admit_functional_report(cx, principal, capability, Some(at), false)?
        {
            return Ok(Err(refusal));
        }
        Ok(result)
    }

    /// Certify a functional consolidation with the native Rate projection,
    /// retained source history and exact group output. Read and Produce
    /// authority precede history loading; the report never changes the book.
    pub async fn certify_functional_consolidation(
        &mut self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        period: &str,
        known_at: Option<CommitSeq>,
    ) -> Outcome<crate::CertifiedReport> {
        let at = match self
            .prepare_functional_report(cx, principal, capability, known_at, true)
            .await?
        {
            Ok(at) => at,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let result = self.certify_report(
            cx,
            crate::ReportSelection::FunctionalConsolidation {
                period: period.to_string(),
            },
            Some(at),
        )?;
        if let Err(refusal) =
            self.admit_functional_report(cx, principal, capability, Some(at), true)?
        {
            return Ok(Err(refusal));
        }
        Ok(result)
    }

    /// Anchor this book as an `AdjustmentLayer` (tax, statutory, or management)
    /// referencing `parent_book_id` at committed sequence `parent_known_at`
    /// (plan §12.2, bead `fa-259c`). Re-anchoring to a higher `parent_known_at`
    /// propagates a parent restatement; switching `parent_book_id` or regressing
    /// `parent_known_at` is refused.
    pub async fn anchor_adjustment_layer(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        parent_book_id: Id128,
        parent_known_at: CommitSeq,
    ) -> Outcome<AdjustmentLayerAnchored> {
        cx.commit().checkpoint().map_err(BookError::Context)?;
        if let Err(denial) = fa_policy::require(
            capability,
            fa_policy::Op::SchemaChange,
            "anchoring an adjustment-layer book",
        )
        .and_then(|()| fa_policy::scope(capability, self.context.book_id))
        .and_then(|()| fa_policy::admit_direct_write(capability))
        .and_then(|()| fa_policy::reach(capability, &fa_policy::Reach::whole_book(true), None))
        {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        let head = match fa_journal::policy::current_at(&self.db, &self.context, capability)? {
            Ok(current) => current.at(),
            Err(refusal) => return Ok(Err(refusal)),
        };
        if parent_book_id == self.context.book_id {
            return Ok(Err(refusal_book_to_book(
                "a book cannot anchor to itself as its own parent book",
                "create a dedicated adjustment-layer book (`fa book create`) and anchor it to the distinct parent book",
            )));
        }
        if parent_known_at.0 == 0 {
            return Ok(Err(refusal_book_to_book(
                "parent_known_at must be a committed sequence >= 1",
                "supply the parent book's committed known-at sequence (e.g. from `fa book info` or a parent trial-balance certificate)",
            )));
        }
        if let BookKind::AdjustmentLayer {
            parent_book_id: existing_parent,
            parent_known_at: existing_seq,
        } = book_kind_at_db(&self.db, &self.context, head)?
        {
            if existing_parent != parent_book_id {
                return Ok(Err(refusal_book_to_book(
                    format!(
                        "this book is already anchored to parent book {}; an adjustment-layer book cannot switch parents",
                        existing_parent.to_hex()
                    ),
                    "create a separate adjustment-layer book for another parent book",
                )));
            }
            if parent_known_at.0 < existing_seq {
                return Ok(Err(refusal_book_to_book(
                    format!(
                        "parent_known_at {} precedes the existing adjustment-layer anchor {}",
                        parent_known_at.0, existing_seq
                    ),
                    "advance parent_known_at monotonically when propagating a parent restatement, or read an earlier snapshot via --as-known-at",
                )));
            }
        }
        let policy = fa_registry::evidence_policy::EvidencePolicy::embedded()
            .map_err(|e| KernelError::Corrupt(e.to_string()))?;
        let grade = fa_journal::upload::upload_grade(&policy, capability.sod_profile())?;
        let bytes =
            encode_adjustment_layer_anchor(self.context.book_id, parent_book_id, parent_known_at.0)
                .map_err(|e| KernelError::Model(e.into()))?;
        let doc = fa_journal::Document {
            book_id: self.context.book_id,
            kind: ADJUSTMENT_LAYER_DOCUMENT_KIND,
            mime: ADJUSTMENT_LAYER_MIME.to_string(),
            grade,
            retrieved_by: capability.holder(),
            bytes,
        };
        let added = match self.add_document(cx, &doc).await? {
            Ok(added) => added,
            Err(refusal) => return Ok(Err(refusal)),
        };
        Ok(Ok(AdjustmentLayerAnchored {
            document_oid: added.oid,
            doc_commit: added.doc_commit,
            parent_book_id,
            parent_known_at,
            recorded_at: added.recorded_at,
            already_recorded: added.already_recorded,
        }))
    }

    /// Read this book's [`BookKind`] (`Primary` or `AdjustmentLayer`) as known
    /// at `known_at` (`HEAD` when `None`).
    pub fn book_kind_at(
        &self,
        cx: &PurposeContexts,
        known_at: Option<CommitSeq>,
        capability: &Capability,
    ) -> Outcome<BookKind> {
        self.query(cx, |db, book| {
            let at = match crate::subledger::admitted_at(db, book, capability, known_at)? {
                Ok(at) => at,
                Err(refusal) => return Ok(Err(refusal)),
            };
            Ok(Ok(book_kind_at_db(db, book, at)?))
        })
    }

    /// Attach a sealed Schedule M-1/M-3 / statutory / management reason-code
    /// and rule-version tag (`fa.book_to_book`) to an adjustment entry proposal
    /// before planning or posting it in an `AdjustmentLayer` book (plan §12.2).
    pub fn attach_book_to_book_tag(
        &self,
        cx: &PurposeContexts,
        proposal: &mut fa_model::EntryPayload,
        reason_code: BookToBookReasonCode,
        rule_version_oid: fa_model::Oid,
    ) -> Result<(), BookError> {
        let bytes = encode_book_to_book_tag(reason_code, rule_version_oid)
            .map_err(|e| KernelError::Model(e.into()))?;
        let sealed = self.seal_tag_bytes(cx, bytes)?;
        proposal.tags.retain(|t| t.key != BOOK_TO_BOOK_TAG_KEY);
        proposal.tags.push(fa_model::Tag {
            key: BOOK_TO_BOOK_TAG_KEY.to_string(),
            value: sealed,
        });
        proposal.tags.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(())
    }

    /// Reconcile this `AdjustmentLayer` book against its parent book's stock
    /// trial balance at `period` or `as_of`, producing a deterministic,
    /// round-trip-verified [`BookToBookReconciliation`] (`recon.book_to_book`,
    /// plan §12.2, FA-INV-13, bead `fa-259c`).
    #[allow(clippy::too_many_arguments)]
    pub fn reconcile_book_to_book(
        &self,
        cx: &PurposeContexts,
        capability: &Capability,
        parent_book_id: Id128,
        parent_known_at: CommitSeq,
        parent_tb: &fa_registers::TrialBalance,
        period: Option<&str>,
        as_of: Option<DateDay>,
        known_at: Option<CommitSeq>,
    ) -> Outcome<BookToBookReconciliation> {
        self.query(cx, |db, book| {
            if let Err(denial) =
                fa_policy::require(capability, fa_policy::Op::Reconcile, "book-to-book bridge")
            {
                return Ok(Err(fa_journal::policy::refusal(&denial)));
            }
            let at = match crate::subledger::admitted_at(db, book, capability, known_at)? {
                Ok(at) => at,
                Err(refusal) => return Ok(Err(refusal)),
            };
            reconcile_book_to_book_at(
                db,
                book,
                at,
                parent_book_id,
                parent_known_at,
                parent_tb,
                period,
                as_of,
            )
        })
    }
}

pub const ADJUSTMENT_LAYER_DOCUMENT_KIND: u8 = 21;
pub const ADJUSTMENT_LAYER_MIME: &str = "application/vnd.franken.adjustment-layer.v1";
pub const ADJUSTMENT_LAYER_ANCHOR_DOMAIN: &[u8] = b"fa:adjustment-layer:v1";
pub const BOOK_TO_BOOK_TAG_KEY: &str = "fa.book_to_book";
pub const BOOK_TO_BOOK_TAG_DOMAIN: &[u8] = b"fa:book-to-book-tag:v1";

const BOOK_TO_BOOK_CITE: &str =
    "plan §12.2, FA-INV-13 (multi-book adjustment layers and book-to-book reconciliation bridges)";

/// Receipt from anchoring a book as an `AdjustmentLayer` (plan §12.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdjustmentLayerAnchored {
    pub document_oid: fa_model::Oid,
    pub doc_commit: [u8; 32],
    pub parent_book_id: Id128,
    pub parent_known_at: CommitSeq,
    pub recorded_at: CommitSeq,
    pub already_recorded: bool,
}

/// Deterministic, verified book-to-book reconciliation result (`recon.book_to_book`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BookToBookReconciliation {
    pub effective_through: DateDay,
    pub period: Option<String>,
    pub bridge: BookToBookBridge,
    pub bridge_digest: fa_model::Oid,
    pub unit_codes: BTreeMap<u32, String>,
}

fn refusal_book_to_book(why: impl Into<String>, fix: impl Into<String>) -> Refusal {
    Refusal::new(
        CONSOLIDATION_REFUSED,
        exit::REFUSAL,
        why,
        BOOK_TO_BOOK_CITE,
        fix,
    )
}

pub fn encode_book_to_book_tag(
    reason_code: BookToBookReasonCode,
    rule_version_oid: fa_model::Oid,
) -> Result<Vec<u8>, fa_model::EncodeError> {
    let mut w = Writer::new();
    w.fixed(BOOK_TO_BOOK_TAG_DOMAIN)
        .str(reason_code.as_str())
        .fixed(&rule_version_oid.0);
    w.finish()
}

pub fn decode_book_to_book_tag(
    bytes: &[u8],
) -> Result<(BookToBookReasonCode, fa_model::Oid), fa_model::DecodeError> {
    let mut r = fa_model::Reader::new(bytes);
    let magic = r.fixed::<{ BOOK_TO_BOOK_TAG_DOMAIN.len() }>("book_to_book_tag.magic")?;
    if magic != BOOK_TO_BOOK_TAG_DOMAIN {
        return Err(r.invalid("book-to-book tag header"));
    }
    let code_str = r.str(64, "book_to_book_tag.reason_code")?;
    let Some(reason_code) = BookToBookReasonCode::parse(code_str) else {
        return Err(r.invalid("book-to-book reason code"));
    };
    let rule_version_oid = fa_model::Oid(r.fixed::<32>("book_to_book_tag.rule_version_oid")?);
    r.finish()?;
    Ok((reason_code, rule_version_oid))
}

fn encode_adjustment_layer_anchor(
    book_id: Id128,
    parent_book_id: Id128,
    parent_known_at: u64,
) -> Result<Vec<u8>, fa_model::EncodeError> {
    let mut w = Writer::new();
    w.fixed(ADJUSTMENT_LAYER_ANCHOR_DOMAIN)
        .fixed(&book_id.0)
        .fixed(&parent_book_id.0)
        .u64(parent_known_at);
    w.finish()
}

fn decode_adjustment_layer_anchor(
    bytes: &[u8],
) -> Result<(Id128, Id128, u64), fa_model::DecodeError> {
    let mut r = fa_model::Reader::new(bytes);
    let magic =
        r.fixed::<{ ADJUSTMENT_LAYER_ANCHOR_DOMAIN.len() }>("adjustment_layer_anchor.magic")?;
    if magic != ADJUSTMENT_LAYER_ANCHOR_DOMAIN {
        return Err(r.invalid("adjustment-layer anchor header"));
    }
    let book_id = Id128(r.fixed::<16>("adjustment_layer_anchor.book_id")?);
    let parent_book_id = Id128(r.fixed::<16>("adjustment_layer_anchor.parent_book_id")?);
    let parent_known_at = r.u64("adjustment_layer_anchor.parent_known_at")?;
    r.finish()?;
    Ok((book_id, parent_book_id, parent_known_at))
}

pub(crate) fn book_kind_at_db<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    at: CommitSeq,
) -> Result<BookKind, BookError> {
    let policy = fa_registry::evidence_policy::EvidencePolicy::embedded()
        .map_err(|e| KernelError::Corrupt(e.to_string()))?;
    let mut anchors: Vec<(CommitSeq, u64, fa_model::Oid, Id128)> = Vec::new();
    for row in db.vertices_at(at).map_err(KernelError::from)? {
        if !row.labels.contains(&label::DOCUMENT) {
            continue;
        }
        let doc = fa_journal::evidence::verify_row(&row, &policy)
            .map_err(|why| KernelError::Corrupt(format!("document {:032x}: {why}", row.vid.0)))?;
        if doc.book_id != book.book_id || doc.mime != ADJUSTMENT_LAYER_MIME {
            continue;
        }
        let fa_journal::evidence::Storage::Inline(ref payload) = doc.storage else {
            return Err(
                KernelError::Corrupt("adjustment-layer anchor must be inline".into()).into(),
            );
        };
        let (anchor_book, parent_book_id, parent_known_at) =
            decode_adjustment_layer_anchor(payload)
                .map_err(|e| KernelError::Corrupt(format!("adjustment-layer anchor: {e}")))?;
        if anchor_book != book.book_id || parent_book_id == book.book_id || parent_known_at == 0 {
            return Err(KernelError::Corrupt(
                "adjustment-layer anchor carries invalid book or sequence metadata".into(),
            )
            .into());
        }
        let oid = doc.oid();
        let receipt_vid = fa_journal::custody::custody_vid(doc.book_id, &oid, 0);
        let intake = db
            .vertex_at(receipt_vid, at)
            .map_err(KernelError::from)?
            .ok_or_else(|| {
                KernelError::Corrupt("adjustment-layer anchor lacks custody receipt".into())
            })?;
        anchors.push((intake.created_at, parent_known_at, oid, parent_book_id));
    }
    if anchors.is_empty() {
        return Ok(BookKind::Primary);
    }
    anchors.sort_by_key(|(rec, seq, oid, _)| (*rec, *seq, *oid));
    let first_parent = anchors[0].3;
    let mut prev_seq = 0u64;
    for (_, seq, _, parent) in &anchors {
        if *parent != first_parent || *seq < prev_seq {
            return Err(KernelError::Corrupt(
                "adjustment-layer anchor history changed parent or regressed parent_known_at"
                    .into(),
            )
            .into());
        }
        prev_seq = *seq;
    }
    let &(_, latest_parent_known_at, _, parent_book_id) =
        anchors.last().expect("non-empty anchors");
    Ok(BookKind::AdjustmentLayer {
        parent_book_id,
        parent_known_at: latest_parent_known_at,
    })
}

#[allow(clippy::too_many_arguments)]
fn reconcile_book_to_book_at<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    at: CommitSeq,
    parent_book_id: Id128,
    parent_known_at: CommitSeq,
    parent_tb: &fa_registers::TrialBalance,
    period: Option<&str>,
    as_of: Option<DateDay>,
) -> Outcome<BookToBookReconciliation> {
    crate::certificate::context_at(db, book, at)?;
    let (through, resolved_period) = match (period, as_of) {
        (Some(p), None) => {
            let Some(period_row) = db
                .vertex_at(period_vid(&book.calendar.id, p), at)
                .map_err(KernelError::from)?
                .filter(|row| row.labels.contains(&label::PERIOD))
            else {
                return Ok(Err(refusal_book_to_book(
                    format!("unknown period `{p}` at sequence {}", at.0),
                    "name a period of the adjustment-layer book's calendar (fa period list)",
                )));
            };
            let period_row = PeriodRow::decode(&period_row)?;
            let day = DateDay(
                period_row
                    .end
                    .0
                    .checked_sub(1)
                    .ok_or_else(|| KernelError::Corrupt("period end underflow".into()))?,
            );
            (day, Some(p.to_string()))
        }
        (None, Some(day)) => (day, None),
        _ => {
            return Ok(Err(refusal_book_to_book(
                "book-to-book reconciliation requires exactly one of --period or --as-of",
                "pass --period <code> or --as-of YYYY-MM-DD",
            )));
        }
    };
    if parent_tb.activity {
        return Ok(Err(refusal_book_to_book(
            "parent trial balance is period activity rather than cumulative stock",
            "certify or read a cumulative stock trial balance (omit --activity) for the parent book",
        )));
    }
    if parent_tb.known_at != parent_known_at {
        return Ok(Err(refusal_book_to_book(
            format!(
                "parent trial balance known-at {} differs from supplied parent known-at {}",
                parent_tb.known_at.0, parent_known_at.0
            ),
            "supply the exact parent known-at that produced the parent trial balance",
        )));
    }
    if parent_tb.effective_through != Some(through) {
        return Ok(Err(refusal_book_to_book(
            format!(
                "parent trial balance cutoff ({}) does not match layered cutoff {}",
                parent_tb
                    .effective_through
                    .map_or_else(|| "none".into(), |d| d.render()),
                through.render()
            ),
            "select the same period or --as-of cutoff date in both the parent book and the adjustment-layer book",
        )));
    }

    let layered_kind = book_kind_at_db(db, book, at)?;
    let mut chart = Vec::new();
    let mut code_to_vid: BTreeMap<String, u128> = BTreeMap::new();
    let mut vid_to_meta: BTreeMap<u128, (String, String)> = BTreeMap::new();
    for row in db.vertices_at(at).map_err(KernelError::from)? {
        if !row.labels.contains(&label::ACCOUNT) {
            continue;
        }
        if bytes(&row, property::BOOK_ID, "book-to-book account book")? != book.book_id.0 {
            return Err(KernelError::Corrupt(
                "book-to-book account belongs to another book".into(),
            )
            .into());
        }
        let account = AccountRow::decode(&row)?;
        code_to_vid.insert(account.code.clone(), account.vid.0);
        vid_to_meta.insert(account.vid.0, (account.code.clone(), account.name.clone()));
        chart.push(Account {
            id: account.vid.0,
            code: account.code,
            name: account.name,
            account_type: account.account_type,
            is_leaf: account.is_leaf,
        });
    }
    chart.sort_by(|a, b| a.code.cmp(&b.code).then(a.id.cmp(&b.id)));

    let mut units_set: BTreeSet<u32> = BTreeSet::new();
    let mut unit_codes: BTreeMap<u32, String> = BTreeMap::new();
    for (unit_id, unit) in book.units.iter() {
        units_set.insert(unit_id.0);
        unit_codes.insert(unit_id.0, unit.code.clone());
    }

    let mut parent_cells: BTreeMap<(u128, u32), (i128, i128)> = BTreeMap::new();
    for row in &parent_tb.rows {
        if row.debits == 0 && row.credits == 0 {
            continue;
        }
        let Some(&layered_acct_id) = code_to_vid.get(&row.code) else {
            return Ok(Err(refusal_book_to_book(
                format!(
                    "parent book carries non-zero balance on account `{}`, which is absent from the adjustment-layer book's chart",
                    row.code
                ),
                format!(
                    "install or add matching account `{}` in the adjustment-layer book (fa chart add / fa chart install)",
                    row.code
                ),
            )));
        };
        if !units_set.contains(&row.unit_id) {
            return Ok(Err(refusal_book_to_book(
                format!(
                    "parent trial balance references unit id {} absent from the adjustment-layer book",
                    row.unit_id
                ),
                "ensure the adjustment-layer book declares every unit used by its parent book",
            )));
        }
        let slot = parent_cells
            .entry((layered_acct_id, row.unit_id))
            .or_default();
        slot.0 = slot
            .0
            .checked_add(row.debits)
            .ok_or(fa_registers::RegisterError::Overflow)
            .map_err(BookError::from)?;
        slot.1 = slot
            .1
            .checked_add(row.credits)
            .ok_or(fa_registers::RegisterError::Overflow)
            .map_err(BookError::from)?;
    }

    let layered_own =
        fa_registers::balance_as_of(db, book, through, Some(at)).map_err(BookError::from)?;
    let mut layered_cells = parent_cells.clone();
    for row in &layered_own.rows {
        if row.debits == 0 && row.credits == 0 {
            continue;
        }
        units_set.insert(row.unit_id);
        let slot = layered_cells
            .entry((row.account.0, row.unit_id))
            .or_default();
        slot.0 = slot
            .0
            .checked_add(row.debits)
            .ok_or(fa_registers::RegisterError::Overflow)
            .map_err(BookError::from)?;
        slot.1 = slot
            .1
            .checked_add(row.credits)
            .ok_or(fa_registers::RegisterError::Overflow)
            .map_err(BookError::from)?;
    }

    let parent_balances: Vec<AccountBalance> = parent_cells
        .iter()
        .map(
            |(&(account_id, unit_id), &(debits, credits))| AccountBalance {
                account_id,
                unit_id,
                debits,
                credits,
            },
        )
        .collect();
    let layered_balances: Vec<AccountBalance> = layered_cells
        .iter()
        .map(
            |(&(account_id, unit_id), &(debits, credits))| AccountBalance {
                account_id,
                unit_id,
                debits,
                credits,
            },
        )
        .collect();

    // Extract reason-coded adjustment legs from visible posted entries in the
    // adjustment-layer book through `through` at `at`. Any monetary entry
    // lacking a `fa.book_to_book` tag moves `layered_balances` without adding
    // an `AdjustmentLayerLeg`, so `reconcile_book_to_book` refuses with
    // `UnexplainedBookDifference`.
    let mut adjustments = Vec::new();
    let mut runs = BTreeMap::new();
    let mut visible_entries = Vec::new();
    for row in db.vertices_at(at).map_err(KernelError::from)? {
        if !row.labels.contains(&label::ENTRY) {
            continue;
        }
        let entry = fa_journal::entry_storage::decode_at(db, &row, at)?;
        if entry.proposal.book_id != book.book_id || entry.proposal.branch_id != Id128::TRUNK {
            continue;
        }
        if !fa_journal::migration::visible_at(db, &entry, at, &mut runs)? {
            continue;
        }
        if entry.proposal.control.is_some()
            || entry.proposal.pending.is_some()
            || entry.proposal.effective_date > through
        {
            continue;
        }
        visible_entries.push((row.created_at, row.vid, entry));
    }
    visible_entries.sort_by_key(|(created_at, vid, _)| (*created_at, vid.0));

    for (_, vid, entry) in visible_entries {
        let Some(tag) = entry
            .proposal
            .tags
            .iter()
            .find(|t| t.key == BOOK_TO_BOOK_TAG_KEY)
        else {
            continue;
        };
        let tag_val = tag
            .value
            .open(&book.seal_key, 256)
            .map_err(|e| KernelError::Corrupt(format!("open fa.book_to_book tag: {e}")))?;
        let fa_model::TagValue::Bytes(raw) = tag_val else {
            return Err(KernelError::Corrupt("fa.book_to_book tag must carry bytes".into()).into());
        };
        let (reason_code, rule_version_oid) = decode_book_to_book_tag(&raw)
            .map_err(|e| KernelError::Corrupt(format!("decode fa.book_to_book tag: {e}")))?;
        for leg in &entry.proposal.legs {
            let (debits, credits) = match leg.side {
                fa_money::Side::Debit => (leg.amount.mantissa, 0),
                fa_money::Side::Credit => (0, leg.amount.mantissa),
            };
            adjustments.push(AdjustmentLayerLeg {
                entry_id: vid.0,
                rule_version_oid,
                reason_code,
                account_id: leg.account_ref.0,
                unit_id: leg.amount.unit.0,
                debits,
                credits,
            });
        }
    }

    let input = BookToBookInput {
        parent_book_id,
        parent_known_at: parent_known_at.0,
        layered_book_id: book.book_id,
        layered_kind,
        layered_known_at: at.0,
        accounts: chart,
        units: units_set.into_iter().collect(),
        parent_balances,
        layered_balances,
        adjustments,
    };
    let bridge = match reconcile_book_to_book(&input) {
        Ok(bridge) => bridge,
        Err(err) => {
            let fix = match &err {
                ConcordatError::ParentBookMismatch { .. } => {
                    "anchor the layered book to its parent book first (`fa recon anchor --parent-book <dir> ...`)"
                }
                ConcordatError::ParentBookRestated { .. } => {
                    "propagate any required tax/statutory adjustment into the layered book, then advance its anchor (`fa recon anchor --parent-book <dir>`)"
                }
                ConcordatError::UnexplainedBookDifference { .. } => {
                    "every adjustment entry in a layered book must carry a Schedule M-1/M-3 or statutory reason code (`fa recon post --reason-code <code> ...`); reverse the unattributed entry and repost via `fa recon post`"
                }
                _ => {
                    "correct the adjustment-layer inputs or accounts and rerun `fa recon book-to-book`"
                }
            };
            return Ok(Err(concordat_book_to_book_refusal(
                &err,
                &vid_to_meta,
                &book.units,
                fix,
            )));
        }
    };
    let encoded = bridge
        .canonical_bytes()
        .map_err(|e| KernelError::Model(e.into()))?;
    if !encoded.starts_with(BOOK_TO_BOOK_BRIDGE_FORMAT) {
        return Err(
            KernelError::Corrupt("book-to-book bridge canonical header mismatch".into()).into(),
        );
    }
    let decoded = BookToBookBridge::decode(&encoded)
        .map_err(|e| KernelError::Corrupt(format!("book-to-book bridge decode drift: {e}")))?;
    if decoded != bridge {
        return Err(KernelError::Corrupt(
            "book-to-book bridge canonical round-trip drifted".into(),
        )
        .into());
    }
    let bridge_digest = bridge.digest().map_err(|e| KernelError::Model(e.into()))?;
    Ok(Ok(BookToBookReconciliation {
        effective_through: through,
        period: resolved_period,
        bridge,
        bridge_digest,
        unit_codes,
    }))
}

fn concordat_book_to_book_refusal(
    error: &ConcordatError,
    accounts: &BTreeMap<u128, (String, String)>,
    units: &fa_money::UnitRegistry,
    fix: &str,
) -> Refusal {
    let why = match error {
        ConcordatError::UnexplainedBookDifference {
            account_code,
            unit_id,
            parent_net,
            adjustments_net,
            layered_net,
            residual,
        } => {
            let fmt_amt =
                |m: i128| fa_money::Amount::new(fa_money::UnitId(*unit_id), m).render(units);
            format!(
                "unexplained book-to-book difference on account `{account_code}`: parent ({}) + reason-coded adjustments ({}) != layered ({}), residual = {}",
                fmt_amt(*parent_net),
                fmt_amt(*adjustments_net),
                fmt_amt(*layered_net),
                fmt_amt(*residual),
            )
        }
        other => {
            let mut msg = other.to_string();
            for (id, (code, _)) in accounts {
                msg = msg.replace(&format!("{id:032x}"), code);
            }
            msg
        }
    };
    refusal_book_to_book(why, fix)
}
