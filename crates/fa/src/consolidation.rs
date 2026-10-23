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
//! bytes. Consolidation across books (an entity per book, translation and
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
use fa_money::rounding::RoundingLaw;
use fa_policy::Capability;
use fa_statements::concordat::{
    ConcordatError, ConsolidationInput, EntityMemberInput, IncomeInput, OwnershipSpec, consolidate,
};
pub use fa_statements::concordat::{
    ConsolidatedEquityReconciliation, ConsolidationRun, EliminationEntry, EliminationLeg,
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
    crate::certificate::context_at(db, book, at)?;
    let spec = fa_journal::genesis::read_book_spec_at(db, at)?.ok_or(BookError::NoBook)?;
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
    for (owned, (parent, _)) in &parent_of {
        if let Some((_, parent_bps)) = parent_of.get(parent)
            && *parent_bps < 10_000
        {
            return Ok(Err(refusal(
                format!(
                    "{parent} owns {owned} and is itself {parent_bps} bps owned: the NCI in {parent} shares in {owned}'s earnings, which a direct-ownership consolidation does not allocate"
                ),
                "consolidate groups whose partly owned subsidiaries own no other member; tiered NCI is not available yet (fa-76hy)",
            )));
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
    let stock =
        fa_registers::stock_by_entity(db, book, through, Some(at)).map_err(BookError::from)?;
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
    // The members partition the book: their stock sums to its posted stock.
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

    // Each member's activity in the period, outside the classes the income
    // statement excludes (Closing entries and their reversals), as `fa
    // statement income-statement` folds it.
    let income_definition = fa_statements::StatementDefinition::embedded("income-statement")
        .map_err(|e| KernelError::Corrupt(format!("embedded income statement: {e}")))?;
    let excluded = income_definition.excluded_classes();
    let periods = [period.to_string()];
    let activity = fa_registers::period_activity_by_entity(db, book, &periods, Some(at), excluded)
        .map_err(BookError::from)?;
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
        units: book.units.iter().map(|(id, _)| id.0).collect(),
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
    Ok(Ok(Consolidation {
        period: period.to_string(),
        known_at: at,
        effective_through: through,
        members,
        rounding_law: CONSOLIDATION_ROUNDING,
        run,
        run_digest,
        entity_codes,
        accounts,
    }))
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
}
