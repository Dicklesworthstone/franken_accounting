//! The book's committed journal in the shape every interop exporter reads
//! (plan §8.6, §15.9, §16.3). The AICPA ADS, OECD SAF-T, CSV GL, Beancount
//! and hledger writers in `fa-formats` all consume one [`FormatJournal`], so
//! they agree with each other by construction.
//!
//! The entry selection is the trial balance's (FA-INV-04). It takes every
//! entry visible at the known-at prefix (a migration chunk only once its run
//! is final) whose effective date is on or before `effective_through`, that
//! has legs and is not a pending hold. Refolding the exported legs therefore
//! gives the stock trial balance at the same coordinate, and that tie-out
//! travels with the export: one balance assertion per account and unit as
//! of `effective_through`. Every format carries assertions; without them an
//! ADS package's derived trial balance would read back as assertions the
//! journal never had. Protected text
//! (descriptions, leg memos, migration source ids) is opened with the book's
//! key. A field that key does not open (erased, or sealed under a subject's
//! own key) exports empty, never as a placeholder.

use std::collections::BTreeMap;

use asupersync::fs::Vfs;
use fa_formats::{FormatAccount, FormatAssertion, FormatEntry, FormatJournal, FormatLeg};
use fa_journal::KernelError;
use fa_model::{AccountType, EntryClass, EntryOrigin, limits};
use fa_money::{Amount, Side};
use fa_time::DateDay;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::{AsyncBook, BookError, Outcome};

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// XBRL v2 supplements stock with the income statement's accounting-class
    /// law. The same admitted prefix supplies its activity and account roles;
    /// no labels, mutable balances or caller-authored reversal hints decide.
    pub fn xbrl_report_inputs(
        &self,
        cx: &PurposeContexts,
        effective_through: DateDay,
        known_at: Option<CommitSeq>,
        capability: &fa_policy::Capability,
    ) -> Outcome<fa_formats::xbrl::XbrlReportInputs> {
        self.query(cx, |db, book| {
            let at = match crate::subledger::admitted_at(db, book, capability, known_at)? {
                Ok(at) => at,
                Err(refusal) => return Ok(Err(refusal)),
            };
            let chart = fa_journal::chart::read_at(db, book, at)?;
            let roles = fa_journal::account_roles_at(db, book, at)?;
            let codes_for = |role: &str| -> Result<std::collections::BTreeSet<String>, BookError> {
                let members = roles.accounts_with(role);
                let codes = chart
                    .accounts()
                    .values()
                    .filter(|account| members.contains(&account.vid))
                    .map(|account| account.code.clone())
                    .collect::<std::collections::BTreeSet<_>>();
                if codes.len() != members.len() {
                    return Err(KernelError::Corrupt(format!(
                        "XBRL role {role} names an account absent from the historical chart"
                    ))
                    .into());
                }
                Ok(codes)
            };
            let definition = fa_statements::StatementDefinition::embedded("income-statement")
                .map_err(|error| KernelError::Corrupt(format!("income statement: {error}")))?;
            let activity = fa_registers::activity_as_of_excluding_classes(
                db,
                book,
                effective_through,
                Some(at),
                definition.excluded_classes(),
            )?;
            let mut balances = BTreeMap::new();
            for row in activity.rows {
                // Pending columns are separate from posted activity. A
                // pending-only foreign unit need not occur in FormatJournal,
                // which deliberately omits unresolved holds altogether.
                if (row.debits == 0 && row.credits == 0)
                    || !matches!(
                        row.account_type,
                        AccountType::REVENUE | AccountType::EXPENSE
                    )
                {
                    continue;
                }
                let unit = book
                    .units
                    .get(fa_money::UnitId(row.unit_id))
                    .ok_or_else(|| {
                        KernelError::Corrupt("XBRL activity names an unregistered unit".into())
                    })?;
                let net = row
                    .debits
                    .checked_sub(row.credits)
                    .ok_or(fa_registers::RegisterError::Overflow)?;
                balances.insert((row.code, unit.code.clone()), net);
            }
            Ok(Ok(fa_formats::xbrl::XbrlReportInputs {
                equity: fa_formats::xbrl::XbrlEquityAttribution {
                    noncontrolling_accounts: codes_for("noncontrolling_interest")?,
                },
                noncontrolling_income_accounts: codes_for("noncontrolling_interest_income")?,
                known_at_seq: at.0,
                effective_through,
                income_balances: balances,
            }))
        })
    }
    /// The committed journal at `(known_at, effective_through)` as one
    /// interop [`FormatJournal`] carrying its export coordinate certificate.
    pub fn format_journal(
        &self,
        cx: &PurposeContexts,
        effective_through: DateDay,
        known_at: Option<CommitSeq>,
    ) -> Result<FormatJournal, BookError> {
        self.query(cx, |db, book| {
            let seq = fa_registers::resolve_known_at(db, known_at)?;
            let spec = fa_journal::genesis::read_book_spec(db)?
                .ok_or_else(|| KernelError::Corrupt("the book has no genesis spec".into()))?;
            let unit = |id| {
                book.units.get(id).ok_or_else(|| {
                    KernelError::Corrupt(format!("unit {id:?} is not registered in this book"))
                })
            };
            let base = unit(spec.base_unit)?;
            let mut codes: BTreeMap<VId, String> = BTreeMap::new();
            let mut accounts = Vec::new();
            // A historical export must not load or decode today's chart
            // before discarding accounts created beyond its admitted pin.
            let chart = fa_journal::chart::read_at(db, book, seq)?;
            let roles = fa_journal::account_role::account_roles_at(db, book, seq)?;
            let mut roles_by_account: BTreeMap<VId, Vec<String>> = BTreeMap::new();
            for control in roles.assigned() {
                roles_by_account
                    .entry(control.spec.account)
                    .or_default()
                    .push(control.spec.role.clone());
            }
            let mut historical_accounts: Vec<_> = chart.accounts().values().cloned().collect();
            historical_accounts.sort_by(|left, right| left.code.cmp(&right.code));
            for row in historical_accounts {
                codes.insert(row.vid, row.code.clone());
                accounts.push(FormatAccount {
                    code: row.code,
                    name: row.name,
                    account_type: AccountType(row.account_type),
                    normal_side: if row.normal_balance == 0 {
                        Side::Debit
                    } else {
                        Side::Credit
                    },
                    roles: roles_by_account.remove(&row.vid).unwrap_or_default(),
                });
            }
            let key = &book.seal_key;
            let mut entries = Vec::new();
            for (vid, entry, recorded_at) in fa_registers::entries_at(db, book, seq)? {
                let proposal = &entry.proposal;
                if proposal.legs.is_empty()
                    || proposal.class == EntryClass::PENDING
                    || proposal.effective_date > effective_through
                {
                    continue;
                }
                let mut legs = Vec::with_capacity(proposal.legs.len());
                for leg in &proposal.legs {
                    let account_code = codes.get(&leg.account_ref).cloned().ok_or_else(|| {
                        KernelError::Corrupt(format!(
                            "entry {:032x} posts to an account absent at its prefix",
                            vid.0
                        ))
                    })?;
                    let leg_unit = unit(leg.amount.unit)?;
                    legs.push(FormatLeg {
                        account_code,
                        side: leg.side,
                        amount: leg.amount,
                        unit_code: leg_unit.code.clone(),
                        unit_scale: leg_unit.scale,
                        memo: leg
                            .memo
                            .as_ref()
                            .and_then(|m| m.open(key, limits::MAX_MEMO_BYTES).ok())
                            .filter(|m| !m.is_empty()),
                    });
                }
                let migrated_from = match &proposal.origin {
                    EntryOrigin::Migration {
                        source_system,
                        source_id,
                        ..
                    } => Some(format!(
                        "{source_system}:{}",
                        source_id
                            .open(key, limits::MAX_DESCRIPTION_BYTES)
                            .unwrap_or_default()
                    )),
                    _ => None,
                };
                entries.push(FormatEntry {
                    entry_id: format!("{:032x}", vid.0),
                    effective_date: proposal.effective_date,
                    recorded_seq: recorded_at.0,
                    class: proposal.class,
                    description: proposal
                        .description
                        .open(key, limits::MAX_DESCRIPTION_BYTES)
                        .unwrap_or_default(),
                    migrated_from,
                    legs,
                });
            }
            // The trial balance the exported legs fold to, per account and
            // unit, in exact checked arithmetic.
            let mut folded: BTreeMap<(String, String), (i128, fa_money::UnitId, u8)> =
                BTreeMap::new();
            for leg in entries.iter().flat_map(|e| &e.legs) {
                let cell = folded
                    .entry((leg.account_code.clone(), leg.unit_code.clone()))
                    .or_insert((0, leg.amount.unit, leg.unit_scale));
                let moved = match leg.side {
                    Side::Debit => cell.0.checked_add(leg.amount.mantissa),
                    Side::Credit => cell.0.checked_sub(leg.amount.mantissa),
                };
                cell.0 = moved.ok_or_else(|| {
                    KernelError::Corrupt("an exported balance exceeds the exact fold range".into())
                })?;
            }
            let mut assertions = Vec::with_capacity(folded.len());
            for ((account_code, unit_code), (balance, unit, unit_scale)) in folded {
                let magnitude = balance.checked_abs().ok_or_else(|| {
                    KernelError::Corrupt("an exported balance exceeds the exact fold range".into())
                })?;
                assertions.push(FormatAssertion {
                    account_code,
                    as_of: effective_through,
                    side: if balance < 0 {
                        Side::Credit
                    } else {
                        Side::Debit
                    },
                    amount: Amount::new(unit, magnitude),
                    unit_code,
                    unit_scale,
                });
            }
            FormatJournal::new(
                &spec.name,
                &base.code,
                base.scale,
                effective_through,
                seq.0,
                accounts,
                entries,
                assertions,
            )
            .map_err(|e| KernelError::Corrupt(format!("interop journal: {e}")).into())
        })
    }
}
