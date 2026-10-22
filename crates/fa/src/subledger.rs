//! Native AR/AP detail and reconciliation at explicit recorded/effective coordinates.
//!
//! These reports fold immutable journal legs by party and compare their exact
//! native-unit columns with an independent stock trial balance of the control
//! leaf. They are not external-feed attestations or replay certificates.

use std::collections::{BTreeMap, BTreeSet};

use asupersync::fs::Vfs;
use fa_journal::{BookContext, KernelError, Refusal, exit};
use fa_model::{EntryClass, PARTY_DIMENSION, Writer};
use fa_money::Side;
use fa_policy::Capability;
use fa_registers::RegisterError;
use fa_time::DateDay;
use fgdb::Database;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::{AsyncBook, BookError, Outcome};

pub use fa_journal::subledger::{
    NativeSubledger, NativeSubledgerKind, NativeSubledgerRecorded, NativeSubledgerSpec,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeSubledgerRow {
    /// The Party vertex and its party-dimension value are distinct identities.
    pub party: VId,
    pub party_value: VId,
    pub party_code: String,
    pub unit_id: u32,
    pub debits: i128,
    pub credits: i128,
    pub debits_pending: i128,
    pub credits_pending: i128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeSubledgerTotal {
    pub unit_id: u32,
    pub detail_debits: i128,
    pub detail_credits: i128,
    pub detail_debits_pending: i128,
    pub detail_credits_pending: i128,
    pub control_debits: i128,
    pub control_credits: i128,
    pub control_debits_pending: i128,
    pub control_credits_pending: i128,
}

impl NativeSubledgerTotal {
    #[must_use]
    pub const fn is_reconciled(&self) -> bool {
        self.detail_debits == self.control_debits
            && self.detail_credits == self.control_credits
            && self.detail_debits_pending == self.control_debits_pending
            && self.detail_credits_pending == self.control_credits_pending
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeSubledgerReconciliation {
    pub subledger: NativeSubledger,
    pub known_at: CommitSeq,
    pub effective_through: DateDay,
    /// Deterministic (party code, native unit) ordering. Gross debit/credit
    /// and pending columns remain separate; no implicit currency conversion.
    pub rows: Vec<NativeSubledgerRow>,
    pub totals: Vec<NativeSubledgerTotal>,
    pub reconciled: bool,
}

impl NativeSubledgerReconciliation {
    /// Canonical report bytes, not a signature or certification claim.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, fa_model::EncodeError> {
        let mut w = Writer::new();
        w.fixed(b"fa:native-subledger-reconciliation:v1")
            .u128(self.subledger.vid.0)
            .bytes(&self.subledger.spec.encode()?)
            .u128(self.subledger.entry.vid.0)
            .fixed(&self.subledger.entry.entry_digest)
            .u64(self.subledger.recorded_at.0)
            .u64(self.known_at.0)
            .i32(self.effective_through.0)
            .list(&self.rows, |w, row| {
                w.u128(row.party.0)
                    .u128(row.party_value.0)
                    .str(&row.party_code)
                    .u32(row.unit_id)
                    .i128(row.debits)
                    .i128(row.credits)
                    .i128(row.debits_pending)
                    .i128(row.credits_pending);
            })
            .list(&self.totals, |w, total| {
                w.u32(total.unit_id)
                    .i128(total.detail_debits)
                    .i128(total.detail_credits)
                    .i128(total.detail_debits_pending)
                    .i128(total.detail_credits_pending)
                    .i128(total.control_debits)
                    .i128(total.control_credits)
                    .i128(total.control_debits_pending)
                    .i128(total.control_credits_pending);
            })
            .bool(self.reconciled);
        w.finish()
    }
}

pub(crate) fn admitted_at<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    capability: &Capability,
    known_at: Option<CommitSeq>,
) -> Outcome<CommitSeq> {
    // Scope admission is intentionally before the first storage observation.
    if let Err(denial) = fa_policy::admit_read(capability, capability.holder(), book.book_id) {
        return Ok(Err(fa_journal::policy::refusal(&denial)));
    }
    if let Err(denial) = fa_policy::reach(
        capability,
        &fa_policy::Reach {
            branch: Some(fa_model::Id128::TRUNK),
            observes: known_at.map_or(fa_policy::Observes::Head, fa_policy::Observes::At),
            periods: None,
            through: None,
            accounts: None,
        },
        None,
    ) {
        return Ok(Err(fa_journal::policy::refusal(&denial)));
    }
    let head = db.frontier().map_err(KernelError::from)?;
    if let Err(denial) = fa_policy::current(capability, head) {
        return Ok(Err(fa_journal::policy::refusal(&denial)));
    }
    if let Err(refusal) = fa_journal::policy::capability_admitted(db, book, capability)? {
        return Ok(Err(refusal));
    }
    let at = known_at.unwrap_or(head);
    if at > head {
        return Ok(Err(Refusal::new(
            fa_journal::refusal::code::STRUCTURE,
            exit::USAGE,
            format!("known-at {} is beyond the book head {}", at.0, head.0),
            "plan §7.5 (recorded/effective report coordinates)",
            "select a retained known-at frontier at or before the book head",
        )));
    }
    Ok(Ok(at))
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    #[allow(clippy::too_many_arguments)]
    pub async fn create_native_subledger(
        &mut self,
        cx: &PurposeContexts,
        spec: &NativeSubledgerSpec,
        principal: VId,
        effective_date: DateDay,
        key: &[u8],
        capability: &Capability,
    ) -> Outcome<NativeSubledgerRecorded> {
        let description = self.seal_text(cx, &format!("create native subledger {}", spec.code))?;
        Ok(fa_journal::subledger::create_native_subledger(
            &mut self.db,
            cx,
            &self.context,
            spec,
            principal,
            effective_date,
            key,
            description,
            capability,
        )
        .await?)
    }

    /// Read immutable designations under current whole-book authority.
    pub fn native_subledgers(
        &self,
        cx: &PurposeContexts,
        known_at: Option<CommitSeq>,
        capability: &Capability,
    ) -> Outcome<Vec<NativeSubledger>> {
        self.query(cx, |db, book| {
            let at = match admitted_at(db, book, capability, known_at)? {
                Ok(at) => at,
                Err(refusal) => return Ok(Err(refusal)),
            };
            Ok(Ok(fa_journal::subledger::native_subledgers_at(
                db, book, at,
            )?))
        })
    }

    /// Native detail reconciliation, pinned once at known-at and folded
    /// through the inclusive civil date. Resolutions release original holds
    /// at the recorded frontier, irrespective of their own effective dates.
    pub fn reconcile_native_subledger(
        &self,
        cx: &PurposeContexts,
        code: &str,
        effective_through: DateDay,
        known_at: Option<CommitSeq>,
        capability: &Capability,
    ) -> Outcome<NativeSubledgerReconciliation> {
        self.query(cx, |db, book| {
            let at = match admitted_at(db, book, capability, known_at)? {
                Ok(at) => at,
                Err(refusal) => return Ok(Err(refusal)),
            };
            let definitions = fa_journal::subledger::native_subledgers_at(db, book, at)?;
            let Some(subledger) = definitions.into_iter().find(|item| item.spec.code == code)
            else {
                return Ok(Err(Refusal::new(
                    fa_journal::refusal::code::STRUCTURE,
                    exit::USAGE,
                    format!(
                        "native subledger '{code}' does not exist at known-at {}",
                        at.0
                    ),
                    "plan §4.1 Subledger",
                    "list native subledgers at this frontier or register a control leaf",
                )));
            };
            // The control fold is independent of the party grouping below.
            // It also validates resolution targets and migration visibility.
            let source = fa_registers::balance_as_of(db, book, effective_through, Some(at))?;
            let entries = fa_registers::entries_at(db, book, at)?;
            let rea = fa_journal::read_rea_at(db, book, at)?;
            let parties: BTreeMap<_, _> = rea
                .parties
                .values()
                .map(|party| (party.dimension_value_vid, party))
                .collect();
            let resolved: BTreeSet<_> = entries
                .iter()
                .filter_map(|(_, entry, _)| {
                    if entry.proposal.class != EntryClass::RESOLUTION {
                        return None;
                    }
                    entry
                        .proposal
                        .pending
                        .as_ref()
                        .and_then(|pending| pending.resolution_of)
                        .map(|target| target.vid)
                })
                .collect();
            let mut detail: BTreeMap<(VId, u32), [i128; 4]> = BTreeMap::new();
            let query = cx.query();
            for (vid, entry, _) in &entries {
                query.checkpoint().map_err(BookError::Context)?;
                let pending = entry.proposal.class == EntryClass::PENDING;
                if (pending && resolved.contains(vid))
                    || entry.proposal.effective_date > effective_through
                {
                    continue;
                }
                for leg in &entry.proposal.legs {
                    if leg.account_ref != subledger.spec.control_account {
                        continue;
                    }
                    let Some((_, party)) = leg
                        .dimension_set
                        .iter()
                        .find(|(kind, _)| *kind == PARTY_DIMENSION)
                    else {
                        return Err(KernelError::Corrupt(
                            "native subledger historical leg has no party detail".into(),
                        )
                        .into());
                    };
                    if !parties.contains_key(party) {
                        return Err(KernelError::Corrupt(
                            "native subledger leg refers to an undeclared party".into(),
                        )
                        .into());
                    }
                    let columns = detail.entry((*party, leg.amount.unit.0)).or_insert([0; 4]);
                    let column = match (pending, leg.side) {
                        (false, Side::Debit) => 0,
                        (false, Side::Credit) => 1,
                        (true, Side::Debit) => 2,
                        (true, Side::Credit) => 3,
                    };
                    columns[column] = columns[column]
                        .checked_add(leg.amount.mantissa)
                        .ok_or(RegisterError::Overflow)?;
                }
            }
            let mut rows = Vec::with_capacity(detail.len());
            let mut detail_totals: BTreeMap<u32, [i128; 4]> = BTreeMap::new();
            for ((party_value, unit_id), columns) in detail {
                let party = parties.get(&party_value).ok_or_else(|| {
                    KernelError::Corrupt(
                        "native subledger party disappeared within a pinned snapshot".into(),
                    )
                })?;
                let totals = detail_totals.entry(unit_id).or_insert([0; 4]);
                for (total, amount) in totals.iter_mut().zip(columns) {
                    *total = total.checked_add(amount).ok_or(RegisterError::Overflow)?;
                }
                rows.push(NativeSubledgerRow {
                    party: party.vid,
                    party_value,
                    party_code: party.code.clone(),
                    unit_id,
                    debits: columns[0],
                    credits: columns[1],
                    debits_pending: columns[2],
                    credits_pending: columns[3],
                });
            }
            rows.sort_by(|a, b| {
                a.party_code
                    .cmp(&b.party_code)
                    .then(a.unit_id.cmp(&b.unit_id))
            });
            let control: BTreeMap<_, _> = source
                .rows
                .into_iter()
                .filter(|row| row.account == subledger.spec.control_account)
                .map(|row| {
                    (
                        row.unit_id,
                        [
                            row.debits,
                            row.credits,
                            row.debits_pending,
                            row.credits_pending,
                        ],
                    )
                })
                .collect();
            let units: BTreeSet<_> = detail_totals
                .keys()
                .chain(control.keys())
                .copied()
                .collect();
            let totals: Vec<_> = units
                .into_iter()
                .map(|unit_id| {
                    let detail = detail_totals.get(&unit_id).copied().unwrap_or([0; 4]);
                    let account = control.get(&unit_id).copied().unwrap_or([0; 4]);
                    NativeSubledgerTotal {
                        unit_id,
                        detail_debits: detail[0],
                        detail_credits: detail[1],
                        detail_debits_pending: detail[2],
                        detail_credits_pending: detail[3],
                        control_debits: account[0],
                        control_credits: account[1],
                        control_debits_pending: account[2],
                        control_credits_pending: account[3],
                    }
                })
                .collect();
            let reconciled = totals.iter().all(NativeSubledgerTotal::is_reconciled);
            Ok(Ok(NativeSubledgerReconciliation {
                subledger,
                known_at: at,
                effective_through,
                rows,
                totals,
                reconciled,
            }))
        })
    }
}
