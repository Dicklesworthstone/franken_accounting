//! Exact balance explanations reconstructed from the authenticated journal.
//! The whole-period register commitment is replayed, including entries outside
//! the displayed account. Evidence heads describe committed citations; they do
//! not authenticate the underlying documents or the economic facts they assert.
use super::{ReportError, failed, metadata, open_items, registry};
use crate::blake3::hash_parts;
use crate::codec::Writer;
use crate::envelope::{LeafEnvelope, Leg};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExplanationColumn {
    Posted,
    Pending,
    Released,
}
impl ExplanationColumn {
    pub fn name(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Pending => "pending",
            Self::Released => "released",
        }
    }
    fn tag(self) -> u8 {
        match self {
            Self::Posted => 0,
            Self::Pending => 1,
            Self::Released => 2,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExplanationCell {
    pub account: u128,
    pub unit_id: u32,
    pub period: String,
    pub debits: i128,
    pub credits: i128,
    pub entry_count: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExplanationSupersession {
    pub target: u128,
    pub entry_digest: [u8; 32],
    pub kind: u8,
    pub reason_code: u16,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExplanationEvidence {
    pub document_oid: [u8; 32],
    pub doc_commit: [u8; 32],
    pub role: u8,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExplanationContribution {
    pub entry: u128,
    pub entry_digest: [u8; 32],
    pub class: u16,
    pub effective_date: i32,
    pub recorded_at: u64,
    pub visible_at: u64,
    pub ordinal: u16,
    pub debit: bool,
    pub unit_id: u32,
    pub mantissa: i128,
    pub column: ExplanationColumn,
    pub released_at: Option<u64>,
    pub resolves: Option<u128>,
    pub supersedes: Vec<ExplanationSupersession>,
    pub evidence: Vec<ExplanationEvidence>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExplanationCellChange {
    pub recorded_at: u64,
    pub unit_id: u32,
    pub debits: i128,
    pub credits: i128,
    pub debits_pending: i128,
    pub credits_pending: i128,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedBalanceExplanation {
    pub account: u128,
    pub account_row: super::VerifiedReportAccount,
    pub period: String,
    pub known_at: u64,
    pub fold_digest: [u8; 32],
    pub watermark: Option<u64>,
    pub cells: Vec<ExplanationCell>,
    pub pending: Vec<ExplanationCell>,
    pub contributions: Vec<ExplanationContribution>,
    pub history: Vec<ExplanationCellChange>,
    /// Authenticated definitions used to render the retained numeric reasons.
    pub supersession_reasons: BTreeMap<u16, super::ExplanationReason>,
}
impl VerifiedBalanceExplanation {
    pub fn last_changed_at(&self) -> Option<u64> {
        self.history.last().map(|change| change.recorded_at)
    }
}

fn add(a: i128, b: i128) -> Result<i128, ReportError> {
    a.checked_add(b).ok_or_else(|| {
        failed(
            "exact_arithmetic",
            "balance explanation accumulator overflow",
        )
    })
}
fn budget(total: &mut usize, bytes: usize) -> Result<(), ReportError> {
    *total = total
        .checked_add(bytes)
        .filter(|n| *n <= super::MAX_REPORT_BUNDLE_BYTES)
        .ok_or_else(|| {
            failed(
                "bounded_input",
                "balance explanation exceeds the 64 MiB reconstruction bound",
            )
        })?;
    Ok(())
}
fn cells_bytes(w: &mut Writer, cells: &[ExplanationCell]) {
    w.count(cells.len());
    for cell in cells {
        w.u128(cell.account)
            .u32(cell.unit_id)
            .bytes(cell.period.as_bytes())
            .i128(cell.debits)
            .i128(cell.credits)
            .u64(cell.entry_count);
    }
}
fn chain(previous: [u8; 32], at: u64, entry: u128, ordinal: u16, leg: &Leg) -> [u8; 32] {
    hash_parts(
        b"fa:register-leg-contribution:v1",
        &[
            &previous,
            &at.to_le_bytes(),
            &entry.to_le_bytes(),
            &ordinal.to_le_bytes(),
            &leg.account.to_le_bytes(),
            &leg.unit.to_le_bytes(),
            &[u8::from(!leg.debit)],
            &leg.mantissa.to_le_bytes(),
        ],
    )
}
fn bump(
    deltas: &mut BTreeMap<(u64, u32), [i128; 4]>,
    at: u64,
    unit: u32,
    slot: usize,
    amount: i128,
) -> Result<(), ReportError> {
    let value = deltas.entry((at, unit)).or_insert([0; 4]);
    value[slot] = add(value[slot], amount)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn replay(
    known_at: u64,
    account: u128,
    period: &str,
    units: &[u32],
    reasons: &BTreeMap<u16, registry::Reason>,
    schema: &metadata::Schema,
    envelopes: &[LeafEnvelope],
    infos: &BTreeMap<usize, metadata::EntryInfo<'_>>,
    legs: &[Vec<Leg>],
    visible_migrations: &BTreeSet<u64>,
    migration_activations: &BTreeMap<u64, u64>,
    releases: &BTreeMap<usize, u64>,
) -> Result<(VerifiedBalanceExplanation, Vec<u8>), ReportError> {
    schema.period_kind(period)?;
    let account_row = open_items::account(account, schema)?;
    if !account_row.is_leaf {
        return Err(failed(
            "account_metadata",
            "balance explanations require a historical leaf account",
        ));
    }
    if let super::OpenItemUnitPolicy::Single(unit) = account_row.unit_policy
        && units.binary_search(&unit).is_err()
    {
        return Err(failed(
            "registry_closure",
            "explained account declares an unregistered unit",
        ));
    }
    let mut selected = Vec::new();
    let mut identities = BTreeMap::new();
    for (&index, info) in infos {
        let envelope = &envelopes[index];
        if !(1..=30).contains(&envelope.class) {
            return Err(failed(
                "registry_closure",
                "entry class is outside the authenticated vocabulary",
            ));
        }
        if envelope.class >= 16 && !legs[index].is_empty() {
            return Err(failed(
                "entry_lineage",
                "control entry carries monetary legs",
            ));
        }
        if envelope.class == 12 && !visible_migrations.contains(&(index as u64)) {
            continue;
        }
        if envelope.class <= 15 && identities.insert(info.identity, index).is_some() {
            return Err(failed(
                "entry_identity",
                "duplicate monetary entry identity in the visible prefix",
            ));
        }
        if !legs[index].is_empty() {
            selected.push(index);
        }
    }
    // Prefix ordinals authenticate a set of records. Register leg commitments
    // instead use native (creating sequence, derived entry VId, leg ordinal).
    selected.sort_by_key(|index| (envelopes[*index].commit_seq, infos[index].identity));
    let mut posted = BTreeMap::<(u128, u32), ExplanationCell>::new();
    let mut pending = BTreeMap::<(u128, u32), ExplanationCell>::new();
    let mut posted_digest = [0; 32];
    let mut holds = BTreeMap::<(u64, u128), [u8; 32]>::new();
    let mut watermark: Option<u64> = None;
    let mut contributions = Vec::new();
    let mut output_budget = 256 + account_row.code.len() + account_row.name.len() + period.len();
    let mut fold_budget = 64 + period.len();
    for index in selected {
        let info = &infos[&index];
        let envelope = &envelopes[index];
        let day = envelope
            .effective_day
            .ok_or_else(|| failed("report_selector", "monetary entry lacks an effective day"))?;
        if schema.entry_period(info, day)? != period {
            continue;
        }
        let visible_at = if envelope.class == 12 {
            *migration_activations
                .get(&(index as u64))
                .filter(|at| **at > envelope.commit_seq && **at <= known_at)
                .ok_or_else(|| {
                    failed(
                        "migration_visibility",
                        "visible migration chunk lacks its later finalization",
                    )
                })?
        } else {
            envelope.commit_seq
        };
        watermark = Some(watermark.map_or(visible_at, |at| at.max(visible_at)));
        let released_at = if envelope.class == 2 {
            releases.get(&index).copied()
        } else {
            None
        };
        if let Some(at) = released_at {
            watermark = Some(watermark.map_or(at, |prior| prior.max(at)));
        }
        let column = if envelope.class != 2 {
            ExplanationColumn::Posted
        } else if released_at.is_some() {
            ExplanationColumn::Released
        } else {
            ExplanationColumn::Pending
        };
        let mut touched = BTreeSet::new();
        let mut hold_digest = [0; 32];
        for (ordinal, leg) in legs[index].iter().enumerate() {
            let ordinal = u16::try_from(ordinal)
                .map_err(|_| failed("bounded_input", "leg ordinal exceeds u16"))?;
            if leg.mantissa < 0 {
                return Err(failed("exact_arithmetic", "negative journal leg magnitude"));
            }
            if units.binary_search(&leg.unit).is_err() {
                return Err(failed(
                    "registry_closure",
                    "whole-period fold names an unregistered unit",
                ));
            }
            if !schema.accounts.contains_key(&leg.account) {
                return Err(failed(
                    "account_metadata",
                    "whole-period fold names an undeclared account",
                ));
            }
            let cells = match column {
                ExplanationColumn::Posted => {
                    posted_digest = chain(
                        posted_digest,
                        envelope.commit_seq,
                        info.identity,
                        ordinal,
                        leg,
                    );
                    Some(&mut posted)
                }
                ExplanationColumn::Pending => {
                    hold_digest = chain(
                        hold_digest,
                        envelope.commit_seq,
                        info.identity,
                        ordinal,
                        leg,
                    );
                    Some(&mut pending)
                }
                ExplanationColumn::Released => None,
            };
            if let Some(cells) = cells {
                let key = (leg.account, leg.unit);
                if !cells.contains_key(&key) {
                    budget(&mut fold_budget, 64 + period.len())?;
                }
                let cell = cells.entry(key).or_insert_with(|| ExplanationCell {
                    account: leg.account,
                    unit_id: leg.unit,
                    period: period.into(),
                    debits: 0,
                    credits: 0,
                    entry_count: 0,
                });
                if leg.debit {
                    cell.debits = add(cell.debits, leg.mantissa)?;
                } else {
                    cell.credits = add(cell.credits, leg.mantissa)?;
                }
                touched.insert(key);
            }
            if leg.account != account {
                continue;
            }
            budget(
                &mut output_budget,
                128 + 51 * info.supersession.len() + 65 * info.evidence.len(),
            )?;
            let mut supersedes = Vec::with_capacity(info.supersession.len());
            for ((target, digest, kind), reason_code) in
                info.supersession.iter().zip(&info.supersession_reasons)
            {
                let target_index = identities.get(target).copied().ok_or_else(|| {
                    if infos.values().any(|entry| entry.legacy_identity == Some(*target)) {
                        failed("supported_report", "legacy key-derived replacement lineage is not unambiguously authenticated by this portable explanation")
                    } else {
                        failed("entry_lineage", "explanation lineage target is absent from the visible prefix")
                    }
                })?;
                if envelopes[target_index].record_digest != *digest
                    || envelopes[target_index].commit_seq > envelope.commit_seq
                    || target_index == index
                {
                    return Err(failed(
                        "entry_lineage",
                        "explanation lineage target is self-referential, later, or has another digest",
                    ));
                }
                if !reasons.contains_key(reason_code) {
                    return Err(failed(
                        "registry_closure",
                        "explanation supersession reason is not registered in its bound scope",
                    ));
                }
                supersedes.push(ExplanationSupersession {
                    target: *target,
                    entry_digest: *digest,
                    kind: *kind,
                    reason_code: *reason_code,
                });
            }
            contributions.push(ExplanationContribution {
                entry: info.identity,
                entry_digest: envelope.record_digest,
                class: envelope.class,
                effective_date: day,
                recorded_at: envelope.commit_seq,
                visible_at,
                ordinal,
                debit: leg.debit,
                unit_id: leg.unit,
                mantissa: leg.mantissa,
                column,
                released_at,
                resolves: info.resolution.map(|target| target.0),
                supersedes,
                evidence: info
                    .evidence
                    .iter()
                    .map(|(document_oid, doc_commit, role)| ExplanationEvidence {
                        document_oid: *document_oid,
                        doc_commit: *doc_commit,
                        role: *role,
                    })
                    .collect(),
            });
        }
        let cells = if column == ExplanationColumn::Posted {
            &mut posted
        } else {
            &mut pending
        };
        for key in touched {
            let cell = cells.get_mut(&key).ok_or_else(|| {
                failed(
                    "report_recomputation",
                    "missing reconstructed register cell",
                )
            })?;
            cell.entry_count = cell
                .entry_count
                .checked_add(1)
                .ok_or_else(|| failed("exact_arithmetic", "register entry count overflow"))?;
        }
        if column == ExplanationColumn::Pending {
            budget(&mut fold_budget, 56)?;
            holds.insert((envelope.commit_seq, info.identity), hold_digest);
        }
    }
    let all_posted: Vec<_> = posted.into_values().collect();
    let all_pending: Vec<_> = pending.into_values().collect();
    let mut fold = Writer::default();
    fold.bytes(period.as_bytes())
        .u8(u8::from(watermark.is_some()));
    if let Some(at) = watermark {
        fold.u64(at);
    }
    fold.fixed(&posted_digest).count(holds.len());
    for ((at, identity), digest) in holds {
        fold.u64(at).u128(identity).fixed(&digest);
    }
    cells_bytes(&mut fold, &all_posted);
    cells_bytes(&mut fold, &all_pending);
    let fold_digest = hash_parts(b"fa:register-fold:v2", &[&fold.buf]);
    let cells: Vec<_> = all_posted
        .into_iter()
        .filter(|cell| cell.account == account)
        .collect();
    let pending: Vec<_> = all_pending
        .into_iter()
        .filter(|cell| cell.account == account)
        .collect();
    budget(
        &mut output_budget,
        (cells.len() + pending.len()) * (64 + period.len()),
    )?;
    let mut deltas = BTreeMap::new();
    for contribution in &contributions {
        let side = usize::from(!contribution.debit);
        match contribution.column {
            ExplanationColumn::Posted => bump(
                &mut deltas,
                contribution.visible_at,
                contribution.unit_id,
                side,
                contribution.mantissa,
            )?,
            ExplanationColumn::Pending => bump(
                &mut deltas,
                contribution.recorded_at,
                contribution.unit_id,
                side + 2,
                contribution.mantissa,
            )?,
            ExplanationColumn::Released => {
                let released_at = contribution.released_at.ok_or_else(|| {
                    failed(
                        "pending_resolution",
                        "released contribution lacks its resolution",
                    )
                })?;
                bump(
                    &mut deltas,
                    contribution.recorded_at,
                    contribution.unit_id,
                    side + 2,
                    contribution.mantissa,
                )?;
                bump(
                    &mut deltas,
                    released_at,
                    contribution.unit_id,
                    side + 2,
                    -contribution.mantissa,
                )?;
            }
        }
    }
    budget(&mut output_budget, deltas.len() * 76)?;
    let mut running = BTreeMap::<u32, [i128; 4]>::new();
    let mut history = Vec::with_capacity(deltas.len());
    for ((at, unit_id), delta) in deltas {
        let values = running.entry(unit_id).or_insert([0; 4]);
        for (value, change) in values.iter_mut().zip(delta) {
            *value = add(*value, change)?;
        }
        history.push(ExplanationCellChange {
            recorded_at: at,
            unit_id,
            debits: values[0],
            credits: values[1],
            debits_pending: values[2],
            credits_pending: values[3],
        });
    }
    let report = VerifiedBalanceExplanation {
        account,
        account_row,
        period: period.into(),
        known_at,
        fold_digest,
        watermark,
        cells,
        pending,
        contributions,
        history,
        supersession_reasons: reasons.clone(),
    };
    let output = encode(&report);
    if output.len() > super::MAX_REPORT_BUNDLE_BYTES {
        return Err(failed(
            "bounded_input",
            "canonical balance explanation exceeds 64 MiB",
        ));
    }
    Ok((report, output))
}

fn encode(report: &VerifiedBalanceExplanation) -> Vec<u8> {
    let mut w = Writer::default();
    w.fixed(b"fa:balance-explanation:v1").u128(report.account);
    let account = &report.account_row;
    w.u128(account.account)
        .bytes(account.code.as_bytes())
        .bytes(account.name.as_bytes())
        .u8(account.account_type)
        .u8(account.normal_balance)
        .u8(u8::from(account.is_leaf));
    match account.unit_policy {
        super::OpenItemUnitPolicy::Single(unit) => {
            w.u8(0).u32(unit);
        }
        super::OpenItemUnitPolicy::AnyCurrency => {
            w.u8(1);
        }
        super::OpenItemUnitPolicy::AnyUnit => {
            w.u8(2);
        }
    }
    w.u8(u8::from(account.limit.is_some()));
    if let Some(limit) = &account.limit {
        for bound in [limit.lower, limit.upper] {
            w.u8(u8::from(bound.is_some()));
            if let Some(amount) = bound {
                w.i128(amount);
            }
        }
        w.u8(u8::from(limit.period_scoped));
    }
    w.u64(account.created_at)
        .bytes(report.period.as_bytes())
        .u64(report.known_at)
        .fixed(&report.fold_digest)
        .u8(u8::from(report.watermark.is_some()));
    if let Some(at) = report.watermark {
        w.u64(at);
    }
    cells_bytes(&mut w, &report.cells);
    cells_bytes(&mut w, &report.pending);
    w.count(report.contributions.len());
    for c in &report.contributions {
        w.u128(c.entry)
            .fixed(&c.entry_digest)
            .u16(c.class)
            .i32(c.effective_date)
            .u64(c.recorded_at)
            .u64(c.visible_at)
            .u16(c.ordinal)
            .u8(u8::from(!c.debit))
            .u32(c.unit_id)
            .i128(c.mantissa)
            .u8(c.column.tag())
            .u8(u8::from(c.released_at.is_some()));
        if let Some(at) = c.released_at {
            w.u64(at);
        }
        w.u8(u8::from(c.resolves.is_some()));
        if let Some(target) = c.resolves {
            w.u128(target);
        }
        w.count(c.supersedes.len());
        for s in &c.supersedes {
            w.u128(s.target)
                .fixed(&s.entry_digest)
                .u8(s.kind)
                .u16(s.reason_code);
        }
        w.count(c.evidence.len());
        for e in &c.evidence {
            w.fixed(&e.document_oid).fixed(&e.doc_commit).u8(e.role);
        }
    }
    w.count(report.history.len());
    for change in &report.history {
        w.u64(change.recorded_at)
            .u32(change.unit_id)
            .i128(change.debits)
            .i128(change.credits)
            .i128(change.debits_pending)
            .i128(change.credits_pending);
    }
    w.buf
}
