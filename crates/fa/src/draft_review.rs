//! Atomic rehearsal of an existing draft and its exact, replayable balance
//! comparison (plan §7.5 / §15.2).
//!
//! The source is the complete historical draft at one trunk prefix. Every
//! planned intent posts in one scratch transaction under its original
//! planner's capability and approvals. Neither the draft state nor trunk
//! changes. The certificate combines a native trunk trial-balance certificate
//! with the exact draft source witness and a re-performed atomic rehearsal;
//! it does not claim that scratch has trunk's native snapshot identity.

use std::collections::BTreeMap;

use fa_journal::{DraftRehearsal, DraftRehearsalSource, Refusal, exit};
use fa_model::{EntryRef, Id128, Reader, Writer, domain_digest};
use fa_policy::{Capability, Observes, Op, Reach};
use fa_registers::TrialBalance;
use fgdb_types::{CommitSeq, VId};

use crate::{
    Book, Outcome, ReportCertificate, ReportOutput, ReportSelection, RetainedCertificate,
    TrialBalanceSelection,
};

pub const DRAFT_DIFF_CERTIFICATE_FORMAT: &[u8] = b"fa:draft-diff-certificate:v1";
pub const DRAFT_DIFF_OUTPUT_FORMAT: &str = "fa:draft-diff:v1";
const DIGEST_DOMAIN: &[u8] = b"fa:draft-diff-certificate-digest:v1";
pub const MAX_DRAFT_DIFF_CERTIFICATE_BYTES: usize = crate::certificate::MAX_CERTIFICATE_BYTES;
/// The complete comparison population is bounded; an excess refuses the
/// report rather than truncating it to a misleading subset.
pub const MAX_DRAFT_DIFF_ROWS: usize = 65_536;
const MAX_PERIOD_BYTES: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DraftDiffRow {
    pub account: VId,
    pub code: String,
    pub name: String,
    pub unit_id: u32,
    pub trunk_debits: i128,
    pub trunk_credits: i128,
    pub draft_debits: i128,
    pub draft_credits: i128,
    pub delta: i128,
    pub trunk_debits_pending: i128,
    pub trunk_credits_pending: i128,
    pub draft_debits_pending: i128,
    pub draft_credits_pending: i128,
    pub pending_delta: i128,
}

/// One period's stock comparison. Amounts are exact unit mantissas; posted
/// and pending columns remain separate, and only changed rows are shown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DraftDiff {
    pub name: String,
    pub draft: VId,
    pub owner: VId,
    pub source_known_at: CommitSeq,
    pub source_digest: [u8; 32],
    pub period: String,
    pub plans: usize,
    pub seq_map_digest: [u8; 32],
    pub rehearsal_known_at: CommitSeq,
    pub batch_outcome: VId,
    /// All rehearsed members, in draft planning order, including members
    /// whose effects are outside the selected report period.
    pub entries: Vec<EntryRef>,
    pub rows: Vec<DraftDiffRow>,
}

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        crate::certificate::code::CERTIFICATE_INVALID,
        exit::VERIFICATION,
        message,
        "plan §7.5 / §15.2 (an existing draft is rehearsed atomically at its complete source prefix)",
        "replay the complete draft diff certificate in its original book; a new current review is certified separately",
    )
}

fn encoded_error(error: impl std::fmt::Display) -> Refusal {
    invalid(error.to_string())
}

fn check_period(period: &str) -> Result<(), Refusal> {
    if period.is_empty() || period.len() > MAX_PERIOD_BYTES {
        return Err(invalid("a draft diff names one bounded period code"));
    }
    Ok(())
}

impl DraftDiff {
    /// Every displayed field is part of the canonical result.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        check_period(&self.period)?;
        if self.name.is_empty()
            || self.name.len() > fa_journal::draft::MAX_DRAFT_NAME_BYTES
            || self.plans == 0
            || self.plans > fa_model::limits::MAX_BATCH_ENTRIES
            || self.entries.len() != self.plans
            || self.rows.len() > MAX_DRAFT_DIFF_ROWS
            || self.source_known_at.0.checked_add(1) != Some(self.rehearsal_known_at.0)
        {
            return Err(invalid(
                "a draft diff exceeds or contradicts its atomic rehearsal bounds",
            ));
        }
        let mut w = Writer::new();
        w.str(DRAFT_DIFF_OUTPUT_FORMAT)
            .str(&self.name)
            .u128(self.draft.0)
            .u128(self.owner.0)
            .u64(self.source_known_at.0)
            .fixed(&self.source_digest)
            .str(&self.period)
            .u64(self.plans as u64)
            .fixed(&self.seq_map_digest)
            .u64(self.rehearsal_known_at.0)
            .u128(self.batch_outcome.0)
            .list(&self.entries, |w, entry| entry.encode(w))
            .list(&self.rows, |w, row| {
                w.u128(row.account.0)
                    .str(&row.code)
                    .str(&row.name)
                    .u32(row.unit_id)
                    .i128(row.trunk_debits)
                    .i128(row.trunk_credits)
                    .i128(row.draft_debits)
                    .i128(row.draft_credits)
                    .i128(row.delta)
                    .i128(row.trunk_debits_pending)
                    .i128(row.trunk_credits_pending)
                    .i128(row.draft_debits_pending)
                    .i128(row.draft_credits_pending)
                    .i128(row.pending_delta);
            });
        let bytes = w.finish().map_err(encoded_error)?;
        if bytes.len() > MAX_DRAFT_DIFF_CERTIFICATE_BYTES {
            return Err(invalid("draft diff output exceeds the 64 MiB bound"));
        }
        Ok(bytes)
    }
}

/// A retained-history proof of the source and the re-performed rehearsal.
/// Producer provenance is unsigned and never supplies caller authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DraftDiffCertificate {
    trunk: ReportCertificate,
    source: DraftRehearsalSource,
    seq_map_digest: [u8; 32],
    rehearsal_known_at: CommitSeq,
    producer: VId,
    capability_commitment: [u8; 32],
    output: Vec<u8>,
    digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertifiedDraftDiff {
    pub report: DraftDiff,
    pub certificate: DraftDiffCertificate,
}

impl DraftDiffCertificate {
    fn body(&self) -> Result<Vec<u8>, Refusal> {
        let mut w = Writer::new();
        w.bytes(DRAFT_DIFF_CERTIFICATE_FORMAT)
            .bytes(&self.trunk.canonical_bytes().map_err(encoded_error)?)
            .bytes(&self.source.canonical_bytes().map_err(encoded_error)?)
            .fixed(&self.seq_map_digest)
            .u64(self.rehearsal_known_at.0)
            .u128(self.producer.0)
            .fixed(&self.capability_commitment)
            .bytes(&self.output);
        w.finish().map_err(encoded_error)
    }

    fn validate(&self) -> Result<(), Refusal> {
        if self.trunk.book_id != self.source.body.book_id
            || self.trunk.branch_id != Id128::TRUNK
            || self.trunk.time_selection.is_some()
            || self.trunk.known_at != self.source.known_at
            || self.source.plans.is_empty()
            || self.source.plans.len() > fa_model::limits::MAX_BATCH_ENTRIES
            || self.source.known_at.0.checked_add(1) != Some(self.rehearsal_known_at.0)
        {
            return Err(invalid(
                "draft diff source, trunk coordinate or atomic rehearsal head disagree",
            ));
        }
        check_period(self.period())?;
        if !matches!(
            &self.trunk.selection,
            ReportSelection::TrialBalance(TrialBalanceSelection::Periods(periods))
                if periods.len() == 1
        ) {
            return Err(invalid(
                "a draft diff source is one period's native stock trial balance",
            ));
        }
        if domain_digest(DIGEST_DOMAIN, &[&self.body()?]) != self.digest {
            return Err(invalid("draft diff certificate digest mismatch"));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        let mut bytes = self.body()?;
        bytes.extend_from_slice(&self.digest);
        if bytes.len() > MAX_DRAFT_DIFF_CERTIFICATE_BYTES {
            return Err(invalid("draft diff certificate exceeds the 64 MiB bound"));
        }
        Ok(bytes)
    }

    /// Bounded canonical decoding establishes container integrity. Only
    /// `Book::replay_draft_diff` establishes the historical result.
    pub fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        if bytes.len() > MAX_DRAFT_DIFF_CERTIFICATE_BYTES {
            return Err(invalid("draft diff certificate exceeds the 64 MiB bound"));
        }
        let mut r = Reader::new(bytes);
        if r.bytes(64, "draft diff format").map_err(encoded_error)? != DRAFT_DIFF_CERTIFICATE_FORMAT
        {
            return Err(invalid("not a supported draft diff certificate"));
        }
        let trunk = ReportCertificate::decode(
            r.bytes(MAX_DRAFT_DIFF_CERTIFICATE_BYTES, "draft diff trunk")
                .map_err(encoded_error)?,
        )?;
        let source = DraftRehearsalSource::decode(
            r.bytes(MAX_DRAFT_DIFF_CERTIFICATE_BYTES, "draft diff source")
                .map_err(encoded_error)?,
        )
        .map_err(encoded_error)?;
        let seq_map_digest = r.fixed("draft diff seq map").map_err(encoded_error)?;
        let rehearsal_known_at =
            CommitSeq(r.u64("draft diff rehearsal head").map_err(encoded_error)?);
        let producer = VId(r.u128("draft diff producer").map_err(encoded_error)?);
        let capability_commitment = r.fixed("draft diff capability").map_err(encoded_error)?;
        let output = r
            .bytes(MAX_DRAFT_DIFF_CERTIFICATE_BYTES, "draft diff output")
            .map_err(encoded_error)?
            .to_vec();
        let digest = r.fixed("draft diff digest").map_err(encoded_error)?;
        r.finish().map_err(encoded_error)?;
        let certificate = Self {
            trunk,
            source,
            seq_map_digest,
            rehearsal_known_at,
            producer,
            capability_commitment,
            output,
            digest,
        };
        certificate.validate()?;
        if certificate.canonical_bytes()?.as_slice() != bytes {
            return Err(invalid("noncanonical draft diff certificate"));
        }
        Ok(certificate)
    }

    #[must_use]
    pub fn format(&self) -> &'static [u8] {
        DRAFT_DIFF_CERTIFICATE_FORMAT
    }
    #[must_use]
    pub fn trunk(&self) -> &ReportCertificate {
        &self.trunk
    }
    #[must_use]
    pub fn source(&self) -> &DraftRehearsalSource {
        &self.source
    }
    #[must_use]
    pub fn name(&self) -> &str {
        &self.source.body.name
    }
    #[must_use]
    pub fn draft(&self) -> VId {
        self.source.body.vid()
    }
    #[must_use]
    pub fn known_at(&self) -> CommitSeq {
        self.source.known_at
    }
    #[must_use]
    pub fn rehearsal_known_at(&self) -> CommitSeq {
        self.rehearsal_known_at
    }
    #[must_use]
    pub fn seq_map_digest(&self) -> &[u8; 32] {
        &self.seq_map_digest
    }
    #[must_use]
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    #[must_use]
    pub fn output(&self) -> &[u8] {
        &self.output
    }
    #[must_use]
    pub fn period(&self) -> &str {
        match &self.trunk.selection {
            ReportSelection::TrialBalance(TrialBalanceSelection::Periods(periods)) => {
                periods.first().map_or("", String::as_str)
            }
            _ => "",
        }
    }
}

/// Current authority always precedes source observation. A historical
/// certificate selects At(source); it never treats a past prefix as the
/// authority frontier or silently expands a caller's known-at ceiling.
fn authorize(
    book: &Book,
    principal: VId,
    capability: &Capability,
    known_at: Option<CommitSeq>,
    produce: bool,
) -> Outcome<()> {
    if let Err(refusal) = book.read_scope(principal, capability)? {
        return Ok(Err(refusal));
    }
    let admitted = fa_policy::reach(
        capability,
        &Reach {
            branch: Some(Id128::TRUNK),
            observes: known_at.map_or(Observes::Head, Observes::At),
            periods: None,
            through: None,
            accounts: None,
        },
        None,
    )
    .and_then(|()| {
        if produce {
            fa_policy::require(
                capability,
                Op::Produce,
                "certifying or retaining a draft diff",
            )
        } else {
            Ok(())
        }
    });
    Ok(admitted.map_err(|denial| fa_journal::policy::refusal(&denial)))
}

fn difference(trunk: &TrialBalance, draft: &TrialBalance) -> Result<Vec<DraftDiffRow>, Refusal> {
    let mut cells: BTreeMap<(VId, u32), DraftDiffRow> = BTreeMap::new();
    for (is_draft, report) in [(false, trunk), (true, draft)] {
        for row in &report.rows {
            let key = (row.account, row.unit_id);
            if !cells.contains_key(&key) && cells.len() >= MAX_DRAFT_DIFF_ROWS {
                return Err(invalid("draft comparison population exceeds its row bound"));
            }
            let cell = cells.entry(key).or_insert_with(|| DraftDiffRow {
                account: row.account,
                code: row.code.clone(),
                name: row.name.clone(),
                unit_id: row.unit_id,
                trunk_debits: 0,
                trunk_credits: 0,
                draft_debits: 0,
                draft_credits: 0,
                delta: 0,
                trunk_debits_pending: 0,
                trunk_credits_pending: 0,
                draft_debits_pending: 0,
                draft_credits_pending: 0,
                pending_delta: 0,
            });
            if cell.code != row.code || cell.name != row.name {
                return Err(invalid(
                    "draft rehearsal changed the source account metadata",
                ));
            }
            if is_draft {
                cell.draft_debits = row.debits;
                cell.draft_credits = row.credits;
                cell.draft_debits_pending = row.debits_pending;
                cell.draft_credits_pending = row.credits_pending;
            } else {
                cell.trunk_debits = row.debits;
                cell.trunk_credits = row.credits;
                cell.trunk_debits_pending = row.debits_pending;
                cell.trunk_credits_pending = row.credits_pending;
            }
        }
    }
    let change = |after: (i128, i128), before: (i128, i128)| {
        after
            .0
            .checked_sub(after.1)
            .zip(before.0.checked_sub(before.1))
            .and_then(|(a, b)| a.checked_sub(b))
            .ok_or_else(|| invalid("draft difference exceeds the exact i128 range"))
    };
    let mut rows = Vec::new();
    for mut cell in cells.into_values() {
        let posted = (
            (cell.draft_debits, cell.draft_credits),
            (cell.trunk_debits, cell.trunk_credits),
        );
        let pending = (
            (cell.draft_debits_pending, cell.draft_credits_pending),
            (cell.trunk_debits_pending, cell.trunk_credits_pending),
        );
        if posted.0 == posted.1 && pending.0 == pending.1 {
            continue;
        }
        cell.delta = change(posted.0, posted.1)?;
        cell.pending_delta = change(pending.0, pending.1)?;
        rows.push(cell);
    }
    rows.sort_by(|a, b| (&a.code, a.unit_id, a.account).cmp(&(&b.code, b.unit_id, b.account)));
    Ok(rows)
}

fn assemble(
    rehearsal: &DraftRehearsal,
    trunk: &TrialBalance,
    draft: &TrialBalance,
    period: &str,
) -> Result<DraftDiff, Refusal> {
    let source = &rehearsal.source;
    if trunk.known_at != source.known_at
        || source.known_at.0.checked_add(1) != Some(draft.known_at.0)
        || rehearsal.batch.recorded_at != draft.known_at
        || rehearsal.batch.already_recorded
        || rehearsal.batch.entries.len() != source.plans.len()
        || rehearsal.seq_map.source_book != source.body.book_id
        || rehearsal.seq_map.source_prefix != source.known_at
        || !rehearsal.seq_map.is_monotone()
        || rehearsal
            .seq_map
            .pairs
            .iter()
            .any(|pair| pair.source_seq != pair.scratch_seq)
        || trunk.activity
        || draft.activity
        || trunk.periods.len() != 1
        || draft.periods.len() != 1
        || trunk.periods[0] != period
        || draft.periods[0] != period
        || trunk.effective_through != draft.effective_through
    {
        return Err(invalid(
            "draft rehearsal or trial balances do not share the certified source and one atomic publication",
        ));
    }
    let report = DraftDiff {
        name: source.body.name.clone(),
        draft: source.body.vid(),
        owner: source.body.owner,
        source_known_at: source.known_at,
        source_digest: source.digest().map_err(encoded_error)?,
        period: period.into(),
        plans: source.plans.len(),
        seq_map_digest: rehearsal.seq_map.digest().map_err(encoded_error)?,
        rehearsal_known_at: draft.known_at,
        batch_outcome: rehearsal.batch.outcome,
        entries: rehearsal.batch.entries.clone(),
        rows: difference(trunk, draft)?,
    };
    report.canonical_bytes()?;
    Ok(report)
}

impl Book {
    /// Rehearse the complete currently open draft as one atomic batch and
    /// compare one period's stock balances. This publishes nothing on trunk.
    pub fn draft_diff(
        &mut self,
        principal: VId,
        capability: &Capability,
        name: &str,
        period: &str,
    ) -> Outcome<DraftDiff> {
        if let Err(refusal) = authorize(self, principal, capability, None, false)? {
            return Ok(Err(refusal));
        }
        if let Err(refusal) = check_period(period) {
            return Ok(Err(refusal));
        }
        let known_at = self.head()?;
        let (scratch, rehearsal) =
            match self.rehearse_draft_at(principal, capability, name, known_at)? {
                Ok(rehearsal) => rehearsal,
                Err(refusal) => return Ok(Err(refusal)),
            };
        let periods = vec![period.to_string()];
        let trunk = self.trial_balance_at(&periods, Some(known_at))?;
        let draft = scratch.trial_balance_at(&periods, None)?;
        Ok(assemble(&rehearsal, &trunk, &draft, period))
    }

    /// Certify the complete current source and atomic rehearsal. A certificate
    /// is historical evidence, not an approval, promotion or freshness claim.
    pub fn certify_draft_diff(
        &mut self,
        principal: VId,
        capability: &Capability,
        name: &str,
        period: &str,
    ) -> Outcome<CertifiedDraftDiff> {
        if let Err(refusal) = authorize(self, principal, capability, None, true)? {
            return Ok(Err(refusal));
        }
        if let Err(refusal) = check_period(period) {
            return Ok(Err(refusal));
        }
        let known_at = self.head()?;
        let (scratch, rehearsal) =
            match self.rehearse_draft_at(principal, capability, name, known_at)? {
                Ok(rehearsal) => rehearsal,
                Err(refusal) => return Ok(Err(refusal)),
            };
        let periods = vec![period.to_string()];
        let certified = match self.certify_report(
            ReportSelection::TrialBalance(TrialBalanceSelection::Periods(periods.clone())),
            Some(known_at),
        )? {
            Ok(certified) => certified,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let ReportOutput::TrialBalance(trunk) = certified.report else {
            return Ok(Err(invalid("draft source did not certify a trial balance")));
        };
        let draft = scratch.trial_balance_at(&periods, None)?;
        let report = match assemble(&rehearsal, &trunk, &draft, period) {
            Ok(report) => report,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let seal = || -> Result<DraftDiffCertificate, Refusal> {
            let mut certificate = DraftDiffCertificate {
                trunk: certified.certificate,
                source: rehearsal.source,
                seq_map_digest: report.seq_map_digest,
                rehearsal_known_at: report.rehearsal_known_at,
                producer: principal,
                capability_commitment: capability.commitment().map_err(encoded_error)?,
                output: report.canonical_bytes()?,
                digest: [0; 32],
            };
            certificate.digest = domain_digest(DIGEST_DOMAIN, &[&certificate.body()?]);
            certificate.validate()?;
            certificate.canonical_bytes()?;
            Ok(certificate)
        };
        Ok(seal().map(|certificate| CertifiedDraftDiff {
            report,
            certificate,
        }))
    }

    /// Replay at the certificate's original source prefix. Later planning,
    /// promotion, discard, or trunk entries do not replace that source.
    pub fn replay_draft_diff(
        &mut self,
        principal: VId,
        capability: &Capability,
        certificate: &DraftDiffCertificate,
    ) -> Outcome<DraftDiff> {
        if let Err(refusal) = authorize(
            self,
            principal,
            capability,
            Some(certificate.known_at()),
            false,
        )? {
            return Ok(Err(refusal));
        }
        if let Err(refusal) = certificate.validate() {
            return Ok(Err(refusal));
        }
        if certificate.trunk.book_id != self.context().book_id {
            return Ok(Err(invalid("draft diff belongs to another book")));
        }
        let (scratch, rehearsal) = match self.rehearse_draft_at(
            principal,
            capability,
            certificate.name(),
            certificate.known_at(),
        )? {
            Ok(rehearsal) => rehearsal,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if rehearsal.source != certificate.source {
            return Ok(Err(invalid(
                "the complete historical draft source differs from the certified witness",
            )));
        }
        let trunk = match self.replay_report(&certificate.trunk)? {
            Ok(ReportOutput::TrialBalance(trunk)) => trunk,
            Ok(_) => return Ok(Err(invalid("draft source replay is not a trial balance"))),
            Err(refusal) => return Ok(Err(refusal)),
        };
        let draft = scratch.trial_balance_at(&[certificate.period().to_string()], None)?;
        let report = match assemble(&rehearsal, &trunk, &draft, certificate.period()) {
            Ok(report) => report,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let output = match report.canonical_bytes() {
            Ok(output) => output,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if report.seq_map_digest != certificate.seq_map_digest
            || report.rehearsal_known_at != certificate.rehearsal_known_at
            || output != certificate.output
        {
            return Ok(Err(invalid(
                "the atomic draft rehearsal does not reproduce the certified map, head and complete output",
            )));
        }
        Ok(Ok(report))
    }

    /// Reperform the complete historical review before retaining its original
    /// bytes. The publication is storage only and cannot promote the draft.
    pub fn retain_draft_diff(
        &mut self,
        principal: VId,
        capability: &Capability,
        certificate: &DraftDiffCertificate,
    ) -> Outcome<RetainedCertificate> {
        if let Err(refusal) = authorize(
            self,
            principal,
            capability,
            Some(certificate.known_at()),
            true,
        )? {
            return Ok(Err(refusal));
        }
        let verified_at = self.head()?;
        if let Err(refusal) = self.replay_draft_diff(principal, capability, certificate)? {
            return Ok(Err(refusal));
        }
        self.retain_replayed_draft_diff(principal, capability, certificate, verified_at)
    }
}

#[cfg(test)]
mod tests;
