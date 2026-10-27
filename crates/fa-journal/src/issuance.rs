//! Statement issuance (plan §12.5, §7.4, Appendix A `StatementIssuance`,
//! Appendix B `IssueStatements`; bead fa-wrrw).
//!
//! A `StatementIssuance` is the journaled fact that a certified statement
//! package left the entity: one `IssuanceControl` record (class 28, control
//! kind 15), a `LifecycleTransition` `0 → Issued` on the issuance's
//! `StatementIssuance` vertex, carrying the issuance in extension 15
//! `fa:statement-issuance:v1`:
//!
//! - the period it reports, the statement definition (digest, name and
//!   version) and the retained statement certificate it issued, with that
//!   certificate's known-at coordinate (`certified_at`);
//! - the audience it went to (`issued_to`) and an optional transmittal
//!   document, which is also the record's proof ref;
//! - its ordinal among the period's issuances. The vertex lives at
//!   [`fa_model::statement_issuance_vid`]`(book, period, ordinal)`, numbered
//!   from 1 in commit order, so the period's first issuance, which `AS
//!   ORIGINALLY REPORTED` reads (§7.4), is one point read.
//!
//! The certificate must be retained in this book (the kernel witnesses its
//! `Certificate` vertex); that it is a trunk statement certificate reporting
//! the period at `certified_at` is judged by the facade, which decodes it.
//!
//! **Authority.** An issuance is a trunk record under `close` with one Human
//! approver who is not the preparer (`sod_policy.toml` `statement-issuance`),
//! the same as the `Lock` whose originally-reported pin it supersedes; an
//! Agent prepares none (plan §14.4). Approvals bind the proposal of an
//! [`IssuancePlan`], which fixes the ordinal and seals the description once:
//! approving ordinal 1 approves what the period will be read as originally
//! reported, and an issuance of the period that commits first makes the plan
//! stale instead of renumbering it. An issuance is never withdrawn: a
//! restatement is a later issuance of restated statements, and the first
//! stays on record.

use fa_model::limits::{
    MAX_DESCRIPTION_BYTES, MAX_EXTENSION_BYTES, MAX_IDEMPOTENCY_KEY_BYTES, MAX_PERIOD_REF_BYTES,
};
use fa_model::symbols::{label, property, relation};
use fa_model::{
    ApprovalRef, ControlKind, ControlPayload, EntryClass, EntryOrigin, EntryPayload, Erasable,
    Id128, Oid, Reader, TypedRef, Writer, domain_digest, entry_mirrors, entry_vid, period_vid,
    report_certificate_vid, statement_issuance_vid,
};
use fa_policy::{Capability, Intent, Party};
use fa_registry::evidence_policy::EvidencePolicy;
use fa_time::DateDay;
use fgdb::{Database, VertexRow, WriteBatch, WriteTxn, WriteTxnError};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::evidence::{document_vid, drift, hex, verify_row};
use crate::genesis::BookContext;
use crate::policy::{self, capability_witness, refusal as denial, steward};
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{bytes, edge_id, scalar_bytes, scalar_text};

/// Canonical bytes of an issuance (extension 15): `u16 version ‖ book_id[16]
/// ‖ str period ‖ u32 ordinal ‖ [32] definition_digest ‖ str definition_name
/// ‖ u32 definition_version ‖ [32] certificate ‖ u64 certified_at ‖ u8
/// issued_to ‖ opt oid document`.
pub const ISSUANCE_VERSION: u16 = 1;
/// A statement definition name's bound, in bytes (fa-statements).
pub const MAX_DEFINITION_NAME_BYTES: usize = 64;
/// The plan's leading domain tag; the format is versioned after it.
pub const PLAN_DOMAIN: &[u8; 16] = b"fa:issuance-plan";
const PLAN_VERSION: u16 = 1;
const BODY_DOMAIN: &[u8] = b"fa:statement-issuance:v1";
const RECORD_KEY_DOMAIN: &[u8] = b"fa:issuance-record-key:v1";
/// The issuance vertex's lifecycle: issued (the only state).
const ISSUED: u8 = 1;

/// Who a statement package went to (plan §12.5 `issued_to`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IssuedTo {
    Board,
    Auditor,
    Lender,
    Regulator,
    Sec,
    TaxAuthority,
    Other,
}

impl IssuedTo {
    pub const ALL: [Self; 7] = [
        Self::Board,
        Self::Auditor,
        Self::Lender,
        Self::Regulator,
        Self::Sec,
        Self::TaxAuthority,
        Self::Other,
    ];

    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Board => 1,
            Self::Auditor => 2,
            Self::Lender => 3,
            Self::Regulator => 4,
            Self::Sec => 5,
            Self::TaxAuthority => 6,
            Self::Other => 7,
        }
    }

    #[must_use]
    pub fn from_tag(tag: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.tag() == tag)
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Board => "board",
            Self::Auditor => "auditor",
            Self::Lender => "lender",
            Self::Regulator => "regulator",
            Self::Sec => "sec",
            Self::TaxAuthority => "tax-authority",
            Self::Other => "other",
        }
    }

    /// The audience a `--issued-to` word names.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.name() == name)
    }
}

/// One statement package leaving the entity (Appendix A `StatementIssuance`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatementIssuance {
    pub book_id: Id128,
    /// The period the issued statements report.
    pub period: String,
    /// Its place among the period's issuances, from 1, in commit order.
    pub ordinal: u32,
    pub definition_digest: [u8; 32],
    pub definition_name: String,
    pub definition_version: u32,
    /// The public digest of the retained statement certificate issued.
    pub certificate: [u8; 32],
    /// That certificate's known-at coordinate: what `AS ORIGINALLY REPORTED`
    /// reads when this is the period's first issuance.
    pub certified_at: CommitSeq,
    pub issued_to: IssuedTo,
    /// The transmittal document (a cover letter, a filing receipt), if any.
    pub document: Option<Oid>,
}

impl StatementIssuance {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, KernelError> {
        let mut w = Writer::with_capacity(160 + self.period.len() + self.definition_name.len());
        w.u16(ISSUANCE_VERSION)
            .fixed(&self.book_id.0)
            .str(&self.period)
            .u32(self.ordinal)
            .fixed(&self.definition_digest)
            .str(&self.definition_name)
            .u32(self.definition_version)
            .fixed(&self.certificate)
            .u64(self.certified_at.0)
            .u8(self.issued_to.tag())
            .opt(self.document.as_ref(), |w, oid| {
                w.fixed(&oid.0);
            });
        Ok(w.finish()?)
    }

    /// Decode and validate an issuance; refuses an unknown version, a field
    /// out of its domain, and trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, KernelError> {
        let mut r = Reader::new(bytes);
        if r.u16("issuance.version").map_err(decode)? != ISSUANCE_VERSION {
            return Err(KernelError::Corrupt(
                "unsupported statement issuance version".into(),
            ));
        }
        let book_id = Id128(r.fixed("issuance.book_id").map_err(decode)?);
        let period = r
            .str(MAX_PERIOD_REF_BYTES, "issuance.period")
            .map_err(decode)?
            .to_string();
        let ordinal = r.u32("issuance.ordinal").map_err(decode)?;
        let definition_digest = r.fixed("issuance.definition_digest").map_err(decode)?;
        let definition_name = r
            .str(MAX_DEFINITION_NAME_BYTES, "issuance.definition_name")
            .map_err(decode)?
            .to_string();
        let definition_version = r.u32("issuance.definition_version").map_err(decode)?;
        let certificate = r.fixed("issuance.certificate").map_err(decode)?;
        let certified_at = CommitSeq(r.u64("issuance.certified_at").map_err(decode)?);
        let tag = r.u8("issuance.issued_to").map_err(decode)?;
        let issued_to = IssuedTo::from_tag(tag).ok_or_else(|| {
            KernelError::Corrupt(format!("statement issuance audience tag {tag}"))
        })?;
        let document = r
            .opt("issuance.document", |r| {
                Ok(Oid(r.fixed("issuance.document")?))
            })
            .map_err(decode)?;
        r.finish().map_err(decode)?;
        let issuance = Self {
            book_id,
            period,
            ordinal,
            definition_digest,
            definition_name,
            definition_version,
            certificate,
            certified_at,
            issued_to,
            document,
        };
        issuance
            .check()
            .map_err(|why| KernelError::Corrupt(format!("statement issuance: {why}")))?;
        Ok(issuance)
    }

    /// The field domains an issuance must satisfy, as one sentence.
    pub fn check(&self) -> Result<(), String> {
        if self.period.is_empty() || self.period.len() > MAX_PERIOD_REF_BYTES {
            return Err(format!(
                "a period code is 1..={MAX_PERIOD_REF_BYTES} bytes; `{}` is not",
                self.period
            ));
        }
        if self.ordinal == 0 {
            return Err("issuance ordinals start at 1".into());
        }
        if self.definition_name.is_empty() || self.definition_name.len() > MAX_DEFINITION_NAME_BYTES
        {
            return Err(format!(
                "a statement definition name is 1..={MAX_DEFINITION_NAME_BYTES} bytes"
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<[u8; 32], KernelError> {
        Ok(domain_digest(BODY_DOMAIN, &[&self.canonical_bytes()?]))
    }

    #[must_use]
    pub fn vid(&self) -> VId {
        statement_issuance_vid(self.book_id, &self.period, self.ordinal)
    }
}

fn decode(e: fa_model::DecodeError) -> KernelError {
    KernelError::Model(e.into())
}

/// A planned issuance: the inputs [`issue_statements`] rebuilds its proposal
/// from, with the ordinal fixed and the description sealed once. Approvers
/// bind [`IssuancePlan::proposal_digest`]; the committing principal passes
/// the same plan back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuancePlan {
    pub issuance: StatementIssuance,
    pub principal_ref: VId,
    pub effective_date: DateDay,
    pub idempotency_key: Vec<u8>,
    pub description: Erasable<String>,
}

impl IssuancePlan {
    /// The `IssuanceControl` proposal this plan commits.
    pub fn proposal(&self, book: &BookContext) -> Result<EntryPayload, KernelError> {
        let issuance = &self.issuance;
        Ok(EntryPayload {
            schema_minor: fa_model::entry::EXTENSIONS_MINOR,
            book_id: book.book_id,
            branch_id: Id128::TRUNK,
            class: EntryClass::ISSUANCE_CONTROL,
            effective_date: self.effective_date,
            document_date: None,
            description: self.description.clone(),
            effective_period: None,
            legs: Vec::new(),
            control: Some(ControlPayload::LifecycleTransition {
                object_ref: issuance.vid(),
                from: 0,
                to: ISSUED,
                proof_refs: issuance
                    .document
                    .iter()
                    .map(|oid| TypedRef::Object(*oid))
                    .collect(),
                reason_code: 0,
            }),
            unit_totals: Vec::new(),
            base_totals: None,
            idempotency_key: record_key(&self.idempotency_key),
            origin: EntryOrigin::Control {
                control_kind: ControlKind::STATEMENT_ISSUANCE,
                spec_body_digest: issuance.digest()?,
            },
            principal_ref: self.principal_ref,
            session_ref: None,
            evidence: Vec::new(),
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            extensions: vec![(
                fa_model::entry::STATEMENT_ISSUANCE_EXTENSION,
                issuance.canonical_bytes()?,
            )],
            tags: Vec::new(),
        })
    }

    /// The digest an approval of this plan binds.
    pub fn proposal_digest(&self, book: &BookContext) -> Result<[u8; 32], KernelError> {
        Ok(self.proposal(book)?.proposal_digest()?)
    }

    /// `"fa:issuance-plan" ‖ u16 version ‖ bytes issuance ‖ u128 principal ‖
    /// i32 effective_date ‖ bytes key ‖ erasable description`.
    pub fn encode(&self) -> Result<Vec<u8>, KernelError> {
        let issuance = self.issuance.canonical_bytes()?;
        let mut w = Writer::new();
        w.fixed(PLAN_DOMAIN)
            .u16(PLAN_VERSION)
            .bytes(&issuance)
            .u128(self.principal_ref.0)
            .i32(self.effective_date.0)
            .bytes(&self.idempotency_key);
        self.description.encode(&mut w);
        Ok(w.finish()?)
    }

    /// Decode a plan; refuses another format, an unknown version, an
    /// issuance out of its domain, and trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, KernelError> {
        let mut r = Reader::new(bytes);
        let domain: [u8; 16] = r.fixed("issuance_plan.domain").map_err(decode)?;
        if domain != *PLAN_DOMAIN {
            return Err(decode(r.invalid("issuance_plan.domain")));
        }
        if r.u16("issuance_plan.version").map_err(decode)? != PLAN_VERSION {
            return Err(decode(r.invalid("issuance_plan.version")));
        }
        let issuance = StatementIssuance::decode(
            r.bytes(MAX_EXTENSION_BYTES, "issuance_plan.issuance")
                .map_err(decode)?,
        )?;
        let plan = Self {
            issuance,
            principal_ref: VId(r.u128("issuance_plan.principal").map_err(decode)?),
            effective_date: DateDay(r.i32("issuance_plan.date").map_err(decode)?),
            idempotency_key: r
                .bytes(MAX_IDEMPOTENCY_KEY_BYTES, "issuance_plan.key")
                .map_err(decode)?
                .to_vec(),
            description: Erasable::decode(&mut r, MAX_DESCRIPTION_BYTES).map_err(decode)?,
        };
        r.finish().map_err(decode)?;
        Ok(plan)
    }
}

/// One journaled issuance as its record and vertex state it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuanceRecord {
    pub vid: VId,
    pub issuance: StatementIssuance,
    pub control_entry: VId,
    pub recorded_at: CommitSeq,
    pub principal: VId,
    pub approvals: usize,
}

/// A recorded issuance, and whether this commit found it already journaled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatementsIssued {
    pub record: IssuanceRecord,
    pub already_recorded: bool,
}

fn usage(message: impl Into<String>, fix: &str) -> Refusal {
    Refusal::new(
        code::STRUCTURE,
        exit::USAGE,
        message.into(),
        "plan §12.5, Appendix A StatementIssuance (bead fa-wrrw)",
        fix,
    )
}

/// The certificate cannot be issued for the period: not retained in this
/// book, not a trunk statement certificate, or not one reporting the period.
#[must_use]
pub fn not_issuable(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::NOT_ISSUABLE,
        exit::REFUSAL,
        message.into(),
        "plan §12.5 (a StatementIssuance names the retained statement certificate it issued, for the period it reports)",
        "certify the statement first with `fa statement balance-sheet|income-statement --for <period> --certify --json`, then plan the issuance of its C:<oid> for that period with `fa statement issue --certificate C:<oid> --for <period> --issued-to <audience> --dry-run`",
    )
}

fn fcw(detail: &str) -> Refusal {
    Refusal::new(
        code::CONFLICT,
        exit::CONFLICT,
        format!("a concurrent commit invalidated a witness this issuance read: {detail}"),
        "FG-LAW-FCW-01 (first committer wins)",
        "plan the issuance again with --dry-run; if another issuance of the period took this ordinal, the new plan names the next one and needs its own approval",
    )
}

fn stale_ordinal(issuance: &StatementIssuance) -> Refusal {
    Refusal::new(
        code::CONFLICT,
        exit::CONFLICT,
        format!(
            "the plan issues ordinal {} of period `{}`, which is not the period's next issuance at the head",
            issuance.ordinal, issuance.period
        ),
        "plan §12.5 (a period's issuances are numbered in commit order; the approved plan names its ordinal)",
        "plan the issuance again with `fa statement issue --certificate C:<oid> --for <period> --issued-to <audience> --dry-run` and have its new proposal_digest approved",
    )
}

/// Authority before any read (doctrine 8): the `IssuanceControl` `Issue`
/// row's preparer op, held by the acting principal for this book and
/// current at the head. An issuance is a trunk record, so an Agent is
/// refused.
pub fn admit<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    capability: &Capability,
) -> Outcome<()> {
    let op = steward()?
        .transition_op("IssuanceControl", "Issue")
        .ok_or_else(|| {
            KernelError::Corrupt(
                "sod_policy.toml registers no IssuanceControl Issue rule; the record is refused, never unconstrained".into(),
            )
        })?;
    if let Err(d) = fa_policy::admit(
        capability,
        &Intent {
            principal: capability.holder(),
            trunk: true,
            op,
            book: book.book_id,
            legs: &[],
        },
    ) {
        return Ok(Err(denial(&d)));
    }
    if let Err(d) = fa_policy::current(capability, db.frontier()?) {
        return Ok(Err(denial(&d)));
    }
    Ok(Ok(()))
}

/// A record's idempotency key: `H(domain ‖ caller key)`, within the key
/// bound whatever the caller's key.
fn record_key(key: &[u8]) -> Vec<u8> {
    domain_digest(RECORD_KEY_DOMAIN, &[key]).to_vec()
}

fn checked(book: &BookContext, issuance: &StatementIssuance) -> Result<(), Refusal> {
    if issuance.book_id != book.book_id {
        return Err(usage(
            "the statement issuance names another book",
            "issue a certificate retained in this book",
        ));
    }
    issuance.check().map_err(|why| {
        usage(
            why,
            "fa statement issue --certificate C:<oid> --for <period> --issued-to <audience> --dry-run",
        )
    })
}

/// Plan `issuance` at the period's next ordinal under `capability`, with the
/// description sealed once: admitted first (doctrine 8), then the period's
/// issuances are read. Nothing is written; the commit rechecks everything.
pub fn plan_issuance<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    capability: &Capability,
    mut issuance: StatementIssuance,
    effective_date: DateDay,
    idempotency_key: &[u8],
    description: Erasable<String>,
) -> Outcome<IssuancePlan> {
    if let Err(r) = admit(db, book, capability)? {
        return Ok(Err(r));
    }
    if idempotency_key.len() > MAX_IDEMPOTENCY_KEY_BYTES {
        return Ok(Err(usage(
            format!("an idempotency key is at most {MAX_IDEMPOTENCY_KEY_BYTES} bytes"),
            "fa statement issue --certificate C:<oid> --for <period> --issued-to <audience> --key <K> --dry-run",
        )));
    }
    if db
        .vertex(period_vid(&book.calendar.id, &issuance.period))?
        .is_none()
    {
        return Ok(Err(crate::period::unknown_period(book, &issuance.period)));
    }
    issuance.ordinal = next_ordinal(db, book, &issuance.period)?;
    if let Err(r) = checked(book, &issuance) {
        return Ok(Err(r));
    }
    let plan = IssuancePlan {
        issuance,
        principal_ref: capability.holder(),
        effective_date,
        idempotency_key: idempotency_key.to_vec(),
        description,
    };
    if plan.proposal(book)?.validate().is_err() {
        return Ok(Err(usage(
            "the planned issuance is not a valid IssuanceControl entry",
            "fa statement issue --certificate C:<oid> --for <period> --issued-to <audience> --dry-run",
        )));
    }
    Ok(Ok(plan))
}

/// The ordinal the period's next issuance takes at the head.
pub fn next_ordinal<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    period: &str,
) -> Result<u32, KernelError> {
    let mut ordinal = 1_u32;
    while db
        .vertex(statement_issuance_vid(book.book_id, period, ordinal))?
        .is_some()
    {
        ordinal = next(ordinal, period)?;
    }
    Ok(ordinal)
}

fn next(ordinal: u32, period: &str) -> Result<u32, KernelError> {
    ordinal
        .checked_add(1)
        .ok_or_else(|| KernelError::Corrupt(format!("period `{period}` issuance ordinals")))
}

/// Commit `plan` under `capability` and the cited `approvals`: one commit of
/// the `IssuanceControl` record, the `StatementIssuance` vertex with the
/// immutable issuance and its record's `IN_CASE` edge. The plan's principal
/// must be the capability's holder and its ordinal the period's next; the
/// period and the certificate must be this book's, the transmittal document
/// a verified document of this book, and the approvals must satisfy the
/// `statement-issuance` SoD rule over exactly the plan's proposal. The same
/// plan committed again returns the recorded issuance.
pub async fn issue_statements<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    plan: IssuancePlan,
    approvals: Vec<ApprovalRef>,
) -> Outcome<StatementsIssued> {
    if let Err(r) = admit(db, book, capability)? {
        return Ok(Err(r));
    }
    let principal = capability.holder();
    if plan.principal_ref != principal {
        return Ok(Err(usage(
            format!(
                "the plan was prepared by principal {:032x}, not by the committing principal {:032x}",
                plan.principal_ref.0, principal.0
            ),
            "plan the issuance as the principal who commits it: fa statement issue ... --dry-run",
        )));
    }
    let issuance = plan.issuance.clone();
    if let Err(r) = checked(book, &issuance) {
        return Ok(Err(r));
    }
    let proposal = plan.proposal(book)?;
    if proposal.validate().is_err() {
        return Ok(Err(usage(
            "the planned issuance is not a valid IssuanceControl entry",
            "fa statement issue --certificate C:<oid> --for <period> --issued-to <audience> --dry-run",
        )));
    }
    let proposal_digest = proposal.proposal_digest()?;
    let evid = entry_vid(
        book.book_id,
        &principal.0.to_le_bytes(),
        &proposal.idempotency_key,
    );
    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    // The capability is not revoked (plan §14.2): the first read.
    if let Err(r) = capability_witness(&txn, db, book, capability)? {
        txn.abort();
        return Ok(Err(r));
    }
    let epoch = policy::epoch_witness(&txn, db)?;
    if let Some(row) = txn.vertex(db, evid)? {
        txn.abort();
        return Ok(
            recorded_or_conflict(db, book, &row, &proposal)?.map(|record| StatementsIssued {
                record,
                already_recorded: true,
            }),
        );
    }
    if txn
        .vertex(db, period_vid(&book.calendar.id, &issuance.period))?
        .is_none()
    {
        txn.abort();
        return Ok(Err(crate::period::unknown_period(book, &issuance.period)));
    }
    // Every taken ordinal and the first free one are point witnesses, so an
    // issuance of the period that commits first invalidates this one.
    let mut ordinal = 1_u32;
    while txn
        .vertex(
            db,
            statement_issuance_vid(book.book_id, &issuance.period, ordinal),
        )?
        .is_some()
    {
        ordinal = next(ordinal, &issuance.period)?;
    }
    if ordinal != issuance.ordinal {
        txn.abort();
        return Ok(Err(stale_ordinal(&issuance)));
    }
    let certificate = report_certificate_vid(book.book_id, &issuance.certificate);
    match txn.vertex(db, certificate)? {
        Some(row) if row.labels.as_slice() == [label::CERTIFICATE] => {}
        _ => {
            txn.abort();
            return Ok(Err(not_issuable(format!(
                "certificate {} is not retained in this book",
                hex(&issuance.certificate)
            ))));
        }
    }
    if let Some(document) = &issuance.document
        && let Err(r) = witness_document(&txn, db, document)?
    {
        txn.abort();
        return Ok(Err(r));
    }
    // Segregation of duties (plan §14.3): every cited approval is a
    // witnessed Approval of exactly this proposal under the current epoch,
    // judged by the `statement-issuance` rule.
    let key = fa_policy::sod::control_key("IssuanceControl", None, "Issue");
    let preparer = Party {
        principal,
        profile: capability.profile(),
    };
    if let Err(r) = policy::authorize_approvals(
        &txn,
        db,
        book,
        &approvals,
        &proposal_digest,
        epoch,
        &key,
        0,
        preparer,
    )? {
        txn.abort();
        return Ok(Err(r));
    }
    let cited = approvals.len();
    let entry = proposal.clone().seal(approvals, None)?;
    let vid = issuance.vid();
    let mut props = vec![
        (
            property::FA_PAYLOAD,
            scalar_bytes("issuance._fa_payload", issuance.canonical_bytes()?)?,
        ),
        (
            property::FA_DIGEST,
            scalar_bytes("issuance._fa_digest", issuance.digest()?.to_vec())?,
        ),
        (
            property::BOOK_ID,
            scalar_bytes("book_id", book.book_id.0.to_vec())?,
        ),
        (
            property::CODE,
            scalar_text("issuance.code", &issuance.period)?,
        ),
    ];
    props.sort_by_key(|(k, _)| k.0);
    let mut in_case = WriteBatch::new(relation::IN_CASE);
    in_case.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    in_case.create_vertex(vid, vec![label::STATEMENT_ISSUANCE], props);
    in_case.add_edge(edge_id(relation::IN_CASE, evid, vid), evid, vid, vec![]);
    txn.write(db, in_case)?;
    match txn.commit(db, &ctx.commit()).await {
        Ok(recorded_at) => Ok(Ok(StatementsIssued {
            record: IssuanceRecord {
                vid,
                issuance,
                control_entry: evid,
                recorded_at,
                principal,
                approvals: cited,
            },
            already_recorded: false,
        })),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(fcw(&detail)))
        }
        Err(WriteTxnError::Write(
            fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
        )) => match db.vertex(evid)? {
            Some(row) => Ok(
                recorded_or_conflict(db, book, &row, &proposal)?.map(|record| StatementsIssued {
                    record,
                    already_recorded: true,
                }),
            ),
            // Another issuance of the period took this ordinal first.
            None => Ok(Err(stale_ordinal(&issuance))),
        },
        Err(e) => Err(e.into()),
    }
}

/// A document this book holds, verified.
fn witness_document<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    oid: &Oid,
) -> Outcome<()> {
    let policy = EvidencePolicy::embedded().map_err(|e| KernelError::Corrupt(e.to_string()))?;
    let Some(row) = txn.vertex(db, document_vid(oid))? else {
        return Ok(Err(Refusal::new(
            code::EVIDENCE_UNKNOWN,
            exit::REFUSAL,
            format!("document {} is not in this book", hex(&oid.0)),
            "plan §12.5 (an issuance's transmittal document is a document the book holds)",
            "record it first with `fa document add <file> --kind <Kind> --json` and name the oid it prints",
        )));
    };
    match verify_row(&row, &policy) {
        Ok(_) => Ok(Ok(())),
        Err(why) => Ok(Err(drift(oid, &why))),
    }
}

/// The issuance already journaled under this plan's identity: the same
/// proposal gets it; another under the key is a conflict.
fn recorded_or_conflict<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    row: &VertexRow,
    proposal: &EntryPayload,
) -> Outcome<IssuanceRecord> {
    let (stored, _) = crate::post::entry_of(row)?;
    let recorded = match issuance_of(&stored)? {
        Some(recorded) if stored.proposal_digest == proposal.proposal_digest()? => recorded,
        _ => {
            return Ok(Err(Refusal::new(
                code::IDEMPOTENCY_CONFLICT,
                exit::CONFLICT,
                format!(
                    "this issuance's identity holds different content; the recorded entry is {:032x}",
                    row.vid.0
                ),
                "plan §4.9 (identity is derived from the key; content is bound by proposal_digest)",
                "commit the identical plan to get its recorded outcome, or plan the issuance under a new --key",
            )));
        }
    };
    Ok(Ok(record_of(db, book, recorded.vid())?.ok_or_else(
        || {
            KernelError::Corrupt(format!(
                "issuance record {:032x} has no StatementIssuance vertex",
                row.vid.0
            ))
        },
    )?))
}

/// An `IssuanceControl` record's issuance; `None` for any other entry.
fn issuance_of(entry: &fa_model::Entry) -> Result<Option<StatementIssuance>, KernelError> {
    if entry.proposal.class != EntryClass::ISSUANCE_CONTROL {
        return Ok(None);
    }
    let Some((_, ext)) = entry
        .proposal
        .extensions
        .iter()
        .find(|(tag, _)| *tag == fa_model::entry::STATEMENT_ISSUANCE_EXTENSION)
    else {
        return Ok(None);
    };
    StatementIssuance::decode(ext).map(Some)
}

/// The issuance at `vid` as its vertex and its one record state it, each
/// cross-checked against the other.
fn record_of<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    vid: VId,
) -> Result<Option<IssuanceRecord>, KernelError> {
    let Some(row) = db.vertex(vid)? else {
        return Ok(None);
    };
    if row.labels.as_slice() != [label::STATEMENT_ISSUANCE] {
        return Err(KernelError::Corrupt(format!(
            "issuance identity {:032x} holds a vertex that is not a StatementIssuance",
            vid.0
        )));
    }
    let issuance =
        StatementIssuance::decode(&bytes(&row, property::FA_PAYLOAD, "issuance._fa_payload")?)?;
    if issuance.vid() != vid || issuance.book_id != book.book_id {
        return Err(KernelError::Corrupt(format!(
            "statement issuance {:032x} carries another issuance's body",
            vid.0
        )));
    }
    let mut records = Vec::new();
    for evid in db.in_neighbours(vid, relation::IN_CASE)? {
        let Some(src) = db.vertex(evid)? else {
            continue;
        };
        if !src.labels.contains(&label::ENTRY) {
            continue;
        }
        let (entry, recorded_at) = crate::post::entry_of(&src)?;
        if issuance_of(&entry)?.as_ref() == Some(&issuance) {
            records.push((evid, entry, recorded_at));
        }
    }
    let [(control_entry, entry, recorded_at)] = <[_; 1]>::try_from(records).map_err(|r| {
        KernelError::Corrupt(format!(
            "statement issuance {:032x} has {} records, not one",
            vid.0,
            r.len()
        ))
    })?;
    Ok(Some(IssuanceRecord {
        vid,
        issuance,
        control_entry,
        recorded_at,
        principal: entry.proposal.principal_ref,
        approvals: entry.approvals.len(),
    }))
}

/// Every issuance of `period`, by ordinal.
pub fn issuances<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    period: &str,
) -> Result<Vec<IssuanceRecord>, KernelError> {
    let mut out = Vec::new();
    let mut ordinal = 1_u32;
    while let Some(record) = record_of(
        db,
        book,
        statement_issuance_vid(book.book_id, period, ordinal),
    )? {
        out.push(record);
        ordinal = next(ordinal, period)?;
    }
    Ok(out)
}

/// The period's first issuance to `audience`: what `AS ISSUED TO <audience>`
/// reads (plan §7.4). A period never issued to it is a refusal, never its
/// first issuance to someone else.
pub fn first_issued_to<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    period: &str,
    audience: IssuedTo,
) -> Outcome<IssuanceRecord> {
    if db.vertex(period_vid(&book.calendar.id, period))?.is_none() {
        return Ok(Err(crate::period::unknown_period(book, period)));
    }
    Ok(
        match issuances(db, book, period)?
            .into_iter()
            .find(|r| r.issuance.issued_to == audience)
        {
            Some(record) => Ok(record),
            None => Err(Refusal::new(
                code::NOT_ISSUED_TO,
                exit::REFUSAL,
                format!(
                    "period `{period}` has no statement issuance to {}",
                    audience.name()
                ),
                "plan §7.4 (AS ISSUED TO <audience> selects a specific issuance)",
                format!(
                    "list the period's issuances with `fa statement issuances --for {period} --json`, or read it as originally reported with --as-originally-reported"
                ),
            )),
        },
    )
}

/// `AS REPORTED IN` names a certificate that is not a retained trunk
/// statement certificate reporting the period.
#[must_use]
pub fn not_reported_in(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::NOT_REPORTED_IN,
        exit::REFUSAL,
        message.into(),
        "plan §7.4 (AS REPORTED IN <statement certificate> pins exactly the closure a published statement used)",
        "name the C:<oid> of a retained statement certificate that reports the period (`fa statement issuances --for <period> --json` lists the issued ones), or read it as originally reported with --as-originally-reported",
    )
}

/// The period's first issuance: what `AS ORIGINALLY REPORTED` reads.
pub fn first_issuance<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    period: &str,
) -> Result<Option<IssuanceRecord>, KernelError> {
    record_of(db, book, statement_issuance_vid(book.book_id, period, 1))
}

/// Every issuance in the book, by period then ordinal.
pub fn list_issuances<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
) -> Result<Vec<IssuanceRecord>, KernelError> {
    let mut out = Vec::new();
    for row in db.vertices()? {
        if row.labels.contains(&label::STATEMENT_ISSUANCE)
            && let Some(record) = record_of(db, book, row.vid)?
        {
            out.push(record);
        }
    }
    out.sort_by(|a, b| {
        (&a.issuance.period, a.issuance.ordinal).cmp(&(&b.issuance.period, b.issuance.ordinal))
    });
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issuance() -> StatementIssuance {
        StatementIssuance {
            book_id: Id128([7; 16]),
            period: "FY2026-P03".into(),
            ordinal: 1,
            definition_digest: [1; 32],
            definition_name: "income-statement".into(),
            definition_version: 1,
            certificate: [2; 32],
            certified_at: CommitSeq(41),
            issued_to: IssuedTo::Auditor,
            document: Some(Oid([3; 32])),
        }
    }

    #[test]
    fn an_issuance_round_trips_and_every_field_moves_its_digest() {
        let base = issuance();
        let bytes = base.canonical_bytes().unwrap();
        assert_eq!(StatementIssuance::decode(&bytes).unwrap(), base);
        let variants = [
            StatementIssuance {
                period: "FY2026-P04".into(),
                ..base.clone()
            },
            StatementIssuance {
                ordinal: 2,
                ..base.clone()
            },
            StatementIssuance {
                certificate: [9; 32],
                ..base.clone()
            },
            StatementIssuance {
                certified_at: CommitSeq(42),
                ..base.clone()
            },
            StatementIssuance {
                issued_to: IssuedTo::Lender,
                ..base.clone()
            },
            StatementIssuance {
                document: None,
                ..base.clone()
            },
            StatementIssuance {
                definition_version: 2,
                ..base.clone()
            },
        ];
        let digest = base.digest().unwrap();
        for v in &variants {
            assert_ne!(v.digest().unwrap(), digest, "{v:?}");
        }
        // Book, period and ordinal are the vertex identity.
        assert_ne!(variants[0].vid(), base.vid());
        assert_ne!(variants[1].vid(), base.vid());
        assert_eq!(variants[2].vid(), base.vid());
    }

    #[test]
    fn an_issuance_out_of_its_domain_or_with_trailing_bytes_is_refused() {
        let mut bytes = issuance().canonical_bytes().unwrap();
        bytes.push(0);
        assert!(StatementIssuance::decode(&bytes).is_err(), "trailing byte");
        let zero = StatementIssuance {
            ordinal: 0,
            ..issuance()
        };
        assert!(zero.check().is_err());
        assert!(StatementIssuance::decode(&zero.canonical_bytes().unwrap()).is_err());
        let mut audience = issuance().canonical_bytes().unwrap();
        // issued_to sits just before the 1 + 32 document bytes.
        let at = audience.len() - 34;
        assert_eq!(audience[at], IssuedTo::Auditor.tag());
        audience[at] = 8;
        assert!(StatementIssuance::decode(&audience).is_err(), "audience 8");
        audience[at] = 0;
        assert!(StatementIssuance::decode(&audience).is_err(), "audience 0");
    }

    #[test]
    fn every_audience_has_one_tag_and_one_name() {
        for a in IssuedTo::ALL {
            assert_eq!(IssuedTo::from_tag(a.tag()), Some(a));
            assert_eq!(IssuedTo::parse(a.name()), Some(a));
        }
        assert_eq!(IssuedTo::parse("Auditor"), None);
        assert_eq!(IssuedTo::from_tag(0), None);
    }
}
