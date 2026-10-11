//! Retained-history certificates for the literal trial-balance fold (§13.6).
//!
//! Every certificate fixes the selector, native read closure, accounting journal
//! prefix, registry versions and exact report bytes. Native reads include the
//! chart, calendar, periods and migration state: an entry accumulator alone does
//! not authenticate those inputs. Replay verifies each native input against the
//! retained historical snapshot before refolding, and also detects a later
//! rewrite or retirement of an entry in that prefix.
//!
//! This is the explicit embedded-owner, `fa-fold-over-prefix` posture. It is a
//! local replay certificate, without a witness signature or a scoped outsider
//! completeness claim. The caller may retain its canonical, content-addressed
//! bytes without appending a write to the book being reported on.

use std::collections::BTreeMap;

use asupersync::fs::Vfs;
use fa_journal::genesis::BookContext;
use fa_journal::refusal::{Refusal, exit};
use fa_journal::rows::bytes;
use fa_model::symbols::{label, property};
use fa_model::{ControlPayload, Entry, EntryClass, EntryOrigin, Id128, Reader, Writer};
use fa_notary::journal::Journal;
use fa_registers::TrialBalance;
use fa_time::DateDay;
use fgdb::{Database, NativeResultCertificate};
use fgdb_crypto::Hasher;
use fgdb_gql::{GqlParameters, GqlQueryPolicy};
use fgdb_types::{CommitSeq, QueryCx, VId};

use crate::{BookError, Outcome};

pub mod code {
    pub const CERTIFICATE_INVALID: &str = "FA-REF-150";
}

pub const CERTIFICATE_FORMAT: &[u8] = b"fa:report-certificate:v1";
pub const REPLAY_SCOPE: &str = "fa-fold-over-prefix";
pub const AUTHORITY: &str = "embedded-owner";
pub const OUTPUT_FORMAT: &str = "fa:trial-balance:v1";
pub const MAX_CERTIFICATE_BYTES: usize = 64 * 1024 * 1024;
const MAX_PERIODS: usize = 65_536;
const MAX_NATIVE_BYTES: usize = 1024 * 1024;

// These are exactly the authoritative vertex families the current register
// fold reads. No Leg/Register mirror is evidence for a trial balance. Every
// property decoded by AccountRow, PeriodRow and migration::run_from_row is
// included, even where a field currently only participates in validation.
const INPUTS: &[(&str, &str)] = &[
    (
        "Account",
        "code,name,account_type,normal_balance,posting,unit_policy,lower_bound,upper_bound,limit_scope,_fa_payload,book_id",
    ),
    ("Book", "_fa_payload,book_id,base_unit,symbols_digest"),
    ("Entry", "_fa_payload,_fa_digest"),
    ("FiscalCalendar", "_fa_payload,calendar_id"),
    ("MigrationRun", "_fa_payload,_fa_digest,state"),
    (
        "Period",
        "code,calendar_id,fiscal_year,ordinal,period_kind,period_start,period_end,state",
    ),
    ("Unit", "_fa_payload,unit_id,code,name,scale,version"),
];

/// A stock trial balance by period cutoff/date, or explicit period activity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrialBalanceSelection {
    Periods(Vec<String>),
    AsOf(DateDay),
    Activity(Vec<String>),
}

impl TrialBalanceSelection {
    fn is_canonical(&self) -> bool {
        match self {
            Self::Periods(periods) | Self::Activity(periods) => {
                !periods.is_empty()
                    && periods.len() <= MAX_PERIODS
                    && periods
                        .iter()
                        .all(|period| !period.is_empty() && period.len() <= 128)
                    && periods.windows(2).all(|pair| pair[0] < pair[1])
            }
            Self::AsOf(_) => true,
        }
    }

    fn normalize(mut self) -> Self {
        if let Self::Periods(periods) | Self::Activity(periods) = &mut self {
            periods.sort();
            periods.dedup();
        }
        self
    }

    fn write(&self, w: &mut Writer) {
        match self {
            Self::Periods(periods) | Self::Activity(periods) => {
                w.u8(if matches!(self, Self::Periods(_)) {
                    0
                } else {
                    2
                })
                .list(periods, |w, p| {
                    w.str(p);
                });
            }
            Self::AsOf(day) => {
                w.u8(1).i32(day.0);
            }
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, fa_model::DecodeError> {
        let tag = r.u8("report selector")?;
        match tag {
            0 | 2 => {
                let count = r.count(MAX_PERIODS, "selected periods")?;
                let mut periods = Vec::new();
                for _ in 0..count {
                    periods.push(r.str(128, "period code")?.to_string());
                }
                if periods.is_empty()
                    || periods.iter().any(String::is_empty)
                    || !periods.windows(2).all(|pair| pair[0] < pair[1])
                {
                    return Err(r.invalid("canonical nonempty period selection"));
                }
                Ok(if tag == 0 {
                    Self::Periods(periods)
                } else {
                    Self::Activity(periods)
                })
            }
            1 => Ok(Self::AsOf(DateDay(r.i32("as-of date")?))),
            _ => Err(r.bad_tag("report selector", tag)),
        }
    }

    fn report<V: Vfs + Clone>(
        &self,
        db: &Database<V>,
        book: &BookContext,
        at: CommitSeq,
    ) -> Result<TrialBalance, BookError> {
        Ok(match self {
            Self::Periods(periods) => fa_registers::trial_balance_at(db, book, periods, Some(at))?,
            Self::AsOf(day) => fa_registers::balance_as_of(db, book, *day, Some(at))?,
            Self::Activity(periods) => fa_registers::period_activity(db, book, periods, Some(at))?,
        })
    }
}

/// A versioned content-addressed certificate. Its digest covers all fields
/// except itself; decoding and replay both verify that commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportCertificate {
    pub book_id: Id128,
    pub branch_id: Id128,
    pub known_at: CommitSeq,
    pub selection: TrialBalanceSelection,
    pub registry_digest: [u8; 32],
    pub journal_root: [u8; 32],
    pub journal_leaves: u64,
    pub inputs: Vec<NativeResultCertificate>,
    pub output: Vec<u8>,
    pub output_digest: [u8; 32],
    pub digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertifiedTrialBalance {
    pub report: TrialBalance,
    pub certificate: ReportCertificate,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CertificateStatus {
    Current {
        checked_at: CommitSeq,
    },
    SupersededBy {
        checked_at: CommitSeq,
        later_entries: Vec<VId>,
    },
}

fn invalid(why: impl Into<String>) -> Refusal {
    Refusal::new(
        code::CERTIFICATE_INVALID,
        exit::VERIFICATION,
        why,
        "plan §13.6 / FA-INV-11 (the certified closure and exact output must replay)",
        "recreate the certificate from the original book and selector; retain its certified history and registry versions",
    )
}

fn digest(domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(domain);
    h.update(value);
    h.finalize().0
}

fn encoding(e: fa_model::EncodeError) -> BookError {
    fa_journal::KernelError::from(fa_model::EntryError::from(e)).into()
}

/// Registry identities are explicit inputs, not inferred from the executable's
/// version. A changed law or native engine pin requires the original environment
/// to replay this version; it cannot silently substitute new semantics.
fn registry_digest() -> [u8; 32] {
    const SOURCES: &[(&str, &str)] = &[
        (
            "account_types",
            include_str!("../../../registries/account_types.toml"),
        ),
        (
            "admissibility",
            include_str!("../../../registries/admissibility.toml"),
        ),
        (
            "entry_classes",
            include_str!("../../../registries/entry_classes.toml"),
        ),
        ("limits", include_str!("../../../registries/limits.toml")),
        (
            "rounding_laws",
            include_str!("../../../registries/rounding_laws.toml"),
        ),
        ("symbols", include_str!("../../../registries/symbols.toml")),
        ("units", include_str!("../../../registries/units.toml")),
        ("foundations", include_str!("../../../franken-stack.lock")),
    ];
    let mut h = Hasher::new();
    h.update(b"fa:report-registry-closure:v1");
    for (name, source) in SOURCES {
        h.update(name.as_bytes());
        h.update(&[0]);
        h.update(&digest(b"fa:report-registry:v1", source.as_bytes()));
    }
    h.finalize().0
}

fn statements(at: CommitSeq) -> Vec<String> {
    INPUTS
        .iter()
        .map(|(kind, fields)| {
            let projections: String = fields
                .split(',')
                .map(|field| format!(",n.{field}"))
                .collect();
            format!(
                "MATCH (n:{kind}) FOR SYSTEM_TIME AS OF SEQ {} RETURN n{projections} ORDER BY n",
                at.0
            )
        })
        .collect()
}

fn policy() -> GqlQueryPolicy {
    // Bounded native execution: exceeding the closure budget is a typed source
    // refusal, never a truncated certificate or an ungoverned eager fallback.
    GqlQueryPolicy::new(10_000_000, 1_000_000, 256 * 1024 * 1024, 256 * 1024 * 1024)
}

impl ReportCertificate {
    fn body_bytes(&self) -> Result<Vec<u8>, fa_model::EncodeError> {
        let mut w = Writer::new();
        w.fixed(CERTIFICATE_FORMAT)
            .str(REPLAY_SCOPE)
            .str(AUTHORITY)
            .str(OUTPUT_FORMAT)
            .fixed(&self.book_id.0)
            .fixed(&self.branch_id.0)
            .u64(self.known_at.0);
        self.selection.write(&mut w);
        w.fixed(&self.registry_digest)
            .fixed(&self.journal_root)
            .u64(self.journal_leaves)
            .list(&self.inputs, |w, input| {
                w.bytes(&input.canonical_bytes());
            })
            .bytes(&self.output)
            .fixed(&self.output_digest);
        w.finish()
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, fa_model::EncodeError> {
        let mut body = self.body_bytes()?;
        body.extend_from_slice(&self.digest);
        Ok(body)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        if bytes.len() > MAX_CERTIFICATE_BYTES {
            return Err(invalid(
                "report certificate exceeds the 64 MiB format limit",
            ));
        }
        let decode = || -> Result<Self, fa_model::DecodeError> {
            let mut r = Reader::new(bytes);
            if r.fixed::<{ CERTIFICATE_FORMAT.len() }>("certificate format")? != CERTIFICATE_FORMAT
            {
                return Err(r.invalid("report certificate format"));
            }
            for (name, expected) in [
                ("replay scope", REPLAY_SCOPE),
                ("authority", AUTHORITY),
                ("output format", OUTPUT_FORMAT),
            ] {
                if r.str(64, name)? != expected {
                    return Err(r.invalid(name));
                }
            }
            let book_id = Id128(r.fixed("book id")?);
            let branch_id = Id128(r.fixed("branch id")?);
            let known_at = CommitSeq(r.u64("known-at")?);
            let selection = TrialBalanceSelection::read(&mut r)?;
            let registry_digest = r.fixed("registry closure")?;
            let journal_root = r.fixed("journal root")?;
            let journal_leaves = r.u64("journal leaves")?;
            let count = r.count(INPUTS.len(), "native inputs")?;
            if count != INPUTS.len() {
                return Err(r.invalid("complete native input closure"));
            }
            let mut inputs = Vec::new();
            for _ in 0..count {
                let input = r.bytes(MAX_NATIVE_BYTES, "native certificate")?;
                inputs.push(
                    NativeResultCertificate::decode(input)
                        .map_err(|_| r.invalid("native certificate"))?,
                );
            }
            let output = r.bytes(MAX_CERTIFICATE_BYTES, "report output")?.to_vec();
            let output_digest = r.fixed("output digest")?;
            let digest = r.fixed("certificate digest")?;
            r.finish()?;
            Ok(Self {
                book_id,
                branch_id,
                known_at,
                selection,
                registry_digest,
                journal_root,
                journal_leaves,
                inputs,
                output,
                output_digest,
                digest,
            })
        };
        let certificate =
            decode().map_err(|e| invalid(format!("malformed report certificate: {e}")))?;
        certificate.validate()?;
        Ok(certificate)
    }

    fn validate(&self) -> Result<(), Refusal> {
        if self.branch_id != Id128::TRUNK || !self.selection.is_canonical() {
            return Err(invalid(
                "unsupported branch or noncanonical report selector",
            ));
        }
        let expected = statements(self.known_at);
        if self.inputs.len() != expected.len()
            || self.inputs.iter().zip(expected).any(|(input, statement)| {
                input.statement != statement || input.plan.snapshot_seq != self.known_at
            })
        {
            return Err(invalid(
                "native input closure differs from the report's fixed known-at selector",
            ));
        }
        if self.inputs.windows(2).any(|pair| {
            pair[0].snapshot_identity != pair[1].snapshot_identity
                || pair[0].database_identity != pair[1].database_identity
        }) {
            return Err(invalid(
                "native inputs name different books or snapshot identities",
            ));
        }
        if digest(b"fa:report-output:v1", &self.output) != self.output_digest {
            return Err(invalid(
                "the certified output bytes do not match their digest",
            ));
        }
        let body = self.body_bytes().map_err(|e| invalid(e.to_string()))?;
        if body.len().saturating_add(32) > MAX_CERTIFICATE_BYTES
            || digest(CERTIFICATE_FORMAT, &body) != self.digest
        {
            return Err(invalid(
                "the report certificate's content digest does not match",
            ));
        }
        Ok(())
    }
}

pub(crate) fn certify<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    selection: TrialBalanceSelection,
    known_at: Option<CommitSeq>,
) -> Outcome<CertifiedTrialBalance> {
    cx.checkpoint().map_err(BookError::Context)?;
    let selection = selection.normalize();
    let at = known_at.unwrap_or(db.frontier().map_err(fa_journal::KernelError::from)?);
    // Resolve report selection before native queries. Future/absent period
    // selectors and a seq beyond HEAD retain the ordinary report's refusal.
    let report = selection.report(db, book, at)?;
    if !report.is_balanced() {
        return Ok(Err(invalid(
            "the journal trial balance is not balanced in every unit",
        )));
    }
    let mut inputs = Vec::new();
    for statement in statements(at) {
        cx.checkpoint().map_err(BookError::Context)?;
        let (_, certificate) = db
            .execute_certified(
                cx,
                &statement,
                &GqlParameters::new(),
                book.symbols.clone(),
                policy(),
            )
            .map_err(BookError::CertifiedRead)?;
        inputs.push(certificate);
    }
    let journal = match Journal::read(db, book, Some(at))? {
        Ok(journal) => journal,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if let Err(refusal) = unchanged_entries(db, cx, &journal)? {
        return Ok(Err(refusal));
    }
    let output = report.canonical_bytes().map_err(encoding)?;
    let mut certificate = ReportCertificate {
        book_id: book.book_id,
        branch_id: Id128::TRUNK,
        known_at: at,
        selection,
        registry_digest: registry_digest(),
        journal_root: journal.root(),
        journal_leaves: journal.len(),
        inputs,
        output_digest: digest(b"fa:report-output:v1", &output),
        output,
        digest: [0; 32],
    };
    certificate.digest = digest(
        CERTIFICATE_FORMAT,
        &certificate.body_bytes().map_err(encoding)?,
    );
    if let Err(refusal) = certificate.validate() {
        return Ok(Err(refusal));
    }
    Ok(Ok(CertifiedTrialBalance {
        report,
        certificate,
    }))
}

/// A snapshot-only replay would overlook an in-place rewrite committed after
/// the certificate. The posting journal is immutable, so each certified entry
/// must still exist at HEAD with the same creating sequence and full bytes.
fn unchanged_entries<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    journal: &Journal,
) -> Outcome<()> {
    for leaf in &journal.leaves {
        cx.checkpoint().map_err(BookError::Context)?;
        let Some(row) = db.vertex(leaf.vid).map_err(fa_journal::KernelError::from)? else {
            return Ok(Err(invalid(format!(
                "certified journal entry {:032x} was retired",
                leaf.vid.0
            ))));
        };
        if !row.labels.contains(&label::ENTRY)
            || row.created_at != leaf.envelope.commit_seq
            || bytes(&row, property::FA_PAYLOAD, "certified entry payload")
                .ok()
                .as_deref()
                != Some(leaf.payload.as_slice())
            || bytes(&row, property::FA_DIGEST, "certified entry digest")
                .ok()
                .as_deref()
                != Some(leaf.envelope.record_digest.as_slice())
        {
            return Ok(Err(invalid(format!(
                "certified journal entry {:032x} was rewritten",
                leaf.vid.0
            ))));
        }
    }
    Ok(Ok(()))
}

pub(crate) fn replay<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    certificate: &ReportCertificate,
) -> Outcome<TrialBalance> {
    cx.checkpoint().map_err(BookError::Context)?;
    if let Err(refusal) = certificate.validate() {
        return Ok(Err(refusal));
    }
    if certificate.book_id != book.book_id {
        return Ok(Err(invalid("the certificate belongs to a different book")));
    }
    if certificate.registry_digest != registry_digest() {
        return Ok(Err(invalid(
            "the certificate's registry or foundation versions are unavailable in this executable",
        )));
    }
    for (index, input) in certificate.inputs.iter().enumerate() {
        if let Err(error) = db.replay(
            cx,
            input,
            &GqlParameters::new(),
            book.symbols.clone(),
            policy(),
        ) {
            return Ok(Err(invalid(format!(
                "native input {index} ({}) does not replay: {error}",
                INPUTS[index].0
            ))));
        }
    }
    let journal = match Journal::read(db, book, Some(certificate.known_at))? {
        Ok(journal) => journal,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if journal.root() != certificate.journal_root || journal.len() != certificate.journal_leaves {
        return Ok(Err(invalid(
            "the accounting journal prefix does not match the certified one",
        )));
    }
    if let Err(refusal) = unchanged_entries(db, cx, &journal)? {
        return Ok(Err(refusal));
    }
    let report = certificate
        .selection
        .report(db, book, certificate.known_at)?;
    let output = report.canonical_bytes().map_err(encoding)?;
    if output != certificate.output {
        let first = output
            .iter()
            .zip(&certificate.output)
            .position(|(a, b)| a != b)
            .unwrap_or(output.len().min(certificate.output.len()));
        return Ok(Err(invalid(format!(
            "trial balance differs from its certified output at canonical byte {first}"
        ))));
    }
    Ok(Ok(report))
}

pub(crate) fn status<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    certificate: &ReportCertificate,
) -> Outcome<CertificateStatus> {
    let report = match replay(db, cx, book, certificate)? {
        Ok(report) => report,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let head = db.frontier().map_err(fa_journal::KernelError::from)?;
    let journal = match Journal::read(db, book, Some(head))? {
        Ok(journal) => journal,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let mut entries = BTreeMap::new();
    for leaf in &journal.leaves {
        entries.insert(
            leaf.vid,
            Entry::decode(&leaf.payload).map_err(fa_journal::KernelError::from)?,
        );
    }
    let mut later_entries = Vec::new();
    let mut migration_visibility = BTreeMap::new();
    for leaf in &journal.leaves {
        cx.checkpoint().map_err(BookError::Context)?;
        if leaf.envelope.commit_seq <= certificate.known_at {
            continue;
        }
        let entry = &entries[&leaf.vid];
        let mut relevant =
            fa_journal::migration::visible_at(db, entry, head, &mut migration_visibility)?
                && selected(book, &certificate.selection, &report, entry)?;
        if entry.proposal.class == EntryClass::RESOLUTION
            && let Some(target) = entry
                .proposal
                .pending
                .as_ref()
                .and_then(|p| p.resolution_of)
            && let Some(original) = entries.get(&target.vid)
        {
            relevant |= selected(book, &certificate.selection, &report, original)?;
        }
        if let Some(ControlPayload::MigrationControl { run_ref, kind, .. }) =
            &entry.proposal.control
            && *kind == fa_journal::migration::kind::FINALIZE
        {
            for migrated in entries.values() {
                if matches!(&migrated.proposal.origin, EntryOrigin::Migration { run_ref: origin, .. } if origin == run_ref)
                    && fa_journal::migration::visible_at(
                        db,
                        migrated,
                        head,
                        &mut migration_visibility,
                    )?
                {
                    relevant |= selected(book, &certificate.selection, &report, migrated)?;
                }
            }
        }
        if relevant {
            later_entries.push(leaf.vid);
        }
    }
    Ok(Ok(if later_entries.is_empty() {
        CertificateStatus::Current { checked_at: head }
    } else {
        CertificateStatus::SupersededBy {
            checked_at: head,
            later_entries,
        }
    }))
}

fn selected(
    book: &BookContext,
    selection: &TrialBalanceSelection,
    report: &TrialBalance,
    entry: &Entry,
) -> Result<bool, BookError> {
    // A control's nominal date is not a trial-balance contribution. Releases
    // and migration activation are checked explicitly by their target above.
    if entry.proposal.legs.is_empty() || fa_notary::journal::is_undated(entry.proposal.class) {
        return Ok(false);
    }
    if let Some(through) = report.effective_through {
        return Ok(entry.proposal.effective_date <= through);
    }
    let TrialBalanceSelection::Activity(periods) = selection else {
        return Ok(false);
    };
    let date = entry.proposal.effective_date;
    let fy = book
        .calendar
        .fiscal_year_of(date)
        .map_err(fa_journal::KernelError::from)?;
    let calendar = book
        .calendar
        .periods_for_year(fy)
        .map_err(fa_journal::KernelError::from)?;
    let period = fa_time::resolve_period(
        &calendar,
        date,
        entry
            .proposal
            .effective_period
            .as_ref()
            .map(|p| p.code.as_str()),
    )
    .map_err(|e| {
        BookError::Kernel(fa_journal::KernelError::Corrupt(format!(
            "certificate status period: {e:?}"
        )))
    })?;
    Ok(periods.binary_search(&period.code).is_ok())
}
