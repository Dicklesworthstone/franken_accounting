//! Portable native and dimension-filtered trial balances, statements, open
//! items, summary accounts, balance explanations, aging, native subledger
//! reconciliations, roll-forwards, JET, duplicate, density, LIBR and Benford procedures,
//! and direct cash flow over
//! a payload-complete checkpoint.
//!
//! This is the linear complete-prefix fallback from plan §13.1/§13.3. The
//! independent verifier derives selectors from every record, reconstructs the
//! historical chart and periods from schema controls, and refolds the report.
//! Native FGDB read certificates are retained as part of the source certificate;
//! they are not substituted for outsider-authenticated accounting inputs.

use std::collections::BTreeSet;

use crate::migration_balance::{MigrationInputs, MigrationSourceInputs};
use fa_journal::refusal::{Outcome, Refusal, exit};
use fa_model::{ControlPayload, Entry, EntryClass, EntryOrigin, Oid, Reader, Writer};
use fgdb::Database;
use fgdb_crypto::Hasher;
use fgdb_types::CommitSeq;

use crate::{Bundle, Journal, StoredCheckpoint, code};

mod consolidation;
pub use consolidation::assemble as assemble_consolidation_with_registries;

mod functional;
pub use functional::{
    MAX_FUNCTIONAL_BOOK_BYTES, MAX_FUNCTIONAL_RATE_BYTES, MAX_FUNCTIONAL_RATES,
    rate_oids as functional_rate_oids,
};

mod explanation;
pub use explanation::check_scope as check_explanation_scope;

mod open_items;
pub use open_items::check_scope as check_open_items_scope;

mod procedure;
pub use procedure::profile as offline_procedure_profile;

pub const REPORT_BUNDLE_FORMAT: &[u8] = b"fa:report-bundle:v1";
pub const MAX_REPORT_BUNDLE_BYTES: usize = 64 * 1024 * 1024;

fn refused(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::SCOPE_UNSUPPORTED,
        exit::REFUSAL,
        message,
        "plan §13.1–13.3 (report recomputation needs its complete authenticated closure)",
        "use a native v1/v2 trial-balance, summary trial-balance, native-subledger reconciliation, v8 dimension-filtered trial-balance, v3 open-item or balance-explanation, v4 statement, v11/v12 custom statement, native statement-diff, v6/v7 one-book consolidation, JET round-amount/period-end v1/v2, post-closing v1, exact duplicates v1, round-amount density v1, first-digit Benford v2 or one-account LIBR v2 procedure, effective-date aging, roll-forward, equity roll-forward or equity comparison, direct cash-flow or policy cash-flow certificate and a checkpoint covering its known-at and any retained time frontier; preserve the complete historical schema, registry and migration inputs",
    )
}

/// Read only immutable migration bodies needed by this report's historical
/// prefix. Whole-book read and produce authority must be checked before this
/// function is called, as for every complete-prefix proof export.
pub fn run_bodies<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    journal: &Journal,
    known_at: CommitSeq,
) -> Outcome<MigrationInputs> {
    if known_at > journal.through_seq {
        return Ok(Err(refused(
            "the selected checkpoint does not cover the report's known-at",
        )));
    }
    let mut needed = BTreeSet::new();
    for leaf in &journal.leaves {
        if !leaf.envelope.is_entry() || leaf.envelope.commit_seq > known_at {
            continue;
        }
        let entry = Entry::decode(&leaf.payload)?;
        if let EntryOrigin::Migration { run_ref, .. } = &entry.proposal.origin {
            needed.insert(*run_ref);
        }
    }
    crate::migration_balance::inputs_at(db, journal, &needed, known_at)
}

/// Package an already replayed native or dimension-filtered trial balance, or
/// statement. Open items, balance explanations, aging, roll-forwards and direct
/// cash flow require the authenticated registry closure in
/// `assemble_with_registries`. For an instant-selected certificate, the facade
/// supplies its observed time frontier
/// as `known_at` so the complete upper-tick closure is retained as well.
/// Legacy v1 statements require the recipient to supply the complete unit-ID
/// universe; use `assemble_with_registries` for an authenticated registry closure.
/// The facade performs current authority and retained-history
/// checks first. The returned bytes are deterministic, and their digest can
/// be signed by the existing detached `ProductionReceipt` format.
///
/// Wire: bytes(domain), u16 major=1, u16 minor=0, bytes(certificate),
/// bytes(signed checkpoint), bytes(prefix proof), list(proposal_len u32,
/// bytes(record)), list(open_leaf_index u64, bytes(migration body)). Every
/// checkpoint leaf has exactly one payload, in prefix order. Source-bound runs
/// use minor 1, appending a BindSource-indexed manifest list after the body list.
/// Legacy unbound reports retain minor 0 and their exact prior wire bytes.
pub fn assemble(
    journal: &Journal,
    checkpoint: &StoredCheckpoint,
    certificate: &[u8],
    known_at: CommitSeq,
    bodies: &dyn MigrationSourceInputs,
) -> Outcome<Bundle> {
    assemble_inner(
        journal,
        checkpoint,
        certificate,
        known_at,
        bodies,
        &[],
        None,
    )
}

/// Package a native statement, open-item report, balance explanation, aging,
/// roll-forward or direct cash flow with the exact canonical registry documents
/// bound by its source certificate.
/// The facade verifies their closure and the book's complete unit table before
/// calling this API. Open items pass `check_open_items_scope`; explanations
/// pass `check_explanation_scope` and append their original reason-code
/// registry as the fifth document. Aging retains its outer certificate after
/// replaying the cutoff, buckets and output; its nested OpenItems source needs
/// four documents. Roll-forwards retain their outer schedule and a sequence-
/// selected native closing-stock source with the same exact four documents.
/// Direct cash flow adds its explicit classification over that complete source;
/// policy cash flow also retains the complete counterpart-classification policy
/// and its decision transcript. Both keep the same four-document profile.
/// Aging-to-control reconciliations and whole-chart portfolios retain both
/// original sources and their shared four-document closure. No v1 fallback serves either v3 selector or
/// composed schedule.
/// Native statement comparisons retain both original v4 sources and the exact
/// outer bridge under their shared four-document closure. Each source is
/// reconstructed at its own recorded frontier from the complete prefix.
/// Equity comparisons retain both original v2 equity sources, including their
/// case and movement citations, under the same native four-document profile.
/// Their recipient must independently supply the common equity question.
/// Summary trial balances retain their exact outer root selection and output
/// over a native source and the same four-document closure; historical chart
/// membership is reconstructed from the authenticated prefix.
/// Native custom statements retain their exact v11 selection and native read
/// attestations, with rounding_laws as their fifth registry. Their activation
/// control is carried in the authenticated prefix; independent reconstruction
/// checks its definition and chart commitments without promoting the native
/// approval or definition-object reads into separate membership proofs.
/// The bounded JET round-amount/period-end v1/v2, post-closing v1,
/// exact duplicates v1, round-amount density v1, first-digit Benford v2 and LIBR v2
/// profiles keep their outer certificate and append procedures and sod_policy
/// to the four native documents. Those definitions support independent
/// reproduction of the findings, exact work and complete decision card.
/// JET round-amount/period-end v2 accepts an optional effective cutoff. LIBR v2
/// requires a claim date and canonical account/source handles. Every procedure
/// requires its complete explicit parameter inventory.
/// Native subledger reconciliations retain their exact outer certificate and
/// native AsOf source, appending control_payload and symbols to the four native
/// registry documents. The shared entry_classes document belongs to both
/// independently checked registry closures. Party detail and the designation
/// are reconstructed from the authenticated complete prefix.
/// Native v8 dimension slices use the same four-registry closure as native
/// statements; their hierarchy is independently reconstructed from the prefix.
/// V2 appends a list of (registry name, canonical registry document) frames;
/// existing v1 trial-balance bytes remain unchanged.
pub fn assemble_with_registries(
    journal: &Journal,
    checkpoint: &StoredCheckpoint,
    certificate: &[u8],
    known_at: CommitSeq,
    bodies: &dyn MigrationSourceInputs,
    registries: &[(String, Vec<u8>)],
) -> Outcome<Bundle> {
    let explanation = explanation_certificate(certificate);
    let custom = custom_statement_certificate(certificate)
        || custom_statement_diff_certificate(certificate)
        || custom_statement_trace_certificate(certificate);
    let procedure = procedure_certificate(certificate);
    let native_subledger = native_subledger_certificate(certificate);
    let expected: &[&str] = if explanation {
        &[
            "account_types",
            "entry_classes",
            "units",
            "foundations",
            "reason_codes",
        ]
    } else if custom {
        &[
            "account_types",
            "entry_classes",
            "units",
            "foundations",
            "rounding_laws",
        ]
    } else if procedure {
        &[
            "account_types",
            "entry_classes",
            "units",
            "foundations",
            "procedures",
            "sod_policy",
        ]
    } else if native_subledger {
        &[
            "account_types",
            "entry_classes",
            "units",
            "foundations",
            "control_payload",
            "symbols",
        ]
    } else {
        &["account_types", "entry_classes", "units", "foundations"]
    };
    if !(certificate_format(certificate, b"fa:report-certificate:v4")
        || certificate_format(certificate, b"fa:report-certificate:v8")
        || custom
        || summary_certificate(certificate)
        || open_items_certificate(certificate)
        || aging_certificate(certificate)
        || lots_certificate(certificate)
        || procedure
        || native_subledger
        || due_date_aging_certificate(certificate)
        || reconciliation_certificate(certificate)
        || roll_forward_certificate(certificate)
        || equity_certificate(certificate)
        || equity_diff_certificate(certificate)
        || cash_flow_certificate(certificate)
        || policy_cash_flow_certificate(certificate)
        || split_cash_flow_certificate(certificate)
        || indirect_cash_flow_certificate(certificate)
        || statement_diff_certificate(certificate)
        || statement_trace_certificate(certificate)
        || explanation)
        || registries
            .iter()
            .map(|(name, _)| name.as_str())
            .ne(expected.iter().copied())
        || registries
            .iter()
            .any(|(_, bytes)| bytes.len() > 1024 * 1024)
    {
        return Ok(Err(refused(
            "native reports require their exact canonical registry profile in closure order: four documents for built-in statements, dimension-filtered and summary trial balances, open items, lots, aging, reconciliation, roll-forwards and direct cash flow, five including reason_codes for balance explanations, five including rounding_laws for custom statements, six including procedures and sod_policy for JET round-amount/period-end v1/v2, post-closing v1, exact duplicates v1, round-amount density v1, first-digit Benford v2 or one-account LIBR v2, or six including control_payload and symbols for native subledger reconciliation",
        )));
    }
    assemble_inner(
        journal,
        checkpoint,
        certificate,
        known_at,
        bodies,
        registries,
        None,
    )
}

/// Package a replayed functional trial balance, built-in or custom financial statement or
/// statement comparison or complete publication trace with its
/// original six-registry closure, exact historical version-2 BookSpec, and every authenticated Rate
/// document cited at or before known-at. The facade must govern every Rate read.
/// This profile supports sequence-selected trunk reports under SpotClose,
/// PeriodAverage, aggregate PeriodEndRevaluation, source-bound
/// SettlementCarryingBasis and SettlementSpotCarrying, and YearEndCloseCarrying,
/// including exact inherited reversals. Migration visibility and activation are independently
/// derived from the authenticated lifecycle and run bodies; imported values
/// use base-unit identity or SpotClose. Other valuation laws remain unsupported.
///
/// Major 3 preserves the complete-prefix layout and appends six registry frames,
/// bytes(BookSpec), then list(fixed32 Rate OID, bytes(inline DocumentRecord)).
/// BookSpec is a declared report basis bound by the expected certificate and
/// signed bundle; it does not assert separate checkpoint membership at genesis.
#[allow(clippy::too_many_arguments)]
pub fn assemble_functional_with_registries(
    journal: &Journal,
    checkpoint: &StoredCheckpoint,
    certificate: &[u8],
    known_at: CommitSeq,
    bodies: &dyn MigrationSourceInputs,
    registries: &[(String, Vec<u8>)],
    book_spec: &[u8],
    rates: &[(Oid, Vec<u8>)],
) -> Outcome<Bundle> {
    let expected = [
        "account_types",
        "entry_classes",
        "units",
        "foundations",
        "fx_laws",
        "rounding_laws",
    ];
    if !(functional::certificate(certificate, journal, known_at)
        || functional::comparison_certificate(certificate, journal, known_at)
        || functional::trace_certificate(certificate, journal, known_at))
        || registries
            .iter()
            .map(|(name, _)| name.as_str())
            .ne(expected)
        || registries
            .iter()
            .any(|(_, bytes)| bytes.len() > 1024 * 1024)
    {
        return Ok(Err(refused(
            "functional report requires its exact six-registry closure and supported native source",
        )));
    }
    if let Err(refusal) = functional::validate(journal, known_at, book_spec, rates)? {
        return Ok(Err(refusal));
    }
    assemble_inner(
        journal,
        checkpoint,
        certificate,
        known_at,
        bodies,
        registries,
        Some(BookClosure { book_spec, rates }),
    )
}

struct BookClosure<'a> {
    book_spec: &'a [u8],
    rates: &'a [(Oid, Vec<u8>)],
}

/// Package an already replayed aging-to-control reconciliation with the exact
/// original registry closure shared by both sources. The facade must verify
/// the complete outer certificate, the recipient's explicit question, both
/// native source outputs and their equal book/prefix/registry coordinates
/// before calling. `check_open_items_scope` applies to the nested aging source.
/// A comparison with nonzero differences is valid report data. This function
/// only routes the supported format; it does not establish reconciliation.
///
/// The unchanged major-2 transport carries the original outer certificate and
/// one payload-complete prefix. It never falls back to recipient-supplied units.
pub fn assemble_reconciliation_with_registries(
    journal: &Journal,
    checkpoint: &StoredCheckpoint,
    certificate: &[u8],
    known_at: CommitSeq,
    bodies: &dyn MigrationSourceInputs,
    registries: &[(String, Vec<u8>)],
) -> Outcome<Bundle> {
    if !reconciliation_certificate(certificate) {
        return Ok(Err(refused(
            "portable reconciliation requires an aging source and a sequence-selected AsOf trial-balance control",
        )));
    }
    assemble_with_registries(
        journal,
        checkpoint,
        certificate,
        known_at,
        bodies,
        registries,
    )
}

/// The v3 tag and literal output format must agree; neither v3 selector may
/// borrow another family's registry obligations. The facade and independent
/// verifier still validate the complete certificate and reproduce its output.
fn open_items_certificate(certificate: &[u8]) -> bool {
    v3_certificate(certificate, "fa:open-items:v1", 1)
}

fn explanation_certificate(certificate: &[u8]) -> bool {
    v3_certificate(certificate, "fa:balance-explanation:v1", 0)
}

/// Route only the native custom statement tag, output and selector together.
/// Functional custom layouts require the complete v3 valuation closure. This
/// header check does not stand in for activation validation or recomputation.
fn custom_statement_certificate(certificate: &[u8]) -> bool {
    let header = || -> Result<bool, fa_model::DecodeError> {
        let mut reader = Reader::new(certificate);
        if reader.fixed::<{ b"fa:report-certificate:v11".len() }>("custom statement format")?
            != *b"fa:report-certificate:v11"
            || reader.str(64, "custom statement scope")? != "fa-fold-over-prefix"
        {
            return Ok(false);
        }
        reader.str(64, "custom statement authority")?;
        if reader.str(64, "custom statement output")? != "fa:custom-statement-report:v1" {
            return Ok(false);
        }
        reader.fixed::<16>("custom statement book")?;
        Ok(reader.fixed::<16>("custom statement branch")? == [0; 16]
            && reader.u64("custom statement frontier")? > 0
            && reader.u8("custom statement selector")? == 9)
    };
    certificate.len() <= MAX_REPORT_BUNDLE_BYTES && header().unwrap_or(false)
}

// A version tag is followed by the framed replay scope. Matching only its
// byte prefix would admit v10 as v1 (and future v40 as v4), even though the
// portable interpreter does not support those report families.
fn certificate_format(certificate: &[u8], format: &[u8]) -> bool {
    let Some(fields) = certificate.strip_prefix(format) else {
        return false;
    };
    let mut reader = Reader::new(fields);
    reader
        .str(64, "report scope")
        .is_ok_and(|scope| scope == "fa-fold-over-prefix")
}

fn v3_certificate(certificate: &[u8], output: &str, selector: u8) -> bool {
    let header = || -> Result<bool, fa_model::DecodeError> {
        let mut reader = Reader::new(certificate);
        if reader.fixed::<{ b"fa:report-certificate:v3".len() }>("report format")?
            != *b"fa:report-certificate:v3"
        {
            return Ok(false);
        }
        reader.str(128, "report scope")?;
        reader.str(128, "report authority")?;
        if reader.str(128, "report output format")? != output {
            return Ok(false);
        }
        reader.fixed::<16>("report book")?;
        reader.fixed::<16>("report branch")?;
        reader.u64("report known-at")?;
        Ok(reader.u8("report selector")? == selector)
    };
    header().unwrap_or(false)
}

/// Recognize only the effective-date aging wrapper around an OpenItems
/// source. This is format routing, not accounting verification: the facade
/// replays the complete outer certificate before assembly, and the independent
/// verifier checks its digest, source, cutoff and exact output again.
fn aging_certificate(certificate: &[u8]) -> bool {
    aging_certificate_with_format(certificate, b"fa:aging-certificate:v1")
}

fn due_date_aging_certificate(certificate: &[u8]) -> bool {
    aging_certificate_with_format(certificate, b"fa:due-date-aging-certificate:v1")
}

/// Route a lot wrapper only when its native OpenItems source selects one
/// account on trunk. The facade and independent verifier replay the complete
/// certificate; this header check grants no accounting or currency authority.
fn lots_certificate(certificate: &[u8]) -> bool {
    let header = || -> Result<bool, fa_model::DecodeError> {
        let mut reader = Reader::new(certificate);
        let format = reader.bytes(64, "lots format")?;
        if format != b"fa:lots-certificate:v1" && format != b"fa:lots-certificate:v2" {
            return Ok(false);
        }
        reader.u128("lots producer")?;
        reader.fixed::<32>("lots capability")?;
        let source = reader.bytes(MAX_REPORT_BUNDLE_BYTES, "lots source")?;
        if !open_items_certificate(source) {
            return Ok(false);
        }
        let mut native = Reader::new(source);
        native.fixed::<{ b"fa:report-certificate:v3".len() }>("report format")?;
        native.str(128, "report scope")?;
        native.str(128, "report authority")?;
        native.str(128, "report output format")?;
        native.fixed::<16>("report book")?;
        if native.fixed::<16>("report branch")? != [0; 16] {
            return Ok(false);
        }
        native.u64("report known-at")?;
        if native.u8("report selector")? != 1 || native.u8("selected account")? != 1 {
            return Ok(false);
        }
        native.u128("lot account")?;
        Ok(true)
    };
    header().unwrap_or(false)
}

/// Route bounded JET, duplicate, density, LIBR and first-digit Benford profiles.
/// This checks framing and selection; producer replay and the verifier authenticate
/// the complete source, commitments and reproduced output.
fn procedure_certificate(certificate: &[u8]) -> bool {
    let header = || -> Result<bool, fa_model::DecodeError> {
        let mut reader = Reader::new(certificate);
        if reader.bytes(64, "procedure format")? != b"fa:procedure-certificate:v1" {
            return Ok(false);
        }
        let source = reader.bytes(MAX_REPORT_BUNDLE_BYTES, "procedure source")?;
        if !open_items_certificate(source) {
            return Ok(false);
        }
        let mut native = Reader::new(source);
        native.fixed::<{ b"fa:report-certificate:v3".len() }>("report format")?;
        native.str(128, "report scope")?;
        native.str(128, "report authority")?;
        native.str(128, "report output format")?;
        let book = native.fixed::<16>("report book")?;
        if native.fixed::<16>("report branch")? != [0; 16] {
            return Ok(false);
        }
        let known_at = native.u64("report known-at")?;
        if known_at == 0
            || native.u8("report selector")? != 1
            || native.u8("selected account")? != 0
        {
            return Ok(false);
        }
        reader.bytes(1024 * 1024, "procedure native approvals")?;
        reader.fixed::<32>("procedure registry closure")?;
        reader.u128("procedure producer")?;
        reader.fixed::<32>("procedure capability")?;
        let output = reader.bytes(32 * 1024 * 1024, "procedure output")?;
        reader.fixed::<32>("procedure digest")?;
        reader.finish()?;
        let mut output = Reader::new(output);
        if output.bytes(64, "procedure output format")? != b"fa:procedure-output:v1" {
            return Ok(false);
        }
        let id = output.str(128, "procedure id")?;
        let version = output.u16("procedure version")?;
        if output.u8("procedure claim")? != 0 {
            return Ok(false);
        }
        let evidence = output.str(128, "procedure evidence")?;
        if output.fixed::<16>("procedure book")? != book
            || output.u64("procedure known-at")? != known_at
        {
            return Ok(false);
        }
        let effective_through = match output.u8("procedure effective cutoff")? {
            0 => None,
            1 => Some(output.i32("procedure effective cutoff")?),
            _ => return Ok(false),
        };
        let parameters = output.list(7, "procedure parameters", |reader| {
            Ok((
                reader.str(128, "procedure parameter")?,
                reader.i128("procedure parameter value")?,
            ))
        })?;
        let inputs = output.list(2, "procedure input handles", |reader| {
            Ok((
                reader.str(64, "procedure input name")?,
                reader.str(128, "procedure input handle")?,
            ))
        })?;
        Ok(
            offline_procedure_profile(id, version, effective_through, &parameters, &inputs)
                == Some(evidence),
        )
    };
    certificate.len() <= MAX_REPORT_BUNDLE_BYTES && header().unwrap_or(false)
}

/// Route a summary wrapper only when it carries a sequence-selected trunk
/// native trial balance. This is format routing: producer replay and the
/// independent verifier validate the full source, selector and exact output.
fn summary_certificate(certificate: &[u8]) -> bool {
    let header = || -> Result<bool, fa_model::DecodeError> {
        let mut reader = Reader::new(certificate);
        if reader.bytes(64, "summary format")? != b"fa:summary-certificate:v1" {
            return Ok(false);
        }
        let source = reader.bytes(MAX_REPORT_BUNDLE_BYTES, "summary source")?;
        if !certificate_format(source, b"fa:report-certificate:v1") {
            return Ok(false);
        }
        let mut native = Reader::new(source);
        native.fixed::<{ b"fa:report-certificate:v1".len() }>("report format")?;
        native.str(128, "report scope")?;
        native.str(128, "report authority")?;
        if native.str(128, "report output format")? != "fa:trial-balance:v1" {
            return Ok(false);
        }
        native.fixed::<16>("report book")?;
        if native.fixed::<16>("report branch")? != [0; 16] {
            return Ok(false);
        }
        native.u64("report known-at")?;
        Ok(matches!(native.u8("report selector")?, 0..=2))
    };
    header().unwrap_or(false)
}

/// Route the existing native-subledger wrapper only with its exact, sequence-
/// selected trunk AsOf source. This is framing admission, not verification of
/// party detail or the declaration: native replay precedes export and the
/// independent verifier reconstructs every output row from the signed prefix.
fn native_subledger_certificate(certificate: &[u8]) -> bool {
    let header = || -> Result<bool, fa_model::DecodeError> {
        let mut reader = Reader::new(certificate);
        if reader.bytes(64, "native subledger format")? != b"fa:native-subledger-certificate:v1" {
            return Ok(false);
        }
        let source = reader.bytes(MAX_REPORT_BUNDLE_BYTES, "native subledger source")?;
        if !certificate_format(source, b"fa:report-certificate:v1") {
            return Ok(false);
        }
        let mut native = Reader::new(source);
        native.fixed::<{ b"fa:report-certificate:v1".len() }>("report format")?;
        native.str(128, "report scope")?;
        native.str(128, "report authority")?;
        if native.str(128, "report output format")? != "fa:trial-balance:v1" {
            return Ok(false);
        }
        native.fixed::<16>("report book")?;
        if native.fixed::<16>("report branch")? != [0; 16] {
            return Ok(false);
        }
        let known_at = native.u64("report known-at")?;
        if known_at == 0 || native.u8("report selector")? != 1 {
            return Ok(false);
        }
        let through = native.i32("report cutoff")?;
        if reader.str(64, "subledger code")?.is_empty() {
            return Ok(false);
        }
        reader.u128("subledger control")?;
        if reader.i32("subledger cutoff")? != through || reader.u64("subledger prefix")? != known_at
        {
            return Ok(false);
        }
        reader.fixed::<32>("subledger registries")?;
        reader.u128("subledger producer")?;
        reader.fixed::<32>("subledger capability")?;
        let output = reader.bytes(MAX_REPORT_BUNDLE_BYTES, "subledger output")?;
        reader.fixed::<32>("subledger certificate digest")?;
        reader.finish()?;
        Ok(output.starts_with(b"fa:native-subledger-reconciliation:v1"))
    };
    certificate.len() <= MAX_REPORT_BUNDLE_BYTES && header().unwrap_or(false)
}

fn aging_certificate_with_format(certificate: &[u8], format: &[u8]) -> bool {
    let header = || -> Result<bool, fa_model::DecodeError> {
        let mut reader = Reader::new(certificate);
        if reader.bytes(64, "aging format")? != format {
            return Ok(false);
        }
        reader.u128("aging producer")?;
        reader.fixed::<32>("aging capability")?;
        let source = reader.bytes(MAX_REPORT_BUNDLE_BYTES, "aging source")?;
        Ok(open_items_certificate(source))
    };
    header().unwrap_or(false)
}

/// Route only a sequence-selected trunk closing-stock source. The facade and
/// independent verifier still validate the full source and outer output; this
/// header check cannot stand in for replay or authenticate a certificate.
fn roll_forward_certificate(certificate: &[u8]) -> bool {
    let header = || -> Result<bool, fa_model::DecodeError> {
        let mut reader = Reader::new(certificate);
        if reader.bytes(64, "roll-forward format")? != b"fa:roll-forward-certificate:v1" {
            return Ok(false);
        }
        let source = reader.bytes(MAX_REPORT_BUNDLE_BYTES, "roll-forward source")?;
        if !certificate_format(source, b"fa:report-certificate:v1") {
            return Ok(false);
        }
        let mut native = Reader::new(source);
        native.fixed::<{ b"fa:report-certificate:v1".len() }>("report format")?;
        native.str(128, "report scope")?;
        native.str(128, "report authority")?;
        if native.str(128, "report output format")? != "fa:trial-balance:v1" {
            return Ok(false);
        }
        native.fixed::<16>("report book")?;
        if native.fixed::<16>("report branch")? != [0; 16] {
            return Ok(false);
        }
        native.u64("report known-at")?;
        if native.u8("report selector")? != 1 {
            return Ok(false);
        }
        let through = native.i32("report effective-through")?;
        let accounts = reader.count(4096, "roll-forward accounts")?;
        if accounts == 0 {
            return Ok(false);
        }
        for _ in 0..accounts {
            reader.u128("roll-forward account")?;
        }
        let units = reader.count(4096, "roll-forward units")?;
        if units == 0 {
            return Ok(false);
        }
        for _ in 0..units {
            reader.u32("roll-forward unit")?;
        }
        reader.str(256, "roll-forward label")?;
        let from = reader.i32("roll-forward from")?;
        Ok(from <= through && reader.i32("roll-forward through")? == through)
    };
    header().unwrap_or(false)
}

/// These are bounded format routes, not independent replay. The facade checks
/// the full outer report before assembly. Equity adds complete historical chart
/// selection, explicit owner roles and the opening-to-closing reconciliation.
fn equity_certificate(certificate: &[u8]) -> bool {
    let check = || -> Result<bool, fa_model::DecodeError> {
        let mut reader = Reader::new(certificate);
        let format = reader.bytes(64, "equity format")?;
        if format != b"fa:equity-roll-forward-certificate:v1"
            && format != b"fa:equity-roll-forward-certificate:v2"
        {
            return Ok(false);
        }
        Ok(roll_forward_certificate(
            reader.bytes(MAX_REPORT_BUNDLE_BYTES, "equity source")?,
        ))
    };
    check().unwrap_or(false)
}

/// An equity comparison has exactly two original v2 equity sources, each over
/// one native roll-forward. Keep this route at a fixed depth: neither legacy
/// equity semantics, functional valuation nor another comparison may be
/// substituted for a source. The facade and recipient replay the full claims.
fn equity_diff_certificate(certificate: &[u8]) -> bool {
    let check = || -> Result<bool, fa_model::DecodeError> {
        let mut reader = Reader::new(certificate);
        if reader.bytes(64, "equity comparison format")?
            != b"fa:equity-roll-forward-diff-certificate:v1"
        {
            return Ok(false);
        }
        for name in ["before equity source", "after equity source"] {
            let source = reader.bytes(MAX_REPORT_BUNDLE_BYTES, name)?;
            let mut nested = Reader::new(source);
            if nested.bytes(64, "equity source format")? != b"fa:equity-roll-forward-certificate:v2"
                || !equity_certificate(source)
            {
                return Ok(false);
            }
        }
        reader.u128("equity comparison producer")?;
        reader.fixed::<32>("equity comparison capability")?;
        let output = reader.bytes(MAX_REPORT_BUNDLE_BYTES, "equity comparison output")?;
        if Reader::new(output).bytes(64, "equity comparison output format")?
            != b"fa:equity-roll-forward-diff:v1"
        {
            return Ok(false);
        }
        reader.fixed::<32>("equity comparison digest")?;
        reader.finish()?;
        Ok(true)
    };
    certificate.len() <= MAX_REPORT_BUNDLE_BYTES && check().unwrap_or(false)
}

/// Recognize the direct cash wrapper over its native lead schedule. Production
/// replays the full outer report; recipients independently verify every cash
/// movement and its classification. Other wrappers have their own exact route.
fn cash_flow_certificate(certificate: &[u8]) -> bool {
    let header = || -> Result<bool, fa_model::DecodeError> {
        let mut reader = Reader::new(certificate);
        if reader.bytes(64, "cash-flow format")? != b"fa:cash-flow-certificate:v1" {
            return Ok(false);
        }
        Ok(roll_forward_certificate(
            reader.bytes(MAX_REPORT_BUNDLE_BYTES, "cash-flow source")?,
        ))
    };
    header().unwrap_or(false)
}

fn policy_cash_flow_certificate(certificate: &[u8]) -> bool {
    let header = || -> Result<bool, fa_model::DecodeError> {
        let mut reader = Reader::new(certificate);
        if reader.bytes(64, "cash-flow policy format")? != b"fa:cash-flow-policy-certificate:v1" {
            return Ok(false);
        }
        Ok(cash_flow_certificate(reader.bytes(
            MAX_REPORT_BUNDLE_BYTES,
            "cash-flow policy source",
        )?))
    };
    header().unwrap_or(false)
}

fn split_cash_flow_certificate(certificate: &[u8]) -> bool {
    let header = || -> Result<bool, fa_model::DecodeError> {
        let mut reader = Reader::new(certificate);
        if reader.bytes(64, "cash-flow split format")? != b"fa:cash-flow-split-certificate:v1" {
            return Ok(false);
        }
        Ok(roll_forward_certificate(reader.bytes(
            MAX_REPORT_BUNDLE_BYTES,
            "cash-flow split source",
        )?))
    };
    header().unwrap_or(false)
}

/// Each indirect format has one exact cash-basis framing. The full facade and
/// independent verifier replay income and adjustments; routing never treats a
/// nested family's amount-equivalent output as interchangeable provenance.
fn indirect_cash_flow_certificate(certificate: &[u8]) -> bool {
    let header = || -> Result<bool, fa_model::DecodeError> {
        let mut reader = Reader::new(certificate);
        let kind = match reader.bytes(64, "indirect cash-flow format")? {
            b"fa:indirect-cash-flow-certificate:v1" => 0,
            b"fa:indirect-cash-flow-certificate:v2" => match reader.u8("indirect cash basis")? {
                kind @ (1 | 2) => kind,
                _ => return Ok(false),
            },
            _ => return Ok(false),
        };
        let source = reader.bytes(MAX_REPORT_BUNDLE_BYTES, "indirect cash source")?;
        Ok(match kind {
            0 => cash_flow_certificate(source),
            1 => policy_cash_flow_certificate(source),
            2 => split_cash_flow_certificate(source),
            _ => false,
        })
    };
    header().unwrap_or(false)
}

/// A comparison is its complete outer certificate and TWO native statement
/// sources. Custom sources require the additional rounding registry. Never
/// route a functional comparison or a different nested report through a native
/// profile. Full semantic verification is
/// performed by facade replay and again by the independent report interpreter.
fn statement_diff_certificate(certificate: &[u8]) -> bool {
    statement_diff_family(certificate, false) || custom_statement_diff_certificate(certificate)
}

fn custom_statement_diff_certificate(certificate: &[u8]) -> bool {
    statement_diff_family(certificate, true)
}

fn statement_diff_family(certificate: &[u8], custom: bool) -> bool {
    let header = || -> Result<bool, fa_model::DecodeError> {
        let mut reader = Reader::new(certificate);
        let format: &[u8] = if custom {
            b"fa:custom-statement-diff-certificate:v1"
        } else {
            b"fa:statement-diff-certificate:v1"
        };
        if reader.bytes(64, "statement diff format")? != format {
            return Ok(false);
        }
        reader.u128("statement diff producer")?;
        reader.fixed::<32>("statement diff capability")?;
        let before = reader.bytes(MAX_REPORT_BUNDLE_BYTES, "statement diff before")?;
        let after = reader.bytes(MAX_REPORT_BUNDLE_BYTES, "statement diff after")?;
        Ok(if custom {
            custom_statement_certificate(before) && custom_statement_certificate(after)
        } else {
            certificate_format(before, b"fa:report-certificate:v4")
                && certificate_format(after, b"fa:report-certificate:v4")
        })
    };
    certificate.len() <= MAX_REPORT_BUNDLE_BYTES && header().unwrap_or(false)
}

/// A trace retains every consecutive source, even a publication that has no
/// monetary effect. Custom traces require v11 sources and the rounding registry;
/// they cannot be routed through the built-in statement profile. The facade and
/// independent verifier check the complete law.
fn statement_trace_certificate(certificate: &[u8]) -> bool {
    statement_trace_family(certificate, false) || custom_statement_trace_certificate(certificate)
}

fn custom_statement_trace_certificate(certificate: &[u8]) -> bool {
    statement_trace_family(certificate, true)
}

fn statement_trace_family(certificate: &[u8], custom: bool) -> bool {
    let header = || -> Result<bool, fa_model::DecodeError> {
        let mut reader = Reader::new(certificate);
        let format: &[u8] = if custom {
            b"fa:custom-statement-trace-certificate:v1"
        } else {
            b"fa:statement-trace-certificate:v1"
        };
        if reader.bytes(64, "statement trace format")? != format {
            return Ok(false);
        }
        reader.u128("statement trace producer")?;
        reader.fixed::<32>("statement trace capability")?;
        let n = reader.count(257, "statement trace sources")?;
        if n == 0 {
            return Ok(false);
        }
        for _ in 0..n {
            let source = reader.bytes(MAX_REPORT_BUNDLE_BYTES, "statement trace source")?;
            let supported = if custom {
                custom_statement_certificate(source)
            } else {
                certificate_format(source, b"fa:report-certificate:v4")
            };
            if !supported {
                return Ok(false);
            }
        }
        Ok(true)
    };
    certificate.len() <= MAX_REPORT_BUNDLE_BYTES && header().unwrap_or(false)
}

fn reconciliation_certificate(certificate: &[u8]) -> bool {
    let header = || -> Result<bool, fa_model::DecodeError> {
        let mut reader = Reader::new(certificate);
        let format = reader.bytes(64, "reconciliation format")?;
        let portfolio = format == b"fa:aging-portfolio-certificate:v1";
        let due_date = if format == b"fa:due-date-aging-reconciliation-certificate:v1" {
            true
        } else if format == b"fa:aging-reconciliation-certificate:v1" || portfolio {
            false
        } else {
            return Ok(false);
        };
        reader.u128("reconciliation producer")?;
        reader.fixed::<32>("reconciliation capability")?;
        if portfolio {
            match reader.u8("portfolio scope")? {
                0 => {}
                1 => {
                    let count = reader.count(4096, "portfolio accounts")?;
                    let mut previous = None;
                    for _ in 0..count {
                        let account = reader.u128("portfolio account")?;
                        if previous.is_some_and(|prior| prior >= account) {
                            return Ok(false);
                        }
                        previous = Some(account);
                    }
                }
                _ => return Ok(false),
            }
        }
        let aging = reader.bytes(MAX_REPORT_BUNDLE_BYTES, "reconciliation aging")?;
        let control = reader.bytes(MAX_REPORT_BUNDLE_BYTES, "reconciliation control")?;
        let valid_aging = if due_date {
            due_date_aging_certificate(aging)
        } else {
            aging_certificate(aging)
        };
        if !valid_aging || !certificate_format(control, b"fa:report-certificate:v1") {
            return Ok(false);
        }
        let mut control = Reader::new(control);
        control.fixed::<{ b"fa:report-certificate:v1".len() }>("control format")?;
        control.str(128, "control scope")?;
        control.str(128, "control authority")?;
        if control.str(128, "control output format")? != "fa:trial-balance:v1" {
            return Ok(false);
        }
        control.fixed::<16>("control book")?;
        control.fixed::<16>("control branch")?;
        control.u64("control known-at")?;
        if control.u8("control selector")? != 1 {
            return Ok(false);
        }
        control.i32("control cutoff")?;
        Ok(true)
    };
    header().unwrap_or(false)
}

fn assemble_inner(
    journal: &Journal,
    checkpoint: &StoredCheckpoint,
    certificate: &[u8],
    known_at: CommitSeq,
    bodies: &dyn MigrationSourceInputs,
    registries: &[(String, Vec<u8>)],
    functional: Option<BookClosure<'_>>,
) -> Outcome<Bundle> {
    let inputs = bodies;
    let bodies = inputs.bodies();
    let major = if functional.is_some() {
        3
    } else if registries.is_empty() {
        1
    } else {
        2
    };
    if !(major == 1
        && (certificate_format(certificate, b"fa:report-certificate:v1")
            || certificate_format(certificate, b"fa:report-certificate:v2")
            || certificate_format(certificate, b"fa:report-certificate:v4")
            || certificate_format(certificate, b"fa:report-certificate:v8"))
        || major == 2
            && (certificate_format(certificate, b"fa:report-certificate:v4")
                || certificate_format(certificate, b"fa:report-certificate:v8")
                || custom_statement_certificate(certificate)
                || summary_certificate(certificate)
                || open_items_certificate(certificate)
                || explanation_certificate(certificate)
                || aging_certificate(certificate)
                || lots_certificate(certificate)
                || procedure_certificate(certificate)
                || native_subledger_certificate(certificate)
                || due_date_aging_certificate(certificate)
                || reconciliation_certificate(certificate)
                || roll_forward_certificate(certificate)
                || equity_certificate(certificate)
                || equity_diff_certificate(certificate)
                || cash_flow_certificate(certificate)
                || policy_cash_flow_certificate(certificate)
                || split_cash_flow_certificate(certificate)
                || indirect_cash_flow_certificate(certificate)
                || statement_diff_certificate(certificate)
                || statement_trace_certificate(certificate))
        || major == 3
            && (functional::certificate(certificate, journal, known_at)
                || functional::comparison_certificate(certificate, journal, known_at)
                || functional::trace_certificate(certificate, journal, known_at)
                || consolidation::profile(certificate, journal, known_at).is_some()))
    {
        return Ok(Err(refused(
            "offline report bundles require a native v1/v2 trial balance, summary trial balance, native-subledger reconciliation, v8 dimension-filtered trial balance, v4 statement, native or functional statement diff or trace, v5 functional statement, v10 functional trial balance, v13 functional dimension trial balance, v11/v12 custom statement, v6/v7 one-book consolidation, JET round-amount/period-end v1/v2, post-closing v1, exact duplicates v1, round-amount density v1, first-digit Benford v2 or one-account LIBR v2 procedure, or v3 open-item report, balance explanation, lot schedule, effective-date aging, aging reconciliation, roll-forward, equity roll-forward or equity comparison, direct, policy, split or indirect cash-flow with authenticated registries",
        )));
    }
    if known_at > journal.through_seq || checkpoint.checkpoint.body.statement != journal.statement()
    {
        return Ok(Err(refused(
            "the checkpoint must authenticate a complete prefix through the report's known-at and any retained time frontier",
        )));
    }
    let prefix = journal.prefix_proof()?;
    let mut budget = 4usize + REPORT_BUNDLE_FORMAT.len() + 4 + 4 * 3 + 4 * 2;
    for len in [certificate.len(), checkpoint.bytes.len(), prefix.len()] {
        budget = budget.saturating_add(len);
    }
    if major >= 2 {
        budget = budget.saturating_add(4);
        for (name, canonical) in registries {
            budget = budget
                .saturating_add(8)
                .saturating_add(name.len())
                .saturating_add(canonical.len());
        }
    }
    if let Some(closure) = &functional {
        budget = budget
            .saturating_add(8)
            .saturating_add(closure.book_spec.len());
        for (_, payload) in closure.rates {
            budget = budget.saturating_add(36).saturating_add(payload.len());
        }
    }
    let mut ordered = Vec::new();
    let mut supplied = BTreeSet::new();
    for (index, leaf) in journal.leaves.iter().enumerate() {
        budget = budget.saturating_add(8).saturating_add(leaf.payload.len());
        if budget > MAX_REPORT_BUNDLE_BYTES {
            return Ok(Err(refused("the complete report closure exceeds 64 MiB")));
        }
        if leaf.authenticated_record()?.is_none() {
            return Ok(Err(refused(format!(
                "checkpoint leaf {index} does not match its record"
            ))));
        }
        if !leaf.envelope.is_entry() || leaf.envelope.commit_seq > known_at {
            continue;
        }
        let entry = Entry::decode(&leaf.payload)?;
        if entry.proposal.class == EntryClass::MIGRATION_CONTROL
            && let Some(ControlPayload::MigrationControl {
                run_ref,
                kind: 0,
                tie_out_digest,
            }) = &entry.proposal.control
            && let Some(body) = bodies.get(run_ref)
        {
            if !supplied.insert(*run_ref)
                || body.vid() != *run_ref
                || body.digest()? != *tie_out_digest
            {
                return Ok(Err(refused(
                    "a migration body does not match its unique Open control",
                )));
            }
            let bytes = body.canonical_bytes()?;
            budget = budget.saturating_add(12).saturating_add(bytes.len());
            ordered.push((index as u64, bytes));
        }
    }
    if supplied.len() != bodies.len() || budget > MAX_REPORT_BUNDLE_BYTES {
        return Ok(Err(refused(
            "the migration closure is unmatched or exceeds 64 MiB",
        )));
    }
    let source_witnesses = match crate::migration_balance::source_witnesses(
        journal,
        known_at,
        &supplied,
        bodies,
        inputs.source_manifests(),
    )? {
        Ok(witnesses) => witnesses,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let minor = u16::from(!source_witnesses.is_empty());
    if minor == 1 {
        budget = budget.saturating_add(4);
        for (_, bytes) in &source_witnesses {
            budget = budget.saturating_add(12).saturating_add(bytes.len());
        }
    }
    if budget > MAX_REPORT_BUNDLE_BYTES {
        return Ok(Err(refused(
            "the complete source-bound report closure exceeds 64 MiB",
        )));
    }
    let mut w = Writer::with_capacity(budget);
    w.bytes(REPORT_BUNDLE_FORMAT)
        .u16(major)
        .u16(minor)
        .bytes(certificate)
        .bytes(&checkpoint.bytes)
        .bytes(&prefix)
        .list(&journal.leaves, |w, leaf| {
            w.u32(u32::try_from(leaf.proposal_len).unwrap_or(u32::MAX))
                .bytes(&leaf.payload);
        })
        .list(&ordered, |w, (index, bytes)| {
            w.u64(*index).bytes(bytes);
        });
    if minor == 1 {
        w.list(&source_witnesses, |w, (index, bytes)| {
            w.u64(*index as u64).bytes(bytes);
        });
    }
    if major >= 2 {
        w.list(registries, |w, (name, canonical)| {
            w.str(name).bytes(canonical);
        });
    }
    if let Some(closure) = functional {
        w.bytes(closure.book_spec)
            .list(closure.rates, |w, (oid, payload)| {
                w.fixed(&oid.0).bytes(payload);
            });
    }
    let bytes = w.finish().map_err(fa_model::EntryError::from)?;
    if bytes.len() > MAX_REPORT_BUNDLE_BYTES {
        return Ok(Err(refused("the complete report closure exceeds 64 MiB")));
    }
    let mut hash = Hasher::new();
    hash.update(REPORT_BUNDLE_FORMAT);
    hash.update(&bytes);
    Ok(Ok(Bundle {
        bytes,
        digest: hash.finalize().0,
    }))
}

#[cfg(test)]
mod format_tests {
    use super::*;
    fn native_header(version: u8, output: &str, selector: u8) -> Vec<u8> {
        let mut w = Writer::new();
        w.fixed(format!("fa:report-certificate:v{version}").as_bytes())
            .str("fa-fold-over-prefix")
            .str("embedded-owner")
            .str(output)
            .fixed(&[3; 16])
            .fixed(&[0; 16])
            .u64(9)
            .u8(selector)
            .i32(30);
        w.finish().unwrap()
    }

    fn reconciliation_header(source: &[u8], control: &[u8]) -> Vec<u8> {
        let mut aging = Writer::new();
        aging
            .bytes(b"fa:aging-certificate:v1")
            .u128(7)
            .fixed(&[9; 32])
            .bytes(source);
        let mut outer = Writer::new();
        outer
            .bytes(b"fa:aging-reconciliation-certificate:v1")
            .u128(7)
            .fixed(&[8; 32])
            .bytes(&aging.finish().unwrap())
            .bytes(control);
        outer.finish().unwrap()
    }

    #[test]
    fn lot_v2_routing_retains_selected_trunk_open_item_source_requirements() {
        let source = |branch: [u8; 16], selector: u8, selected: u8| {
            let mut writer = Writer::new();
            writer
                .fixed(b"fa:report-certificate:v3")
                .str("fa-fold-over-prefix")
                .str("embedded-owner")
                .str("fa:open-items:v1")
                .fixed(&[3; 16])
                .fixed(&branch)
                .u64(9)
                .u8(selector)
                .u8(selected)
                .u128(7);
            writer.finish().unwrap()
        };
        let wrap = |version: u8, source: &[u8]| {
            let mut writer = Writer::new();
            writer
                .bytes(format!("fa:lots-certificate:v{version}").as_bytes())
                .u128(7)
                .fixed(&[9; 32])
                .bytes(source);
            writer.finish().unwrap()
        };
        let valid = source([0; 16], 1, 1);
        for version in [1, 2] {
            assert!(lots_certificate(&wrap(version, &valid)));
            for wrong in [
                source([1; 16], 1, 1),
                source([0; 16], 0, 1),
                source([0; 16], 1, 0),
                native_header(1, "fa:open-items:v1", 1),
            ] {
                assert!(!lots_certificate(&wrap(version, &wrong)));
            }
            let truncated = wrap(version, &valid);
            assert!(!lots_certificate(&truncated[..truncated.len() - 1]));
        }
        for version in [0, 3, 10, 20] {
            assert!(!lots_certificate(&wrap(version, &valid)));
        }
    }

    #[test]
    fn functional_dimension_routing_requires_v13_output_and_selector() {
        let journal =
            Journal::from_records(fa_model::Id128([3; 16]), CommitSeq(9), Vec::new()).unwrap();
        let valid = native_header(13, "fa:functional-dimension-trial-balance:v1", 11);
        assert!(functional::certificate(&valid, &journal, CommitSeq(9)));
        assert!(!functional::certificate(&valid, &journal, CommitSeq(8)));
        for malformed in [
            native_header(13, "fa:dimension-trial-balance:v1", 11),
            native_header(13, "fa:functional-trial-balance:v1", 11),
            native_header(13, "fa:functional-dimension-trial-balance:v1", 8),
            native_header(8, "fa:functional-dimension-trial-balance:v1", 11),
            native_header(10, "fa:functional-dimension-trial-balance:v1", 11),
            native_header(130, "fa:functional-dimension-trial-balance:v1", 11),
        ] {
            assert!(!functional::certificate(&malformed, &journal, CommitSeq(9)));
        }
    }

    #[test]
    fn custom_statement_routing_keeps_native_and_functional_closures_distinct() {
        let journal =
            Journal::from_records(fa_model::Id128([3; 16]), CommitSeq(9), Vec::new()).unwrap();
        let native = native_header(11, "fa:custom-statement-report:v1", 9);
        let functional = native_header(12, "fa:functional-custom-statement:v1", 10);
        assert!(custom_statement_certificate(&native));
        assert!(!custom_statement_certificate(&functional));
        assert!(functional::certificate(&functional, &journal, CommitSeq(9)));
        assert!(!functional::certificate(&native, &journal, CommitSeq(9)));
        assert!(!functional::certificate(
            &functional,
            &journal,
            CommitSeq(8)
        ));
        for malformed in [
            native_header(11, "fa:functional-custom-statement:v1", 9),
            native_header(11, "fa:custom-statement-report:v1", 10),
            native_header(12, "fa:custom-statement-report:v1", 10),
            native_header(12, "fa:functional-custom-statement:v1", 9),
            native_header(110, "fa:custom-statement-report:v1", 9),
            native_header(120, "fa:functional-custom-statement:v1", 10),
        ] {
            assert!(!custom_statement_certificate(&malformed));
            assert!(!functional::certificate(&malformed, &journal, CommitSeq(9)));
        }
    }

    #[test]
    fn summary_routing_requires_an_exact_sequence_native_trial_balance_source() {
        let wrap = |format: &[u8], source: &[u8]| {
            let mut writer = Writer::new();
            writer.bytes(format).bytes(source);
            writer.finish().unwrap()
        };
        let format = b"fa:summary-certificate:v1";
        for selector in [0, 1, 2] {
            assert!(summary_certificate(&wrap(
                format,
                &native_header(1, "fa:trial-balance:v1", selector),
            )));
        }
        for source in [
            native_header(1, "fa:trial-balance:v1", 3),
            native_header(2, "fa:trial-balance:v1", 1),
            native_header(10, "fa:functional-trial-balance:v1", 1),
            native_header(1, "fa:statement:v1", 0),
            native_header(4, "fa:statement:v1", 0),
            Vec::new(),
        ] {
            assert!(!summary_certificate(&wrap(format, &source)));
        }
        let native = native_header(1, "fa:trial-balance:v1", 1);
        for version in [2, 10] {
            assert!(!summary_certificate(&wrap(
                format!("fa:summary-certificate:v{version}").as_bytes(),
                &native,
            )));
        }
        let valid = wrap(format, &native);
        assert!(!certificate_format(&valid, b"fa:report-certificate:v1"));
        assert!(!summary_certificate(&valid[..valid.len() - 1]));
        let mut fork = Writer::new();
        fork.fixed(b"fa:report-certificate:v1")
            .str("fa-fold-over-prefix")
            .str("embedded-owner")
            .str("fa:trial-balance:v1")
            .fixed(&[3; 16])
            .fixed(&[1; 16])
            .u64(9)
            .u8(1)
            .i32(30);
        assert!(!summary_certificate(&wrap(format, &fork.finish().unwrap())));
    }

    #[test]
    fn reconciliation_routing_requires_aging_and_exact_sequence_stock_control() {
        let source = native_header(3, "fa:open-items:v1", 1);
        let control = native_header(1, "fa:trial-balance:v1", 1);
        let outer = reconciliation_header(&source, &control);
        assert!(reconciliation_certificate(&outer));
        assert!(!aging_certificate(&outer));
        assert!(!certificate_format(&outer, b"fa:report-certificate:v1"));
        for wrong in [
            native_header(1, "fa:trial-balance:v1", 0),
            native_header(1, "fa:trial-balance:v1", 2),
            native_header(2, "fa:trial-balance:v1", 1),
            native_header(10, "fa:functional-trial-balance:v1", 1),
            native_header(1, "fa:open-items:v1", 1),
        ] {
            assert!(!reconciliation_certificate(&reconciliation_header(
                &source, &wrong
            )));
        }
        let explanation = native_header(3, "fa:balance-explanation:v1", 0);
        assert!(!reconciliation_certificate(&reconciliation_header(
            &explanation,
            &control
        )));
        assert!(!reconciliation_certificate(&outer[..outer.len() - 1]));
    }

    #[test]
    fn statement_diff_routing_requires_two_exact_native_statement_sources() {
        let native = native_header(4, "fa:statement:v1", 0);
        let wrap = |format: &[u8], before: &[u8], after: &[u8]| {
            let mut writer = Writer::new();
            writer
                .bytes(format)
                .u128(7)
                .fixed(&[8; 32])
                .bytes(before)
                .bytes(after);
            writer.finish().unwrap()
        };
        let format = b"fa:statement-diff-certificate:v1";
        let valid = wrap(format, &native, &native);
        assert!(statement_diff_certificate(&valid));
        for wrong in [
            native_header(1, "fa:trial-balance:v1", 0),
            native_header(5, "fa:functional-statement:v1", 0),
            native_header(40, "fa:statement:v1", 0),
            Vec::new(),
        ] {
            assert!(!statement_diff_certificate(&wrap(format, &wrong, &native)));
            assert!(!statement_diff_certificate(&wrap(format, &native, &wrong)));
        }
        assert!(!statement_diff_certificate(&wrap(
            b"fa:functional-statement-diff-certificate:v1",
            &native,
            &native,
        )));
        for end in 0..valid.len() {
            assert!(!statement_diff_certificate(&valid[..end]));
        }
        assert!(!certificate_format(&valid, b"fa:report-certificate:v4"));
    }

    #[test]
    fn equity_comparison_routes_only_two_original_v2_native_equity_sources() {
        let equity = |version: u8, source: &[u8]| {
            let mut roll = Writer::new();
            roll.bytes(b"fa:roll-forward-certificate:v1")
                .bytes(source)
                .list(&[7_u128], |w, id| {
                    w.u128(*id);
                })
                .list(&[1_u32], |w, unit| {
                    w.u32(*unit);
                })
                .str("Equity")
                .i32(1)
                .i32(30);
            let mut w = Writer::new();
            w.bytes(format!("fa:equity-roll-forward-certificate:v{version}").as_bytes())
                .bytes(&roll.finish().unwrap());
            w.finish().unwrap()
        };
        let wrap = |before: &[u8], after: &[u8], output: &[u8]| {
            let mut w = Writer::new();
            w.bytes(b"fa:equity-roll-forward-diff-certificate:v1")
                .bytes(before)
                .bytes(after)
                .u128(7)
                .fixed(&[8; 32])
                .bytes(output)
                .fixed(&[9; 32]);
            w.finish().unwrap()
        };
        let mut output = Writer::new();
        output.bytes(b"fa:equity-roll-forward-diff:v1");
        let output = output.finish().unwrap();
        let native = native_header(1, "fa:trial-balance:v1", 1);
        let v2 = equity(2, &native);
        let valid = wrap(&v2, &v2, &output);
        assert!(equity_diff_certificate(&valid));
        assert!(!equity_certificate(&valid));
        assert!(!statement_diff_certificate(&valid));
        assert!(!custom_statement_diff_certificate(&valid));
        for wrong in [
            equity(1, &native),
            equity(20, &native),
            equity(2, &native_header(1, "fa:trial-balance:v1", 0)),
            equity(2, &native_header(2, "fa:trial-balance:v1", 1)),
            equity(2, &native_header(10, "fa:functional-trial-balance:v1", 1)),
            native.clone(),
            valid.clone(),
            Vec::new(),
        ] {
            assert!(!equity_diff_certificate(&wrap(&wrong, &v2, &output)));
            assert!(!equity_diff_certificate(&wrap(&v2, &wrong, &output)));
        }
        assert!(!equity_diff_certificate(&wrap(&v2, &v2, &v2)));
        for end in 0..valid.len() {
            assert!(!equity_diff_certificate(&valid[..end]));
        }
        let mut trailing = valid;
        trailing.push(0);
        assert!(!equity_diff_certificate(&trailing));
    }

    #[test]
    fn functional_comparison_routing_requires_v5_sources_in_one_ordered_book_prefix() {
        let journal =
            Journal::from_records(fa_model::Id128([3; 16]), CommitSeq(12), Vec::new()).unwrap();
        let source = |version: u8, book: [u8; 16], branch: [u8; 16], at: u64, selector: u8| {
            let mut w = Writer::new();
            w.fixed(format!("fa:report-certificate:v{version}").as_bytes())
                .str("fa-fold-over-prefix")
                .str("embedded-owner")
                .str("fa:functional-statement:v1")
                .fixed(&book)
                .fixed(&branch)
                .u64(at)
                .u8(selector);
            w.finish().unwrap()
        };
        let wrap = |before: &[u8], after: &[u8]| {
            let mut w = Writer::new();
            w.bytes(b"fa:functional-statement-diff-certificate:v1")
                .u128(7)
                .fixed(&[8; 32])
                .bytes(before)
                .bytes(after);
            w.finish().unwrap()
        };
        let before = source(5, [3; 16], [0; 16], 8, 3);
        let after = source(5, [3; 16], [0; 16], 9, 3);
        let valid = wrap(&before, &after);
        assert!(functional::comparison_certificate(
            &valid,
            &journal,
            CommitSeq(9)
        ));
        assert!(!statement_diff_certificate(&valid));
        assert!(!functional::comparison_certificate(
            &valid,
            &journal,
            CommitSeq(10)
        ));
        for wrong in [
            source(4, [3; 16], [0; 16], 8, 3),
            source(50, [3; 16], [0; 16], 8, 3),
            source(5, [4; 16], [0; 16], 8, 3),
            source(5, [3; 16], [1; 16], 8, 3),
            source(5, [3; 16], [0; 16], 8, 2),
            source(5, [3; 16], [0; 16], 10, 3),
        ] {
            assert!(!functional::comparison_certificate(
                &wrap(&wrong, &after),
                &journal,
                CommitSeq(9)
            ));
        }
        for end in 0..valid.len() {
            assert!(!functional::comparison_certificate(
                &valid[..end],
                &journal,
                CommitSeq(9)
            ));
        }
    }

    #[test]
    fn custom_native_comparisons_route_only_two_v11_sources_to_the_rounding_profile() {
        let native = native_header(11, "fa:custom-statement-report:v1", 9);
        let wrap = |format: &[u8], before: &[u8], after: &[u8]| {
            let mut w = Writer::new();
            w.bytes(format)
                .u128(7)
                .fixed(&[8; 32])
                .bytes(before)
                .bytes(after);
            w.finish().unwrap()
        };
        let format = b"fa:custom-statement-diff-certificate:v1";
        let valid = wrap(format, &native, &native);
        assert!(custom_statement_diff_certificate(&valid));
        assert!(statement_diff_certificate(&valid));
        assert!(!custom_statement_certificate(&valid));
        for wrong in [
            native_header(4, "fa:statement:v1", 0),
            native_header(5, "fa:functional-statement:v1", 3),
            native_header(12, "fa:functional-custom-statement:v1", 10),
            native_header(110, "fa:custom-statement-report:v1", 9),
            native_header(11, "fa:custom-statement-report:v1", 10),
            native_header(11, "fa:functional-custom-statement:v1", 9),
            Vec::new(),
        ] {
            assert!(!statement_diff_certificate(&wrap(format, &wrong, &native)));
            assert!(!statement_diff_certificate(&wrap(format, &native, &wrong)));
        }
        for wrong_format in [
            b"fa:statement-diff-certificate:v1".as_slice(),
            b"fa:functional-custom-statement-diff-certificate:v1".as_slice(),
        ] {
            assert!(!statement_diff_certificate(&wrap(
                wrong_format,
                &native,
                &native
            )));
        }
        for end in 0..valid.len() {
            assert!(!statement_diff_certificate(&valid[..end]));
        }
    }

    #[test]
    fn custom_functional_comparisons_route_only_two_v12_sources_in_one_book_prefix() {
        let journal =
            Journal::from_records(fa_model::Id128([3; 16]), CommitSeq(12), Vec::new()).unwrap();
        let source =
            |version: u8, output: &str, book: [u8; 16], branch: [u8; 16], at: u64, selector: u8| {
                let mut w = Writer::new();
                w.fixed(format!("fa:report-certificate:v{version}").as_bytes())
                    .str("fa-fold-over-prefix")
                    .str("embedded-owner")
                    .str(output)
                    .fixed(&book)
                    .fixed(&branch)
                    .u64(at)
                    .u8(selector);
                w.finish().unwrap()
            };
        let wrap = |format: &[u8], before: &[u8], after: &[u8]| {
            let mut w = Writer::new();
            w.bytes(format)
                .u128(7)
                .fixed(&[8; 32])
                .bytes(before)
                .bytes(after);
            w.finish().unwrap()
        };
        let output = "fa:functional-custom-statement:v1";
        let format = b"fa:functional-custom-statement-diff-certificate:v1";
        let before = source(12, output, [3; 16], [0; 16], 8, 10);
        let after = source(12, output, [3; 16], [0; 16], 9, 10);
        let valid = wrap(format, &before, &after);
        assert!(functional::comparison_certificate(
            &valid,
            &journal,
            CommitSeq(9)
        ));
        assert!(!statement_diff_certificate(&valid));
        assert!(!custom_statement_diff_certificate(&valid));
        assert!(!functional::comparison_certificate(
            &valid,
            &journal,
            CommitSeq(10)
        ));
        for wrong in [
            source(11, "fa:custom-statement-report:v1", [3; 16], [0; 16], 8, 9),
            source(5, "fa:functional-statement:v1", [3; 16], [0; 16], 8, 3),
            source(120, output, [3; 16], [0; 16], 8, 10),
            source(12, "fa:functional-statement:v1", [3; 16], [0; 16], 8, 10),
            source(12, output, [4; 16], [0; 16], 8, 10),
            source(12, output, [3; 16], [1; 16], 8, 10),
            source(12, output, [3; 16], [0; 16], 8, 9),
            source(12, output, [3; 16], [0; 16], 10, 10),
        ] {
            assert!(!functional::comparison_certificate(
                &wrap(format, &wrong, &after),
                &journal,
                CommitSeq(9)
            ));
            assert!(!functional::comparison_certificate(
                &wrap(format, &before, &wrong),
                &journal,
                CommitSeq(9)
            ));
        }
        for wrong_format in [
            b"fa:functional-statement-diff-certificate:v1".as_slice(),
            b"fa:custom-statement-diff-certificate:v1".as_slice(),
        ] {
            assert!(!functional::comparison_certificate(
                &wrap(wrong_format, &before, &after),
                &journal,
                CommitSeq(9)
            ));
        }
        for end in 0..valid.len() {
            assert!(!functional::comparison_certificate(
                &valid[..end],
                &journal,
                CommitSeq(9)
            ));
        }
    }

    #[test]
    fn custom_native_traces_keep_every_v11_source_in_the_rounding_profile() {
        let native = native_header(11, "fa:custom-statement-report:v1", 9);
        let wrap = |format: &[u8], sources: &[Vec<u8>]| {
            let mut writer = Writer::new();
            writer
                .bytes(format)
                .u128(7)
                .fixed(&[8; 32])
                .list(sources, |writer, source| {
                    writer.bytes(source);
                });
            writer.finish().unwrap()
        };
        let format = b"fa:custom-statement-trace-certificate:v1";
        let sources = vec![native.clone(); 3];
        let valid = wrap(format, &sources);
        assert!(custom_statement_trace_certificate(&valid));
        assert!(statement_trace_certificate(&valid));
        assert!(!statement_trace_family(&valid, false));
        assert!(!custom_statement_diff_certificate(&valid));
        for wrong in [
            native_header(4, "fa:statement:v1", 0),
            native_header(5, "fa:functional-statement:v1", 3),
            native_header(12, "fa:functional-custom-statement:v1", 10),
            native_header(110, "fa:custom-statement-report:v1", 9),
            native_header(11, "fa:custom-statement-report:v1", 10),
            native_header(11, "fa:functional-custom-statement:v1", 9),
            Vec::new(),
        ] {
            for index in 0..sources.len() {
                let mut changed = sources.clone();
                changed[index] = wrong.clone();
                assert!(!statement_trace_certificate(&wrap(format, &changed)));
            }
        }
        for wrong_format in [
            b"fa:statement-trace-certificate:v1".as_slice(),
            b"fa:functional-custom-statement-trace-certificate:v1".as_slice(),
        ] {
            assert!(!statement_trace_certificate(&wrap(wrong_format, &sources)));
        }
        for end in 0..valid.len() {
            assert!(!statement_trace_certificate(&valid[..end]));
        }
        for count in [0, 1, 257, 258] {
            assert_eq!(
                custom_statement_trace_certificate(&wrap(format, &vec![native.clone(); count])),
                matches!(count, 1 | 257)
            );
        }
    }

    #[test]
    fn custom_functional_traces_route_every_original_v12_frontier() {
        let journal =
            Journal::from_records(fa_model::Id128([3; 16]), CommitSeq(300), Vec::new()).unwrap();
        let source =
            |version: u8, output: &str, book: [u8; 16], branch: [u8; 16], at: u64, selector: u8| {
                let mut writer = Writer::new();
                writer
                    .fixed(format!("fa:report-certificate:v{version}").as_bytes())
                    .str("fa-fold-over-prefix")
                    .str("embedded-owner")
                    .str(output)
                    .fixed(&book)
                    .fixed(&branch)
                    .u64(at)
                    .u8(selector);
                writer.finish().unwrap()
            };
        let wrap = |format: &[u8], sources: &[Vec<u8>]| {
            let mut writer = Writer::new();
            writer
                .bytes(format)
                .u128(7)
                .fixed(&[8; 32])
                .list(sources, |writer, source| {
                    writer.bytes(source);
                });
            writer.finish().unwrap()
        };
        let format = b"fa:functional-custom-statement-trace-certificate:v1";
        let output = "fa:functional-custom-statement:v1";
        let sources: Vec<_> = (8..=10)
            .map(|at| source(12, output, [3; 16], [0; 16], at, 10))
            .collect();
        let valid = wrap(format, &sources);
        assert!(functional::trace_certificate(
            &valid,
            &journal,
            CommitSeq(10)
        ));
        assert!(!statement_trace_certificate(&valid));
        assert!(!functional::comparison_certificate(
            &valid,
            &journal,
            CommitSeq(10)
        ));
        for wrong in [
            source(5, "fa:functional-statement:v1", [3; 16], [0; 16], 9, 3),
            source(11, "fa:custom-statement-report:v1", [3; 16], [0; 16], 9, 9),
            source(120, output, [3; 16], [0; 16], 9, 10),
            source(12, "fa:functional-statement:v1", [3; 16], [0; 16], 9, 10),
            source(12, output, [4; 16], [0; 16], 9, 10),
            source(12, output, [3; 16], [1; 16], 9, 10),
            source(12, output, [3; 16], [0; 16], 9, 9),
            source(12, output, [3; 16], [0; 16], 8, 10),
            source(12, output, [3; 16], [0; 16], 10, 10),
        ] {
            let mut changed = sources.clone();
            changed[1] = wrong;
            assert!(!functional::trace_certificate(
                &wrap(format, &changed),
                &journal,
                CommitSeq(10)
            ));
        }
        for wrong_format in [
            b"fa:functional-statement-trace-certificate:v1".as_slice(),
            b"fa:custom-statement-trace-certificate:v1".as_slice(),
        ] {
            assert!(!functional::trace_certificate(
                &wrap(wrong_format, &sources),
                &journal,
                CommitSeq(10)
            ));
        }
        for at in [1, 9, 11] {
            assert!(!functional::trace_certificate(
                &valid,
                &journal,
                CommitSeq(at)
            ));
        }
        let omitted = vec![sources[0].clone(), sources[2].clone()];
        assert!(!functional::trace_certificate(
            &wrap(format, &omitted),
            &journal,
            CommitSeq(10)
        ));
        for end in 0..valid.len() {
            assert!(!functional::trace_certificate(
                &valid[..end],
                &journal,
                CommitSeq(10)
            ));
        }
        for count in [0, 1, 257, 258] {
            let bounded: Vec<_> = (0..count)
                .map(|at| source(12, output, [3; 16], [0; 16], at, 10))
                .collect();
            assert_eq!(
                functional::trace_certificate(
                    &wrap(format, &bounded),
                    &journal,
                    CommitSeq(count.saturating_sub(1))
                ),
                matches!(count, 1 | 257)
            );
        }
    }

    #[test]
    fn functional_trace_routes_only_complete_bounded_consecutive_v5_sources() {
        let journal =
            Journal::from_records(fa_model::Id128([3; 16]), CommitSeq(300), Vec::new()).unwrap();
        let source = |version: u8, book: [u8; 16], branch: [u8; 16], at: u64, selector: u8| {
            let mut writer = Writer::new();
            writer
                .fixed(format!("fa:report-certificate:v{version}").as_bytes())
                .str("fa-fold-over-prefix")
                .str("embedded-owner")
                .str("fa:functional-statement:v1")
                .fixed(&book)
                .fixed(&branch)
                .u64(at)
                .u8(selector);
            writer.finish().unwrap()
        };
        let wrap = |format: &[u8], sources: &[Vec<u8>]| {
            let mut writer = Writer::new();
            writer
                .bytes(format)
                .u128(7)
                .fixed(&[8; 32])
                .u32(sources.len() as u32);
            for source in sources {
                writer.bytes(source);
            }
            writer.finish().unwrap()
        };
        let format = b"fa:functional-statement-trace-certificate:v1";
        let sources: Vec<_> = (8..=10)
            .map(|at| source(5, [3; 16], [0; 16], at, 3))
            .collect();
        let valid = wrap(format, &sources);
        assert!(functional::trace_certificate(
            &valid,
            &journal,
            CommitSeq(10)
        ));
        assert!(!statement_trace_certificate(&valid));
        assert!(!functional::comparison_certificate(
            &valid,
            &journal,
            CommitSeq(10)
        ));
        assert!(!functional::trace_certificate(
            &valid,
            &journal,
            CommitSeq(9)
        ));
        assert!(!functional::trace_certificate(
            &valid,
            &journal,
            CommitSeq(11)
        ));
        assert!(!functional::trace_certificate(
            &wrap(b"fa:statement-trace-certificate:v1", &sources),
            &journal,
            CommitSeq(10)
        ));
        for bad in [
            source(4, [3; 16], [0; 16], 9, 3),
            source(50, [3; 16], [0; 16], 9, 3),
            source(10, [3; 16], [0; 16], 9, 8),
            source(5, [4; 16], [0; 16], 9, 3),
            source(5, [3; 16], [1; 16], 9, 3),
            source(5, [3; 16], [0; 16], 9, 2),
            source(5, [3; 16], [0; 16], 8, 3),
            source(5, [3; 16], [0; 16], 10, 3),
            valid.clone(),
        ] {
            let mut changed = sources.clone();
            changed[1] = bad;
            assert!(!functional::trace_certificate(
                &wrap(format, &changed),
                &journal,
                CommitSeq(10)
            ));
        }
        let omitted = vec![sources[0].clone(), sources[2].clone()];
        assert!(!functional::trace_certificate(
            &wrap(format, &omitted),
            &journal,
            CommitSeq(10)
        ));
        for end in 0..valid.len() {
            assert!(!functional::trace_certificate(
                &valid[..end],
                &journal,
                CommitSeq(10)
            ));
        }
        for count in [0, 1, 257, 258] {
            let bounded: Vec<_> = (0..count)
                .map(|at| source(5, [3; 16], [0; 16], at, 3))
                .collect();
            assert_eq!(
                functional::trace_certificate(
                    &wrap(format, &bounded),
                    &journal,
                    CommitSeq(count.saturating_sub(1))
                ),
                matches!(count, 1 | 257)
            );
        }
        assert!(!functional::trace_certificate(
            &valid,
            &journal,
            CommitSeq(1)
        ));
    }

    #[test]
    fn cash_flow_routes_only_its_exact_bounded_roll_forward_source_chain() {
        let wrap = |format: &[u8], source: &[u8]| {
            let mut writer = Writer::new();
            writer.bytes(format).bytes(source);
            writer.finish().unwrap()
        };
        let source = |version: u8, branch: [u8; 16], selector: u8| {
            let mut writer = Writer::new();
            writer
                .fixed(format!("fa:report-certificate:v{version}").as_bytes())
                .str("fa-fold-over-prefix")
                .str("native read certificate")
                .str("fa:trial-balance:v1")
                .fixed(&[1; 16])
                .fixed(&branch)
                .u64(7)
                .u8(selector)
                .i32(20_500);
            writer.finish().unwrap()
        };
        let roll_forward = |source: &[u8]| {
            let mut writer = Writer::new();
            writer
                .bytes(b"fa:roll-forward-certificate:v1")
                .bytes(source)
                .list(&[1_u128], |writer, account| {
                    writer.u128(*account);
                })
                .list(&[0_u32], |writer, unit| {
                    writer.u32(*unit);
                })
                .str("Cash")
                .i32(20_000)
                .i32(20_500);
            writer.finish().unwrap()
        };
        let cash = b"fa:cash-flow-certificate:v1".as_slice();
        let policy = b"fa:cash-flow-policy-certificate:v1".as_slice();
        let split = b"fa:cash-flow-split-certificate:v1".as_slice();
        let native = source(1, [0; 16], 1);
        let roll_forward_bytes = roll_forward(&native);
        let direct = wrap(cash, &roll_forward_bytes);
        let classified = wrap(policy, &direct);
        let split_cash = wrap(split, &roll_forward_bytes);
        let indirect = |kind: Option<u8>, source: &[u8]| {
            let mut writer = Writer::new();
            if let Some(kind) = kind {
                writer
                    .bytes(b"fa:indirect-cash-flow-certificate:v2")
                    .u8(kind);
            } else {
                writer.bytes(b"fa:indirect-cash-flow-certificate:v1");
            }
            writer.bytes(source);
            writer.finish().unwrap()
        };
        assert!(indirect_cash_flow_certificate(&indirect(None, &direct)));
        assert!(indirect_cash_flow_certificate(&indirect(
            Some(1),
            &classified
        )));
        assert!(indirect_cash_flow_certificate(&indirect(
            Some(2),
            &split_cash
        )));
        for wrong in [
            indirect(None, &classified),
            indirect(None, &split_cash),
            indirect(Some(0), &direct),
            indirect(Some(1), &direct),
            indirect(Some(1), &split_cash),
            indirect(Some(2), &classified),
            indirect(Some(3), &split_cash),
            indirect(None, &native),
            wrap(b"fa:indirect-cash-flow-certificate:v3", &direct),
        ] {
            assert!(!indirect_cash_flow_certificate(&wrong));
        }
        for valid in [
            indirect(None, &direct),
            indirect(Some(1), &classified),
            indirect(Some(2), &split_cash),
        ] {
            for end in 0..valid.len() {
                assert!(!indirect_cash_flow_certificate(&valid[..end]));
            }
        }
        assert!(cash_flow_certificate(&direct));
        assert!(policy_cash_flow_certificate(&classified));
        assert!(split_cash_flow_certificate(&split_cash));
        assert!(!split_cash_flow_certificate(&direct));
        assert!(!split_cash_flow_certificate(&classified));
        assert!(!split_cash_flow_certificate(&wrap(split, &native)));
        assert!(!split_cash_flow_certificate(&wrap(split, &direct)));
        assert!(!cash_flow_certificate(&classified));
        assert!(!policy_cash_flow_certificate(&direct));
        assert!(!cash_flow_certificate(&wrap(cash, &native)));
        assert!(!policy_cash_flow_certificate(&wrap(
            policy,
            &roll_forward_bytes
        )));
        for wrong in [
            source(10, [0; 16], 1),
            source(2, [0; 16], 1),
            source(1, [1; 16], 1),
            source(1, [0; 16], 0),
        ] {
            let direct = wrap(cash, &roll_forward(&wrong));
            assert!(!cash_flow_certificate(&direct));
            assert!(!policy_cash_flow_certificate(&wrap(policy, &direct)));
            assert!(!split_cash_flow_certificate(&wrap(
                split,
                &roll_forward(&wrong),
            )));
        }
        for format in [
            b"fa:cash-flow-certificate:v2".as_slice(),
            b"fa:cash-flow-split-certificate:v1".as_slice(),
            b"fa:indirect-cash-flow-certificate:v1".as_slice(),
        ] {
            assert!(!cash_flow_certificate(&wrap(format, &roll_forward_bytes)));
        }
        assert!(!policy_cash_flow_certificate(&wrap(
            b"fa:cash-flow-policy-certificate:v2",
            &direct,
        )));
        assert!(!split_cash_flow_certificate(&wrap(
            b"fa:cash-flow-split-certificate:v2",
            &roll_forward_bytes,
        )));
        let mut truncated = Writer::new();
        truncated.bytes(cash).u32(u32::MAX);
        assert!(!cash_flow_certificate(&truncated.finish().unwrap()));
        for end in 0..classified.len() {
            assert!(!policy_cash_flow_certificate(&classified[..end]));
        }
        for end in 0..split_cash.len() {
            assert!(!split_cash_flow_certificate(&split_cash[..end]));
        }
    }

    #[test]
    fn roll_forward_routing_requires_its_exact_sequence_trunk_closing_source() {
        let source = |version: u8, branch: [u8; 16], selector: u8, through: i32| {
            let mut writer = Writer::new();
            writer
                .fixed(format!("fa:report-certificate:v{version}").as_bytes())
                .str("fa-fold-over-prefix")
                .str("native read certificate")
                .str("fa:trial-balance:v1")
                .fixed(&[1; 16])
                .fixed(&branch)
                .u64(7)
                .u8(selector)
                .i32(through);
            writer.finish().unwrap()
        };
        let wrapper = |source: &[u8], through: i32| {
            let mut writer = Writer::new();
            writer
                .bytes(b"fa:roll-forward-certificate:v1")
                .bytes(source)
                .list(&[1_u128], |writer, account| {
                    writer.u128(*account);
                })
                .list(&[0_u32], |writer, unit| {
                    writer.u32(*unit);
                })
                .str("Lead schedule")
                .i32(0)
                .i32(through);
            writer.finish().unwrap()
        };
        // Routing recognizes the supported header; these fixtures deliberately
        // do not claim to be complete or verified accounting certificates.
        let valid = source(1, [0; 16], 1, 31);
        assert!(roll_forward_certificate(&wrapper(&valid, 31)));
        assert!(!roll_forward_certificate(&valid));
        for invalid in [
            source(10, [0; 16], 1, 31),
            source(2, [0; 16], 1, 31),
            source(1, [1; 16], 1, 31),
            source(1, [0; 16], 0, 31),
            source(1, [0; 16], 2, 31),
        ] {
            assert!(!roll_forward_certificate(&wrapper(&invalid, 31)));
        }
        assert!(!roll_forward_certificate(&wrapper(&valid, 30)));
    }

    #[test]
    fn supported_version_headers_do_not_admit_later_decimal_versions() {
        for version in [1, 2, 4, 8] {
            let format = format!("fa:report-certificate:v{version}");
            let mut writer = Writer::new();
            writer.fixed(format.as_bytes()).str("fa-fold-over-prefix");
            assert!(certificate_format(
                &writer.finish().unwrap(),
                format.as_bytes()
            ));
            for later in [version * 10, version * 10 + 1] {
                let mut writer = Writer::new();
                writer
                    .fixed(format!("fa:report-certificate:v{later}").as_bytes())
                    .str("fa-fold-over-prefix");
                assert!(!certificate_format(
                    &writer.finish().unwrap(),
                    format.as_bytes()
                ));
            }
        }
        assert!(!certificate_format(
            b"fa:report-certificate:v1",
            b"fa:report-certificate:v1"
        ));
    }
}
