//! Portable native and dimension-filtered trial balances, statements, open
//! items, balance explanations, aging, roll-forwards and direct cash flow over
//! a payload-complete checkpoint.
//!
//! This is the linear complete-prefix fallback from plan §13.1/§13.3. The
//! independent verifier derives selectors from every record, reconstructs the
//! historical chart and periods from schema controls, and refolds the report.
//! Native FGDB read certificates are retained as part of the source certificate;
//! they are not substituted for outsider-authenticated accounting inputs.

use std::collections::{BTreeMap, BTreeSet};

use fa_journal::migration::RunBody;
use fa_journal::refusal::{Outcome, Refusal, exit};
use fa_model::{ControlPayload, Entry, EntryClass, EntryOrigin, Oid, Reader, Writer};
use fgdb::Database;
use fgdb_crypto::Hasher;
use fgdb_types::{CommitSeq, VId};

use crate::{Bundle, Journal, StoredCheckpoint, code};

mod functional;
pub use functional::{
    MAX_FUNCTIONAL_BOOK_BYTES, MAX_FUNCTIONAL_RATE_BYTES, MAX_FUNCTIONAL_RATES,
    rate_oids as functional_rate_oids,
};

mod explanation;
pub use explanation::check_scope as check_explanation_scope;

mod open_items;
pub use open_items::check_scope as check_open_items_scope;

pub const REPORT_BUNDLE_FORMAT: &[u8] = b"fa:report-bundle:v1";
pub const MAX_REPORT_BUNDLE_BYTES: usize = 64 * 1024 * 1024;

fn refused(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::SCOPE_UNSUPPORTED,
        exit::REFUSAL,
        message,
        "plan §13.1–13.3 (report recomputation needs its complete authenticated closure)",
        "use a native v1/v2 trial-balance, v8 dimension-filtered trial-balance, v3 open-item or balance-explanation, v4 statement, effective-date aging, roll-forward, equity roll-forward, direct cash-flow or policy cash-flow certificate and a checkpoint covering its known-at and any retained time frontier; preserve the complete historical schema, registry and migration inputs",
    )
}

/// Read only immutable migration bodies needed by this report's historical
/// prefix. Whole-book read and produce authority must be checked before this
/// function is called, as for every complete-prefix proof export.
pub fn run_bodies<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    journal: &Journal,
    known_at: CommitSeq,
) -> Outcome<BTreeMap<VId, RunBody>> {
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
    Ok(crate::migration_balance::run_bodies(db, journal, &needed)?
        .map(|bodies| needed.into_iter().zip(bodies).collect()))
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
/// checkpoint leaf has exactly one payload, in prefix order.
pub fn assemble(
    journal: &Journal,
    checkpoint: &StoredCheckpoint,
    certificate: &[u8],
    known_at: CommitSeq,
    bodies: &BTreeMap<VId, RunBody>,
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
/// Aging-to-control reconciliations retain both original sources and their
/// shared four-document closure. No v1 fallback serves either v3 selector or
/// composed schedule.
/// V2 appends a list of (registry name, canonical registry document) frames;
/// existing v1 trial-balance bytes remain unchanged.
pub fn assemble_with_registries(
    journal: &Journal,
    checkpoint: &StoredCheckpoint,
    certificate: &[u8],
    known_at: CommitSeq,
    bodies: &BTreeMap<VId, RunBody>,
    registries: &[(String, Vec<u8>)],
) -> Outcome<Bundle> {
    let explanation = explanation_certificate(certificate);
    let expected: &[&str] = if explanation {
        &[
            "account_types",
            "entry_classes",
            "units",
            "foundations",
            "reason_codes",
        ]
    } else {
        &["account_types", "entry_classes", "units", "foundations"]
    };
    if !(certificate_format(certificate, b"fa:report-certificate:v4")
        || open_items_certificate(certificate)
        || aging_certificate(certificate)
        || due_date_aging_certificate(certificate)
        || reconciliation_certificate(certificate)
        || roll_forward_certificate(certificate)
        || equity_certificate(certificate)
        || cash_flow_certificate(certificate)
        || policy_cash_flow_certificate(certificate)
        || split_cash_flow_certificate(certificate)
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
            "native reports require their exact canonical registry profile in closure order: four documents for statements, open items, aging, reconciliation, roll-forwards and direct cash flow, five including reason_codes for balance explanations",
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

/// Package a replayed functional trial balance or financial statement with its
/// original six-registry closure, exact historical version-2 BookSpec, and every authenticated Rate
/// document cited at or before known-at. The facade must govern every Rate read.
/// This profile supports sequence-selected trunk reports under SpotClose,
/// PeriodAverage and source-bound SettlementCarryingBasis, including exact
/// inherited reversals. Other valuation laws and migration-origin monetary
/// entries require their own independent interpreter.
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
    bodies: &BTreeMap<VId, RunBody>,
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
    if !functional::certificate(certificate, journal, known_at)
        || registries
            .iter()
            .map(|(name, _)| name.as_str())
            .ne(expected)
        || registries
            .iter()
            .any(|(_, bytes)| bytes.len() > 1024 * 1024)
        || !bodies.is_empty()
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
        Some(FunctionalClosure { book_spec, rates }),
    )
}

struct FunctionalClosure<'a> {
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
    bodies: &BTreeMap<VId, RunBody>,
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

fn reconciliation_certificate(certificate: &[u8]) -> bool {
    let header = || -> Result<bool, fa_model::DecodeError> {
        let mut reader = Reader::new(certificate);
        let format = reader.bytes(64, "reconciliation format")?;
        let due_date = if format == b"fa:due-date-aging-reconciliation-certificate:v1" {
            true
        } else if format == b"fa:aging-reconciliation-certificate:v1" {
            false
        } else {
            return Ok(false);
        };
        reader.u128("reconciliation producer")?;
        reader.fixed::<32>("reconciliation capability")?;
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
    bodies: &BTreeMap<VId, RunBody>,
    registries: &[(String, Vec<u8>)],
    functional: Option<FunctionalClosure<'_>>,
) -> Outcome<Bundle> {
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
                || open_items_certificate(certificate)
                || explanation_certificate(certificate)
                || aging_certificate(certificate)
                || due_date_aging_certificate(certificate)
                || reconciliation_certificate(certificate)
                || roll_forward_certificate(certificate)
                || equity_certificate(certificate)
                || cash_flow_certificate(certificate)
                || policy_cash_flow_certificate(certificate)
                || split_cash_flow_certificate(certificate))
        || major == 3 && functional::certificate(certificate, journal, known_at))
    {
        return Ok(Err(refused(
            "offline report bundles require a native v1/v2 trial balance, v8 dimension-filtered trial balance, v4 statement, v5 functional statement, v10 functional trial balance, or v3 open-item report, balance explanation, effective-date aging, aging reconciliation, roll-forward, direct, policy or split cash-flow with authenticated registries",
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
    let mut w = Writer::with_capacity(budget);
    w.bytes(REPORT_BUNDLE_FORMAT)
        .u16(major)
        .u16(0)
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
