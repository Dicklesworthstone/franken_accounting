//! Native input closure for the second analytic-certificate format.
//!
//! REA semantics are rebuilt by Snapshot::read from immutable SchemaControl
//! entries already bound by the source report. These additional reads bind the
//! materialized vertex populations too. Party identifiers and relationships may
//! legitimately change through later controls, so they are not treated as frozen
//! HEAD caches. Attestations are independent immutable records: their complete
//! historical population, payloads, mirrors and original births are checked.

use super::*;

pub(super) const FORMAT: &[u8] = b"fa:procedure-certificate:v2";

/// This is an explicit audited list, not blanket permission for future catalog
/// additions. The original 22 procedures retain their v1 encoding and closure.
pub const EXTENDED_CERTIFIABLE_PROCEDURES: &[(&str, u16)] = &[
    ("trace.restitution_order", 1),
    ("jet.unusual_accounts", 1),
    ("jet.unusual_preparers", 1),
    ("jet.manual_vs_rule", 1),
    ("jet.large_round_reversals", 1),
    ("jet.suspense_aging", 2),
    ("jet.intercompany_unmatched", 2),
    ("benford.second_digit", 2),
    ("benford.first_two_digits", 2),
    ("numbers.relative_size_factor", 1),
    ("numbers.threshold_splitting", 1),
    ("graph.circular_flows", 1),
    ("graph.layering", 1),
    // fa-b6xs: reads live postings and the REA parties this closure binds.
    ("graph.party_layering", 1),
    ("graph.communities", 2),
    ("graph.related_party_exposure", 2),
    ("graph.shell_signature", 2),
    ("graph.concentration", 1),
    ("graph.identity_resolution", 1),
    ("recon.intercompany", 2),
    ("recon.lapping", 2),
    ("recon.attested_register_compare", 1),
    ("recon.assertion_drift", 1),
    ("completeness.unrecorded_liabilities", 1),
    ("events.subsequent", 1),
    ("party.master_changes", 1),
    ("payroll.ghost", 2),
    ("expense.capitalization", 2),
    ("aging.inventory", 2),
    ("reversal.patterns", 1),
    ("confirm.coverage", 2),
    ("solvency.balance_sheet_test", 2),
    ("solvency.cash_flow_test", 2),
    ("lookback.preferences", 2),
    ("lookback.fraudulent_transfer", 1),
    ("ponzi.net_investment", 2),
    ("distribution.rising_tide", 2),
    ("distribution.pro_rata", 2),
    ("damages.attested_baseline", 1),
];

const INPUTS: &[(&str, &str)] = &[
    ("Attestation", "_fa_payload,_fa_digest,book_id,code"),
    ("Party", "_fa_payload,book_id,code"),
    ("Instrument", "_fa_payload,book_id,code"),
    ("LegalEntity", "_fa_payload,book_id,code"),
    ("ExternalId", "_fa_payload,book_id,code,target_ref"),
    ("Event", "_fa_payload,_fa_digest,book_id,code"),
];

pub(super) const COUNT: usize = INPUTS.len();

pub(super) fn supported(id: &str, version: u16) -> bool {
    EXTENDED_CERTIFIABLE_PROCEDURES.contains(&(id, version))
}

pub(super) fn statements(at: CommitSeq) -> Vec<String> {
    INPUTS
        .iter()
        .map(|(kind, fields)| {
            let projections: String = fields.split(',').map(|p| format!(",n.{p}")).collect();
            format!(
                "MATCH (n:{kind}) FOR SYSTEM_TIME AS OF SEQ {} RETURN n{projections} ORDER BY n",
                at.0
            )
        })
        .collect()
}

pub(super) fn capture<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &fa_journal::BookContext,
    at: CommitSeq,
) -> Result<Vec<NativeResultCertificate>, BookError> {
    let mut inputs = Vec::with_capacity(COUNT);
    for statement in statements(at) {
        cx.query().checkpoint().map_err(BookError::Context)?;
        let (_, native) = db
            .execute_certified(
                &cx.query(),
                &statement,
                &GqlParameters::new(),
                book.symbols.clone(),
                policy(),
            )
            .map_err(BookError::CertifiedRead)?;
        inputs.push(native);
    }
    Ok(inputs)
}

/// Validate statements, count and native identity BEFORE accepting any framing.
/// A valid certificate from a different population or snapshot cannot be swapped
/// in merely by recomputing the public outer digest.
pub(super) fn validate(certificate: &ProcedureCertificate) -> Result<(), Refusal> {
    let inputs = &certificate.extended_inputs;
    if !supported(&certificate.report.procedure, certificate.report.version) {
        if !inputs.is_empty() {
            return Err(invalid(
                "unexpected extended native inputs for a v1 procedure",
            ));
        }
        return Ok(());
    }
    let basis = certificate
        .source
        .inputs
        .first()
        .ok_or_else(|| invalid("missing native source"))?;
    if inputs.len() != COUNT {
        return Err(invalid(
            "extended procedure requires its complete native input closure",
        ));
    }
    for (native, statement) in inputs.iter().zip(statements(certificate.known_at())) {
        if native.statement != statement
            || native.plan.snapshot_seq != certificate.known_at()
            || native.snapshot_identity != basis.snapshot_identity
            || native.database_identity != basis.database_identity
            || native.canonical_bytes().len() > MAX_NATIVE
        {
            return Err(invalid(
                "extended input is not the required certified native population and snapshot",
            ));
        }
    }
    Ok(())
}

pub(super) fn replay<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &fa_journal::BookContext,
    certificate: &ProcedureCertificate,
) -> Outcome<()> {
    for native in &certificate.extended_inputs {
        cx.query().checkpoint().map_err(BookError::Context)?;
        if let Err(e) = db.replay(
            &cx.query(),
            native,
            &GqlParameters::new(),
            book.symbols.clone(),
            policy(),
        ) {
            return Ok(Err(invalid(format!(
                "extended native input does not replay: {e}"
            ))));
        }
    }
    Ok(Ok(()))
}

/// Validate every attestation in the population, not merely those cited by a
/// positive finding: absence of a discrepancy can depend on a corroboration.
/// The predecessor check catches a rewrite completed before certificate creation
/// as well as an altered-then-restored record after it. Current reader authority
/// is checked by the caller; the stored attester binding does not authorize it.
pub(super) fn unchanged_attestations<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    snapshot: &Snapshot,
) -> Outcome<()> {
    use fa_journal::rows::{bytes, prop};
    use fgdb_types::CanonicalScalar;
    let head = db.frontier().map_err(KernelError::from)?;
    for (&vid, stored) in &snapshot.attestations {
        cx.query().checkpoint().map_err(BookError::Context)?;
        let Some(old) = db
            .vertex_at(vid, snapshot.coordinate.known_at)
            .map_err(KernelError::from)?
        else {
            return Ok(Err(invalid("historical procedure attestation is missing")));
        };
        let Some(now) = db.vertex_at(vid, head).map_err(KernelError::from)? else {
            return Ok(Err(invalid("procedure attestation was retired")));
        };
        let original = old
            .created_at
            .0
            .checked_sub(1)
            .ok_or_else(|| invalid("attestation has no native birth"));
        let original = match original {
            Ok(at) => CommitSeq(at),
            Err(r) => return Ok(Err(r)),
        };
        let payload = bytes(&old, property::FA_PAYLOAD, "attestation payload")?;
        let att = &stored.attestation;
        if !old.labels.contains(&label::ATTESTATION)
            || old.retired_at.is_some()
            || now.retired_at.is_some()
            || now.created_at != old.created_at
            || now.labels != old.labels
            || now.props != old.props
            || db
                .vertex_at(vid, original)
                .map_err(KernelError::from)?
                .is_some()
            || att.book_id != snapshot.coordinate.book_id
            || att.vid() != Some(vid)
            || bytes(&old, property::FA_DIGEST, "attestation digest")? != stored.signed_digest
            || att.canonical_bytes(&stored.binding)? != payload
            || !matches!(prop(&old, property::CODE), Some(CanonicalScalar::Text(t)) if t.as_bytes() == att.claim.name().as_bytes())
            || !matches!(prop(&old, property::BOOK_ID), Some(CanonicalScalar::Bytes(b)) if b.as_slice() == att.book_id.0.as_slice())
        {
            return Ok(Err(invalid(
                "a procedure attestation was rebound, rewritten or has inconsistent mirrors",
            )));
        }
    }
    Ok(Ok(()))
}
