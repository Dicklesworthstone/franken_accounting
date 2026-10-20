//! Complete native closure for the bank statement drift procedure.
//!
//! The source report already binds Entry, account, unit, calendar and migration
//! populations. V3 additionally binds every bank decision, source metadata row
//! and relationship population, including empty populations. Native history is
//! independently refolded on every execution: a certified query digest alone
//! does not prove an attestation's original cash balance or immutable birth.

use super::*;

pub(super) const FORMAT: &[u8] = b"fa:procedure-certificate:v3";
pub(super) const PROCEDURE: &str = "recon.bank_statement_drift";

const VERTICES: &[(&str, &str)] = &[
    ("Attestation", "_fa_payload,_fa_digest,book_id,code"),
    ("BankMatch", "_fa_payload,_fa_digest,book_id,code"),
    ("BankMatchedLeg", "_fa_payload,_fa_digest,book_id"),
    ("BankUnmatch", "_fa_payload,_fa_digest,book_id,code"),
    ("BankStatementLink", "_fa_payload,_fa_digest,book_id"),
    (
        "Document",
        "_fa_payload,_fa_digest,book_id,code,custody_len",
    ),
    (
        "Leg",
        "_fa_effective_day,side,account_ref,unit_id,amount,amount_bytes,ordinal",
    ),
];

// Complete relation populations bind both required edges and their absence.
// MATCHES carries the confirmation digest and policy code; the other protected
// links have no properties. Their endpoints and native identities are retained.
const EDGES: &[(&str, &str)] = &[
    ("ATTESTS", ""),
    ("CITES", ""),
    ("IN_BOOK", ""),
    ("MATCHES", "_fa_digest,code"),
    ("SUPERSEDES", ""),
    ("DERIVED_FROM", ""),
    ("HAS_LEG", ""),
    ("POSTS_TO", ""),
];

pub(super) const COUNT: usize = VERTICES.len() + EDGES.len();

pub(super) fn supported(id: &str, version: u16) -> bool {
    id == PROCEDURE && version == 1
}

pub(super) fn statements(at: CommitSeq) -> Vec<String> {
    let mut statements: Vec<_> = VERTICES
        .iter()
        .map(|(kind, fields)| {
            let projections: String = fields.split(',').map(|p| format!(",n.{p}")).collect();
            format!(
                "MATCH (n:{kind}) FOR SYSTEM_TIME AS OF SEQ {} RETURN n{projections} ORDER BY n",
                at.0
            )
        })
        .collect();
    statements.extend(EDGES.iter().map(|(kind, fields)| {
        let projections: String = fields
            .split(',')
            .filter(|p| !p.is_empty())
            .map(|p| format!(",e.{p}"))
            .collect();
        format!(
            "MATCH (s)-[e:{kind}]->(t) FOR SYSTEM_TIME AS OF SEQ {} RETURN s,e,t{projections} ORDER BY s,e,t",
            at.0
        )
    }));
    statements
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

pub(super) fn validate(certificate: &ProcedureCertificate) -> Result<(), Refusal> {
    if !supported(&certificate.report.procedure, certificate.report.version)
        || certificate.extended_inputs.len() != COUNT
    {
        return Err(invalid(
            "bank procedure requires its complete v3 native input closure",
        ));
    }
    let basis = certificate
        .source
        .inputs
        .first()
        .ok_or_else(|| invalid("missing native source"))?;
    for (native, statement) in certificate
        .extended_inputs
        .iter()
        .zip(statements(certificate.known_at()))
    {
        if native.statement != statement
            || native.plan.snapshot_seq != certificate.known_at()
            || native.snapshot_identity != basis.snapshot_identity
            || native.database_identity != basis.database_identity
            || native.canonical_bytes().len() > MAX_NATIVE
        {
            return Err(invalid(
                "bank input is not the required certified population, relationship and snapshot",
            ));
        }
    }
    Ok(())
}

/// Populate only from independently verified native records. The HEAD check
/// detects later tampering without folding later cash into the saved output.
pub(super) fn populate<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &fa_journal::BookContext,
    capability: &Capability,
    snapshot: &mut Snapshot,
) -> Outcome<()> {
    if let Err(refusal) =
        fa_journal::bank::verify_bank_reconciliation_history(db, cx, book, capability, None)?
    {
        return Ok(Err(refusal));
    }
    let states = match fa_journal::bank::read_bank_reconciliation_states(
        db,
        cx,
        book,
        capability,
        Some(snapshot.coordinate.known_at),
    )? {
        Ok(states) => states,
        Err(refusal) => return Ok(Err(refusal)),
    };
    snapshot.bank_reconciliations = Some(states);
    Ok(Ok(()))
}
