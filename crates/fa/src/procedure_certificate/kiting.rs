//! Native v4 adds original import custody to the fixed v3 bank populations.
//! ImportRun controls are already in the complete journal source. Statements,
//! canonical lines and manifests are content-addressed Documents; their bytes
//! are independently fetched and reparsed before every run and native replay.
//! No portable/offline profile is implied by this native-store closure.

use super::*;

pub(super) const FORMAT: &[u8] = b"fa:procedure-certificate:v4";
pub(super) const PROCEDURE: &str = "graph.kiting";
pub(super) const COUNT: usize = bank::COUNT + 4;

pub(super) fn supported(id: &str, version: u16) -> bool {
    id == PROCEDURE && version == 1
}

fn statements(at: CommitSeq) -> Vec<String> {
    let mut statements = bank::statements(at);
    for kind in ["ImportReceipt", "CustodyTransfer"] {
        statements.push(format!(
            "MATCH (n:{kind}) FOR SYSTEM_TIME AS OF SEQ {} RETURN n,n._fa_payload,n._fa_digest,n.book_id ORDER BY n",
            at.0
        ));
    }
    for kind in ["CUSTODY_OF", "IMPORTED_BY"] {
        statements.push(format!(
            "MATCH (s)-[e:{kind}]->(t) FOR SYSTEM_TIME AS OF SEQ {} RETURN s,e,t ORDER BY s,e,t",
            at.0
        ));
    }
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
            "kiting requires its complete v4 native bank and source-custody closure",
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
                "kiting input is not its required complete native population and snapshot",
            ));
        }
    }
    Ok(())
}

pub(super) fn populate(
    prepared: Option<&crate::bank::PreparedBankTransfers>,
    snapshot: &mut Snapshot,
) -> Result<(), Refusal> {
    prepared.ok_or_else(missing_sources)?.populate(snapshot)
}

pub(super) fn missing_sources() -> Refusal {
    invalid(
        "graph.kiting requires authenticated original statements; use the with_history procedure entrypoint under current Read, Reconcile and Privileged authority",
    )
}
