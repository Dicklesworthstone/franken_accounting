//! AccessEvent: who read what (plan §9.7, §14.5, Appendix G; bead fa-7dw).
//!
//! The surface records bound reads and plan-only deliveries as one immutable
//! AccessEvent vertex before the command observes the book. Agent and writing
//! sessions are included: write authority is never an exemption from recording
//! a read. A delivered answer therefore has its record; a command that then
//! fails leaves an attempted read with nothing delivered (over-recording, never
//! under-recording). These are pre-disclosure attempts, not acknowledgments of
//! complete delivery or per-object access receipts. Like a retained certificate,
//! the record is a native vertex with its own sequence and no journal Entry.
//!
//! The payload names the head the read observed. Each record advances the
//! head, so two reads never share an identity.

use asupersync::fs::Vfs;
use fa_journal::genesis::BookContext;
use fa_journal::refusal::{KernelError, Refusal, code, exit};
use fa_journal::rows::{prop, scalar_bytes};
pub use fa_model::AccessRecord;
use fa_model::access_event::ACCESS_EVENT_DIGEST_DOMAIN as DIGEST_DOMAIN;
use fa_model::symbols::{label, property, relation};
use fa_model::{AccessEvent, Id128, access_event_vid, domain_digest};
pub use fa_steward::{AccessAuditRecord, audit_capability_op, profile_default_ops};
use fgdb::{Database, WriteBatch};
use fgdb_gql::RelationBind;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::{BookError, Outcome};

/// A recorded read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordedAccess {
    pub vid: VId,
    pub digest: [u8; 32],
    pub record: AccessRecord,
    /// The head the read observed: every book state it could disclose.
    pub observed_at: CommitSeq,
    pub recorded_at: CommitSeq,
}

/// The digest of a bound argument list, as recorded.
#[must_use]
pub fn request_digest(argv: &[String]) -> [u8; 32] {
    let parts: Vec<&[u8]> = argv.iter().map(String::as_bytes).collect();
    domain_digest(b"fa:access-request:v1", &parts)
}

/// Evaluate whether `capability` is admitted to read the access log of `book_id`
/// and return the structured [`AccessAuditRecord`] alongside the admission result.
pub fn audit_access_log_read(
    book_id: Id128,
    capability: &fa_policy::Capability,
) -> (AccessAuditRecord, Result<(), fa_policy::Denial>) {
    let default_ops = profile_default_ops(capability.profile());
    debug_assert!(default_ops.contains(&fa_policy::Op::Read));
    audit_capability_op(
        book_id,
        capability,
        fa_policy::Op::Read,
        "reading the access log",
    )
}

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::STRUCTURE,
        exit::USAGE,
        message,
        "plan §9.7 (AccessEvent fields are bounded)",
        "name a shorter principal or command; no access is served without its record",
    )
}

fn corrupt(vid: VId, message: &str) -> BookError {
    KernelError::Corrupt(format!("access event {:032x}: {message}", vid.0)).into()
}

fn encode(book: Id128, record: &AccessRecord, observed_at: CommitSeq) -> Result<Vec<u8>, Refusal> {
    record.validate().map_err(invalid)?;
    AccessEvent {
        book_id: book,
        record: record.clone(),
        observed_at,
    }
    .canonical_bytes()
    .map_err(|e| invalid(format!("the access record does not encode: {e}")))
}

fn decode(bytes: &[u8]) -> Result<(Id128, AccessRecord, CommitSeq), String> {
    let event = AccessEvent::decode(bytes).map_err(|e| e.to_string())?;
    Ok((event.book_id, event.record, event.observed_at))
}

/// Commit one AccessEvent at the current head.
pub(crate) async fn record<V: Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    record: &AccessRecord,
) -> Outcome<RecordedAccess> {
    cx.query().checkpoint().map_err(BookError::Context)?;
    let mut txn = db.begin(&cx.txn()).map_err(KernelError::from)?;
    let observed_at = txn.basis();
    let payload = match encode(book.book_id, record, observed_at) {
        Ok(payload) => payload,
        Err(refusal) => {
            txn.abort();
            return Ok(Err(refusal));
        }
    };
    let digest = domain_digest(DIGEST_DOMAIN, &[&payload]);
    let vid = access_event_vid(book.book_id, &digest);
    let mut properties = vec![
        (
            property::FA_PAYLOAD,
            scalar_bytes("access event payload", payload)?,
        ),
        (
            property::FA_DIGEST,
            scalar_bytes("access event digest", digest.to_vec())?,
        ),
        (
            property::BOOK_ID,
            scalar_bytes("access event book", book.book_id.0.to_vec())?,
        ),
    ];
    properties.sort_by_key(|(key, _)| key.0);
    let mut batch = WriteBatch::new(relation::DERIVED_FROM);
    batch.create_vertex(vid, vec![label::ACCESS_EVENT], properties);
    if let Err(error) = txn.write(db, batch) {
        txn.abort();
        return Err(KernelError::from(error).into());
    }
    cx.commit().checkpoint().map_err(BookError::Context)?;
    let recorded_at = txn
        .commit(db, &cx.commit())
        .await
        .map_err(KernelError::from)?;
    Ok(Ok(RecordedAccess {
        vid,
        digest,
        record: record.clone(),
        observed_at,
        recorded_at,
    }))
}

/// Every AccessEvent recorded after `since`, in recording order. Each row is
/// checked against its identity: label, book, digest and vid.
pub(crate) fn log<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    since: CommitSeq,
) -> Result<Vec<RecordedAccess>, BookError> {
    let head = db.frontier().map_err(KernelError::from)?;
    let bind = RelationBind::new().with_label("AccessEvent", label::ACCESS_EVENT);
    // The time is pinned by execute_prepared_gql_at, not by the statement;
    // the rows are ordered below.
    let statement = "MATCH (n:AccessEvent) RETURN n";
    let plan = db
        .prepare_gql_plan(statement, &bind)
        .map_err(|e| KernelError::Corrupt(format!("access log query: {e}")))?;
    let vids = db
        .execute_prepared_gql_at(&plan, head)
        .map_err(|e| KernelError::Corrupt(format!("access log query: {e}")))?;
    let mut out = Vec::new();
    for vid in vids {
        let row = db
            .vertex(vid)
            .map_err(KernelError::from)?
            .ok_or_else(|| corrupt(vid, "listed but absent"))?;
        if row.labels.as_slice() != [label::ACCESS_EVENT] {
            return Err(corrupt(vid, "carries other labels"));
        }
        let bytes = |key, what: &str| match prop(&row, key) {
            Some(CanonicalScalar::Bytes(b)) => Ok(b.as_slice().to_vec()),
            _ => Err(corrupt(vid, what)),
        };
        let payload = bytes(property::FA_PAYLOAD, "missing payload")?;
        let digest = domain_digest(DIGEST_DOMAIN, &[&payload]);
        if bytes(property::FA_DIGEST, "missing digest")? != digest
            || bytes(property::BOOK_ID, "missing book")? != book.book_id.0
            || access_event_vid(book.book_id, &digest) != vid
        {
            return Err(corrupt(vid, "does not match its identity"));
        }
        let (event_book, record, observed_at) = decode(&payload).map_err(|e| corrupt(vid, &e))?;
        if event_book != book.book_id || observed_at >= row.created_at {
            return Err(corrupt(
                vid,
                "belongs to another book or observed its own record",
            ));
        }
        if row.created_at > since {
            out.push(RecordedAccess {
                vid,
                digest,
                record,
                observed_at,
                recorded_at: row.created_at,
            });
        }
    }
    out.sort_by_key(|e| (e.recorded_at, e.vid));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fa_model::access_event::MAX_ACCESS_NAME as MAX_NAME;

    fn sample() -> AccessRecord {
        AccessRecord {
            principal: VId(7),
            principal_name: "auditor-1".into(),
            capability_commitment: [3; 32],
            ops: vec!["produce".into(), "read".into()],
            command: "tb".into(),
            request_digest: request_digest(&["tb".to_string(), "--json".to_string()]),
        }
    }

    #[test]
    fn the_payload_round_trips_and_refuses_unbounded_or_unordered_fields() {
        let book = Id128([9; 16]);
        let bytes = encode(book, &sample(), CommitSeq(41)).expect("encode");
        assert_eq!(
            decode(&bytes).expect("decode"),
            (book, sample(), CommitSeq(41))
        );
        let mut truncated = bytes.clone();
        truncated.pop();
        assert!(decode(&truncated).is_err());
        for bad in [
            AccessRecord {
                ops: vec!["read".into(), "produce".into()],
                ..sample()
            },
            AccessRecord {
                command: String::new(),
                ..sample()
            },
            AccessRecord {
                principal_name: "x".repeat(MAX_NAME + 1),
                ..sample()
            },
        ] {
            assert!(encode(book, &bad, CommitSeq(1)).is_err(), "{bad:?}");
        }
    }
}
