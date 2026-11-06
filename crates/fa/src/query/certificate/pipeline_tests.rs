//! A query pipeline certificate must prove its intermediate accounting, not
//! merely reproduce a final row digest. Hostile fixtures repair the outer
//! digest so that framing checks cannot stand in for historical replay.

use super::*;
use crate::query::QueryCell;
use crate::query::pipeline::tests::Fixture;
use crate::{ReportArtifact, ReportArtifactFamily};
use fa_model::{EntryClass, Pending, Settlement};
use fa_money::Amount;

const PRINCIPAL: VId = VId(7);

fn cap(ops: &[&str]) -> Capability {
    Capability::embedded(PRINCIPAL, ops).unwrap()
}

fn statement(account: &str, cutoff: &str, seq: CommitSeq, tail: &str) -> String {
    format!(
        "MATCH (l:Leg)-[:POSTS_TO]->(a:Account {{code:'{account}'}}), (l)-[:IN_UNIT]->(u:Unit) \
         CALL fa.open_amount(l) YIELD open, age_days {tail} EFFECTIVE AT '{cutoff}' AS KNOWN AT {}",
        seq.0
    )
}

fn certify(f: &Fixture, text: &str) -> CertifiedQuery {
    f.book
        .certify_query(PRINCIPAL, &cap(&["read", "produce"]), text)
        .unwrap()
        .unwrap()
}

/// Encode attacker-controlled fields and recompute the public outer digest
/// without using the producer's semantic validation. No signature is claimed.
fn redigested(value: &QueryCertificate, format: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.bytes(format)
        .bytes(&value.source.canonical_bytes().unwrap())
        .str(&value.statement);
    if let Some(evidence) = &value.pipeline {
        w.bytes(&evidence.source.canonical_bytes())
            .fixed(&evidence.parameters_digest);
    }
    w.bytes(&value.native.canonical_bytes())
        .bytes(&value.output);
    let mut body = w.finish().unwrap();
    let domain = if format == QUERY_CERTIFICATE_FORMAT_V2 {
        DIGEST_DOMAIN_V2
    } else {
        DIGEST_DOMAIN
    };
    let digest = domain_digest(domain, &[&body]);
    body.extend_from_slice(&digest);
    body
}

fn replay_refuses(f: &Fixture, value: &QueryCertificate, message: &str) {
    let bytes = redigested(value, value.format());
    let decoded = QueryCertificate::decode(&bytes).expect("valid framing and repaired hash");
    let refusal = f
        .book
        .replay_query(PRINCIPAL, &cap(&["read"]), &decoded)
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, crate::certificate::code::CERTIFICATE_INVALID);
    assert_eq!(refusal.exit, exit::VERIFICATION);
    assert!(refusal.message.contains(message), "{refusal:?}");
}

#[test]
fn a_pipeline_certificate_replays_historical_parameters_and_retains_both_stages() {
    let mut f = Fixture::new();
    let invoice = f.post(f.proposal("invoice", "2026-03-01", f.usd, "ar", "sales", 10_000));
    let original = f.book.head().unwrap();
    let mut receipt = f.proposal("receipt", "2026-03-10", f.usd, "cash", "ar", 4_000);
    receipt.legs[1].settles.push(Settlement {
        target: invoice,
        ordinal: 0,
        amount: Amount::new(f.usd, 4_000),
    });
    f.post(receipt);
    let mut pending = f.proposal("pending", "2026-03-02", f.usd, "ar", "cash", 9_000);
    pending.class = EntryClass::PENDING;
    pending.pending = Some(Pending {
        timeout_ns: None,
        resolution_of: None,
        disposition: None,
    });
    f.post(pending);
    let at = f.book.head().unwrap();
    let tail = "WHERE open IS NOT NULL RETURN u.code AS unit, SUM(open) AS total ORDER BY unit";
    let text = statement("ar", "2026-03-20", at, tail);
    let certified = certify(&f, &format!("EXPLAIN (CERTIFICATE) {text}"));
    assert_eq!(
        certified.rows.rows,
        vec![vec![
            QueryCell::Text("USD".into()),
            QueryCell::Decimal("60".into())
        ]]
    );
    let certificate = &certified.certificate;
    assert_eq!(certificate.format(), QUERY_CERTIFICATE_FORMAT_V2);
    assert_eq!(certificate.known_at(), at);
    assert_eq!(certificate.native().plan.snapshot_seq, at);
    assert_eq!(certificate.pipeline_source().unwrap().plan.snapshot_seq, at);
    assert_ne!(
        certificate.native().statement,
        certificate.pipeline_source().unwrap().statement
    );
    assert!(certificate.parameters_digest().is_some());
    let bytes = certificate.canonical_bytes().unwrap();
    assert_eq!(QueryCertificate::decode(&bytes).unwrap(), *certificate);
    assert_eq!(f.book.head().unwrap(), at, "certification is read-only");
    assert_eq!(
        f.book
            .replay_query(PRINCIPAL, &cap(&["read"]), certificate)
            .unwrap()
            .unwrap(),
        certified.rows
    );

    // The recorded prefix and civil cutoff are independent inputs. A receipt
    // recorded at this prefix must not reduce a report selected before it.
    let earlier = certify(&f, &statement("ar", "2026-03-05", at, tail));
    assert_eq!(earlier.rows.rows[0][1], QueryCell::Decimal("100".into()));
    let original_prefix = certify(&f, &statement("ar", "2026-03-20", original, tail));
    assert_eq!(
        original_prefix.rows.rows[0][1],
        QueryCell::Decimal("100".into())
    );
    let nullable = certify(
        &f,
        &statement("ar", "2026-03-20", at, "RETURN open, age_days"),
    );
    assert!(
        nullable
            .rows
            .rows
            .contains(&vec![QueryCell::Null, QueryCell::Null])
    );
    assert!(
        nullable
            .rows
            .rows
            .contains(&vec![QueryCell::Decimal("60".into()), QueryCell::Int(19)])
    );
    assert_eq!(
        f.book
            .replay_query(PRINCIPAL, &cap(&["read"]), &nullable.certificate)
            .unwrap()
            .unwrap(),
        nullable.rows
    );

    let artifact = ReportArtifact::decode(&bytes).unwrap();
    assert_eq!(artifact.family(), ReportArtifactFamily::Query);
    assert_eq!(artifact.output(), certified.rows.canonical_bytes().unwrap());
    f.book
        .retain_report_artifact(
            PRINCIPAL,
            &cap(&["read", "produce"]),
            &bytes,
            Some(certificate.digest()),
        )
        .unwrap()
        .unwrap();
    let retained_at = f.book.head().unwrap();
    let retained = f
        .book
        .read_report_artifact(PRINCIPAL, &cap(&["read"]), certificate.digest())
        .unwrap()
        .unwrap();
    assert_eq!(retained.canonical_bytes().unwrap(), bytes);
    f.book
        .retain_report_artifact(
            PRINCIPAL,
            &cap(&["read", "produce"]),
            &bytes,
            Some(certificate.digest()),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        f.book.head().unwrap(),
        retained_at,
        "an exact retention retry publishes nothing"
    );
    f.book
        .replay_report_artifact(
            PRINCIPAL,
            &cap(&["read"]),
            &bytes,
            Some(certificate.digest()),
        )
        .unwrap()
        .unwrap();
    assert!(matches!(
        f.book
            .query_certificate_status(PRINCIPAL, &cap(&["read"]), certificate)
            .unwrap()
            .unwrap(),
        QueryCertificateStatus::Current { .. }
    ));

    // A later-effective settlement leaves the March 20 answer current even
    // though it is known now. A newly recorded March 15 settlement changes
    // today's answer, while replay remains fixed to the certified prefix.
    let mut future = f.proposal("future", "2026-03-25", f.usd, "cash", "ar", 1_000);
    future.legs[1].settles.push(Settlement {
        target: invoice,
        ordinal: 0,
        amount: Amount::new(f.usd, 1_000),
    });
    f.post(future);
    assert!(matches!(
        f.book
            .query_certificate_status(PRINCIPAL, &cap(&["read"]), certificate)
            .unwrap()
            .unwrap(),
        QueryCertificateStatus::Current { .. }
    ));
    let mut backdated = f.proposal("backdated", "2026-03-15", f.usd, "cash", "ar", 2_000);
    backdated.legs[1].settles.push(Settlement {
        target: invoice,
        ordinal: 0,
        amount: Amount::new(f.usd, 2_000),
    });
    f.post(backdated);
    let QueryCertificateStatus::Changed { current, .. } = f
        .book
        .query_certificate_status(PRINCIPAL, &cap(&["read"]), certificate)
        .unwrap()
        .unwrap()
    else {
        panic!("the backdated settlement changes the current query");
    };
    assert_eq!(current.rows[0][1], QueryCell::Decimal("40".into()));
    assert_eq!(
        f.book
            .replay_query(PRINCIPAL, &cap(&["read"]), certificate)
            .unwrap()
            .unwrap(),
        certified.rows
    );
    let head = f.book.head().unwrap();
    let denied = f
        .book
        .replay_query(PRINCIPAL, &cap(&["produce"]), certificate)
        .unwrap()
        .unwrap_err();
    assert_eq!(denied.exit, exit::SAFETY);
    assert_eq!(f.book.head().unwrap(), head);
}

#[test]
fn repaired_hashes_cannot_substitute_pipeline_parameters_native_stages_or_output() {
    let mut f = Fixture::new();
    f.post(f.proposal("invoice", "2026-03-01", f.usd, "ar", "sales", 10_000));
    let at = f.book.head().unwrap();
    let tail = "WHERE age_days > 1000 RETURN open, age_days";
    let certified = certify(&f, &statement("ar", "2026-03-20", at, tail));
    let other = certify(&f, &statement("cash", "2026-03-20", at, tail));
    assert!(certified.rows.rows.is_empty());
    assert_eq!(
        other.rows.rows, certified.rows.rows,
        "both final results are empty"
    );
    assert_eq!(
        other.certificate.native.statement,
        certified.certificate.native.statement
    );
    assert_ne!(
        other.certificate.parameters_digest(),
        certified.certificate.parameters_digest()
    );

    let mut forged = certified.certificate.clone();
    forged.native = other.certificate.native.clone();
    forged.pipeline.as_mut().unwrap().parameters_digest =
        *other.certificate.parameters_digest().unwrap();
    replay_refuses(&f, &forged, "regenerated open_amount parameters");

    let mut forged = certified.certificate.clone();
    forged.native = other.certificate.native.clone();
    replay_refuses(&f, &forged, "pipeline continuation");

    let mut forged = certified.certificate.clone();
    forged.pipeline.as_mut().unwrap().source.result_digest.0[0] ^= 1;
    replay_refuses(&f, &forged, "pipeline source read");

    let mut forged = certified.certificate.clone();
    let last = forged.output.len() - 1;
    forged.output[last] ^= 1;
    replay_refuses(&f, &forged, "replayed result differs");

    // A valid framing hash does not authorize storage of a counterfeit
    // derivation, even when the final output has no rows to distinguish it.
    let mut forged = certified.certificate.clone();
    forged.pipeline.as_mut().unwrap().parameters_digest[0] ^= 1;
    let bytes = redigested(&forged, QUERY_CERTIFICATE_FORMAT_V2);
    let head = f.book.head().unwrap();
    let refusal = f
        .book
        .retain_report_artifact(PRINCIPAL, &cap(&["read", "produce"]), &bytes, None)
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, crate::certificate::code::CERTIFICATE_INVALID);
    assert!(refusal.message.contains("parameters"));
    assert_eq!(
        f.book.head().unwrap(),
        head,
        "refused retention publishes nothing"
    );

    let mut wrong_source_stage = certified.certificate.clone();
    wrong_source_stage.pipeline.as_mut().unwrap().source =
        other.certificate.pipeline_source().unwrap().clone();
    let mut wrong_statement = certified.certificate.clone();
    wrong_statement.statement = other.certificate.statement.clone();
    let mut wrong_continuation = certified.certificate.clone();
    wrong_continuation.native = certified.certificate.pipeline_source().unwrap().clone();
    for forged in [wrong_source_stage, wrong_statement, wrong_continuation] {
        let refusal = QueryCertificate::decode(&redigested(&forged, QUERY_CERTIFICATE_FORMAT_V2))
            .unwrap_err();
        assert_eq!(refusal.code, crate::certificate::code::CERTIFICATE_INVALID);
    }
    f.post(f.proposal("later", "2026-03-02", f.usd, "ar", "sales", 100));
    let later = certify(
        &f,
        &statement("ar", "2026-03-20", f.book.head().unwrap(), tail),
    );
    let mut wrong_source_prefix = certified.certificate.clone();
    wrong_source_prefix.source = later.certificate.source;
    assert!(
        QueryCertificate::decode(&redigested(
            &wrong_source_prefix,
            QUERY_CERTIFICATE_FORMAT_V2
        ))
        .is_err()
    );
}

#[test]
fn pipeline_versions_require_every_bounded_stage_and_preserve_v1_bytes() {
    let mut f = Fixture::new();
    f.post(f.proposal("invoice", "2026-03-01", f.usd, "ar", "sales", 100));
    let at = f.book.head().unwrap();
    let certified = certify(&f, &statement("ar", "2026-03-20", at, "RETURN open"));
    let v2 = &certified.certificate;
    let mut missing = v2.clone();
    missing.pipeline = None;
    assert!(QueryCertificate::decode(&redigested(&missing, QUERY_CERTIFICATE_FORMAT_V2)).is_err());
    assert!(QueryCertificate::decode(&redigested(v2, QUERY_CERTIFICATE_FORMAT)).is_err());
    let bytes = v2.canonical_bytes().unwrap();
    assert!(QueryCertificate::decode(&bytes[..bytes.len() - 1]).is_err());
    for oversized_stage in 0..2 {
        let mut w = Writer::new();
        w.bytes(QUERY_CERTIFICATE_FORMAT_V2)
            .bytes(&v2.source.canonical_bytes().unwrap())
            .str(&v2.statement);
        if oversized_stage == 1 {
            let evidence = v2.pipeline.as_ref().unwrap();
            w.bytes(&evidence.source.canonical_bytes())
                .fixed(&evidence.parameters_digest);
        }
        w.u32(u32::try_from(MAX_NATIVE_BYTES + 1).unwrap());
        let refusal = QueryCertificate::decode(&w.finish().unwrap()).unwrap_err();
        assert_eq!(refusal.code, crate::certificate::code::CERTIFICATE_INVALID);
    }

    let v1 = certify(&f, "MATCH (a:Account) RETURN a.code ORDER BY a.code");
    assert_eq!(v1.certificate.format(), QUERY_CERTIFICATE_FORMAT);
    assert!(v1.certificate.pipeline_source().is_none());
    assert!(v1.certificate.parameters_digest().is_none());
    let legacy = redigested(&v1.certificate, b"fa:query-certificate:v1");
    assert_eq!(
        v1.certificate.canonical_bytes().unwrap(),
        legacy,
        "the original v1 layout and digest domain are unchanged"
    );
    let decoded = QueryCertificate::decode(&legacy).unwrap();
    assert_eq!(decoded, v1.certificate);
    assert_eq!(
        f.book
            .replay_query(PRINCIPAL, &cap(&["read"]), &decoded)
            .unwrap()
            .unwrap(),
        v1.rows
    );
    let mut invented_stage = v1.certificate.clone();
    invented_stage.pipeline = v2.pipeline.clone();
    assert!(
        QueryCertificate::decode(&redigested(&invented_stage, QUERY_CERTIFICATE_FORMAT_V2))
            .is_err()
    );
}

#[test]
fn a_pipeline_certificate_replays_bound_period_ranges() {
    let mut f = Fixture::new();
    f.post(f.proposal("invoice", "2026-03-01", f.usd, "ar", "sales", 123));
    let text = statement(
        "ar",
        "2026-03-20",
        f.book.head().unwrap(),
        "RETURN open, age_days",
    );
    for period in [
        "FOR PERIOD 'FY2026-P03'",
        "FOR PERIOD 'FY2026-P03'..'FY2026-P04'",
    ] {
        let certified = certify(&f, &format!("{text} {period}"));
        assert_eq!(
            certified.rows.rows,
            vec![vec![QueryCell::Decimal("1.23".into()), QueryCell::Int(19)]]
        );
        let decoded =
            QueryCertificate::decode(&certified.certificate.canonical_bytes().unwrap()).unwrap();
        assert_eq!(
            f.book
                .replay_query(PRINCIPAL, &cap(&["read"]), &decoded)
                .unwrap()
                .unwrap(),
            certified.rows
        );
    }
}
