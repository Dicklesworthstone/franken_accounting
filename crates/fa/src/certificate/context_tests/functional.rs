//! Real retained Rate documents and posted entries exercise the v5 closure.

#[path = "functional_trial_balance.rs"]
mod trial_balance;

use super::*;
use crate::certificate::{
    FUNCTIONAL_STATEMENT_CERTIFICATE_FORMAT, FUNCTIONAL_STATEMENT_OUTPUT_FORMAT, ReportCertificate,
    digest,
};
use crate::{CertificateStatus, ReportArtifact, ReportArtifactFamily, StatementSelection};
use fa_journal::fx::{FxLawId, FxRateDocument, FxRatePurpose, RATE_DOCUMENT_KIND};
use fa_model::Entry;
use fa_money::RoundingLaw;
use fa_money::rate::{ArithmeticBudget, BudgetLimits};

fn selection() -> StatementSelection {
    StatementSelection {
        definition: crate::StatementDefinition::embedded("income-statement").unwrap(),
        periods: vec![PERIOD.into()],
        comparative: vec!["FY2026-P02".into()],
    }
}

fn original(h: &Harness) -> EntryPayload {
    h.book
        .db
        .vertices_at(h.head())
        .unwrap()
        .into_iter()
        .filter(|row| row.labels.contains(&label::ENTRY))
        .map(|row| {
            Entry::decode(&bytes(&row, property::FA_PAYLOAD, "test entry").unwrap()).unwrap()
        })
        .find(|entry| entry.proposal.idempotency_key == b"symbol-post")
        .unwrap()
        .proposal
}

fn fixture() -> (Harness, FxRateDocument) {
    let mut h = Harness::new(registry_digest(&fa_registry::Symbols::embedded().unwrap()));
    h.populate();
    let cx = h.cx();
    let units = &h.book.context().units;
    let rate = FxRateDocument {
        base_unit: units.lookup("USD").unwrap(),
        quote_unit: units.lookup("EUR").unwrap(),
        rate_num: 5,
        rate_den: 4,
        rounding: RoundingLaw::HalfEven,
        as_of: day(),
        retrieved_at_ns: 1,
        purpose: FxRatePurpose::SpotClose,
        source: "retained functional statement fixture".into(),
    };
    let document = Document {
        book_id: BOOK,
        kind: RATE_DOCUMENT_KIND,
        mime: "application/vnd.fa.fx-rate".into(),
        grade: 3,
        retrieved_by: PRINCIPAL,
        bytes: rate.canonical_bytes().unwrap(),
    };
    h.runtime
        .block_on(h.book.add_document(&cx, &document))
        .unwrap()
        .unwrap();
    let mut proposal = original(&h);
    proposal.idempotency_key = b"functional-foreign-invoice".to_vec();
    proposal.origin = EntryOrigin::Intent {
        intent_oid: Oid([0x71; 32]),
        intent_kind: 1,
    };
    for leg in &mut proposal.legs {
        leg.amount = Amount::new(rate.quote_unit, 10_000);
    }
    proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
    let arithmetic = h.root.restrict::<asupersync::cx::cap::None>();
    let mut budget = ArithmeticBudget::new(&arithmetic, BudgetLimits::uniform(1_000_000, 0), 4096);
    let proposal = cx
        .merge_eval()
        .with_restriction(|| {
            fa_journal::fx::value_proposal(
                &mut budget,
                proposal,
                &spec(),
                &h.book.context().units,
                FxLawId::SpotClose,
                std::slice::from_ref(&rate),
            )
        })
        .unwrap();
    h.runtime
        .block_on(h.book.post(
            &cx,
            PostRequest {
                proposal,
                approvals: Vec::new(),
                plan_certificate: None,
                capability: cap(&["post"]),
            },
        ))
        .unwrap()
        .unwrap();
    (h, rate)
}

fn certified(h: &mut Harness) -> crate::CertifiedStatement {
    let cx = h.cx();
    h.runtime
        .block_on(h.book.certify_functional_statement(
            &cx,
            PRINCIPAL,
            &cap(&["read", "produce"]),
            selection(),
            None,
        ))
        .unwrap()
        .unwrap()
}

fn reseal(certificate: &mut ReportCertificate) {
    certificate.output_digest = digest(b"fa:report-output:v1", &certificate.output);
    certificate.digest = digest(certificate.format(), &certificate.body_bytes().unwrap());
}

#[test]
fn retained_v5_replays_before_additive_close_law_but_cannot_claim_that_law() {
    let (mut h, _) = fixture();
    let certified = certified(&mut h);
    let mut prior = certified.certificate.clone();
    prior.registry_digest =
        crate::certificate::pre_carrying_registry_digest(&prior.selection).unwrap();
    assert_ne!(prior.registry_digest, certified.certificate.registry_digest);
    assert_ne!(prior.registry_digest, prior.legacy_v2_registry_closure());
    reseal(&mut prior);
    let retained = ReportCertificate::decode(&prior.canonical_bytes().unwrap()).unwrap();
    assert_eq!(
        h.book.replay_report(&h.cx(), &retained).unwrap().unwrap(),
        ReportOutput::FunctionalStatement(Box::new(certified.statement)),
    );

    // The compatibility closure cannot cover a new source-bound close, even
    // when an otherwise valid valuation's totals and amounts are unchanged.
    let mut valued = h
        .book
        .db
        .vertices_at(h.head())
        .unwrap()
        .into_iter()
        .filter(|row| row.labels.contains(&label::ENTRY))
        .map(|row| {
            Entry::decode(&bytes(&row, property::FA_PAYLOAD, "valued entry").unwrap())
                .unwrap()
                .proposal
        })
        .find(|proposal| proposal.base_totals.is_some())
        .unwrap();
    assert!(crate::certificate::pre_carrying_registry_covers(&valued));
    valued.base_totals.as_mut().unwrap().fx_law_oid = FxLawId::YearEndCloseCarrying.oid();
    assert!(!crate::certificate::pre_carrying_registry_covers(&valued));
    valued.base_totals.as_mut().unwrap().fx_law_oid = Oid([0xff; 32]);
    assert!(!crate::certificate::pre_carrying_registry_covers(&valued));
}

#[test]
fn functional_certificate_replays_rates_and_retains_a_distinct_output_basis() {
    let (mut h, rate) = fixture();
    let certified = certified(&mut h);
    assert_eq!(certified.certificate.inputs.len(), 8);
    assert!(
        certified.certificate.inputs[7]
            .statement
            .contains("WHERE n.code = 'Rate'")
    );
    assert_eq!(
        certified.certificate.output_format(),
        FUNCTIONAL_STATEMENT_OUTPUT_FORMAT
    );
    let bytes = certified.certificate.canonical_bytes().unwrap();
    assert!(bytes.starts_with(FUNCTIONAL_STATEMENT_CERTIFICATE_FORMAT));
    assert!(
        certified
            .certificate
            .output
            .starts_with(FUNCTIONAL_STATEMENT_OUTPUT_FORMAT.as_bytes())
    );
    assert!(
        certified
            .statement
            .lines
            .iter()
            .all(|line| line.unit_id == rate.base_unit.0)
    );
    let revenue = certified
        .statement
        .lines
        .iter()
        .find(|line| line.code == "revenue")
        .unwrap();
    assert_eq!(revenue.amounts, [25_050, 0]);

    let decoded = ReportCertificate::decode(&bytes).unwrap();
    let replayed = h.book.replay_report(&h.cx(), &decoded).unwrap().unwrap();
    assert_eq!(
        replayed,
        ReportOutput::FunctionalStatement(Box::new(certified.statement.clone()))
    );
    assert_eq!(replayed.canonical_bytes().unwrap(), decoded.output);
    let native = h
        .book
        .certify_statement(&h.cx(), selection(), Some(decoded.known_at))
        .unwrap()
        .unwrap();
    assert_eq!(native.certificate.inputs.len(), 7);
    assert!(
        native
            .certificate
            .canonical_bytes()
            .unwrap()
            .starts_with(b"fa:report-certificate:v4")
    );
    assert_ne!(native.certificate.output, decoded.output);

    let artifact = ReportArtifact::decode(&bytes).unwrap();
    assert_eq!(artifact.family(), ReportArtifactFamily::Native);
    let cx = h.cx();
    let retained = h
        .runtime
        .block_on(h.book.retain_report_artifact(
            &cx,
            PRINCIPAL,
            &cap(&["read", "produce"]),
            &bytes,
            Some(&decoded.digest),
        ))
        .unwrap()
        .unwrap();
    let stored = h
        .runtime
        .block_on(h.book.read_certificate(&cx, &retained.digest))
        .unwrap()
        .unwrap();
    assert_eq!(stored, decoded);
    assert_eq!(
        h.book.replay_report(&cx, &stored).unwrap().unwrap(),
        replayed
    );
    assert!(matches!(
        h.book.certificate_status(&cx, &stored).unwrap().unwrap(),
        CertificateStatus::Current { .. }
    ));
}

#[test]
fn functional_certificate_rejects_resealed_output_and_missing_rate_closure() {
    let (mut h, _) = fixture();
    let certified = certified(&mut h);
    let mut altered = certified.certificate.clone();
    let mut report = certified.statement;
    report
        .lines
        .iter_mut()
        .find(|line| line.code == "revenue")
        .unwrap()
        .amounts[0] += 1;
    altered.output = ReportOutput::FunctionalStatement(Box::new(report))
        .canonical_bytes()
        .unwrap();
    reseal(&mut altered);
    ReportCertificate::decode(&altered.canonical_bytes().unwrap()).unwrap();
    let refusal = h
        .book
        .replay_report(&h.cx(), &altered)
        .unwrap()
        .unwrap_err();
    assert!(
        refusal
            .message
            .contains("differs from its certified output"),
        "{refusal:?}"
    );

    let mut incomplete = certified.certificate.clone();
    incomplete.inputs.pop();
    reseal(&mut incomplete);
    assert!(ReportCertificate::decode(&incomplete.canonical_bytes().unwrap()).is_err());

    let mut legacy_laws = certified.certificate.clone();
    legacy_laws.registry_digest = legacy_laws.legacy_v2_registry_closure();
    reseal(&mut legacy_laws);
    let refusal = h
        .book
        .replay_report(&h.cx(), &legacy_laws)
        .unwrap()
        .unwrap_err();
    assert_eq!(
        refusal.code,
        crate::certificate::code::CERTIFICATE_REGISTRY_UNAVAILABLE
    );
}

#[test]
fn functional_certificate_keeps_old_output_and_detects_backdated_contributions() {
    let (mut h, _) = fixture();
    let certified = certified(&mut h);
    let mut proposal = original(&h);
    proposal.idempotency_key = b"functional-backdated".to_vec();
    proposal.origin = EntryOrigin::Intent {
        intent_oid: Oid([0x72; 32]),
        intent_kind: 1,
    };
    for leg in &mut proposal.legs {
        leg.amount.mantissa = 100;
    }
    proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
    let cx = h.cx();
    let posted = h
        .runtime
        .block_on(h.book.post(
            &cx,
            PostRequest {
                proposal,
                approvals: Vec::new(),
                plan_certificate: None,
                capability: cap(&["post"]),
            },
        ))
        .unwrap()
        .unwrap();
    assert_eq!(
        h.book
            .replay_report(&cx, &certified.certificate)
            .unwrap()
            .unwrap(),
        ReportOutput::FunctionalStatement(Box::new(certified.statement))
    );
    assert_eq!(
        h.book
            .certificate_status(&cx, &certified.certificate)
            .unwrap()
            .unwrap(),
        CertificateStatus::SupersededBy {
            checked_at: posted.recorded_at(),
            later_entries: vec![posted.entry_ref().vid],
            cases: Vec::new(),
        }
    );
}

#[test]
fn functional_rate_projection_refuses_rebound_citations_and_forged_kind_mirrors() {
    let (mut h, rate) = fixture();
    let certificate = certified(&mut h).certificate;
    let rate_oid = rate.oid(BOOK).unwrap();
    let rate_vid = fa_journal::evidence::document_vid(&rate_oid);
    let mut batch = WriteBatch::new(relation::IN_BOOK);
    batch.set_vertex_property(
        rate_vid,
        property::CODE,
        Some(fa_journal::rows::scalar_text("rate kind", "Invoice").unwrap()),
    );
    let cx = h.cx();
    h.runtime
        .block_on(h.book.db.write(&cx.commit(), batch))
        .unwrap();
    let refusal = h
        .book
        .replay_report(&cx, &certificate)
        .unwrap()
        .unwrap_err();
    assert!(
        refusal.message.contains("Rate document") && refusal.message.contains("rewritten"),
        "{refusal:?}"
    );
    let refusal = h
        .runtime
        .block_on(
            h.book
                .functional_statement(&cx, PRINCIPAL, &cap(&["read"]), selection(), None),
        )
        .unwrap()
        .unwrap_err();
    assert!(refusal.message.contains("Rate document"), "{refusal:?}");

    let (mut h, _) = fixture();
    let invoice_oid = original(&h).evidence[0].document_oid;
    let mut batch = WriteBatch::new(relation::IN_BOOK);
    batch.set_vertex_property(
        fa_journal::evidence::document_vid(&invoice_oid),
        property::CODE,
        Some(fa_journal::rows::scalar_text("forged kind", "Rate").unwrap()),
    );
    let cx = h.cx();
    h.runtime
        .block_on(h.book.db.write(&cx.commit(), batch))
        .unwrap();
    let refusal = h
        .runtime
        .block_on(h.book.certify_functional_statement(
            &cx,
            PRINCIPAL,
            &cap(&["read", "produce"]),
            selection(),
            None,
        ))
        .unwrap()
        .unwrap_err();
    assert!(refusal.message.contains("Rate projection"), "{refusal:?}");
}
