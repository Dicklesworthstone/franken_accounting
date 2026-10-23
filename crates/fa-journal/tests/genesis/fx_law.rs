use super::*;
use fa_journal::fx::{
    FxConversionVerification, FxLawId, FxRateDocument, FxRatePurpose, FxRateTerms,
    RATE_EVIDENCE_ROLE, value_proposal, verify_fx_conversions,
};
use fa_money::RoundingLaw;
use fa_money::rate::{ArithmeticBudget, BudgetLimits};
use fgdb_types::CommitSeq;

fn valued_source() -> (Harness, Document, EntryRef) {
    let mut h = harness();
    let foreign = h.book.units.lookup("EUR").unwrap();
    let accounts = [("1288", 1, 0), ("4088", 4, 1)]
        .into_iter()
        .map(|(code, account_type, normal_balance)| AccountSpec {
            code: code.into(),
            name: code.into(),
            account_type,
            normal_balance,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(foreign),
            parent_code: None,
            limit: None,
        })
        .collect::<Vec<_>>();
    let cx = h.ctx();
    let date = h.day();
    let description = h
        .proposal(vec![], b"fx-chart", EntryClass::ORIGINAL)
        .description;
    h.runtime
        .block_on(install_chart(
            &mut h.db,
            &cx,
            &h.book,
            &accounts,
            PRINCIPAL,
            date,
            b"fx-identity-chart",
            description,
            &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
        ))
        .unwrap()
        .unwrap();
    let rate = FxRateDocument::new(
        FxRateTerms {
            base_unit: h.usd,
            quote_unit: foreign,
            rate_num: 11,
            rate_den: 10,
            rounding: RoundingLaw::HalfEven,
        },
        date,
        1,
        FxRatePurpose::SpotClose,
        "Recorded source quote",
    )
    .unwrap();
    let document = rate
        .document(h.book.book_id, PRINCIPAL, HUMAN_UPLOAD)
        .unwrap();
    h.add_document(&document).unwrap();
    let proposal = h.proposal(
        vec![
            LegPayload::simple(
                Side::Debit,
                account_vid(h.book.book_id, "1288"),
                Amount::new(foreign, 100),
            ),
            LegPayload::simple(
                Side::Credit,
                account_vid(h.book.book_id, "4088"),
                Amount::new(foreign, 100),
            ),
        ],
        b"source-bound-quote",
        EntryClass::ORIGINAL,
    );
    let arithmetic = h.root.restrict::<asupersync::cx::cap::None>();
    let mut budget = ArithmeticBudget::new(&arithmetic, BudgetLimits::uniform(100_000, 0), 4096);
    let proposal = value_proposal(
        &mut budget,
        proposal,
        &fa_journal::genesis::read_book_spec(&h.db).unwrap().unwrap(),
        &h.book.units,
        FxLawId::SpotClose,
        &[rate],
    )
    .unwrap();
    let posted = h.post(h.request(proposal, &["post"])).unwrap().entry_ref();
    assert!(verify(&h, h.db.frontier().unwrap()).is_green());
    (h, document, posted)
}

fn verify(h: &Harness, at: CommitSeq) -> FxConversionVerification {
    let cx = h.ctx();
    cx.query()
        .with_restriction(|| verify_fx_conversions(&h.db, &cx, &h.book, at))
        .unwrap()
}

#[test]
fn fx_verification_rejects_rebound_rate_content_even_when_its_quote_is_unchanged() {
    let (mut h, document, source) = valued_source();
    let before = h.db.frontier().unwrap();
    let mut quote = FxRateDocument::decode(&document.bytes).unwrap();
    quote.source = "A different source with the same numeric rate".into();
    let substitute = quote
        .document(h.book.book_id, PRINCIPAL, HUMAN_UPLOAD)
        .unwrap();
    assert_ne!(substitute.oid(), document.oid());
    let mut damage = fgdb::WriteBatch::new(relation::IN_BOOK);
    let vid = document_vid(&document.oid());
    damage.set_vertex_property(
        vid,
        property::FA_PAYLOAD,
        Some(CanonicalScalar::bytes(substitute.canonical_bytes().unwrap()).unwrap()),
    );
    damage.set_vertex_property(
        vid,
        property::FA_DIGEST,
        Some(CanonicalScalar::bytes(substitute.doc_commit().to_vec()).unwrap()),
    );
    h.write_raw(damage);
    let current = verify(&h, h.db.frontier().unwrap());
    assert_eq!(current.drift.len(), 1);
    assert_eq!(current.drift[0].entry, source.vid);
    assert!(current.drift[0].problem.contains("identity"));
    assert!(
        verify(&h, before).is_green(),
        "the saved prefix keeps its original quote"
    );
}

#[test]
fn fx_verification_requires_rate_book_kind_and_digest_mirrors() {
    for (key, value) in [
        (
            property::BOOK_ID,
            CanonicalScalar::bytes(vec![99; 16]).unwrap(),
        ),
        (
            property::FA_DIGEST,
            CanonicalScalar::bytes(vec![99; 32]).unwrap(),
        ),
        (
            property::CODE,
            CanonicalScalar::ucs_basic_text("Invoice").unwrap(),
        ),
    ] {
        let (mut h, document, _) = valued_source();
        let mut damage = fgdb::WriteBatch::new(relation::IN_BOOK);
        damage.set_vertex_property(document_vid(&document.oid()), key, Some(value));
        h.write_raw(damage);
        let current = verify(&h, h.db.frontier().unwrap());
        assert_eq!(current.drift.len(), 1);
        assert!(current.drift[0].problem.contains("mirrors"));
    }
}

#[test]
fn fx_verification_binds_the_recorded_rate_citation_commitment() {
    let (mut h, document, source) = valued_source();
    let (entry, _) = read_entry(&h.db, source.vid).unwrap().unwrap();
    let mut proposal = entry.proposal;
    let citation = proposal
        .evidence
        .iter_mut()
        .find(|evidence| {
            evidence.document_oid == document.oid() && evidence.role == RATE_EVIDENCE_ROLE
        })
        .unwrap();
    citation.doc_commit = [99; 32];
    proposal.evidence.sort();
    let damaged = proposal
        .seal(entry.approvals, entry.plan_certificate)
        .unwrap();
    let mut damage = fgdb::WriteBatch::new(relation::IN_BOOK);
    damage.set_vertex_property(
        source.vid,
        property::FA_PAYLOAD,
        Some(CanonicalScalar::bytes(damaged.encode().unwrap()).unwrap()),
    );
    damage.set_vertex_property(
        source.vid,
        property::FA_DIGEST,
        Some(CanonicalScalar::bytes(damaged.entry_digest.to_vec()).unwrap()),
    );
    h.write_raw(damage);
    let current = verify(&h, h.db.frontier().unwrap());
    assert_eq!(current.drift.len(), 1);
    assert!(current.drift[0].problem.contains("citation"));
}
