//! fa-81lu: `jet.self_sourced_evidence` (plan §9.3) flags the entries whose
//! only evidence, cited and supplemental, is self-sourced, and leaves alone
//! an entry with any document a person or third party supplied.

use super::*;
use fa_journal::attestation::record_review;
use fa_journal::evidence::{SupplementalEvidence, attach_evidence};
use fa_lantern::jet::SelfSourcedEvidence;
use fa_model::EntryRef;

/// evidence_policy.toml's `AgentUpload` grade (self-sourced).
const AGENT_UPLOAD: u8 = 4;

/// Records a document of `grade` that `by` brought in; its citation in
/// role 1.
fn document(h: &mut Harness, grade: u8, by: VId, text: &[u8]) -> EvidenceRef {
    let doc = Document {
        book_id: h.book.book_id,
        kind: 1,
        mime: "text/plain".into(),
        grade,
        retrieved_by: by,
        bytes: text.to_vec(),
    };
    let ctx = h.ctx();
    let (db, book) = (&mut h.db, &h.book);
    h.runtime
        .block_on(async { add_document(db, &ctx, book, &doc).await })
        .expect("kernel")
        .expect("admitted");
    doc.evidence_ref(1)
}

/// `reviewer` records a Reviewed attestation over `document`.
fn review(h: &mut Harness, reviewer: VId, document: Oid) {
    let capability = Capability::embedded(reviewer, &["approve"]).expect("approve");
    let ctx = h.ctx();
    let (db, book) = (&mut h.db, &h.book);
    h.runtime
        .block_on(async {
            record_review(db, &ctx, book, &capability, reviewer, document, Vec::new()).await
        })
        .expect("kernel")
        .expect("admitted");
}

/// The preparer attaches `documents` to the committed `entry`.
fn attach(h: &mut Harness, entry: VId, documents: Vec<EvidenceRef>) {
    let snapshot = Snapshot::read(&h.db, &h.ctx().query(), &h.book, None, None).unwrap();
    let entry_digest = snapshot
        .entries
        .iter()
        .find(|e| e.vid == entry)
        .expect("posted")
        .entry
        .entry_digest;
    let supplement = SupplementalEvidence {
        book_id: h.book.book_id,
        entry_ref: EntryRef {
            vid: entry,
            entry_digest,
        },
        documents,
        attached_by: PREPARER,
    };
    let capability = Capability::embedded(PREPARER, &["post"]).expect("post");
    let ctx = h.ctx();
    let (db, book) = (&mut h.db, &h.book);
    h.runtime
        .block_on(async { attach_evidence(db, &ctx, book, &capability, &supplement).await })
        .expect("kernel")
        .expect("admitted");
}

fn flagged(run: &ProcedureRun) -> Vec<VId> {
    let entries: Vec<VId> = run
        .findings
        .iter()
        .filter_map(|f| match f.cites.first() {
            Some(Cite::Entry(v)) => Some(*v),
            _ => None,
        })
        .collect();
    assert_eq!(
        entries.len(),
        run.findings.len(),
        "a finding cites its entry first"
    );
    entries
}

#[test]
fn self_sourced_evidence_flags_agent_upload_only() {
    let mut h = harness();
    let person = h.evidence[0];
    let agent = document(
        &mut h,
        AGENT_UPLOAD,
        PREPARER,
        b"RECEIPT (an agent's upload)",
    );
    let late = document(
        &mut h,
        AGENT_UPLOAD,
        PREPARER,
        b"MEMO (an agent's later upload)",
    );
    // An Original needs one document; a self-sourced one counts once a
    // principal other than its uploader reviews it (FA-REF-086 before).
    review(&mut h, REVIEWER, agent.document_oid);
    let mut both = vec![person, agent];
    both.sort();

    h.evidence = vec![agent];
    let own = h.post(&Spec::simple(day(2026, 3, 9), "6000", "1000", 4_200));
    h.evidence = both;
    let mixed = h.post(&Spec::simple(day(2026, 3, 10), "6000", "1000", 4_300));
    h.evidence = vec![person];
    let independent = h.post(&Spec::simple(day(2026, 3, 11), "6000", "1000", 4_400));
    // A supplement of the agent's own leaves a person-supported entry alone.
    attach(&mut h, independent, vec![late]);

    let procedure = SelfSourcedEvidence::new().unwrap();
    let snapshot = Snapshot::read(&h.db, &h.ctx().query(), &h.book, None, None).unwrap();
    assert_eq!(snapshot.supplements[&independent][0].documents, vec![late]);
    let r = run_over(&snapshot, &h.book, &procedure).unwrap();
    h.assert_cites_resolve(&r);
    println!("self_sourced findings={:?}", r.findings);
    assert_eq!(
        flagged(&r),
        vec![own],
        "only the entry whose only evidence is the agent's"
    );
    let f = &r.findings[0];
    assert_eq!(
        f.cites,
        vec![Cite::Entry(own), Cite::Document(agent.document_oid)]
    );
    assert_eq!(
        f.statistic,
        Statistic::count("self_sourced_documents", 1, 3)
    );
    assert_eq!(
        f.severity,
        Severity::Medium,
        "reviewed by someone other than its uploader"
    );
    assert!(!flagged(&r).contains(&mixed) && !flagged(&r).contains(&independent));
    let row = fa_lantern::bind(SelfSourcedEvidence::ID).unwrap();
    assert!(
        r.work.within_registered_bound(&row.complexity, &snapshot),
        "{:?}",
        r.work
    );
    assert!(
        determinism(&snapshot, &h.book, &procedure)
            .unwrap()
            .deterministic()
    );

    // The same entry without its review is High: severity reads the reviews.
    let mut unreviewed = snapshot.clone();
    unreviewed.attestations.clear();
    let r = run_over(&unreviewed, &h.book, &procedure).unwrap();
    assert_eq!(flagged(&r), vec![own]);
    assert_eq!(r.findings[0].severity, Severity::High);

    // A supplement a person supplied takes the entry out of the population's
    // hits: its evidence is no longer only the book's own.
    let receipt = document(&mut h, 3, REVIEWER, b"BANK ADVICE (a person's upload)");
    attach(&mut h, own, vec![receipt]);
    let snapshot = Snapshot::read(&h.db, &h.ctx().query(), &h.book, None, None).unwrap();
    let r = run_over(&snapshot, &h.book, &procedure).unwrap();
    assert!(r.findings.is_empty(), "{:?}", r.findings);
}
