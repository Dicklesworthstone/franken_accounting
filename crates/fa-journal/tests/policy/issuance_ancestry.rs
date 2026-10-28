//! Admission must establish the whole authority path before observing or
//! writing accounting data. The budget bounds the path, never revocation.

use super::*;
use fa_journal::policy::{authority_lineage, capability_admitted, capability_witness};
use fa_model::limits::MAX_ISSUANCE_LINEAGE;

fn child(issuer: &Capability, holder: VId, salt: u8) -> Capability {
    Capability::new(
        holder,
        Profile::Human,
        &[Op::Read, Op::Post, Op::IssueCapability],
        issuer.holder(),
    )
    .unwrap()
    .holder_bound(possession_digest(&[salt; 32]))
}

fn chain(h: &mut Harness, depth: usize) -> (Capability, Vec<Capability>) {
    let root = human(PREPARER, &["read", "post", "issue_capability"]);
    let mut descendants = Vec::new();
    for index in 0..depth {
        let issuer = descendants.last().unwrap_or(&root);
        let issued = child(issuer, VId(1_000 + index as u128), index as u8 + 1);
        h.issue(issuer, &issued, format!("ancestry-{index}").as_bytes())
            .expect("an issuance within the registered ancestry budget");
        descendants.push(issued);
    }
    (root, descendants)
}

fn write_fixture(h: &mut Harness, batch: WriteBatch) {
    let ctx = h.ctx();
    h.runtime
        .block_on(h.db.write(&ctx.commit(), batch))
        .unwrap();
}

fn overwrite_entry(h: &mut Harness, vid: VId, proposal: EntryPayload) {
    let entry = proposal.seal(Vec::new(), None).unwrap();
    let mut batch = WriteBatch::new(relation::IN_BOOK);
    for (key, value) in fa_model::entry_mirrors(&entry).unwrap() {
        batch.set_vertex_property(vid, key, Some(value));
    }
    write_fixture(h, batch);
}

fn transaction_refusal(h: &mut Harness, capability: &Capability) -> Refusal {
    let ctx = h.ctx();
    let txn = h.db.begin(&ctx.txn()).unwrap();
    let result = capability_witness(&txn, &h.db, &h.book, capability)
        .unwrap()
        .unwrap_err();
    txn.abort();
    result
}

#[test]
fn issuance_budget_admits_its_boundary_and_refuses_another_child_without_writes() {
    let mut h = harness();
    let (_, descendants) = chain(&mut h, MAX_ISSUANCE_LINEAGE);
    for depth in [MAX_ISSUANCE_LINEAGE - 1, MAX_ISSUANCE_LINEAGE] {
        let capability = &descendants[depth - 1];
        admit_reads(&h.db, &h.book, capability.holder(), capability)
            .unwrap()
            .expect("the complete path at and below the budget reads");
        h.post(
            h.proposal(
                capability.holder(),
                100,
                format!("ancestry-post-{depth}").as_bytes(),
                EntryClass::ORIGINAL,
            ),
            capability.clone(),
            Vec::new(),
        )
        .expect("the complete path at and below the budget posts");
        assert_eq!(
            read_issued(&h.db, &h.book, &capability.commitment().unwrap())
                .unwrap()
                .unwrap()
                .revoked_at,
            None,
        );
    }
    let issuer = descendants.last().unwrap();
    let issued = child(issuer, BOB, 100);
    let head = h.db.frontier().unwrap();
    let rows = h.db.vertices().unwrap();
    let refusal = h.issue(issuer, &issued, b"ancestry-too-deep").unwrap_err();
    assert_eq!((refusal.code, refusal.exit), ("FA-REF-156", exit::SAFETY));
    assert!(refusal.message.contains("max_issuance_lineage=16"));
    assert!(refusal.fix.contains("fa capability issue"));
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), rows);

    // The source is still usable at the boundary; inability to delegate
    // farther must not make its own exact issuance retry a new publication.
    let retry = h
        .issue(
            &descendants[MAX_ISSUANCE_LINEAGE - 2],
            issuer,
            format!("ancestry-{}", MAX_ISSUANCE_LINEAGE - 1).as_bytes(),
        )
        .unwrap();
    assert!(retry.already_recorded);
    assert_eq!(h.db.frontier().unwrap(), head);
}

#[test]
fn a_previously_written_over_budget_chain_never_becomes_truncated_authority() {
    let mut h = harness();
    let (root, descendants) = chain(&mut h, MAX_ISSUANCE_LINEAGE);
    let issuer = descendants.last().unwrap();
    let issued = child(issuer, BOB, 101);
    let commitment = issued.commitment().unwrap();
    let body = issued.canonical_bytes().unwrap();

    // The previous writer permitted this additional issuance. Reproduce its
    // canonical retained row directly to exercise admission of existing books,
    // independently of the new issuance-time refusal above.
    let template_vid = issuance_vid(h.book.book_id, &issuer.commitment().unwrap());
    let (template, _) = read_entry(&h.db, template_vid).unwrap().unwrap();
    let mut proposal = template.proposal;
    proposal.principal_ref = issuer.holder();
    proposal.idempotency_key = b"old-writer-over-budget".to_vec();
    proposal.origin = EntryOrigin::Control {
        control_kind: fa_model::ControlKind::CAPABILITY_ISSUANCE,
        spec_body_digest: issuer.commitment().unwrap(),
    };
    proposal.control = Some(ControlPayload::CapabilityEvent {
        kind: fa_journal::policy::CAPABILITY_EVENT_ISSUE,
        commitment,
        caveats_digest: fa_model::domain_digest(b"fa:capability-body:v1", &[&body]),
    });
    proposal.extensions = vec![(fa_model::entry::CAPABILITY_BODY_EXTENSION, body)];
    let entry = proposal.seal(Vec::new(), None).unwrap();
    let mut batch = WriteBatch::new(relation::IN_BOOK);
    batch.create_vertex(
        issuance_vid(h.book.book_id, &commitment),
        vec![label::ENTRY],
        fa_model::entry_mirrors(&entry).unwrap(),
    );
    write_fixture(&mut h, batch);
    h.revoke(
        &human(CAROL, &["issue_capability"]),
        &root,
        b"revoke-distant-root",
    )
    .unwrap();
    let head = h.db.frontier().unwrap();
    let rows = h.db.vertices().unwrap();
    let refused = admit_reads(&h.db, &h.book, issued.holder(), &issued)
        .unwrap()
        .unwrap_err();
    assert_eq!((refused.code, refused.exit), ("FA-REF-156", exit::SAFETY));
    assert_eq!(transaction_refusal(&mut h, &issued).code, refused.code);
    let refused = h
        .post(
            h.proposal(BOB, 100, b"truncated-authority", EntryClass::ORIGINAL),
            issued.clone(),
            Vec::new(),
        )
        .unwrap_err();
    assert_eq!(refused.code, "FA-REF-156");
    assert!(matches!(
        read_issued(&h.db, &h.book, &commitment),
        Err(KernelError::Corrupt(message)) if message.contains("max_issuance_lineage"),
    ));
    let ctx = h.ctx();
    let txn = h.db.begin(&ctx.txn()).unwrap();
    assert_eq!(
        authority_lineage(&txn, &h.db, &h.book, &commitment).unwrap(),
        None,
        "an incomplete exclusion must never be an empty, apparently independent lineage",
    );
    txn.abort();
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), rows);
}

#[test]
fn distant_root_revocation_reaches_reads_writes_and_status_at_the_budget_boundary() {
    let mut h = harness();
    let (root, descendants) = chain(&mut h, MAX_ISSUANCE_LINEAGE);
    let leaf = descendants.last().unwrap();
    let commitment = leaf.commitment().unwrap();
    let revoked = h
        .revoke(
            &human(CAROL, &["issue_capability"]),
            &root,
            b"revoke-complete-chain-root",
        )
        .unwrap();
    let head = h.db.frontier().unwrap();
    let refusal = admit_reads(&h.db, &h.book, leaf.holder(), leaf)
        .unwrap()
        .unwrap_err();
    assert_eq!(refusal.code, "FA-REF-023");
    assert_eq!(transaction_refusal(&mut h, leaf).code, "FA-REF-023");
    assert_eq!(
        h.post(
            h.proposal(
                leaf.holder(),
                100,
                b"revoked-chain-post",
                EntryClass::ORIGINAL
            ),
            leaf.clone(),
            Vec::new(),
        )
        .unwrap_err()
        .code,
        "FA-REF-023",
    );
    assert_eq!(
        read_issued(&h.db, &h.book, &commitment)
            .unwrap()
            .unwrap()
            .revoked_at,
        Some(revoked.recorded_at),
    );
    assert_eq!(h.db.frontier().unwrap(), head);
}

#[test]
fn every_ancestor_revocation_is_a_transaction_witness() {
    let mut h = harness();
    let (root, descendants) = chain(&mut h, MAX_ISSUANCE_LINEAGE);
    let leaf = descendants.last().unwrap();
    let key = b"post-racing-distant-revocation";
    let proposal = h.proposal(leaf.holder(), 100, key, EntryClass::ORIGINAL);
    let vid = fa_model::entry_vid(h.book.book_id, &leaf.holder().0.to_le_bytes(), key);
    let ctx = h.ctx();
    let PostPreparation::Ready(prepared) = prepare_post(
        &mut h.db,
        &ctx,
        &h.book,
        PostRequest {
            proposal,
            capability: leaf.clone(),
            approvals: Vec::new(),
            plan_certificate: None,
        },
    )
    .unwrap()
    .unwrap() else {
        panic!("a live complete ancestry prepares")
    };
    h.revoke(
        &human(CAROL, &["issue_capability"]),
        &root,
        b"racing-root-revocation",
    )
    .unwrap();
    let head = h.db.frontier().unwrap();
    let rows = h.db.vertices().unwrap();
    let refused = h
        .runtime
        .block_on(prepared.commit(&mut h.db, &ctx))
        .unwrap()
        .unwrap_err();
    assert_eq!(refused.exit, exit::CONFLICT);
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), rows);
    assert!(h.db.vertex(vid).unwrap().is_none());
}

#[test]
fn ancestor_issuance_and_revocation_point_reads_are_the_cause_of_race_conflicts() {
    for change in ["issuance", "revocation"] {
        for witness in [false, true] {
            let mut h = harness();
            let (root, descendants) = chain(&mut h, MAX_ISSUANCE_LINEAGE);
            let leaf = descendants.last().unwrap();
            let ctx = h.ctx();
            let txn_cx = ctx.txn();
            let mut txn = h.db.begin(&txn_cx).unwrap();
            if witness {
                capability_witness(&txn, &h.db, &h.book, leaf)
                    .unwrap()
                    .unwrap();
            }
            if change == "revocation" {
                h.revoke(
                    &human(CAROL, &["issue_capability"]),
                    &root,
                    b"witness-only-root-revocation",
                )
                .unwrap();
            } else {
                let ancestor = &descendants[0];
                let vid = issuance_vid(h.book.book_id, &ancestor.commitment().unwrap());
                let (entry, _) = read_entry(&h.db, vid).unwrap().unwrap();
                let mut proposal = entry.proposal;
                proposal.description = Erasable::seal(
                    &"changed ancestor".to_owned(),
                    None,
                    &h.book.seal_key,
                    [106; 32],
                    [107; 24],
                );
                overwrite_entry(&mut h, vid, proposal);
            }
            let refreshed = txn.refresh_snapshot(&h.db, &txn_cx);
            txn.abort();
            if witness {
                assert!(
                    matches!(
                        refreshed,
                        Err(WriteTxnError::Write(
                            fgdb::WriteError::FirstCommitterWins { .. }
                        )),
                    ),
                    "{change}: an observed distant authority identity must conflict: {refreshed:?}",
                );
            } else {
                assert!(
                    refreshed.is_ok(),
                    "{change}: without the authority witness this interleaving is harmless: {refreshed:?}",
                );
            }
        }
    }
}

#[test]
fn cyclic_issuances_refuse_instead_of_ending_the_authority_walk() {
    let mut h = harness();
    let root = human(PREPARER, &["read", "post", "issue_capability"]);
    let first = child(&root, PREPARER, 102);
    let second = child(&first, PREPARER, 103);
    h.issue(&root, &first, b"cyclic-first").unwrap();
    h.issue(&first, &second, b"cyclic-second").unwrap();
    let first_vid = issuance_vid(h.book.book_id, &first.commitment().unwrap());
    let (first_entry, _) = read_entry(&h.db, first_vid).unwrap().unwrap();
    let mut proposal = first_entry.proposal;
    proposal.origin = EntryOrigin::Control {
        control_kind: fa_model::ControlKind::CAPABILITY_ISSUANCE,
        spec_body_digest: second.commitment().unwrap(),
    };
    overwrite_entry(&mut h, first_vid, proposal);
    let head = h.db.frontier().unwrap();
    let refused = capability_admitted(&h.db, &h.book, &second)
        .unwrap()
        .unwrap_err();
    assert_eq!((refused.code, refused.exit), ("FA-REF-156", exit::SAFETY));
    assert!(refused.message.contains("cyclic"));
    assert!(
        transaction_refusal(&mut h, &second)
            .message
            .contains("cyclic")
    );
    assert!(matches!(
        read_issued(&h.db, &h.book, &second.commitment().unwrap()),
        Err(KernelError::Corrupt(message)) if message.contains("cyclic"),
    ));
    let next = child(&second, BOB, 104);
    assert_eq!(
        h.issue(&second, &next, b"cyclic-third").unwrap_err().code,
        "FA-REF-156",
    );
    assert_eq!(h.db.frontier().unwrap(), head);
}

#[test]
fn malformed_ancestors_propagate_errors_instead_of_becoming_embedded_roots() {
    for damage in ["payload", "mirror", "body", "issuer", "parent-holder"] {
        let mut h = harness();
        let (_, descendants) = chain(&mut h, 3);
        let ancestor = &descendants[0];
        let leaf = &descendants[2];
        let ancestor_vid = issuance_vid(h.book.book_id, &ancestor.commitment().unwrap());
        if matches!(damage, "payload" | "mirror") {
            let mut batch = WriteBatch::new(relation::IN_BOOK);
            let (key, value) = if damage == "payload" {
                (
                    property::FA_PAYLOAD,
                    CanonicalScalar::bytes(vec![0xff; 8]).unwrap(),
                )
            } else {
                (property::CLASS, CanonicalScalar::Int(255))
            };
            batch.set_vertex_property(ancestor_vid, key, Some(value));
            write_fixture(&mut h, batch);
        } else {
            let target = if damage == "parent-holder" {
                issuance_vid(h.book.book_id, &leaf.commitment().unwrap())
            } else {
                ancestor_vid
            };
            let (entry, _) = read_entry(&h.db, target).unwrap().unwrap();
            let mut proposal = entry.proposal;
            match damage {
                "body" => {
                    proposal.extensions[0].1 = ancestor
                        .clone()
                        .holder_bound(possession_digest(&[105; 32]))
                        .canonical_bytes()
                        .unwrap();
                }
                "issuer" => proposal.principal_ref = CAROL,
                "parent-holder" => {
                    // A leaf names its grandparent as its parent. The body
                    // still names the actual direct issuer, so holders differ.
                    proposal.origin = EntryOrigin::Control {
                        control_kind: fa_model::ControlKind::CAPABILITY_ISSUANCE,
                        spec_body_digest: ancestor.commitment().unwrap(),
                    };
                }
                _ => unreachable!(),
            }
            overwrite_entry(&mut h, target, proposal);
        }
        let head = h.db.frontier().unwrap();
        let rows = h.db.vertices().unwrap();
        assert!(
            capability_admitted(&h.db, &h.book, leaf).is_err(),
            "{damage}: a malformed ancestor must not terminate read admission",
        );
        let ctx = h.ctx();
        let txn = h.db.begin(&ctx.txn()).unwrap();
        assert!(
            capability_witness(&txn, &h.db, &h.book, leaf).is_err(),
            "{damage}: a malformed ancestor must not terminate write admission",
        );
        assert!(
            authority_lineage(&txn, &h.db, &h.book, &leaf.commitment().unwrap()).is_err(),
            "{damage}: SoD must not derive an independent principal from corrupt history",
        );
        txn.abort();
        assert!(
            read_issued(&h.db, &h.book, &leaf.commitment().unwrap()).is_err(),
            "{damage}: status cannot describe corrupt authority as unrevoked",
        );
        let proposal = h.proposal(
            leaf.holder(),
            100,
            b"corrupt-chain-post",
            EntryClass::ORIGINAL,
        );
        assert!(
            h.runtime
                .block_on(post(
                    &mut h.db,
                    &ctx,
                    &h.book,
                    PostRequest {
                        proposal,
                        capability: leaf.clone(),
                        approvals: Vec::new(),
                        plan_certificate: None,
                    },
                ))
                .is_err(),
            "{damage}: corrupt ancestry must not publish accounting data",
        );
        assert_eq!(h.db.frontier().unwrap(), head);
        assert_eq!(h.db.vertices().unwrap(), rows);
    }
}

#[test]
fn explicitly_unlinked_legacy_issuance_origins_remain_readable() {
    for self_link in [false, true] {
        let mut h = harness();
        let (_, descendants) = chain(&mut h, 1);
        let capability = &descendants[0];
        let commitment = capability.commitment().unwrap();
        let vid = issuance_vid(h.book.book_id, &commitment);
        let (entry, _) = read_entry(&h.db, vid).unwrap().unwrap();
        let mut proposal = entry.proposal;
        proposal.origin = EntryOrigin::Control {
            control_kind: fa_model::ControlKind::CAPABILITY_ISSUANCE,
            spec_body_digest: if self_link { commitment } else { [0; 32] },
        };
        overwrite_entry(&mut h, vid, proposal);
        capability_admitted(&h.db, &h.book, capability)
            .unwrap()
            .expect("legacy unlinked origins retain their existing meaning");
        assert_eq!(
            read_issued(&h.db, &h.book, &commitment)
                .unwrap()
                .unwrap()
                .revoked_at,
            None,
        );
        h.post(
            h.proposal(
                capability.holder(),
                100,
                b"legacy-root-post",
                EntryClass::ORIGINAL,
            ),
            capability.clone(),
            Vec::new(),
        )
        .expect("legacy issuance remains usable under its recorded authority");
    }
}
