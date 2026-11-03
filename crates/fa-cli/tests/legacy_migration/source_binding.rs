//! Explicit native source-population admission through the real import CLI.
//! These tests keep the original package, independent approvals, durable
//! history and independent proof reader; equal net balances are insufficient.

use super::*;
use fa_journal::migration::{SourceChunk, SourceManifest};
use fa_model::{ApprovalRef, migration_entry_vid, principal_vid};
use fgdb_types::CommitSeq;

fn prepare(fixture: &Fixture) -> Json {
    let path = fixture.file("bound-import.json", &fixture.intent().render());
    let prepared = ok(
        &fixture.book,
        &[
            "migrate",
            "import",
            "--action",
            "prepare",
            "--intent",
            &path,
            "--bind-source",
        ],
    );
    assert_eq!(text(&prepared, "event"), "migration_import_prepared");
    prepared
}

fn binding(prepared: &Json) -> &Json {
    let value = data(prepared).get("source_binding").unwrap();
    assert!(matches!(value, Json::Obj(_)), "{prepared:?}");
    value
}

fn receipt(prepared: &Json) -> &Json {
    let value = data(prepared).get("source_binding_receipt").unwrap();
    assert!(matches!(value, Json::Obj(_)), "{prepared:?}");
    value
}

fn vid(value: &str) -> VId {
    VId(u128::from_str_radix(value, 16).unwrap())
}

fn staged(fixture: &Fixture, prepared: &Json, index: usize) -> Json {
    let chunk = &rows(data(prepared), "chunks")[index];
    let digest = text(chunk, "proposal_digest");
    let first = fixture.approve(digest, "source-reviewer-one");
    let second = fixture.approve(digest, "source-reviewer-two");
    fixture.stage(
        text(data(prepared), "package_oid"),
        index,
        &[&first, &second],
    )
}

fn retained(fixture: &Fixture, package: &str) -> (fa_journal::Document, Vec<EntryPayload>) {
    let mut book = fixture.open();
    let reader_cap =
        Capability::embedded(principal_vid("source-fixture-reader"), &["read"]).unwrap();
    let DocumentRead::Full(document) = book
        .read_document_for(&reader_cap, &parse_oid(package))
        .unwrap()
        .unwrap()
    else {
        panic!("full retained package required");
    };
    let domain = b"FA-LEGACY-OPENING-IMPORT\0";
    assert!(document.bytes.starts_with(domain));
    let mut reader = Reader::new(&document.bytes[domain.len()..]);
    assert_eq!(reader.u16("version").unwrap(), 1);
    reader.fixed::<16>("book").unwrap();
    reader.u128("run").unwrap();
    reader.fixed::<32>("body").unwrap();
    reader.fixed::<32>("source").unwrap();
    reader.fixed::<32>("source_commit").unwrap();
    Erasable::<String>::decode(&mut reader, 1024 * 1024).unwrap();
    let count = reader.count(4096, "proposals").unwrap();
    let mut proposals = Vec::new();
    for _ in 0..count {
        proposals.push(
            Entry::decode(
                reader
                    .bytes(fa_model::limits::MAX_ENTRY_BYTES, "proposal")
                    .unwrap(),
            )
            .unwrap()
            .proposal,
        );
    }
    reader.finish().unwrap();
    (document, proposals)
}

#[test]
fn bound_cli_refuses_offsetting_omission_and_preserves_terminal_retry_and_v4_proof() {
    let source = format!(
        "{QB}source-increase,2025-12-30,{LEGACY_CASH},700.00,,USD,Retained increase,,\nsource-increase,2025-12-30,{LEGACY_EQUITY},,700.00,USD,Retained increase,,\nsource-reversal,2025-12-31,{LEGACY_CASH},,700.00,USD,Exact reversal,,\nsource-reversal,2025-12-31,{LEGACY_EQUITY},700.00,,USD,Exact reversal,,\n"
    );
    let fixture = Fixture::new(
        "quickbooks-csv",
        &source,
        "USD",
        "Spreadsheet",
        "2026-07-01",
    );
    let before = head(&fixture.book);
    let prepared = prepare(&fixture);
    let package = text(data(&prepared), "package_oid");
    let bound = binding(&prepared);
    let first_receipt = receipt(&prepared);
    assert_eq!(integer(data(&prepared), "row_count"), 8);
    assert_eq!(integer(data(&prepared), "chunk_count"), 4);
    assert_eq!(integer(bound, "source_rows"), 8);
    assert_eq!(integer(bound, "expected_chunks"), 4);
    assert_eq!(integer(bound, "recorded_chunks"), 0);
    assert_eq!(rows(bound, "missing_chunks").len(), 4);
    assert!(rows(bound, "unexpected_chunks").is_empty());
    assert_eq!(bound.get("complete"), Some(&Json::Bool(false)));
    for key in [
        "run_vid",
        "run_body_digest",
        "source_oid",
        "source_commit",
        "package_oid",
        "package_commit",
    ] {
        assert_eq!(bound.get(key), data(&prepared).get(key));
    }
    assert_eq!(integer(data(&prepared), "recorded_at"), before + 1);
    assert_eq!(integer(first_receipt, "recorded_at"), before + 2);
    assert_eq!(head(&fixture.book), before + 2);
    assert_eq!(
        first_receipt.get("already_recorded"),
        Some(&Json::Bool(false))
    );

    let book = fixture.open();
    let manifest = book
        .migration_source_manifest(vid(&fixture.run_vid), None)
        .unwrap()
        .unwrap();
    assert_eq!(text(bound, "book_id"), hex(&book.context().book_id.0));
    assert_eq!(manifest.source_rows, 8);
    assert_eq!(
        hex(&manifest.digest().unwrap()),
        text(bound, "manifest_digest")
    );
    assert_eq!(
        format!("{:032x}", manifest.vid().0),
        text(bound, "manifest_vid")
    );
    assert!(
        book.migration_source_manifest(
            vid(&fixture.run_vid),
            Some(CommitSeq((before + 1) as u64)),
        )
        .unwrap()
        .is_none()
    );
    let original_control = book
        .read_entry(vid(text(first_receipt, "control_entry")))
        .unwrap()
        .unwrap();
    drop(book);
    let (original_package, original_proposals) = retained(&fixture, package);
    for (chunk, proposal) in manifest.chunks.iter().zip(&original_proposals) {
        assert_eq!(
            chunk.entry_vid,
            migration_entry_vid(
                manifest.book_id,
                manifest.run_ref,
                &proposal.idempotency_key
            )
        );
        assert_eq!(chunk.proposal_digest, proposal.proposal_digest().unwrap());
    }

    let retry_head = head(&fixture.book);
    let repeated = prepare(&fixture);
    assert_eq!(head(&fixture.book), retry_head);
    assert_eq!(
        data(&repeated).get("recorded_at"),
        data(&prepared).get("recorded_at")
    );
    assert_eq!(data(&repeated).get("chunks"), data(&prepared).get("chunks"));
    assert_eq!(
        receipt(&repeated).get("control_entry"),
        first_receipt.get("control_entry")
    );
    assert_eq!(
        receipt(&repeated).get("recorded_at"),
        first_receipt.get("recorded_at")
    );
    assert_eq!(
        receipt(&repeated).get("already_recorded"),
        Some(&Json::Bool(true))
    );

    staged(&fixture, &prepared, 0);
    staged(&fixture, &prepared, 1);
    let partial = fixture.show(package);
    assert_eq!(data(&partial).get("ties_out"), Some(&Json::Bool(true)));
    assert_eq!(binding(&partial).get("complete"), Some(&Json::Bool(false)));
    assert_eq!(rows(binding(&partial), "missing_chunks").len(), 2);
    assert_eq!(fixture.cash(None), "0.00 USD");
    let before_refusal = head(&fixture.book);
    let (status, refused) = run(
        &fixture.book,
        &["migrate", "finalize", &fixture.run_vid, "--dry-run"],
    );
    assert_eq!(status, 3, "{refused:?}");
    assert_eq!(text(data(&refused), "refusal_id"), "FA-REF-131");
    assert_eq!(head(&fixture.book), before_refusal);
    assert!(refused.render().contains("source chunks"));

    // Package order is immutable; publication order is intentionally different.
    staged(&fixture, &prepared, 3);
    staged(&fixture, &prepared, 2);
    let complete = fixture.show(package);
    assert_eq!(binding(&complete).get("complete"), Some(&Json::Bool(true)));
    assert!(rows(binding(&complete), "missing_chunks").is_empty());
    assert!(rows(binding(&complete), "unexpected_chunks").is_empty());
    let before_finalized = head(&fixture.book);
    fixture.finalize("source-complete.plan");
    assert_eq!(fixture.cash(None), "125.50 USD");
    assert_eq!(fixture.cash(Some(before_finalized)), "0.00 USD");
    let terminal_head = head(&fixture.book);
    let terminal_retry = prepare(&fixture);
    assert_eq!(head(&fixture.book), terminal_head);
    assert_eq!(text(data(&terminal_retry), "run_state"), "Finalized");
    assert_eq!(
        receipt(&terminal_retry).get("control_entry"),
        first_receipt.get("control_entry")
    );
    assert_eq!(
        receipt(&terminal_retry).get("recorded_at"),
        first_receipt.get("recorded_at")
    );
    assert_eq!(
        receipt(&terminal_retry).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(retained(&fixture, package).0, original_package);

    let mut book = fixture.open();
    assert_eq!(
        book.read_entry(vid(text(first_receipt, "control_entry")))
            .unwrap()
            .unwrap(),
        original_control
    );
    let principal = principal_vid("source-proof-reader");
    let cap = Capability::embedded(principal, &["read", "produce", "witness"]).unwrap();
    let checkpoint = book.checkpoint(principal, &cap).unwrap().unwrap().stored;
    let proof = book
        .export_proof(
            principal,
            &cap,
            fa::ProofRequest {
                state: Some(checkpoint.oid),
                kind: fa::ProofKind::Balance {
                    account: fa_model::account_vid(book.context().book_id, "1000"),
                    unit: book.context().units.lookup("USD").unwrap(),
                    effective_through: None,
                },
            },
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        Reader::new(&proof.bytes).bytes(128, "format").unwrap(),
        b"fa:acc-balance-proof:v4"
    );
    let anchor = fa_verify::Checkpoint {
        book_id: checkpoint.state.book_id.0,
        branch_id: checkpoint.state.branch_id.0,
        through_seq: checkpoint.state.through_seq.0,
        leaf_count: checkpoint.state.leaf_count,
        root: checkpoint.state.root,
    };
    let verified = fa_verify::verify_balance(&proof.bytes, &anchor).unwrap();
    assert_eq!(verified.scope, "recomputation");
    assert_eq!(
        (verified.claim.debits, verified.claim.credits),
        (82_550, 70_000)
    );
    assert_eq!(verified.contributing.len(), 4);
}

#[test]
fn binding_is_opt_in_and_never_retrofits_staged_or_terminal_legacy_runs() {
    for terminal in [false, true] {
        let fixture = Fixture::quickbooks();
        let prepared = fixture.prepare();
        let package = text(data(&prepared), "package_oid");
        assert_eq!(data(&prepared).get("source_binding"), Some(&Json::Null));
        assert_eq!(
            data(&prepared).get("source_binding_receipt"),
            Some(&Json::Null)
        );
        staged(&fixture, &prepared, 0);
        if terminal {
            staged(&fixture, &prepared, 1);
            fixture.finalize("legacy-unbound.plan");
        }
        let before = head(&fixture.book);
        let path = fixture.file("late-bind.json", &fixture.intent().render());
        let (status, refused) = run(
            &fixture.book,
            &[
                "migrate",
                "import",
                "--action",
                "prepare",
                "--intent",
                &path,
                "--bind-source",
            ],
        );
        assert_ne!(status, 0, "{refused:?}");
        assert_eq!(head(&fixture.book), before);
        assert_eq!(
            data(&fixture.show(package)).get("source_binding"),
            Some(&Json::Null)
        );
        let retry = fixture.prepare();
        assert_eq!(data(&retry).get("source_binding"), Some(&Json::Null));
        assert_eq!(text(data(&retry), "package_oid"), package);
        assert_eq!(head(&fixture.book), before);
    }

    let fixture = Fixture::quickbooks();
    let unbound = fixture.prepare();
    let before = head(&fixture.book);
    let bound = prepare(&fixture);
    assert_eq!(head(&fixture.book), before + 1);
    assert_eq!(
        data(&bound).get("package_oid"),
        data(&unbound).get("package_oid")
    );
    assert_eq!(data(&bound).get("chunks"), data(&unbound).get("chunks"));
    assert_eq!(
        data(&bound).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(
        receipt(&bound).get("already_recorded"),
        Some(&Json::Bool(false))
    );
    let before = head(&fixture.book);
    let (status, refused) = run(
        &fixture.book,
        &[
            "migrate",
            "import",
            "--action",
            "show",
            "--package",
            text(data(&bound), "package_oid"),
            "--bind-source",
        ],
    );
    assert_eq!(status, 2, "{refused:?}");
    assert_eq!(head(&fixture.book), before);
    let (status, refused) = run(
        &fixture.book,
        &[
            "migrate",
            "open",
            "--intent",
            "missing-must-not-be-read.json",
            "--bind-source",
        ],
    );
    assert_eq!(status, 2, "{refused:?}");
    assert!(refused.render().contains("only to migrate import"));
    assert_eq!(head(&fixture.book), before);
}

#[test]
fn bound_import_rejects_resealed_package_substitution_and_native_foreign_members() {
    let fixture = Fixture::quickbooks();
    let prepared = prepare(&fixture);
    let package = text(data(&prepared), "package_oid");
    let (_, proposals) = retained(&fixture, package);

    // This replacement retains every plaintext value and is a valid replay of
    // the source. Its new sealed proposal bytes still cannot replace the bound
    // original package, even while the run contains no staged entries.
    let substituted = rewrite_package(&fixture, package, |book, proposals| {
        let description = proposals[0]
            .description
            .open(&book.context().seal_key, 1024)
            .unwrap();
        proposals[0].description = book.seal_text(&description).unwrap();
    });
    assert_ne!(substituted, package);
    let before = head(&fixture.book);
    let (status, refused) = run(
        &fixture.book,
        &[
            "migrate",
            "import",
            "--action",
            "show",
            "--package",
            &substituted,
        ],
    );
    assert_eq!(status, 8, "{refused:?}");
    assert!(refused.render().contains("native source binding differs"));
    assert_eq!(head(&fixture.book), before);

    for foreign_identity in [true, false] {
        let mut proposal = proposals[0].clone();
        if foreign_identity {
            proposal.idempotency_key = b"outside-bound-source-package".to_vec();
        } else {
            let book = fixture.open();
            proposal.description = book.seal_text("Changed source proposal").unwrap();
        }
        let proposal_digest = proposal.proposal_digest().unwrap();
        let digest = hex(&proposal_digest);
        let approvals = [
            fixture.approve(&digest, "foreign-reviewer-one"),
            fixture.approve(&digest, "foreign-reviewer-two"),
        ];
        let mut book = fixture.open();
        let before = book.head().unwrap();
        let refusal = book
            .post(fa_journal::PostRequest {
                proposal,
                approvals: approvals
                    .iter()
                    .map(|value| ApprovalRef {
                        approval_vid: vid(value),
                        approved_digest: proposal_digest,
                    })
                    .collect(),
                capability: Capability::embedded(
                    principal_vid("operator"),
                    &["read", "post", "migrate"],
                )
                .unwrap(),
                plan_certificate: None,
            })
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.code, fa_journal::refusal::code::TIE_OUT_MISMATCH);
        assert_eq!(book.head().unwrap(), before);
    }
    assert_eq!(
        integer(binding(&fixture.show(package)), "recorded_chunks"),
        0
    );
}

#[test]
fn upload_then_binding_expiry_preserves_package_and_recovers_under_current_authority() {
    use fa_policy::{CapabilityToken, Op, Profile, possession_digest};
    use fa_time::DateDay;

    let fixture = Fixture::quickbooks();
    let mut book = fixture.open();
    let issuer = Capability::embedded(
        principal_vid("source-binding-issuer"),
        &["issue_capability", "read", "post", "migrate"],
    )
    .unwrap();
    let before_issue = book.head().unwrap();
    // Issuance and package upload each consume a sequence. Binding must check
    // current authority after the upload, and cannot reuse its prior admission.
    let expires = CommitSeq(before_issue.0 + 2);
    let secret = [0xc9; 32];
    let capability = Capability::new(
        principal_vid("operator"),
        Profile::Human,
        &[Op::Read, Op::Post, Op::Migrate],
        issuer.holder(),
    )
    .unwrap()
    .holder_bound(possession_digest(&secret))
    .expiring_at(expires);
    book.issue_capability(
        issuer,
        capability.clone(),
        DateDay::parse("2026-01-01").unwrap(),
        b"source-binding-expiry",
        "source binding recovery fixture",
    )
    .unwrap()
    .unwrap();
    let token = CapabilityToken::new("operator", capability, secret).unwrap();
    let authority =
        LaunchAuthority::from_operator_token(fixture.book.clone(), None, &token).unwrap();
    drop(book);
    let args = [
        "migrate",
        "import",
        "--action",
        "prepare",
        "--intent",
        "-",
        "--bind-source",
        "--json",
    ]
    .map(str::to_owned);
    let execute = |stdin| {
        let (status, captured) = fa_with_authority(
            &args,
            Files {
                cwd: Some(fixture.dir.clone()),
                stdin,
            },
            &authority,
            true,
        );
        let events = captured
            .stdout
            .lines()
            .map(|line| {
                fa_cli::verbs::registry().unwrap().check_line(line).unwrap();
                json::parse(line).unwrap()
            })
            .collect::<Vec<_>>();
        (status, events)
    };
    let input = fixture.intent().render().into_bytes();
    let (status, events) = execute(Stdin::Forwarded(input.clone()));
    assert_eq!(status, 7, "{events:?}");
    assert_eq!(events.len(), 1);
    assert_eq!(text(data(&events[0]), "refusal_id"), "FA-REF-014");
    assert_eq!(head(&fixture.book), i128::from(expires.0));
    assert!(
        fixture
            .open()
            .migration_source_manifest(vid(&fixture.run_vid), None)
            .unwrap()
            .is_none()
    );
    let retained = fixture.prepare();
    assert_eq!(
        data(&retained).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(
        integer(data(&retained), "recorded_at"),
        i128::from(expires.0)
    );
    assert_eq!(data(&retained).get("source_binding"), Some(&Json::Null));
    assert_eq!(head(&fixture.book), i128::from(expires.0));
    let recovered = prepare(&fixture);
    for key in ["package_oid", "package_commit", "recorded_at", "chunks"] {
        assert_eq!(data(&recovered).get(key), data(&retained).get(key));
    }
    assert_eq!(
        data(&recovered).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(
        receipt(&recovered).get("already_recorded"),
        Some(&Json::Bool(false))
    );
    assert_eq!(head(&fixture.book), i128::from(expires.0 + 1));

    // An old binding receipt never makes an expired caller current, and input
    // absence cannot replace the authority refusal or cause a read side effect.
    for stdin in [Stdin::Forwarded(input), Stdin::Missing] {
        let before = head(&fixture.book);
        let (status, events) = execute(stdin);
        assert_eq!(status, 7, "{events:?}");
        assert_eq!(events.len(), 1);
        assert_eq!(text(data(&events[0]), "refusal_id"), "FA-REF-014");
        assert_eq!(head(&fixture.book), before);
    }
    let before = head(&fixture.book);
    let repeated = prepare(&fixture);
    assert_eq!(
        receipt(&repeated).get("recorded_at"),
        receipt(&recovered).get("recorded_at")
    );
    assert_eq!(
        receipt(&repeated).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(head(&fixture.book), before);
}

#[test]
fn an_existing_binding_does_not_lend_its_original_principal_to_a_prepare_retry() {
    let fixture = Fixture::quickbooks();
    let prepared = fixture.prepare();
    let package = text(data(&prepared), "package_oid");
    let (document, proposals) = retained(&fixture, package);
    let mut book = fixture.open();
    let native_run = book
        .migration_run(vid(&fixture.run_vid), None)
        .unwrap()
        .unwrap();
    let source = parse_oid(text(data(&prepared), "source_oid"));
    let source_commit: [u8; 32] = parse_oid(text(data(&prepared), "source_commit")).0;
    let manifest = SourceManifest {
        book_id: book.context().book_id,
        run_ref: native_run.vid,
        run_body_digest: native_run.body.digest().unwrap(),
        source_oid: source,
        source_commit,
        package_oid: document.oid(),
        package_commit: document.doc_commit(),
        source_rows: 4,
        chunks: proposals
            .iter()
            .map(|proposal| SourceChunk {
                entry_vid: migration_entry_vid(
                    book.context().book_id,
                    native_run.vid,
                    &proposal.idempotency_key,
                ),
                proposal_digest: proposal.proposal_digest().unwrap(),
            })
            .collect(),
    };
    let principal = principal_vid("independently-authorized-binding-operator");
    let proposal = book
        .migration_source_proposal(
            principal,
            &native_run,
            &manifest,
            book.seal_text("Independent native source binding").unwrap(),
        )
        .unwrap();
    let bound = book
        .bind_migration_source(
            &manifest,
            &document.bytes,
            fa_journal::RunControlRequest {
                proposal,
                capability: Capability::embedded(principal, &["migrate"]).unwrap(),
                approvals: Vec::new(),
            },
        )
        .unwrap()
        .unwrap();
    let before = book.head().unwrap();
    drop(book);
    assert_eq!(
        text(binding(&fixture.show(package)), "manifest_digest"),
        hex(&manifest.digest().unwrap())
    );
    let path = fixture.file("other-principal-retry.json", &fixture.intent().render());
    let (status, refused) = run(
        &fixture.book,
        &[
            "migrate",
            "import",
            "--action",
            "prepare",
            "--intent",
            &path,
            "--bind-source",
        ],
    );
    assert_eq!(status, 6, "{refused:?}");
    assert_eq!(text(data(&refused), "refusal_id"), "FA-REF-032");
    assert_eq!(head(&fixture.book), i128::from(before.0));
    let book = fixture.open();
    assert_eq!(
        book.read_entry(bound.control_entry)
            .unwrap()
            .unwrap()
            .0
            .proposal
            .principal_ref,
        principal
    );
}
