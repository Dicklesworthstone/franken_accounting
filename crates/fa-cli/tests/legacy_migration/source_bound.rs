//! Explicit native source populations reached through retained-source imports.

use super::*;

#[path = "source_bound/scoped_ads.rs"]
mod scoped_ads;

fn run_id(fixture: &Fixture) -> VId {
    VId(u128::from_str_radix(&fixture.run_vid, 16).unwrap())
}

fn prepare_bound(fixture: &Fixture) -> Json {
    let path = fixture.file("explicit-source-binding.json", &fixture.intent().render());
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

fn source_binding(event: &Json) -> &Json {
    let value = data(event).get("source_binding").unwrap();
    assert!(matches!(value, Json::Obj(_)), "{event:?}");
    value
}

fn binding_receipt(event: &Json) -> &Json {
    let value = data(event).get("source_binding_receipt").unwrap();
    assert!(matches!(value, Json::Obj(_)), "{event:?}");
    value
}

fn approvals(fixture: &Fixture, prepared: &Json) -> Vec<[String; 2]> {
    rows(data(prepared), "chunks")
        .iter()
        .map(|chunk| {
            let digest = text(chunk, "proposal_digest");
            [
                fixture.approve(digest, "source-reviewer-one"),
                fixture.approve(digest, "source-reviewer-two"),
            ]
        })
        .collect()
}

fn stage_group(
    fixture: &Fixture,
    package: &str,
    selected: &[usize],
    approvals: &[[String; 2]],
) -> Json {
    let selection = obj(vec![(
        "chunks",
        Json::Arr(
            selected
                .iter()
                .map(|index| {
                    obj(vec![
                        ("index", Json::Int(*index as i128)),
                        (
                            "approvals",
                            Json::Arr(approvals[*index].iter().map(s).collect()),
                        ),
                    ])
                })
                .collect(),
        ),
    )]);
    let path = fixture.file("source-stage-selection.json", &selection.render());
    let result = ok(
        &fixture.book,
        &[
            "migrate",
            "import",
            "--action",
            "stage",
            "--package",
            package,
            "--intent",
            &path,
        ],
    );
    assert_eq!(text(&result, "event"), "migration_import_group_staged");
    result
}

fn unhex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn prove_source_report(fixture: &Fixture, functional_dimension: bool) {
    let name = if functional_dimension {
        "fund"
    } else {
        "native"
    };
    let path = fixture.dir.join(format!("source-{name}.cert"));
    let mut args = vec!["tb", "--period", OPENING];
    if functional_dimension {
        args.extend(["--functional", "--dimension", "fund=EMPTY"]);
    }
    args.extend(["--certificate-out", path.to_str().unwrap()]);
    let (status, output) = run_events(&fixture.book, &args);
    assert_eq!(status, 0, "{output:?}");
    assert_eq!(output.len(), 2);
    let certificate = fa::ReportCertificate::decode(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        certificate.inputs.len(),
        if functional_dimension { 11 } else { 9 }
    );
    let reference = format!("C:{}", text(data(&output[1]), "oid"));
    let checkpoint = ok(
        &fixture.book,
        &["checkpoint", "create", "--grant", "witness"],
    );
    let signed = ok(
        &fixture.book,
        &[
            "proof",
            "signed-checkpoint",
            "--state",
            text(data(&checkpoint), "oid"),
        ],
    );
    let key: [u8; 32] = unhex(text(data(&signed), "checkpoint_public_key"))
        .try_into()
        .unwrap();
    let produced = ok(
        &fixture.book,
        &[
            "bundle",
            "produce",
            "--certificate",
            &reference,
            "--state",
            text(data(&checkpoint), "oid"),
        ],
    );
    let bundle = unhex(text(data(&produced), "bytes"));
    let mut header = Reader::new(&bundle);
    assert_eq!(header.bytes(128, "format").unwrap(), b"fa:report-bundle:v1");
    assert_eq!(
        header.u16("major").unwrap(),
        if functional_dimension { 3 } else { 1 }
    );
    assert_eq!(header.u16("minor").unwrap(), 1);
    let verified = fa_verify::report::verify_report_expected(
        &bundle,
        &[key],
        None,
        Some(&unhex(text(data(&produced), "receipt"))),
        Some(&certificate.digest),
    )
    .expect("the native source-bound report independently verifies its full population");
    assert_eq!(verified.output, certificate.output);
    if functional_dimension {
        let report = verified.functional_trial_balance.unwrap();
        assert!(report.cells.is_empty());
        assert_eq!(report.entries, 0);
        assert_eq!(verified.dimension.unwrap().values, ["EMPTY"]);
    } else {
        assert_eq!(
            verified.rows.iter().map(|row| row.debits).sum::<i128>(),
            22_550
        );
        assert_eq!(
            verified.rows.iter().map(|row| row.credits).sum::<i128>(),
            22_550
        );
        let cash = verified.rows.iter().find(|row| row.code == "1000").unwrap();
        assert_eq!(cash.debits - cash.credits, 12_550);
    }
}

#[test]
fn source_bound_groups_require_offsetting_members_and_export_complete_minor_one_reports() {
    let source = format!(
        "{QB}offsetting-in,2025-12-30,{LEGACY_CASH},50.00,,USD,Offsetting receipt,,\n\
offsetting-in,2025-12-30,{LEGACY_EQUITY},,50.00,USD,Offsetting equity,,\n\
offsetting-out,2025-12-31,{LEGACY_CASH},,50.00,USD,Offsetting repayment,,\n\
offsetting-out,2025-12-31,{LEGACY_EQUITY},50.00,,USD,Offsetting equity reversal,,\n"
    );
    let fixture = Fixture::new(
        "quickbooks-csv",
        &source,
        "USD",
        "Spreadsheet",
        "2026-07-01",
    );
    ok(
        &fixture.book,
        &[
            "dimension",
            "add",
            "fund",
            "EMPTY",
            "--name",
            "Excluded fund",
        ],
    );
    let prepared = prepare_bound(&fixture);
    let package = text(data(&prepared), "package_oid");
    let digest = text(source_binding(&prepared), "manifest_digest");
    assert_eq!(digest.len(), 64);
    assert_eq!(integer(data(&prepared), "row_count"), 8);
    assert_eq!(integer(data(&prepared), "chunk_count"), 4);
    assert_eq!(
        source_binding(&prepared).get("complete"),
        Some(&Json::Bool(false))
    );
    let book = fixture.open();
    let manifest = book
        .migration_source_manifest(run_id(&fixture), None)
        .unwrap()
        .unwrap();
    assert_eq!(hex(&manifest.digest().unwrap()), digest);
    assert_eq!(manifest.source_rows, 8);
    assert_eq!(manifest.chunks.len(), 4);
    assert_eq!(manifest.package_oid, parse_oid(package));
    for (expected, chunk) in manifest.chunks.iter().zip(rows(data(&prepared), "chunks")) {
        assert_eq!(
            format!("{:032x}", expected.entry_vid.0),
            text(chunk, "entry_vid")
        );
        assert_eq!(
            hex(&expected.proposal_digest),
            text(chunk, "proposal_digest")
        );
    }
    drop(book);
    // Identical cleartext re-sealed into a second valid package is still a
    // different approved population. Exact native binding cannot be replaced
    // by replaying the same economic content with new proposal digests.
    let resealed = rewrite_package(&fixture, package, |book, proposals| {
        let description = proposals[0]
            .description
            .open(&book.context().seal_key, 1024 * 1024)
            .unwrap();
        proposals[0].description = book.seal_text(&description).unwrap();
    });
    assert_ne!(resealed, package);
    for action in ["show", "stage"] {
        let mut args = vec![
            "migrate",
            "import",
            "--action",
            action,
            "--package",
            &resealed,
        ];
        if action == "stage" {
            args.extend(["--chunk", "0"]);
        }
        let before = head(&fixture.book);
        let (status, refusal) = run(&fixture.book, &args);
        assert_eq!(status, 8, "{refusal:?}");
        assert!(text(data(&refusal), "message").contains("native source binding differs"));
        assert_eq!(head(&fixture.book), before);
    }
    let before_retry = head(&fixture.book);
    let repeated = prepare_bound(&fixture);
    assert_eq!(
        source_binding(&repeated).get("manifest_digest"),
        Some(&s(digest))
    );
    assert_eq!(
        binding_receipt(&repeated).get("control_entry"),
        binding_receipt(&prepared).get("control_entry")
    );
    assert_eq!(
        binding_receipt(&repeated).get("recorded_at"),
        binding_receipt(&prepared).get("recorded_at")
    );
    assert_eq!(
        binding_receipt(&repeated).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(data(&repeated).get("chunks"), data(&prepared).get("chunks"));
    assert_eq!(head(&fixture.book), before_retry);
    let approved = approvals(&fixture, &prepared);
    let incomplete = stage_group(&fixture, package, &[0, 1], &approved);
    assert_eq!(
        data(&incomplete).get("ready_to_finalize"),
        Some(&Json::Bool(false))
    );
    let shown = fixture.show(package);
    assert_eq!(data(&shown).get("ties_out"), Some(&Json::Bool(true)));
    assert_eq!(
        source_binding(&shown).get("complete"),
        Some(&Json::Bool(false))
    );
    assert_eq!(fixture.cash(None), "0.00 USD");
    let denied_plan = fixture.dir.join("omitted-offsetting.plan");
    let before = head(&fixture.book);
    let (status, refusal) = run(
        &fixture.book,
        &[
            "migrate",
            "finalize",
            &fixture.run_vid,
            "--plan-out",
            denied_plan.to_str().unwrap(),
        ],
    );
    assert_eq!(status, 3, "{refusal:?}");
    assert_eq!(text(data(&refusal), "refusal_id"), "FA-REF-131");
    assert!(text(data(&refusal), "message").contains("2 of 4 exact source chunks"));
    assert!(!denied_plan.exists());
    assert_eq!(head(&fixture.book), before);

    // Source order stays immutable while grouped publication may be reversed.
    let completed = stage_group(&fixture, package, &[0, 1, 3, 2], &approved);
    assert_eq!(
        data(&completed).get("ready_to_finalize"),
        Some(&Json::Bool(true))
    );
    let receipts = rows(data(&completed), "chunks");
    assert_eq!(receipts[0].get("already_recorded"), Some(&Json::Bool(true)));
    assert_eq!(receipts[1].get("already_recorded"), Some(&Json::Bool(true)));
    assert_eq!(
        receipts[2].get("already_recorded"),
        Some(&Json::Bool(false))
    );
    assert_eq!(
        receipts[3].get("already_recorded"),
        Some(&Json::Bool(false))
    );
    assert_eq!(
        source_binding(&fixture.show(package)).get("complete"),
        Some(&Json::Bool(true))
    );
    assert_eq!(fixture.cash(None), "0.00 USD");
    let before_finalize = head(&fixture.book);
    fixture.finalize("complete-source-finalize.plan");
    assert_eq!(fixture.cash(None), "125.50 USD");
    assert_eq!(fixture.cash(Some(before_finalize)), "0.00 USD");
    let before_retry = head(&fixture.book);
    let retry = stage_group(&fixture, package, &[3, 0, 2, 1], &approved);
    assert!(
        rows(data(&retry), "chunks")
            .iter()
            .all(|row| row.get("already_recorded") == Some(&Json::Bool(true)))
    );
    assert_eq!(head(&fixture.book), before_retry);
    prove_source_report(&fixture, false);
    // A fund selector excluding every imported leg must still authenticate
    // the complete bound population before returning its empty projection.
    prove_source_report(&fixture, true);
}

/// Encode the original v1 package and upload it without BindSource. The
/// optional parser input represents the historical whole-second interpretation
/// of the source timestamps. The package still binds the original Document.
fn unbound_package(fixture: &Fixture, parsed_source: Option<&str>) -> (String, Vec<EntryPayload>) {
    let mut book = fixture.open();
    let cap = Capability::embedded(
        fa_model::principal_vid("operator"),
        &["read", "post", "migrate"],
    )
    .unwrap();
    let run = book.migration_run(run_id(fixture), None).unwrap().unwrap();
    let full = |book: &mut Book, oid: &str| {
        let DocumentRead::Full(document) = book
            .read_document_for(&cap, &parse_oid(oid))
            .unwrap()
            .unwrap()
        else {
            panic!("full original source document")
        };
        document
    };
    let source = full(&mut book, &fixture.source);
    let trial_balance = full(&mut book, &fixture.trial_balance);
    let mut mappings = fa_formats::legacy::AccountMap::new(["1000", "3000"]);
    mappings.allow_passthrough_leaf_codes = false;
    mappings.insert(LEGACY_CASH, "1000");
    mappings.insert(LEGACY_EQUITY, "3000");
    let batch = fa_formats::legacy::parse_quickbooks_csv(
        parsed_source.unwrap_or_else(|| std::str::from_utf8(&source.bytes).unwrap()),
        &fa_formats::UnitCatalog::embedded().unwrap(),
        &mappings,
        "USD",
    )
    .unwrap();
    let mut evidence = vec![source.evidence_ref(1), trial_balance.evidence_ref(1)];
    evidence.sort();
    let proposals = batch
        .to_chunk_proposals_with_sealer(
            book.context(),
            run.vid,
            run.body.opening_date,
            Some(OPENING),
            cap.holder(),
            source.oid(),
            evidence,
            |text| Ok::<_, fa_formats::FormatError>(book.seal_text(text).unwrap()),
        )
        .unwrap();
    let mut config = fixture.intent();
    set_field(&mut config, "source", s(&fixture.source));
    set_field(&mut config, "default_unit", s("USD"));
    let config = book.seal_text(&config.render()).unwrap();
    let mut writer = Writer::new();
    writer
        .fixed(b"FA-LEGACY-OPENING-IMPORT\0")
        .u16(1)
        .fixed(&book.context().book_id.0)
        .u128(run.vid.0)
        .fixed(&run.body.digest().unwrap())
        .fixed(&source.oid().0)
        .fixed(&source.doc_commit());
    config.encode(&mut writer);
    writer.u32(proposals.len() as u32);
    for proposal in &proposals {
        writer.bytes(
            &proposal
                .clone()
                .seal(Vec::new(), None)
                .unwrap()
                .encode()
                .unwrap(),
        );
    }
    let policy = fa_registry::evidence_policy::EvidencePolicy::embedded().unwrap();
    let added = book
        .upload_document(
            &cap,
            fa_journal::UploadRequest {
                kind: policy.kind_by_name("Workpaper").unwrap().tag,
                mime: "application/vnd.frankenaccounting.legacy-opening-import.v1".into(),
                bytes: writer.finish().unwrap(),
                asserted_grade: Some(policy.grade_by_name("HumanUpload").unwrap().tag),
            },
        )
        .unwrap()
        .unwrap();
    assert!(
        book.migration_source_manifest(run.vid, None)
            .unwrap()
            .is_none()
    );
    (hex(&added.oid.0), proposals)
}

#[test]
fn empty_retained_packages_resume_binding_without_regeneration_or_invalid_selection_writes() {
    for resume in ["prepare", "stage"] {
        let fixture = Fixture::quickbooks();
        let (package, proposals) = unbound_package(&fixture, None);
        let shown = fixture.show(&package);
        assert_eq!(data(&shown).get("source_binding"), Some(&Json::Null));
        let before = head(&fixture.book);
        let invalid = fixture.file(
            "invalid-first-stage.json",
            r#"{"chunks":[{"index":0,"approvals":[]},{"index":2,"approvals":[]}]}"#,
        );
        let (status, refusal) = run(
            &fixture.book,
            &[
                "migrate",
                "import",
                "--action",
                "stage",
                "--package",
                &package,
                "--intent",
                &invalid,
            ],
        );
        assert_eq!(status, 2, "{refusal:?}");
        assert_eq!(head(&fixture.book), before);
        assert!(
            fixture
                .open()
                .migration_source_manifest(run_id(&fixture), None)
                .unwrap()
                .is_none()
        );

        // Recovering the retained upload alone does not claim completeness.
        // Binding is a separate explicit operation, before any chunk is staged.
        let unbound = fixture.prepare();
        assert_eq!(text(data(&unbound), "package_oid"), package);
        assert_eq!(data(&unbound).get("chunks"), data(&shown).get("chunks"));
        assert_eq!(
            data(&unbound).get("already_recorded"),
            Some(&Json::Bool(true))
        );
        assert_eq!(data(&unbound).get("source_binding"), Some(&Json::Null));
        assert_eq!(
            data(&unbound).get("source_binding_receipt"),
            Some(&Json::Null)
        );
        assert_eq!(head(&fixture.book), before);
        let approved = if resume == "stage" {
            let approved = approvals(&fixture, &shown);
            let before = head(&fixture.book);
            let (status, refusal) = run(
                &fixture.book,
                &[
                    "migrate",
                    "import",
                    "--action",
                    "stage",
                    "--package",
                    &package,
                    "--chunk",
                    "0",
                    "--bind-source",
                ],
            );
            assert_eq!(status, 2, "{refusal:?}");
            assert!(text(data(&refusal), "message").contains("only to migration import prepare"));
            assert_eq!(head(&fixture.book), before);
            Some(approved)
        } else {
            None
        };

        let before_binding = head(&fixture.book);
        let prepared = prepare_bound(&fixture);
        for key in ["package_oid", "package_commit", "recorded_at", "chunks"] {
            assert_eq!(data(&prepared).get(key), data(&unbound).get(key));
        }
        assert_eq!(
            data(&prepared).get("already_recorded"),
            Some(&Json::Bool(true))
        );
        assert_eq!(
            source_binding(&prepared).get("complete"),
            Some(&Json::Bool(false))
        );
        assert_eq!(integer(source_binding(&prepared), "expected_chunks"), 2);
        assert_eq!(integer(source_binding(&prepared), "recorded_chunks"), 0);
        assert_eq!(
            binding_receipt(&prepared).get("already_recorded"),
            Some(&Json::Bool(false))
        );
        assert_eq!(
            integer(binding_receipt(&prepared), "recorded_at"),
            before_binding + 1
        );
        assert_eq!(
            head(&fixture.book),
            before_binding + 1,
            "only the explicitly requested missing source binding publishes"
        );
        let bound = head(&fixture.book);
        let repeated = prepare_bound(&fixture);
        assert_eq!(source_binding(&repeated), source_binding(&prepared));
        assert_eq!(
            binding_receipt(&repeated).get("control_entry"),
            binding_receipt(&prepared).get("control_entry")
        );
        assert_eq!(
            binding_receipt(&repeated).get("recorded_at"),
            binding_receipt(&prepared).get("recorded_at")
        );
        assert_eq!(
            binding_receipt(&repeated).get("already_recorded"),
            Some(&Json::Bool(true))
        );
        assert_eq!(head(&fixture.book), bound);

        if let Some(approved) = approved {
            // The approvals collected before binding still name the exact
            // retained proposals; stage publishes only those native chunks.
            stage_group(&fixture, &package, &[1, 0], &approved);
            assert_eq!(head(&fixture.book), bound + 2, "two native chunks only");
            let shown = fixture.show(&package);
            assert_eq!(
                source_binding(&shown).get("complete"),
                Some(&Json::Bool(true))
            );
            assert_eq!(integer(source_binding(&shown), "recorded_chunks"), 2);
            assert!(rows(source_binding(&shown), "missing_chunks").is_empty());
            assert!(rows(source_binding(&shown), "unexpected_chunks").is_empty());
        }
        let manifest = fixture
            .open()
            .migration_source_manifest(run_id(&fixture), None)
            .unwrap()
            .unwrap();
        assert_eq!(manifest.package_oid, parse_oid(&package));
        for (member, proposal) in manifest.chunks.iter().zip(proposals) {
            assert_eq!(member.proposal_digest, proposal.proposal_digest().unwrap());
        }
    }
}

#[test]
fn historical_timestamp_packages_replay_and_stage_original_approved_bytes() {
    for second_row in [
        "2025-12-20T12:30:00.123456789Z",
        "2025-12-20T12:30:00.123456790Z",
    ] {
        let source = QB
            .replacen("2025-12-20T12:30:00Z", "2025-12-20T12:30:00.123456789Z", 1)
            .replacen("2025-12-20T12:30:00Z", second_row, 1);
        let fixture = Fixture::new(
            "quickbooks-csv",
            &source,
            "USD",
            "Spreadsheet",
            "2026-07-01",
        );
        let path = fixture.file("historical-import.json", &fixture.intent().render());
        if second_row.ends_with(".123456790Z") {
            let before = head(&fixture.book);
            let (status, refused) = run(
                &fixture.book,
                &[
                    "migrate", "import", "--action", "prepare", "--intent", &path,
                ],
            );
            assert_eq!(status, 2, "{refused:?}");
            assert!(refused.render().contains("conflicting recorded timestamp"));
            assert_eq!(head(&fixture.book), before);
        }
        let (package, proposals) = unbound_package(&fixture, Some(QB));
        let before = head(&fixture.book);
        let (prepare_status, prepared) = run(
            &fixture.book,
            &[
                "migrate", "import", "--action", "prepare", "--intent", &path,
            ],
        );
        let (show_status, shown) = run(
            &fixture.book,
            &[
                "migrate",
                "import",
                "--action",
                "show",
                "--package",
                &package,
            ],
        );
        assert_eq!(
            (prepare_status, show_status),
            (0, 0),
            "{prepared:?}\n{shown:?}"
        );
        assert_eq!(text(data(&prepared), "package_oid"), package);
        assert_eq!(
            data(&prepared).get("already_recorded"),
            Some(&Json::Bool(true))
        );
        assert_eq!(data(&prepared).get("chunks"), data(&shown).get("chunks"));
        assert_eq!(head(&fixture.book), before);
        for (row, proposal) in rows(data(&shown), "chunks").iter().zip(&proposals) {
            assert_eq!(
                text(row, "proposal_digest"),
                hex(&proposal.proposal_digest().unwrap())
            );
        }
        let approved = approvals(&fixture, &shown);
        prepare_bound(&fixture);
        stage_group(&fixture, &package, &[0, 1], &approved);
        let vid = VId(u128::from_str_radix(
            text(&rows(data(&shown), "chunks")[0], "entry_vid"),
            16,
        )
        .unwrap());
        let (entry, _) = fixture.open().read_entry(vid).unwrap().unwrap();
        assert_eq!(entry.proposal, proposals[0]);
        assert_eq!(fixture.cash(None), "0.00 USD");
        fixture.finalize("historical-timestamp-finalize.plan");
        assert_eq!(fixture.cash(None), "125.50 USD");
    }
}

#[test]
fn exact_timestamp_packages_reject_mixed_or_wrong_timestamp_interpretations() {
    let source = QB
        .replace("2025-12-20T12:30:00Z", "2025-12-20T12:30:00.123456789Z")
        .replace("2025-12-29T09:00:00Z", "2025-12-29T09:00:00.987654321Z");
    for marked in [false, true] {
        let fixture = Fixture::new(
            "quickbooks-csv",
            &source,
            "USD",
            "Spreadsheet",
            "2026-07-01",
        );
        let package = if marked {
            let prepared = fixture.prepare();
            text(data(&prepared), "package_oid").to_owned()
        } else {
            unbound_package(&fixture, None).0
        };
        let shown = fixture.show(&package);
        let before = head(&fixture.book);
        let retry = fixture.prepare();
        assert_eq!(text(data(&retry), "package_oid"), package);
        assert_eq!(data(&retry).get("chunks"), data(&shown).get("chunks"));
        assert_eq!(head(&fixture.book), before);

        let forged = rewrite_package(&fixture, &package, |_, proposals| {
            // A marked package must not accept historical truncation even
            // when it reproduces every timestamp. For an unmarked package
            // only one complete interpretation is valid across all chunks.
            let count = if marked { 2 } else { 1 };
            for proposal in proposals.iter_mut().take(count) {
                let fa_model::EntryOrigin::Migration {
                    source_recorded_at_ns: Some(timestamp),
                    ..
                } = &mut proposal.origin
                else {
                    panic!("exact native migration timestamp");
                };
                *timestamp -= timestamp.rem_euclid(1_000_000_000);
            }
        });
        assert_ne!(forged, package);
        let before_refusal = head(&fixture.book);
        for action in ["show", "stage"] {
            let mut args = vec![
                "migrate",
                "import",
                "--action",
                action,
                "--package",
                &forged,
            ];
            if action == "stage" {
                args.extend(["--chunk", "0"]);
            }
            let (status, refused) = run(&fixture.book, &args);
            assert_eq!(status, 8, "{refused:?}");
            assert!(refused.render().contains("retained proposal structure"));
            assert_eq!(head(&fixture.book), before_refusal);
        }

        let approved = approvals(&fixture, &shown);
        prepare_bound(&fixture);
        stage_group(&fixture, &package, &[0, 1], &approved);
        let first = &rows(data(&shown), "chunks")[0];
        let vid = VId(u128::from_str_radix(text(first, "entry_vid"), 16).unwrap());
        let (entry, _) = fixture.open().read_entry(vid).unwrap().unwrap();
        let fa_model::EntryOrigin::Migration {
            source_recorded_at_ns,
            ..
        } = entry.proposal.origin
        else {
            panic!("native migration provenance");
        };
        assert_eq!(source_recorded_at_ns, Some(1_766_233_800_123_456_789));
    }
}

#[test]
fn staged_legacy_unbound_packages_keep_retry_and_finalization_without_retroactive_binding() {
    let fixture = Fixture::quickbooks();
    let (package, proposals) = unbound_package(&fixture, None);
    let shown = fixture.show(&package);
    let approved = approvals(&fixture, &shown);
    let mut book = fixture.open();
    let cap = Capability::embedded(
        fa_model::principal_vid("operator"),
        &["read", "post", "migrate"],
    )
    .unwrap();
    let proposal = proposals[0].clone();
    let digest = proposal.proposal_digest().unwrap();
    let recorded = book
        .post(fa_journal::PostRequest {
            proposal,
            capability: cap,
            plan_certificate: None,
            approvals: approved[0]
                .iter()
                .map(|identity| fa_model::ApprovalRef {
                    approval_vid: VId(u128::from_str_radix(identity, 16).unwrap()),
                    approved_digest: digest,
                })
                .collect(),
        })
        .unwrap()
        .unwrap();
    assert!(
        book.migration_source_manifest(run_id(&fixture), None)
            .unwrap()
            .is_none()
    );
    drop(book);
    let before = head(&fixture.book);
    let prepared = fixture.prepare();
    assert_eq!(data(&prepared).get("source_binding"), Some(&Json::Null));
    assert_eq!(
        data(&prepared).get("source_binding_receipt"),
        Some(&Json::Null)
    );
    assert_eq!(head(&fixture.book), before);
    let path = fixture.file("legacy-late-bind.json", &fixture.intent().render());
    let (status, refusal) = run(
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
    assert_eq!(status, 3, "{refusal:?}");
    assert_eq!(text(data(&refusal), "refusal_id"), "FA-REF-131");
    assert!(text(data(&refusal), "message").contains("late binding is refused"));
    assert_eq!(head(&fixture.book), before);
    let staged = stage_group(&fixture, &package, &[0, 1], &approved);
    let retried = &rows(data(&staged), "chunks")[0];
    assert_eq!(retried.get("already_recorded"), Some(&Json::Bool(true)));
    assert_eq!(
        integer(retried, "recorded_at"),
        i128::from(recorded.recorded_at().0)
    );
    assert!(
        fixture
            .open()
            .migration_source_manifest(run_id(&fixture), None)
            .unwrap()
            .is_none()
    );
    fixture.finalize("legacy-unbound-finalize.plan");
    assert_eq!(fixture.cash(None), "125.50 USD");
    let before = head(&fixture.book);
    let retry = stage_group(&fixture, &package, &[1, 0], &approved);
    assert!(
        rows(data(&retry), "chunks")
            .iter()
            .all(|row| row.get("already_recorded") == Some(&Json::Bool(true)))
    );
    assert_eq!(head(&fixture.book), before);
    let shown = fixture.show(&package);
    assert_eq!(data(&shown).get("source_binding"), Some(&Json::Null));
    assert!(
        fixture
            .open()
            .migration_source_manifest(run_id(&fixture), None)
            .unwrap()
            .is_none()
    );
}
