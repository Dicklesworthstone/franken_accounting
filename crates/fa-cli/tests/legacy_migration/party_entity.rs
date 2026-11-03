//! Named source counterparties and legal entities remain native leg attribution.
//! Every CLI command reopens the persisted book; imported parties/entities are
//! references to declared objects, never implicit schema changes.

use super::*;

const SOURCE: &str = concat!(
    "entry,date,account,amount,investor,company,department\n",
    "A,2025-12-20,Private legacy checking account,100.00,Case-001,Entity-A,0100001\n",
    "A,2025-12-20,Private legacy opening equity,-100.00, ,Entity-A,\n",
    "B,2025-12-29,Private legacy checking account,25.50,case-001,Entity-B,0100001\n",
    "B,2025-12-29,Private legacy opening equity,-25.50,,Entity-B,\n",
);

const COLUMN_MAP: &str = concat!(
    "[columns]\nentry_id_column = \"entry\"\neffective_date_column = \"date\"\n",
    "account_column = \"account\"\nsigned_amount_column = \"amount\"\n",
    "[dimension_columns]\nparty = \"investor\"\nlegal_entity = \"company\"\n",
    "department = \"department\"\n",
);

fn fixture(source: &str) -> Fixture {
    let fixture = Fixture::with_entities(
        "csv",
        source,
        "USD",
        "Spreadsheet",
        "2026-07-01",
        &["Entity-A:Alpha", "Entity-B:Beta"],
    );
    ok(
        &fixture.book,
        &[
            "dimension",
            "add",
            "department",
            "0100001",
            "--name",
            "Retained department",
        ],
    );
    fixture
}

fn add_party(fixture: &Fixture, code: &str) {
    let path = fixture.file(
        &format!("party-{code}.json"),
        &obj(vec![
            ("code", s(code)),
            ("kind", s("Counterparty")),
            ("name", s(code)),
        ])
        .render(),
    );
    ok(&fixture.book, &["party", "add", &path]);
}

fn prepare(fixture: &Fixture) -> (Json, String) {
    let mut intent = fixture.intent();
    set_field(&mut intent, "column_map", s(COLUMN_MAP));
    let path = fixture.file("party-entity-import.json", &intent.render());
    let prepared = ok(
        &fixture.book,
        &[
            "migrate", "import", "--action", "prepare", "--intent", &path,
        ],
    );
    assert_eq!(integer(data(&prepared), "row_count"), 4);
    assert_eq!(integer(data(&prepared), "chunk_count"), 2);
    (prepared, path)
}

fn dimensions(leg: &Json) -> Vec<(u32, u128)> {
    rows(leg, "dimensions")
        .iter()
        .map(|dimension| {
            (
                u32::try_from(integer(dimension, "dimension")).unwrap(),
                u128::from_str_radix(text(dimension, "value"), 16).unwrap(),
            )
        })
        .collect()
}

fn expected_dimensions(fixture: &Fixture) -> Vec<Vec<(u32, u128)>> {
    let book_id = fixture.open().context().book_id;
    let parties = ok(&fixture.book, &["party", "list"]);
    let parties = rows(data(&parties), "parties");
    assert_eq!(parties.len(), 2);
    let mut expected = Vec::new();
    for (entity, code) in [("Entity-A", "Case-001"), ("Entity-B", "case-001")] {
        let party = parties
            .iter()
            .find(|party| text(party, "code") == code)
            .unwrap();
        let party_value = u128::from_str_radix(text(party, "dimension_value_vid"), 16).unwrap();
        assert_eq!(
            party_value,
            fa_model::party_value_vid(book_id, code).0,
            "the public inventory names the actual registered DimensionValue"
        );
        let entity = fa_model::entity_value_vid(book_id, entity).0;
        expected.push(vec![
            (1, entity),
            (
                3,
                fa_model::dimension_value_vid(book_id, "department", "0100001").0,
            ),
            (12, party_value),
        ]);
        expected.push(vec![(1, entity)]);
    }
    expected
}

#[test]
fn party_and_entity_codes_survive_retained_migration_activation_retry_and_exports() {
    let fixture = fixture(SOURCE);
    add_party(&fixture, "Case-001");
    add_party(&fixture, "case-001");
    let expected = expected_dimensions(&fixture);
    let (prepared, path) = prepare(&fixture);
    let package = text(data(&prepared), "package_oid");
    let chunks = rows(data(&prepared), "chunks");
    let actual: Vec<_> = chunks
        .iter()
        .flat_map(|chunk| rows(chunk, "legs").iter().map(dimensions))
        .collect();
    assert_eq!(actual, expected);
    assert_ne!(expected[0][2], expected[2][2], "party case is significant");

    let before_retry = head(&fixture.book);
    let repeated = ok(
        &fixture.book,
        &[
            "migrate", "import", "--action", "prepare", "--intent", &path,
        ],
    );
    assert_eq!(text(data(&repeated), "package_oid"), package);
    assert_eq!(data(&repeated).get("chunks"), data(&prepared).get("chunks"));
    assert_eq!(head(&fixture.book), before_retry);

    let mut approvals = Vec::new();
    for (index, chunk) in chunks.iter().enumerate() {
        let digest = text(chunk, "proposal_digest");
        let first = fixture.approve(digest, "attribution-reviewer-one");
        let second = fixture.approve(digest, "attribution-reviewer-two");
        fixture.stage(package, index, &[&first, &second]);
        assert_eq!(fixture.cash(None), "0.00 USD");
        approvals.push((first, second));
    }
    let before_finalize = head(&fixture.book);
    fixture.finalize("party-entity-activation.plan");
    assert_eq!(fixture.cash(None), "125.50 USD");
    assert_eq!(fixture.cash(Some(before_finalize)), "0.00 USD");
    let reopened = fixture.show(package);
    assert_eq!(text(data(&reopened), "run_state"), "Finalized");
    for (index, chunk) in rows(data(&reopened), "chunks").iter().enumerate() {
        let legs = rows(chunk, "legs");
        assert_eq!(dimensions(&legs[0]), expected[index * 2]);
        assert_eq!(dimensions(&legs[1]), expected[index * 2 + 1]);
    }
    let before_retry = head(&fixture.book);
    for (index, (first, second)) in approvals.iter().enumerate() {
        let repeated = fixture.stage(package, index, &[first, second]);
        assert_eq!(
            data(&repeated).get("already_recorded"),
            Some(&Json::Bool(true))
        );
    }
    assert_eq!(head(&fixture.book), before_retry);
    ok(&fixture.book, &["verify", "registers"]);
    assert_eq!(
        rows(data(&ok(&fixture.book, &["entity", "list"])), "entities").len(),
        2,
        "import never declares another entity"
    );

    let units = fa_formats::UnitCatalog::embedded().unwrap();
    for format in ["csv-gl", "ads"] {
        let exported = ok(&fixture.book, &["export", format, "--period", OPENING]);
        assert_eq!(integer(data(&exported), "entries"), 2);
        let files = rows(data(&exported), "files");
        let content = |name: &str| {
            text(
                files
                    .iter()
                    .find(|file| text(file, "name") == name)
                    .unwrap(),
                "content",
            )
            .to_string()
        };
        let journal = if format == "csv-gl" {
            let csv = content("gl.csv");
            let journal = fa_formats::csv_gl::read_csv_gl(&csv, &units).unwrap();
            let changed = csv.replace(
                &format!("12:{:032x}", expected[0][2].1),
                &format!("12:{:032x}", expected[2][2].1),
            );
            assert_ne!(changed, csv);
            assert!(
                fa_formats::csv_gl::read_csv_gl(&changed, &units).is_err(),
                "same-money party substitution breaks the retained export certificate"
            );
            journal
        } else {
            let package = fa_formats::ads::AdsPackage {
                chart_of_accounts: content("Chart_of_Accounts.txt"),
                gl_detail: content("GL_Detail.txt"),
                trial_balance: content("Trial_Balance.txt"),
                certificate_toml: content("ADS_Coordinate_Certificate.toml"),
            };
            let journal = fa_formats::ads::read_ads_package(&package, &units).unwrap();
            let mut changed = package.clone();
            changed.gl_detail = changed.gl_detail.replace(
                &format!("1:{:032x}", expected[0][0].1),
                &format!("1:{:032x}", expected[2][0].1),
            );
            assert_ne!(changed.gl_detail, package.gl_detail);
            assert!(
                fa_formats::ads::read_ads_package(&changed, &units).is_err(),
                "same-money entity substitution breaks the retained export certificate"
            );
            journal
        };
        assert_eq!(
            hex(&journal.coordinate.content_digest),
            text(data(&exported), "content_digest")
        );
        assert_eq!(journal.entries.len(), 2);
        for (index, mantissa) in [(0, 10_000), (1, 2_550)] {
            let entry = journal
                .entries
                .iter()
                .find(|entry| entry.legs[0].amount.mantissa == mantissa)
                .unwrap();
            assert_eq!(entry.legs.len(), 2);
            assert_eq!(entry.legs[0].account_code, "1000");
            assert_eq!(entry.legs[0].side, fa_money::Side::Debit);
            assert_eq!(entry.legs[1].account_code, "3000");
            assert_eq!(entry.legs[1].side, fa_money::Side::Credit);
            assert_eq!(entry.legs[1].amount.mantissa, mantissa);
            assert_eq!(entry.legs[0].dimensions, expected[index * 2]);
            assert_eq!(entry.legs[1].dimensions, expected[index * 2 + 1]);
        }
    }
}

#[test]
fn source_attribution_substitution_refuses_even_with_valid_native_values_and_same_money() {
    let fixture = fixture(SOURCE);
    add_party(&fixture, "Case-001");
    add_party(&fixture, "case-001");
    let (prepared, _) = prepare(&fixture);
    let package = text(data(&prepared), "package_oid");
    for kind in [1, 12] {
        let forged = rewrite_package(&fixture, package, |book, proposals| {
            for leg in &mut proposals[0].legs {
                for (dimension, value) in &mut leg.dimension_set {
                    if *dimension == kind {
                        *value = if kind == 1 {
                            fa_model::entity_value_vid(book.context().book_id, "Entity-B")
                        } else {
                            fa_model::party_value_vid(book.context().book_id, "case-001")
                        };
                    }
                }
            }
        });
        let before = head(&fixture.book);
        let (status, refused) = run(
            &fixture.book,
            &[
                "migrate",
                "import",
                "--action",
                "show",
                "--package",
                &forged,
            ],
        );
        assert_eq!(status, 8, "{}", refused.render());
        assert_eq!(head(&fixture.book), before);
        assert_eq!(integer(data(&fixture.show(package)), "recorded_count"), 0);
    }
}

#[test]
fn missing_party_or_entity_and_cross_entity_imbalance_cannot_stage_or_create_objects() {
    let wrong_case_entity = SOURCE.replace("Entity-A", "entity-a");
    let missing_entity = SOURCE.replace("Case-001,Entity-A", "Case-001,");
    let cross_entity = SOURCE.replace("-100.00, ,Entity-A", "-100.00, ,Entity-B");
    for (source, create_first_party, status, reason) in [
        (SOURCE, false, 2, "does not exist in this book"),
        (
            wrong_case_entity.as_str(),
            true,
            3,
            "none of this book's entities",
        ),
        (missing_entity.as_str(), true, 3, "names no legal entity"),
        (
            cross_entity.as_str(),
            true,
            3,
            "balances per unit but not per legal entity",
        ),
    ] {
        let fixture = fixture(source);
        // The lower-case party already exists even in the missing-party case.
        // No case folding, inference, or implicit creation can repair the ref.
        add_party(&fixture, "case-001");
        if create_first_party {
            add_party(&fixture, "Case-001");
        }
        let (prepared, _) = prepare(&fixture);
        let package = text(data(&prepared), "package_oid");
        let chunk = &rows(data(&prepared), "chunks")[0];
        let first = fixture.approve(text(chunk, "proposal_digest"), "invalid-ref-reviewer-one");
        let second = fixture.approve(text(chunk, "proposal_digest"), "invalid-ref-reviewer-two");
        let before = head(&fixture.book);
        let (actual, refused) = run(
            &fixture.book,
            &[
                "migrate",
                "import",
                "--action",
                "stage",
                "--package",
                package,
                "--chunk",
                "0",
                "--approval",
                &first,
                "--approval",
                &second,
            ],
        );
        assert_eq!(actual, status, "{}", refused.render());
        assert!(refused.render().contains(reason), "{}", refused.render());
        assert_eq!(head(&fixture.book), before);
        assert_eq!(integer(data(&fixture.show(package)), "recorded_count"), 0);
        assert_eq!(fixture.cash(None), "0.00 USD");
        assert_eq!(
            rows(data(&ok(&fixture.book, &["party", "list"])), "parties").len(),
            if create_first_party { 2 } else { 1 }
        );
        assert_eq!(
            rows(data(&ok(&fixture.book, &["entity", "list"])), "entities").len(),
            2
        );
    }
}
