//! Tamper-evidence red-team matrix (`fa-70o`, plan §13.2, FA-INV-02/04/05/14/16).
//!
//! Exercises storage-level rewrites performed directly through the substrate
//! (`fgdb::Database` + `WriteBatch` using the book's keys) or the filesystem,
//! bypassing Folio. Every row is either:
//! - detected with exit code `8` (`exit::VERIFICATION`) by the named `fa`
//!   verification command, or
//! - honestly asserted as `undetectable_until = "witnessed checkpoints (fa-l3c)"`
//!   for local-only verification when an adversary with the book keys rolls
//!   back the entire directory or rewrites history from genesis with a fresh
//!   self-consistent checkpoint chain.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use asupersync::Budget;
use asupersync::runtime::RuntimeBuilder;
use fa::book::{Book, BookKeys, Entropy};
use fa_cli::json::{self, Json};
use fa_cli::verbs::registry;
use fa_journal::BookSpec;
use fa_journal::evidence::{Document, document_vid};
use fa_journal::limit::limit_cell_vid;
use fa_journal::rows::{book_root, leg_vid, mantissa_scalar};
use fa_model::symbols::{label, property, relation};
use fa_model::{Entry, EntryPayload, Id128, Oid, account_vid, period_vid};
use fa_registers::{CellKey, register_vid};
use fgdb::{Database, DatabaseKeys, WriteBatch};
use fgdb_types::context::PurposeContexts;
use fgdb_types::ids::DatabaseSecurityNamespaceId;
use fgdb_types::{CanonicalScalar, VId};

const SEED: u8 = 61;
const BOOK_ID: Id128 = Id128([0x70; 16]);

fn run(book: &Path, args: &[&str]) -> (i32, String, String) {
    let result = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(book)
        .args(args)
        .env_remove("FA_BOOK")
        .output()
        .expect("run fa");
    let code = result.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&result.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&result.stderr).into_owned();
    if args.contains(&"--json") {
        let lines: Vec<_> = stdout.lines().collect();
        assert_eq!(lines.len(), 1, "args={args:?}: {stdout}\n{stderr}");
        registry()
            .expect("verb registry")
            .check_line(lines[0])
            .unwrap_or_else(|error| panic!("args={args:?}: {error}\n{stdout}"));
    }
    (code, stdout, stderr)
}

fn ok(book: &Path, args: &[&str]) -> String {
    let (code, stdout, stderr) = run(book, args);
    assert_eq!(code, 0, "args={args:?}\n{stdout}\n{stderr}");
    stdout
}

fn parsed(text: &str) -> Json {
    json::parse(text.trim()).expect("one JSON object")
}

fn get<'a>(value: &'a Json, key: &str) -> Option<&'a Json> {
    value
        .get("data")
        .and_then(|data| data.get(key))
        .or_else(|| value.get(key))
}

fn text<'a>(value: &'a Json, key: &str) -> &'a str {
    get(value, key).and_then(Json::as_str).expect(key)
}

fn fixture() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("fa-tamper-cli-{}-{id}", std::process::id()));
        match std::fs::create_dir(&path) {
            Ok(()) => return path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("create retained fixture {}: {error}", path.display()),
        }
    }
}

fn write_file(dir: &Path, name: &str, contents: &[u8]) -> String {
    let path = dir.join(name);
    std::fs::write(&path, contents).expect("write fixture");
    path.display().to_string()
}

fn copy_dir_recursive(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).expect("create dst dir");
    for entry in std::fs::read_dir(src).expect("read src dir") {
        let entry = entry.expect("dir entry");
        let file_type = entry.file_type().expect("file type");
        let target = dst.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_recursive(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).expect("copy file");
        }
    }
}

fn db_keys() -> DatabaseKeys {
    DatabaseKeys::new(
        [SEED; 32],
        DatabaseSecurityNamespaceId([SEED.wrapping_add(1); 32]),
        [SEED.wrapping_add(2); 32],
    )
}

fn mutate_store<F>(book: &Path, f: F)
where
    F: FnOnce(&mut Database<asupersync::fs::UnixVfs>, &PurposeContexts) -> Vec<WriteBatch>,
{
    let runtime = RuntimeBuilder::new().build().expect("runtime");
    let root = runtime.request_cx_with_budget(Budget::INFINITE);
    let ctx = PurposeContexts::narrow_runtime_root(&root);
    let mut db = runtime
        .block_on(async { Database::open(&ctx.commit(), &book.join("store"), db_keys()).await })
        .expect("reopen store through substrate");
    let batches = f(&mut db, &ctx);
    for batch in batches {
        runtime
            .block_on(async { db.write(&ctx.commit(), batch).await })
            .expect("commit adversary WriteBatch");
    }
}

struct GoldenBook {
    dir: PathBuf,
    base_book: PathBuf,
    snapshot_v1: PathBuf,
    invoice_entry: VId,
    receipt_entry: VId,
    checkpoint_1_oid: Oid,
    checkpoint_2_oid: Oid,
    inline_doc_oid: String,
    external_doc_oid: String,
    external_doc_commit: String,
    cash_vid: VId,
    usd_unit_id: u32,
}

impl GoldenBook {
    fn build() -> Self {
        let dir = fixture();
        let base_book = dir.join("base_book");
        let snapshot_v1 = dir.join("snapshot_v1");
        let units = fa_money::UnitRegistry::embedded().expect("units");
        let usd = units.lookup("USD").expect("USD");
        let keys = BookKeys::for_development(SEED);
        let handle = Book::create_dir(
            &base_book,
            keys.clone(),
            BookSpec {
                book_id: BOOK_ID,
                name: "Red-Team Fixture Co".into(),
                base_unit: usd,
                calendar: fa_time::FiscalCalendar::monthly("fiscal", 1, 1).expect("calendar"),
                time_zone_policy: None,
                entities: Vec::new(),
                opening_date: None,
            },
            Entropy::deterministic(SEED as u64),
        )
        .expect("create persisted book");
        keys.save(&base_book.join("book.keys"))
            .expect("save fixture keys");
        drop(handle);

        let chart = write_file(
            &dir,
            "chart.json",
            br#"{"accounts":[
                {"code":"1000","name":"Cash","type":"Asset","unit":"USD","lower_bound":"0.00"},
                {"code":"1200","name":"Accounts Receivable","type":"Asset","unit":"USD"},
                {"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"}
            ]}"#,
        );
        ok(&base_book, &["chart", "import", &chart, "--json"]);
        ok(
            &base_book,
            &["period", "create", "--fiscal-year", "2026", "--json"],
        );
        ok(&base_book, &["period", "open", "FY2026-P03", "--json"]);

        let inline_path = write_file(
            &dir,
            "invoice.txt",
            b"Invoice #101: 500.00 USD billed to customer.",
        );
        let inline_doc = parsed(&ok(
            &base_book,
            &[
                "document",
                "add",
                &inline_path,
                "--kind",
                "Invoice",
                "--grade",
                "HumanUpload",
                "--json",
            ],
        ));
        let inline_doc_oid = text(&inline_doc, "oid").to_string();

        // External document (> 12 KiB inline bound) stored in <book>/blobs/.
        let external_bytes = vec![b'X'; 16 * 1024];
        let external_path = write_file(&dir, "statement.bin", &external_bytes);
        let external_doc = parsed(&ok(
            &base_book,
            &[
                "document",
                "add",
                &external_path,
                "--kind",
                "Receipt",
                "--grade",
                "HumanUpload",
                "--json",
            ],
        ));
        let external_doc_oid = text(&external_doc, "oid").to_string();
        let external_doc_commit = text(&external_doc, "doc_commit").to_string();

        let invoice_intent = write_file(
            &dir,
            "invoice.json",
            br#"{"effective_date":"2026-03-05","idempotency_key":"inv-101","legs":[
                {"side":"debit","account":"1200","amount":"500.00 USD"},
                {"side":"credit","account":"4000","amount":"500.00 USD"}
            ]}"#,
        );
        let invoice_posted = parsed(&ok(
            &base_book,
            &[
                "post",
                "--intent",
                &invoice_intent,
                "--evidence",
                &inline_doc_oid,
                "--json",
            ],
        ));
        let invoice_hex = text(&invoice_posted, "vid");
        let invoice_entry = VId(u128::from_str_radix(invoice_hex, 16).expect("invoice vid"));

        let cp1 = parsed(&ok(
            &base_book,
            &["checkpoint", "create", "--grant", "witness", "--json"],
        ));
        let checkpoint_1_oid = Oid(hex32(text(&cp1, "oid")));

        // Retain a directory snapshot at checkpoint 1 for the rollback row.
        copy_dir_recursive(&base_book, &snapshot_v1);

        let receipt_intent = write_file(
            &dir,
            "receipt.json",
            format!(
                r#"{{"effective_date":"2026-03-15","idempotency_key":"rcpt-101","legs":[
                    {{"side":"debit","account":"1000","amount":"300.00 USD"}},
                    {{"side":"credit","account":"1200","amount":"300.00 USD","settles":[{{"entry":"{invoice_hex}","ordinal":0,"amount":"300.00 USD"}}]}}
                ]}}"#
            )
            .as_bytes(),
        );
        let receipt_posted = parsed(&ok(
            &base_book,
            &[
                "post",
                "--intent",
                &receipt_intent,
                "--evidence",
                &external_doc_oid,
                "--json",
            ],
        ));
        let receipt_entry =
            VId(u128::from_str_radix(text(&receipt_posted, "vid"), 16).expect("receipt vid"));

        ok(
            &base_book,
            &[
                "registers",
                "materialize",
                "--period",
                "FY2026-P03",
                "--yes",
                "--json",
            ],
        );
        let cp2 = parsed(&ok(
            &base_book,
            &["checkpoint", "create", "--grant", "witness", "--json"],
        ));
        let checkpoint_2_oid = Oid(hex32(text(&cp2, "oid")));

        // Sanity-check that the untampered golden book is green on every surface.
        for args in [
            &["verify", "accumulator", "--json"][..],
            &["verify", "registers", "--period", "FY2026-P03", "--json"][..],
            &["verify", "projections", "--json"][..],
            &["verify", "availability", "--json"][..],
            &["verify", "open-items", "--json"][..],
            &["verify", "periods", "--json"][..],
            &["document", "read", &inline_doc_oid, "--json"][..],
            &["document", "read", &external_doc_oid, "--json"][..],
        ] {
            ok(&base_book, args);
        }

        Self {
            dir,
            base_book,
            snapshot_v1,
            invoice_entry,
            receipt_entry,
            checkpoint_1_oid,
            checkpoint_2_oid,
            inline_doc_oid,
            external_doc_oid,
            external_doc_commit,
            cash_vid: account_vid(BOOK_ID, "1000"),
            usd_unit_id: usd.0,
        }
    }

    fn clone_case(&self, name: &str) -> PathBuf {
        let dst = self.dir.join(name);
        copy_dir_recursive(&self.base_book, &dst);
        dst
    }
}

fn hex32(text: &str) -> [u8; 32] {
    assert_eq!(text.len(), 64, "expected 64 hex chars: {text}");
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex byte");
    }
    out
}

#[derive(Clone, Debug)]
enum ExpectedOutcome {
    Detected {
        detector: &'static str,
        invariant: &'static str,
        finding_substring: String,
    },
    UndetectableUntil {
        local_command: &'static str,
        undetectable_until: &'static str,
        out_of_band_detector: &'static str,
    },
}

#[derive(Clone, Debug)]
struct MatrixRow {
    id: &'static str,
    attack: &'static str,
    outcome: ExpectedOutcome,
    observed_exit: i32,
    observed_summary: String,
}

#[test]
fn tamper_evidence_red_team_matrix() {
    let golden = GoldenBook::build();
    let mut rows: Vec<MatrixRow> = Vec::new();

    // 1. Rewrite an Entry's _fa_payload without recomputing _fa_digest.
    {
        let book = golden.clone_case("01_rewrite_entry_payload_no_digest");
        let target = golden.invoice_entry;
        mutate_store(&book, |db, _| {
            let row = db.vertex(target).expect("read").expect("invoice entry");
            let raw = match row
                .props
                .iter()
                .find(|(k, _)| *k == property::FA_PAYLOAD)
                .map(|(_, v)| v)
            {
                Some(CanonicalScalar::Bytes(b)) => b.as_slice().to_vec(),
                other => panic!("unexpected payload prop: {other:?}"),
            };
            let entry = Entry::decode(&raw).expect("decode entry");
            let mut proposal = entry.proposal;
            proposal.legs[0].amount.mantissa += 10_000;
            proposal.legs[1].amount.mantissa += 10_000;
            proposal.unit_totals =
                EntryPayload::fold_unit_totals(&proposal.legs).expect("unit totals");
            let forged = proposal
                .seal(entry.approvals, entry.plan_certificate)
                .expect("seal forged entry");
            let rewritten = forged.encode().expect("encode entry");
            let mut batch = WriteBatch::new(relation::DERIVED_FROM);
            batch.set_vertex_property(
                target,
                property::FA_PAYLOAD,
                Some(CanonicalScalar::bytes(rewritten).expect("scalar")),
            );
            vec![batch]
        });
        let (code, out, err) = run(&book, &["verify", "accumulator", "--json"]);
        assert_eq!(code, 8, "{out}\n{err}");
        let msg = text(&parsed(&out), "message").to_string();
        assert!(out.contains(&format!("{:032x}", target.0)), "{out}");
        let (reg_code, _, _) = run(
            &book,
            &["verify", "registers", "--period", "FY2026-P03", "--json"],
        );
        assert_eq!(reg_code, 8);
        rows.push(MatrixRow {
            id: "T01",
            attack: "Rewrite `Entry._fa_payload` without recomputing `_fa_digest`",
            outcome: ExpectedOutcome::Detected {
                detector: "fa verify accumulator --json",
                invariant: "FA-INV-14 / FA-INV-04",
                finding_substring: format!("{:032x}", target.0),
            },
            observed_exit: code,
            observed_summary: msg,
        });
    }

    // 2. Rewrite an Entry's _fa_payload AND recompute _fa_digest to match.
    {
        let book = golden.clone_case("02_rewrite_entry_payload_with_digest");
        let target = golden.invoice_entry;
        mutate_store(&book, |db, _| {
            let row = db.vertex(target).expect("read").expect("invoice entry");
            let raw = match row
                .props
                .iter()
                .find(|(k, _)| *k == property::FA_PAYLOAD)
                .map(|(_, v)| v)
            {
                Some(CanonicalScalar::Bytes(b)) => b.as_slice().to_vec(),
                other => panic!("unexpected payload prop: {other:?}"),
            };
            let entry = Entry::decode(&raw).expect("decode entry");
            let mut proposal = entry.proposal;
            proposal.legs[0].amount.mantissa += 10_000;
            proposal.legs[1].amount.mantissa += 10_000;
            proposal.unit_totals =
                EntryPayload::fold_unit_totals(&proposal.legs).expect("unit totals");
            let forged = proposal
                .seal(entry.approvals, entry.plan_certificate)
                .expect("seal forged entry");
            let rewritten = forged.encode().expect("encode entry");
            let mut batch = WriteBatch::new(relation::DERIVED_FROM);
            batch.set_vertex_property(
                target,
                property::FA_PAYLOAD,
                Some(CanonicalScalar::bytes(rewritten).expect("scalar")),
            );
            batch.set_vertex_property(
                target,
                property::FA_DIGEST,
                Some(CanonicalScalar::bytes(forged.entry_digest.to_vec()).expect("scalar")),
            );
            batch.set_vertex_property(
                target,
                property::PROPOSAL_DIGEST,
                Some(CanonicalScalar::bytes(forged.proposal_digest.to_vec()).expect("scalar")),
            );
            vec![batch]
        });
        let (code, out, err) = run(&book, &["verify", "accumulator", "--json"]);
        assert_eq!(code, 8, "{out}\n{err}");
        assert!(
            out.contains(&format!("checkpointed journal entry {:032x}", target.0)),
            "{out}"
        );
        let (reg_code, reg_out, _) = run(
            &book,
            &["verify", "registers", "--period", "FY2026-P03", "--json"],
        );
        assert_eq!(reg_code, 8, "{reg_out}");
        rows.push(MatrixRow {
            id: "T02",
            attack: "Rewrite `Entry._fa_payload` and recompute `_fa_digest` in place",
            outcome: ExpectedOutcome::Detected {
                detector: "fa verify accumulator --json",
                invariant: "FA-INV-14 / FA-INV-04",
                finding_substring: "entry accumulator differs from the journal".into(),
            },
            observed_exit: code,
            observed_summary: text(&parsed(&out), "message").to_string(),
        });
    }

    // 3. Retire (delete) a committed Entry vertex.
    {
        let book = golden.clone_case("03_retire_entry_vertex");
        let target = golden.invoice_entry;
        mutate_store(&book, |_, _| {
            let mut batch = WriteBatch::new(relation::DERIVED_FROM);
            batch.delete_vertex(target);
            vec![batch]
        });
        let (code, out, err) = run(&book, &["verify", "accumulator", "--json"]);
        assert_eq!(code, 8, "{out}\n{err}");
        assert!(
            out.contains(&format!(
                "checkpointed journal entry {:032x} was retired or is absent",
                target.0
            )),
            "{out}"
        );
        let (reg_code, _, _) = run(
            &book,
            &["verify", "registers", "--period", "FY2026-P03", "--json"],
        );
        assert_eq!(reg_code, 8);
        rows.push(MatrixRow {
            id: "T03",
            attack: "Retire (delete) a committed `Entry` vertex from the store",
            outcome: ExpectedOutcome::Detected {
                detector: "fa verify accumulator --json",
                invariant: "FA-INV-14 / FA-INV-04",
                finding_substring: "entry accumulator differs from the journal".into(),
            },
            observed_exit: code,
            observed_summary: text(&parsed(&out), "message").to_string(),
        });
    }

    // 4. Insert a back-dated Entry vertex (and verify deleted VId reuse is refused by the substrate as IdentitySpent).
    {
        let book = golden.clone_case("04_insert_backdated_entry_vertex");
        let target = golden.receipt_entry;
        mutate_store(&book, |db, ctx| {
            let row = db.vertex(target).expect("read").expect("receipt entry");
            // First verify that deleting and recreating the same VId is refused by the substrate (IdentitySpent),
            // then insert a back-dated Entry vertex at a fresh VId with effective_date 2026-03-01 and falsified watermark.
            let mut probe = db.begin(&ctx.txn()).expect("begin probe");
            let mut del = WriteBatch::new(relation::DERIVED_FROM);
            del.delete_vertex(target);
            let mut rec = WriteBatch::new(relation::DERIVED_FROM);
            rec.create_vertex(target, row.labels.clone(), row.props.clone());
            let err = probe
                .write_ordered(db, vec![del, rec])
                .expect_err("substrate refuses VId reuse after delete");
            probe.abort();
            assert!(
                format!("{err:?}").contains("IdentitySpent"),
                "expected IdentitySpent, got {err:?}"
            );

            let raw = match row
                .props
                .iter()
                .find(|(k, _)| *k == property::FA_PAYLOAD)
                .map(|(_, v)| v)
            {
                Some(CanonicalScalar::Bytes(b)) => b.as_slice().to_vec(),
                other => panic!("unexpected payload prop: {other:?}"),
            };
            let entry = Entry::decode(&raw).expect("decode entry");
            let mut proposal = entry.proposal;
            proposal.effective_date = fa_time::DateDay::from_ymd(2026, 3, 1).expect("2026-03-01");
            proposal.idempotency_key = b"forged-backdated-entry".to_vec();
            let forged = proposal
                .seal(entry.approvals, entry.plan_certificate)
                .expect("seal backdated entry");
            let props = fa_model::entry_mirrors(&forged).expect("entry mirrors");
            let forged_vid = VId(0xdead_beef_cafe_babe_0000_0000_0000_0004);
            let mut insert_batch = WriteBatch::new(relation::DERIVED_FROM);
            insert_batch.create_vertex(forged_vid, vec![label::ENTRY], props);
            let rvid = register_vid(
                BOOK_ID,
                &CellKey {
                    account: golden.cash_vid,
                    unit_id: golden.usd_unit_id,
                    period: "FY2026-P03".into(),
                },
            );
            insert_batch.set_vertex_property(
                rvid,
                property::WATERMARK,
                Some(CanonicalScalar::Int(99)),
            );
            vec![insert_batch]
        });
        let (code, out, err) = run(
            &book,
            &["verify", "registers", "--period", "FY2026-P03", "--json"],
        );
        assert_eq!(code, 8, "{out}\n{err}");
        assert!(
            out.contains("stored registers differ from the refold"),
            "{out}"
        );
        rows.push(MatrixRow {
            id: "T04",
            attack: "Insert a back-dated `Entry` vertex with forged watermark (`IdentitySpent` blocks `VId` reuse)",
            outcome: ExpectedOutcome::Detected {
                detector: "fa verify registers --period FY2026-P03 --json",
                invariant: "FA-INV-04 / FA-INV-06",
                finding_substring: "stored registers differ from the refold".into(),
            },
            observed_exit: code,
            observed_summary: text(&parsed(&out), "message").to_string(),
        });
    }

    // 5. Edit a Leg scalar mirror without touching Entry._fa_payload.
    {
        let book = golden.clone_case("05_edit_leg_mirror");
        let leg = leg_vid(golden.invoice_entry, 0);
        mutate_store(&book, |_, _| {
            let mut batch = WriteBatch::new(relation::HAS_LEG);
            batch.set_vertex_property(leg, property::SIDE, Some(CanonicalScalar::Int(1)));
            vec![batch]
        });
        let (code, out, err) = run(&book, &["verify", "projections", "--json"]);
        assert_eq!(code, 8, "{out}\n{err}");
        assert!(out.contains("side") || out.contains("mirror"), "{out}");
        rows.push(MatrixRow {
            id: "T05",
            attack: "Edit a `Leg` vertex scalar mirror (`side` / `amount`) in place",
            outcome: ExpectedOutcome::Detected {
                detector: "fa verify projections --json",
                invariant: "FA-INV-16",
                finding_substring: "leg projections differ from canonical entry payloads".into(),
            },
            observed_exit: code,
            observed_summary: text(&parsed(&out), "message").to_string(),
        });
    }

    // 6. Edit a materialized Register cell and its watermark.
    {
        let book = golden.clone_case("06_edit_register_cell_and_watermark");
        let rvid = register_vid(
            BOOK_ID,
            &CellKey {
                account: golden.cash_vid,
                unit_id: golden.usd_unit_id,
                period: "FY2026-P03".into(),
            },
        );
        mutate_store(&book, |_, _| {
            let mut batch = WriteBatch::new(relation::IN_PERIOD);
            batch.set_vertex_property(
                rvid,
                property::DEBITS_POSTED,
                Some(mantissa_scalar("debits_posted", 777_700).expect("scalar")),
            );
            batch.set_vertex_property(rvid, property::WATERMARK, Some(CanonicalScalar::Int(999)));
            vec![batch]
        });
        let (code, out, err) = run(
            &book,
            &["verify", "registers", "--period", "FY2026-P03", "--json"],
        );
        assert_eq!(code, 8, "{out}\n{err}");
        assert!(out.contains("posted cells differ"), "{out}");
        rows.push(MatrixRow {
            id: "T06",
            attack: "Edit a materialized `Register` cell (`debits_posted` + `watermark`)",
            outcome: ExpectedOutcome::Detected {
                detector: "fa verify registers --period FY2026-P03 --json",
                invariant: "FA-INV-04",
                finding_substring: "posted cells differ".into(),
            },
            observed_exit: code,
            observed_summary: text(&parsed(&out), "message").to_string(),
        });
    }

    // 7. Edit or delete an AccumulatorState vertex.
    {
        let book = golden.clone_case("07_delete_accumulator_state");
        let svid = fa_notary::state_vid(&golden.checkpoint_2_oid);
        mutate_store(&book, |_, _| {
            let mut batch = WriteBatch::new(relation::DERIVED_FROM);
            batch.delete_vertex(svid);
            vec![batch]
        });
        let (code, out, err) = run(&book, &["verify", "accumulator", "--json"]);
        assert_eq!(code, 8, "{out}\n{err}");
        assert!(out.contains("named but absent"), "{out}");
        rows.push(MatrixRow {
            id: "T07",
            attack: "Delete or corrupt a committed `AccumulatorState` vertex",
            outcome: ExpectedOutcome::Detected {
                detector: "fa verify accumulator --json",
                invariant: "FA-INV-14",
                finding_substring: "named but absent".into(),
            },
            observed_exit: code,
            observed_summary: text(&parsed(&out), "message").to_string(),
        });
    }

    // 8. Truncate the accumulator state chain (point ACCUMULATOR_HEAD to an earlier state).
    {
        let book = golden.clone_case("08_truncate_state_chain");
        let earlier = golden.checkpoint_1_oid;
        mutate_store(&book, |_, _| {
            let mut batch = WriteBatch::new(relation::DERIVED_FROM);
            batch.set_vertex_property(
                book_root(),
                property::ACCUMULATOR_HEAD,
                Some(CanonicalScalar::bytes(earlier.0.to_vec()).expect("scalar")),
            );
            vec![batch]
        });
        let (code, out, err) = run(&book, &["verify", "accumulator", "--json"]);
        assert_eq!(code, 8, "{out}\n{err}");
        assert!(out.contains("2 unchained states"), "{out}");
        rows.push(MatrixRow {
            id: "T08",
            attack: "Truncate `ACCUMULATOR_HEAD` to an earlier checkpoint OID",
            outcome: ExpectedOutcome::Detected {
                detector: "fa verify accumulator --json",
                invariant: "FA-INV-14",
                finding_substring: "2 unchained states".into(),
            },
            observed_exit: code,
            observed_summary: text(&parsed(&out), "message").to_string(),
        });
    }

    // 9. Swap an inline Document blob in the substrate.
    {
        let book = golden.clone_case("09_swap_inline_document_blob");
        let oid = Oid(hex32(&golden.inline_doc_oid));
        let dvid = document_vid(&oid);
        mutate_store(&book, |db, _| {
            let row = db.vertex(dvid).expect("read").expect("inline doc");
            let raw = match row
                .props
                .iter()
                .find(|(k, _)| *k == property::FA_PAYLOAD)
                .map(|(_, v)| v)
            {
                Some(CanonicalScalar::Bytes(b)) => b.as_slice().to_vec(),
                other => panic!("unexpected doc payload: {other:?}"),
            };
            let mut doc = Document::decode(&raw).expect("decode doc");
            doc.bytes = b"Forged invoice: 99999.00 USD.".to_vec();
            let forged_bytes = doc.canonical_bytes().expect("encode doc");
            let forged_commit = doc.doc_commit();
            let mut batch = WriteBatch::new(relation::CUSTODY_OF);
            batch.set_vertex_property(
                dvid,
                property::FA_PAYLOAD,
                Some(CanonicalScalar::bytes(forged_bytes).expect("scalar")),
            );
            batch.set_vertex_property(
                dvid,
                property::FA_DIGEST,
                Some(CanonicalScalar::bytes(forged_commit.to_vec()).expect("scalar")),
            );
            vec![batch]
        });
        let (code, out, err) = run(
            &book,
            &["document", "read", &golden.inline_doc_oid, "--json"],
        );
        assert_eq!(code, 8, "{out}\n{err}");
        let parsed_out = parsed(&out);
        assert_eq!(text(&parsed_out, "refusal_id"), "FA-REF-085");
        rows.push(MatrixRow {
            id: "T09",
            attack: "Swap inline `Document` payload bytes in the substrate",
            outcome: ExpectedOutcome::Detected {
                detector: "fa document read <oid> --json",
                invariant: "FA-INV-05 (FA-REF-085)",
                finding_substring: "FA-REF-085".into(),
            },
            observed_exit: code,
            observed_summary: text(&parsed_out, "message").to_string(),
        });
    }

    // 10. Swap an external Document blob file in <book>/blobs/<shard>/<locator>.
    {
        let book = golden.clone_case("10_swap_external_document_blob");
        let locator = &golden.external_doc_commit;
        let blob_path = book.join("blobs").join(&locator[..2]).join(locator);
        assert!(blob_path.exists(), "external blob file must exist");
        std::fs::write(&blob_path, vec![b'Z'; 16 * 1024]).expect("tamper external blob");
        let (code, out, err) = run(
            &book,
            &["document", "read", &golden.external_doc_oid, "--json"],
        );
        assert_eq!(code, 8, "{out}\n{err}");
        let parsed_out = parsed(&out);
        assert_eq!(text(&parsed_out, "refusal_id"), "FA-REF-085");
        rows.push(MatrixRow {
            id: "T10",
            attack: "Swap external blob bytes in `<book>/blobs/<shard>/<locator>`",
            outcome: ExpectedOutcome::Detected {
                detector: "fa document read <oid> --json",
                invariant: "FA-INV-05 (FA-REF-085)",
                finding_substring: "do not reproduce the recorded size and commitment".into(),
            },
            observed_exit: code,
            observed_summary: text(&parsed_out, "message").to_string(),
        });
    }

    // 11. Edit a LimitCell vertex in the substrate.
    {
        let book = golden.clone_case("11_edit_limit_cell");
        let cell = limit_cell_vid(golden.cash_vid);
        mutate_store(&book, |_, _| {
            let mut batch = WriteBatch::new(relation::DERIVED_FROM);
            batch.set_vertex_property(
                cell,
                property::DEBITS_POSTED,
                Some(mantissa_scalar("debits_posted", 999_900).expect("scalar")),
            );
            vec![batch]
        });
        let (code, out, err) = run(&book, &["verify", "availability", "--json"]);
        assert_eq!(code, 8, "{out}\n{err}");
        assert!(
            out.contains("limited accounts' stored cells differ"),
            "{out}"
        );
        rows.push(MatrixRow {
            id: "T11",
            attack: "Edit a `LimitCell` availability witness (`debits_posted`)",
            outcome: ExpectedOutcome::Detected {
                detector: "fa verify availability --json",
                invariant: "FA-INV-04",
                finding_substring: "limited accounts' stored cells differ".into(),
            },
            observed_exit: code,
            observed_summary: text(&parsed(&out), "message").to_string(),
        });
    }

    // 12. Edit an open-item `applied` mirror on a Leg vertex.
    {
        let book = golden.clone_case("12_edit_open_item_applied_mirror");
        let invoice_leg = leg_vid(golden.invoice_entry, 0);
        mutate_store(&book, |_, _| {
            let mut batch = WriteBatch::new(relation::SETTLES);
            batch.set_vertex_property(
                invoice_leg,
                property::APPLIED,
                Some(mantissa_scalar("applied", 0).expect("scalar")),
            );
            vec![batch]
        });
        let (code, out, err) = run(&book, &["verify", "open-items", "--json"]);
        assert_eq!(code, 8, "{out}\n{err}");
        assert!(
            out.contains("applied mirrors differ from the open-item fold"),
            "{out}"
        );
        // The fix names the recovery, which rebuilds exactly this mirror from
        // the journal's open-item fold: one leg, and open items verify again.
        assert!(
            text(&parsed(&out), "fix").contains("fa recover projections --dry-run --json"),
            "{out}"
        );
        let (recovered, repaired, err) = run(&book, &["recover", "projections", "--yes", "--json"]);
        assert_eq!(recovered, 0, "{repaired}\n{err}");
        let repaired = parsed(&repaired);
        assert_eq!(get(&repaired, "wrote"), Some(&Json::Bool(true)));
        assert_eq!(get(&repaired, "legs_repaired"), Some(&Json::Int(1)));
        let (reverified, green, err) = run(&book, &["verify", "open-items", "--json"]);
        assert_eq!(reverified, 0, "{green}\n{err}");
        rows.push(MatrixRow {
            id: "T12",
            attack: "Edit an open-item `Leg.applied` settlement mirror in place",
            outcome: ExpectedOutcome::Detected {
                detector: "fa verify open-items --json",
                invariant: "FA-INV-04",
                finding_substring: "applied mirrors differ from the open-item fold".into(),
            },
            observed_exit: code,
            observed_summary: text(&parsed(&out), "message").to_string(),
        });
    }

    // 13. Edit a Period state projection without a PeriodControl entry.
    {
        let book = golden.clone_case("13_edit_period_state_projection");
        let pvid = period_vid("fiscal", "FY2026-P03");
        mutate_store(&book, |_, _| {
            let mut batch = WriteBatch::new(relation::IN_PERIOD);
            // Tag 2 = SoftClosed, while the journaled PeriodControl history is Open (1).
            batch.set_vertex_property(pvid, property::STATE, Some(CanonicalScalar::Int(2)));
            vec![batch]
        });
        let (code, out, err) = run(&book, &["verify", "periods", "--json"]);
        assert_eq!(code, 8, "{out}\n{err}");
        assert!(
            out.contains("period state or mirror discrepancy(s) found"),
            "{out}"
        );
        rows.push(MatrixRow {
            id: "T13",
            attack: "Edit `Period.state` mirror (`Open` -> `SoftClosed`) without a `PeriodControl` entry",
            outcome: ExpectedOutcome::Detected {
                detector: "fa verify periods --json",
                invariant: "FA-INV-02",
                finding_substring: "period state or mirror discrepancy(s) found".into(),
            },
            observed_exit: code,
            observed_summary: text(&parsed(&out), "message").to_string(),
        });
    }

    // 14. Roll the entire book directory back to an older self-consistent copy.
    {
        let book = golden.dir.join("14_directory_rollback");
        copy_dir_recursive(&golden.snapshot_v1, &book);
        let (code, out, err) = run(&book, &["verify", "accumulator", "--json"]);
        assert_eq!(
            code, 0,
            "a self-consistent older directory snapshot is locally green without an external witness: {out}\n{err}"
        );
        rows.push(MatrixRow {
            id: "T14",
            attack: "Roll the book directory back to an older checkpointed snapshot",
            outcome: ExpectedOutcome::UndetectableUntil {
                local_command: "fa verify accumulator --json",
                undetectable_until: "witnessed checkpoints (fa-l3c)",
                out_of_band_detector: "fa-verify consistency / checkpoint against retained external witness receipt",
            },
            observed_exit: code,
            observed_summary: "local verify exits 0 (undetectable_until = witnessed checkpoints (fa-l3c))".into(),
        });
    }

    // 15. Wholesale rewrite of the book directory with a fresh self-consistent chain under the book keys.
    {
        let book = golden.dir.join("15_wholesale_rewrite_fresh_chain");
        let units = fa_money::UnitRegistry::embedded().expect("units");
        let keys = BookKeys::for_development(SEED);
        let handle = Book::create_dir(
            &book,
            keys.clone(),
            BookSpec {
                book_id: BOOK_ID,
                name: "Red-Team Fixture Co".into(),
                base_unit: units.lookup("USD").expect("USD"),
                calendar: fa_time::FiscalCalendar::monthly("fiscal", 1, 1).expect("calendar"),
                time_zone_policy: None,
                entities: Vec::new(),
                opening_date: None,
            },
            Entropy::deterministic(99),
        )
        .expect("create rewritten book");
        keys.save(&book.join("book.keys")).expect("save keys");
        drop(handle);
        ok(
            &book,
            &["checkpoint", "create", "--grant", "witness", "--json"],
        );
        let (code, out, err) = run(&book, &["verify", "accumulator", "--json"]);
        assert_eq!(
            code, 0,
            "a wholesale rewrite with the book keys and a fresh chain is locally green without an external witness: {out}\n{err}"
        );
        let _ = label::ACCUMULATOR_STATE;
        rows.push(MatrixRow {
            id: "T15",
            attack: "Wholesale rewrite of the book directory with a fresh self-consistent chain",
            outcome: ExpectedOutcome::UndetectableUntil {
                local_command: "fa verify accumulator --json",
                undetectable_until: "witnessed checkpoints (fa-l3c)",
                out_of_band_detector: "fa-verify checkpoint / bundle against out-of-band witnessed root",
            },
            observed_exit: code,
            observed_summary: "local verify exits 0 (undetectable_until = witnessed checkpoints (fa-l3c))".into(),
        });
    }

    // Print the full matrix as a Markdown table in test output.
    println!(
        "\n| ID | Storage-Level Attack | Detector / Claim Boundary | Invariant / Gate | Observed Exit | Finding / Status |"
    );
    // 16. Rewrite an ImportReceipt (custody event 0) and recompute its
    // _fa_digest: an evidence record is an accumulator leaf (fa-va02).
    {
        let book = golden.clone_case("16_rewrite_import_receipt_with_digest");
        let document = Oid(hex32(&golden.inline_doc_oid));
        let target = fa_journal::custody::custody_vid(BOOK_ID, &document, 0);
        mutate_store(&book, |db, _| {
            let row = db.vertex(target).expect("read").expect("import receipt");
            let raw = fa_journal::rows::bytes(&row, property::FA_PAYLOAD, "receipt.payload")
                .expect("receipt payload");
            let mut event =
                fa_journal::custody::CustodyEvent::decode(&raw).expect("decode receipt");
            if let fa_journal::custody::CustodyBody::Receipt { received_by, .. } = &mut event.body {
                *received_by = VId(received_by.0 + 1);
            }
            let mut batch = WriteBatch::new(relation::DERIVED_FROM);
            batch.set_vertex_property(
                target,
                property::FA_PAYLOAD,
                Some(
                    CanonicalScalar::bytes(event.canonical_bytes().expect("encode"))
                        .expect("scalar"),
                ),
            );
            batch.set_vertex_property(
                target,
                property::FA_DIGEST,
                Some(
                    CanonicalScalar::bytes(event.digest().expect("digest").to_vec())
                        .expect("scalar"),
                ),
            );
            vec![batch]
        });
        let (code, out, err) = run(&book, &["verify", "accumulator", "--json"]);
        assert_eq!(code, 8, "{out}\n{err}");
        assert!(
            out.contains(&format!(
                "checkpointed journal evidence record {:032x}",
                target.0
            )),
            "{out}"
        );
        rows.push(MatrixRow {
            id: "T16",
            attack: "Rewrite an `ImportReceipt` custody record and recompute `_fa_digest` in place",
            outcome: ExpectedOutcome::Detected {
                detector: "fa verify accumulator --json",
                invariant: "FA-INV-14 / FA-INV-05",
                finding_substring: "entry accumulator differs from the journal".into(),
            },
            observed_exit: code,
            observed_summary: text(&parsed(&out), "message").to_string(),
        });
    }

    println!("|---|---|---|---|---|---|");
    for row in &rows {
        match &row.outcome {
            ExpectedOutcome::Detected {
                detector,
                invariant,
                finding_substring,
            } => {
                assert_eq!(row.observed_exit, 8, "row {} must exit 8", row.id);
                assert!(
                    row.observed_summary.contains(finding_substring)
                        || finding_substring == "FA-REF-085"
                        || row.id == "T01",
                    "row {} summary `{}` did not match `{}`",
                    row.id,
                    row.observed_summary,
                    finding_substring
                );
                println!(
                    "| `{}` | {} | `{}` | `{}` | `{}` | {} |",
                    row.id,
                    row.attack,
                    detector,
                    invariant,
                    row.observed_exit,
                    row.observed_summary
                );
            }
            ExpectedOutcome::UndetectableUntil {
                local_command,
                undetectable_until,
                out_of_band_detector,
            } => {
                assert_eq!(row.observed_exit, 0, "row {} must exit 0 locally", row.id);
                println!(
                    "| `{}` | {} | `{}` (`undetectable_until = \"{}\"` locally; out-of-band: `{}`) | `FA-INV-14` | `{}` | {} |",
                    row.id,
                    row.attack,
                    local_command,
                    undetectable_until,
                    out_of_band_detector,
                    row.observed_exit,
                    row.observed_summary
                );
            }
        }
    }
    assert_eq!(rows.len(), 16);
}
