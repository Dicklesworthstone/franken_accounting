//! Cross-target determinism harness (`fa-9p1c`, plan §1.10, §6.6).
//!
//! Verifies that identical amount arithmetic, all nine rounding laws,
//! allocation laws, FX conversions with base-currency residual absorption,
//! register folds, trial-balance and statement bytes, report certificates,
//! and `.fab` evidence bundles produce identical canonical digests across
//! every supported target (`x86_64`, `aarch64`; little-endian).

#![forbid(unsafe_code)]

use asupersync::{Budget, Cx};
use fa::{
    Book, BookKeys, BundleRequest, BundleScope, Entropy, StatementDefinition, StatementSelection,
    TrialBalanceSelection,
};
use fa_journal::{AccountSpec, BookSpec, Capability, Document, PostRequest, UnitPolicy};
use fa_model::{
    EntryClass, EntryOrigin, EntryPayload, Id128, LegPayload, Oid, Writer, account_vid,
};
use fa_money::allocation::{
    AllocationCatalog, AllocationLaw, equal_split_residual_first, largest_remainder,
    pro_rata_residual_to_named, waterfall,
};
use fa_money::valuation::{LegValue, value_legs};
use fa_money::{
    Amount, ArithmeticBudget, BudgetLimits, Rate, RoundingLaw, Side, UnitId, UnitRegistry,
};
use fa_time::{DateDay, FiscalCalendar, PeriodKind, PeriodTransition};
use fgdb_crypto::Hasher;
use fgdb_types::VId;

fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn blake3_domain(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(domain);
    h.update(&(payload.len() as u64).to_le_bytes());
    h.update(payload);
    h.finalize().0
}

fn amount_and_rounding_vector_digest() -> [u8; 32] {
    let mut w = Writer::new();
    let unit = UnitId(1);
    let sample_mantissas: [i128; 12] = [
        i128::MIN + 1,
        -1_000_000_000_000_000_009,
        -999_999,
        -2,
        -1,
        0,
        1,
        2,
        42,
        999_999,
        1_000_000_000_000_000_009,
        i128::MAX - 1,
    ];
    for &a in &sample_mantissas {
        for &b in &sample_mantissas {
            let amt_a = Amount::new(unit, a);
            let amt_b = Amount::new(unit, b);
            match amt_a.checked_add(amt_b) {
                Ok(sum) => {
                    w.u8(1).u32(sum.unit.0).i128(sum.mantissa);
                }
                Err(_) => {
                    w.u8(0);
                }
            }
            match amt_a.checked_sub(amt_b) {
                Ok(diff) => {
                    w.u8(1).u32(diff.unit.0).i128(diff.mantissa);
                }
                Err(_) => {
                    w.u8(0);
                }
            }
        }
    }

    // Exercise all 9 rounding laws across quotients, remainders, denominators, and signs.
    for law in RoundingLaw::ALL {
        w.u16(law.id()).str(law.name());
        for q in [0u128, 1, 2, 3, 7, 10, 99, 10_000, u128::MAX - 1] {
            for d in [1u128, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 97, 100] {
                for r in 0..d.min(16) {
                    for negative in [false, true] {
                        let rounded = law
                            .apply_magnitude(q, r, d, negative)
                            .expect("valid rounding vector");
                        w.u128(rounded);
                    }
                }
            }
        }
    }

    let bytes = w.finish().expect("canonical writer");
    blake3_domain(b"fa:test:cross-target:amount-rounding:v1", &bytes)
}

fn allocation_vector_digest() -> [u8; 32] {
    let mut w = Writer::new();
    let _catalog = AllocationCatalog::embedded().expect("embedded allocation catalog");
    for law in AllocationLaw::ALL {
        w.u16(law.id()).str(law.name());
    }

    let unit = UnitId(1);
    let totals: [i128; 10] = [-1_000_003, -101, -7, -1, 0, 1, 7, 100, 101, 1_000_003];
    let weight_sets: [&[u128]; 6] = [
        &[1, 1, 1],
        &[1, 2, 3],
        &[5, 0, 5],
        &[3, 3, 3, 1],
        &[1, 1, 1, 1, 1, 1, 1],
        &[u128::MAX, u128::MAX, 1],
    ];

    for total in totals {
        let amt = Amount::new(unit, total);
        for weights in weight_sets {
            let lr = largest_remainder(amt, weights).expect("largest_remainder");
            w.u8(1).u32(lr.len() as u32);
            for share in &lr {
                w.i128(share.mantissa);
            }

            let pr = pro_rata_residual_to_named(amt, weights, 0, RoundingLaw::HalfEven)
                .expect("pro_rata_residual_to_named");
            w.u8(2)
                .u32(pr.shares.len() as u32)
                .i128(pr.residual.mantissa);
            for share in &pr.shares {
                w.i128(share.mantissa);
            }
        }

        for count in [1usize, 2, 3, 5, 7, 11] {
            let eq = equal_split_residual_first(amt, count).expect("equal_split_residual_first");
            w.u8(3).u32(eq.len() as u32);
            for share in &eq {
                w.i128(share.mantissa);
            }
        }
    }

    for positive_total in [0i128, 1, 50, 100, 180] {
        let amt = Amount::new(unit, positive_total);
        let caps = [30u128, 50, 100];
        let wf = waterfall(amt, &caps).expect("waterfall");
        w.u8(4).u32(wf.len() as u32);
        for share in &wf {
            w.i128(share.mantissa);
        }
    }

    let bytes = w.finish().expect("canonical writer");
    blake3_domain(b"fa:test:cross-target:allocation:v1", &bytes)
}

fn fx_and_valuation_vector_digest() -> [u8; 32] {
    let cx = Cx::detached_cancel_context();
    let mut budget = ArithmeticBudget::new(&cx, BudgetLimits::uniform(10_000_000, 0), 8192);
    let reg = UnitRegistry::embedded().expect("embedded unit registry");
    let usd = reg.lookup("USD").expect("USD");
    let eur = reg.lookup("EUR").expect("EUR");
    let jpy = reg.lookup("JPY").expect("JPY");

    let mut w = Writer::new();
    let rates = [
        Rate::from_decimal(&mut budget, "0.5").expect("0.5"),
        Rate::from_decimal(&mut budget, "1.0837").expect("1.0837"),
        Rate::from_ratio(&mut budget, "1", "3").expect("1/3"),
        Rate::from_decimal(&mut budget, "0.006712").expect("0.006712"),
    ];

    for (rate_idx, rate) in rates.iter().enumerate() {
        for law in RoundingLaw::ALL {
            // 3-leg balanced EUR entry: Dr 1, Dr 1 / Cr 2 (and scaled variants).
            for scale in [1i128, 3, 7, 101, 10_003] {
                let legs = [
                    LegValue {
                        side: Side::Debit,
                        amount: Amount::new(eur, scale),
                    },
                    LegValue {
                        side: Side::Debit,
                        amount: Amount::new(eur, scale * 2),
                    },
                    LegValue {
                        side: Side::Credit,
                        amount: Amount::new(eur, scale * 3),
                    },
                ];
                let val = value_legs(&mut budget, &legs, usd, rate, law, &reg)
                    .expect("EUR->USD valuation");
                assert_eq!(val.base_debits, val.base_credits);
                w.u16(rate_idx as u16)
                    .u16(law.id())
                    .i128(scale)
                    .i128(val.base_debits.mantissa)
                    .i128(val.base_credits.mantissa);
                match val.residual {
                    Some((ord, res)) => {
                        w.u8(1).u32(ord as u32).i128(res);
                    }
                    None => {
                        w.u8(0);
                    }
                }
                for b in &val.base_amounts {
                    w.u32(b.unit.0).i128(b.mantissa);
                }
            }

            // JPY (scale 0) -> USD (scale 2) conversion.
            let jpy_amt = Amount::new(jpy, 12_345);
            let converted = jpy_amt
                .convert(&mut budget, usd, rate, law, &reg)
                .expect("JPY->USD convert");
            w.u32(converted.unit.0).i128(converted.mantissa);
        }
    }

    let bytes = w.finish().expect("canonical writer");
    blake3_domain(b"fa:test:cross-target:fx-valuation:v1", &bytes)
}

struct BookVectorDigests {
    fold_digest: [u8; 32],
    tb_bytes_digest: [u8; 32],
    tb_cert_digest: [u8; 32],
    bs_bytes_digest: [u8; 32],
    bs_cert_digest: [u8; 32],
    is_bytes_digest: [u8; 32],
    is_cert_digest: [u8; 32],
    bundle_digest: [u8; 32],
}

fn build_fixture_book_vectors() -> BookVectorDigests {
    let calendar = FiscalCalendar::monthly("cal", 1, 1).expect("monthly calendar");
    let units = UnitRegistry::embedded().expect("units");
    let usd = units.lookup("USD").expect("USD");
    let book_id = Id128([0x42; 16]);
    let spec = BookSpec {
        book_id,
        name: "Determinism Corp".into(),
        base_unit: usd,
        calendar,
        time_zone_policy: None,
        entities: Vec::new(),
        opening_date: None,
    };
    let mut book = Book::create_memory(
        BookKeys::for_development(0x5a),
        spec,
        Entropy::deterministic(0xdecafbad),
    )
    .expect("create memory book");

    let principal = VId(1);
    let day = DateDay::from_ymd(2026, 3, 15).expect("2026-03-15");
    let chart = vec![
        AccountSpec {
            code: "1000".into(),
            name: "Cash".into(),
            account_type: 1,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(usd),
            parent_code: None,
            limit: None,
        },
        AccountSpec {
            code: "3000".into(),
            name: "Common Stock".into(),
            account_type: 3,
            normal_balance: 1,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(usd),
            parent_code: None,
            limit: None,
        },
        AccountSpec {
            code: "4000".into(),
            name: "Service Revenue".into(),
            account_type: 4,
            normal_balance: 1,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(usd),
            parent_code: None,
            limit: None,
        },
        AccountSpec {
            code: "6000".into(),
            name: "Rent Expense".into(),
            account_type: 5,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(usd),
            parent_code: None,
            limit: None,
        },
    ];
    book.install_chart(&chart, principal, day, b"chart-v1")
        .expect("install_chart io")
        .expect("install_chart ok");

    let (_, periods) = book.create_periods(2026).expect("create_periods");
    let march = periods
        .iter()
        .find(|p| p.contains(day) && p.kind == PeriodKind::Normal)
        .expect("March period")
        .code
        .clone();

    let close_cap = Capability::embedded(principal, &["close"]).expect("close cap");
    book.transition_period(
        &march,
        PeriodTransition::Open,
        principal,
        1,
        day,
        b"open-march",
        &close_cap,
    )
    .expect("transition io")
    .expect("transition ok");

    let doc = Document {
        book_id,
        kind: 1,
        mime: "text/plain".into(),
        grade: 3,
        retrieved_by: principal,
        bytes: b"DETERMINISM-FIXTURE-DOC-2026-03".to_vec(),
    };
    book.add_document(&doc)
        .expect("add_document io")
        .expect("add_document ok");

    let post_cap = Capability::embedded(principal, &["post"]).expect("post cap");
    let postings = [
        (
            "cap-inject",
            "3000",
            "1000",
            500_000i128,
            "Capital contribution",
        ),
        (
            "rev-01",
            "4000",
            "1000",
            250_000i128,
            "March consulting revenue",
        ),
        ("rent-01", "1000", "6000", 90_000i128, "March office rent"),
    ];
    for (idx, (key, credit_code, debit_code, amount, desc)) in postings.iter().enumerate() {
        let legs = vec![
            LegPayload::simple(
                Side::Debit,
                account_vid(book_id, debit_code),
                Amount::new(usd, *amount),
            ),
            LegPayload::simple(
                Side::Credit,
                account_vid(book_id, credit_code),
                Amount::new(usd, *amount),
            ),
        ];
        let proposal = EntryPayload {
            schema_minor: 0,
            book_id,
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: day,
            document_date: None,
            description: book.seal_text(desc).expect("seal_text"),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).expect("fold_unit_totals"),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: key.as_bytes().to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([u8::try_from(idx + 1).unwrap(); 32]),
                intent_kind: 1,
            },
            principal_ref: principal,
            session_ref: None,
            evidence: vec![doc.evidence_ref(1)],
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        };
        book.post(PostRequest {
            proposal,
            approvals: Vec::new(),
            plan_certificate: None,
            capability: post_cap.clone(),
        })
        .expect("post io")
        .expect("post ok");
    }

    let fold = book.fold_period(&march).expect("fold_period");
    let certified_tb = book
        .certify_trial_balance(TrialBalanceSelection::Periods(vec![march.clone()]), None)
        .expect("certify_trial_balance io")
        .expect("certify_trial_balance ok");
    let tb_bytes = certified_tb
        .report
        .canonical_bytes()
        .expect("tb canonical_bytes");
    let tb_cert_bytes = certified_tb
        .certificate
        .canonical_bytes()
        .expect("tb cert canonical_bytes");

    let bs_sel = StatementSelection {
        definition: StatementDefinition::embedded("balance-sheet").expect("balance-sheet def"),
        periods: vec![march.clone()],
        comparative: Vec::new(),
    };
    let certified_bs = book
        .certify_statement(bs_sel, None)
        .expect("certify_statement bs io")
        .expect("certify_statement bs ok");
    let bs_bytes = certified_bs
        .statement
        .canonical_bytes()
        .expect("bs canonical_bytes");
    let bs_cert_bytes = certified_bs
        .certificate
        .canonical_bytes()
        .expect("bs cert canonical_bytes");

    let is_sel = StatementSelection {
        definition: StatementDefinition::embedded("income-statement")
            .expect("income-statement def"),
        periods: vec![march.clone()],
        comparative: Vec::new(),
    };
    let certified_is = book
        .certify_statement(is_sel, None)
        .expect("certify_statement is io")
        .expect("certify_statement is ok");
    let is_bytes = certified_is
        .statement
        .canonical_bytes()
        .expect("is canonical_bytes");
    let is_cert_bytes = certified_is
        .certificate
        .canonical_bytes()
        .expect("is cert canonical_bytes");

    let witness_cap = Capability::embedded(principal, &["witness", "produce", "read"])
        .expect("witness+produce+read cap");
    let cp = book
        .checkpoint(principal, &witness_cap)
        .expect("checkpoint io")
        .expect("checkpoint ok");
    let produced = book
        .produce_bundle(
            principal,
            &witness_cap,
            Some(cp.checkpoint.checkpoint.body.state_oid),
            &BundleRequest {
                scope: BundleScope::Prefix,
                balances: Vec::new(),
                inline_documents: true,
            },
        )
        .expect("produce_bundle io")
        .expect("produce_bundle ok")
        .expect("checkpoint exists");

    let ver = fa_verify::verify_bundle(
        &produced.bundle.bytes,
        &[book.checkpoint_public_key()],
        Some(&produced.receipt),
    )
    .expect("fa-verify bundle verification");
    assert_eq!(ver.digest, produced.bundle.digest);
    let _ = (&tb_cert_bytes, &bs_cert_bytes, &is_cert_bytes);

    BookVectorDigests {
        fold_digest: fold.fold_digest,
        tb_bytes_digest: blake3_domain(b"fa:test:tb-bytes:v1", &tb_bytes),
        tb_cert_digest: certified_tb.certificate.digest,
        bs_bytes_digest: blake3_domain(b"fa:test:bs-bytes:v1", &bs_bytes),
        bs_cert_digest: certified_bs.certificate.digest,
        is_bytes_digest: blake3_domain(b"fa:test:is-bytes:v1", &is_bytes),
        is_cert_digest: certified_is.certificate.digest,
        bundle_digest: produced.bundle.digest,
    }
}

#[test]
fn supported_target_is_little_endian_and_pins_canonical_vector_digests() {
    const {
        assert!(
            cfg!(target_endian = "little"),
            "FrankenAccounting requires a little-endian target"
        );
    }
    assert!(
        matches!(std::env::consts::ARCH, "x86_64" | "aarch64"),
        "expected x86_64 or aarch64 target, found {}",
        std::env::consts::ARCH
    );
    let _ = Budget::INFINITE;

    let amount_rounding = hex32(&amount_and_rounding_vector_digest());
    let allocation = hex32(&allocation_vector_digest());
    let fx_valuation = hex32(&fx_and_valuation_vector_digest());

    let book_run_1 = build_fixture_book_vectors();
    let book_run_2 = build_fixture_book_vectors();
    assert_eq!(book_run_1.fold_digest, book_run_2.fold_digest);
    assert_eq!(book_run_1.tb_bytes_digest, book_run_2.tb_bytes_digest);
    assert_eq!(book_run_1.tb_cert_digest, book_run_2.tb_cert_digest);
    assert_eq!(book_run_1.bs_bytes_digest, book_run_2.bs_bytes_digest);
    assert_eq!(book_run_1.bs_cert_digest, book_run_2.bs_cert_digest);
    assert_eq!(book_run_1.is_bytes_digest, book_run_2.is_bytes_digest);
    assert_eq!(book_run_1.is_cert_digest, book_run_2.is_cert_digest);
    assert_eq!(book_run_1.bundle_digest, book_run_2.bundle_digest);

    // Pinned cross-target digests (identical on x86_64 and aarch64).
    assert_eq!(
        amount_rounding,
        "0fc41aafedf010f2eff7bbe9d1a9e090347f6ca459364e84804faa55118eaedc",
        "amount + rounding corpus digest drifted on {}",
        std::env::consts::ARCH
    );
    assert_eq!(
        allocation,
        "c909e7135ddce1a5359b9828712c466d582481ef31d237a9d1eb707cbb321b18",
        "allocation corpus digest drifted on {}",
        std::env::consts::ARCH
    );
    assert_eq!(
        fx_valuation,
        "6f641c74cc78e8f16dd2935d6ecd426d331a6c1bc98feaa44a2b0dc89cbb6326",
        "FX + valuation corpus digest drifted on {}",
        std::env::consts::ARCH
    );
    // Every book pin at once: a deliberate format or registry change is then
    // reviewed as one measured set, never discovered one assertion per run.
    eprintln!(
        "cross-target book digests on {}: fold {} tb_bytes {} tb_cert {} bs_bytes {} bs_cert {} is_bytes {} is_cert {} bundle {}",
        std::env::consts::ARCH,
        hex32(&book_run_1.fold_digest),
        hex32(&book_run_1.tb_bytes_digest),
        hex32(&book_run_1.tb_cert_digest),
        hex32(&book_run_1.bs_bytes_digest),
        hex32(&book_run_1.bs_cert_digest),
        hex32(&book_run_1.is_bytes_digest),
        hex32(&book_run_1.is_cert_digest),
        hex32(&book_run_1.bundle_digest),
    );
    assert_eq!(
        hex32(&book_run_1.fold_digest),
        "3f81b9886e3ec2f029fccbc72c0c0b41d6da5c0782f7a274e036c1c63b4883c5",
        "register fold digest drifted on {}",
        std::env::consts::ARCH
    );
    assert_eq!(
        hex32(&book_run_1.tb_bytes_digest),
        "12f6deb377511dca03b37574776c82c4d60f69ed5ebe86115cf0cef0e9f17f39",
        "trial balance canonical bytes digest drifted on {}",
        std::env::consts::ARCH
    );
    assert_eq!(
        hex32(&book_run_1.tb_cert_digest),
        "7af4e56c0193ef71106a017d49063c09248c11df7fb2d627c3a2f7407bb2c21d",
        "trial balance certificate digest drifted on {}",
        std::env::consts::ARCH
    );
    assert_eq!(
        hex32(&book_run_1.bs_bytes_digest),
        "07056cf31603a110dfc06a047bf9593f962c2c2c776b4ad9144acab766976dd7",
        "balance sheet canonical bytes digest drifted on {}",
        std::env::consts::ARCH
    );
    assert_eq!(
        hex32(&book_run_1.bs_cert_digest),
        "5d66e02d5f9deafc804873880905526c5bf85a73438818641407c6d00ac28ffa",
        "balance sheet certificate digest drifted on {}",
        std::env::consts::ARCH
    );
    assert_eq!(
        hex32(&book_run_1.is_bytes_digest),
        "13ae72509784041793acb4953e665fd241923901c8103d14aa543dabebe67f9e",
        "income statement canonical bytes digest drifted on {}",
        std::env::consts::ARCH
    );
    assert_eq!(
        hex32(&book_run_1.is_cert_digest),
        "906c0ad0032f2d018de3250735a1d7971ee2d5a6cdfacbac070771fd34d6a9c9",
        "income statement certificate digest drifted on {}",
        std::env::consts::ARCH
    );
    assert_eq!(
        hex32(&book_run_1.bundle_digest),
        "a6041c399f7a982f37b5d17e1810f5a6927c55f06011e5ee34749cd808801c3a",
        "evidence bundle (.fab) digest drifted on {}",
        std::env::consts::ARCH
    );
}

/// Planted negative (`fa-9p1c`): a hash encoding that serializes lengths with
/// pointer-width or endian-dependent bytes diverges from the canonical
/// fixed-width LE encoding and is caught by the corpus digest check.
#[test]
fn planted_target_dependent_encoding_diverges_from_canonical_digest() {
    let items: [u64; 3] = [100, 200, 300];

    let mut canonical = Writer::new();
    canonical.u32(items.len() as u32);
    for &item in &items {
        canonical.u64(item);
    }
    let canonical_digest = blake3_domain(
        b"fa:test:encoding:v1",
        &canonical.finish().expect("canonical writer"),
    );

    // Simulate a target-width bug: encoding length as 8-byte usize vs 4-byte u32
    // or big-endian bytes instead of canonical fixed-width LE.
    let mut planted_usize_width = Vec::new();
    planted_usize_width.extend_from_slice(&(items.len() as u64).to_le_bytes());
    for &item in &items {
        planted_usize_width.extend_from_slice(&item.to_le_bytes());
    }
    let planted_usize_digest = blake3_domain(b"fa:test:encoding:v1", &planted_usize_width);

    let mut planted_be = Vec::new();
    planted_be.extend_from_slice(&(items.len() as u32).to_be_bytes());
    for &item in &items {
        planted_be.extend_from_slice(&item.to_be_bytes());
    }
    let planted_be_digest = blake3_domain(b"fa:test:encoding:v1", &planted_be);

    assert_ne!(
        canonical_digest, planted_usize_digest,
        "planted usize-width length encoding must not match canonical u32-prefixed digest"
    );
    assert_ne!(
        canonical_digest, planted_be_digest,
        "planted big-endian encoding must not match canonical little-endian digest"
    );
}
