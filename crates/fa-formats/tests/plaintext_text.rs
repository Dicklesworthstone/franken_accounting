//! Real exports carry arbitrary source descriptions and memos. Text must never
//! turn into a second accounting instruction or lose exact retained evidence.
use fa_formats::{
    FormatAccount, FormatAssertion, FormatEntry, FormatError, FormatJournal, FormatLeg,
    UnitCatalog,
    beancount::{read_beancount, read_hledger, write_beancount, write_hledger},
    format_exact_decimal, verify_round_trip_identity,
};
use fa_model::{AccountType, EntryClass};
use fa_money::{Amount, Side, UnitId};
use fa_time::DateDay;

fn journal(book: &str, description: &str, memo: Option<&str>) -> FormatJournal {
    let accounts = [("1000", AccountType::ASSET), ("5000", AccountType::EXPENSE)]
        .into_iter()
        .map(|(code, kind)| FormatAccount {
            code: code.into(),
            name: format!("Account {code}"),
            account_type: kind,
            normal_side: Side::Debit,
            roles: Vec::new(),
        })
        .collect();
    let entry = FormatEntry {
        entry_id: "source-0001".into(),
        effective_date: DateDay::parse("2024-06-30").unwrap(),
        recorded_seq: 1,
        class: EntryClass::MIGRATION,
        description: description.into(),
        migrated_from: None,
        legs: [("5000", Side::Debit), ("1000", Side::Credit)]
            .into_iter()
            .map(|(code, side)| FormatLeg {
                account_code: code.into(),
                side,
                amount: Amount::new(UnitId(0), 1_234_567),
                unit_code: "USD".into(),
                unit_scale: 2,
                memo: memo.map(str::to_owned),
                dimensions: Vec::new(),
            })
            .collect(),
    };
    FormatJournal::new(
        book,
        "USD",
        2,
        entry.effective_date,
        1,
        accounts,
        vec![entry],
        vec![],
    )
    .unwrap()
}

#[test]
fn beancount_preserves_multiline_source_text_without_creating_directives() {
    let source = journal(
        "  Public \"Finance\"\r\nBook ",
        "  First line; reference\\n\nSecond line\t\"quoted\" ",
        Some("  Vendor\r\n  Expenses:A5000  999999.00 USD\n  Assets:A1000  -999999.00 USD  "),
    );
    let text = write_beancount(&source).unwrap();
    let restored = read_beancount(&text, &UnitCatalog::embedded().unwrap()).unwrap();
    verify_round_trip_identity("beancount-text", &source, &restored).unwrap();
    assert_eq!(restored.entries.len(), 1);
    assert_eq!(restored.entries[0].legs.len(), 2);
    assert_eq!(
        restored.entries[0].legs[0].memo,
        source.entries[0].legs[0].memo
    );
    assert!(
        !text
            .lines()
            .any(|line| line.contains("  999999.00 USD") && !line.trim_start().starts_with(';'))
    );
}

#[test]
fn beancount_preserves_empty_and_whitespace_only_memos() {
    for memo in ["", "   ", "\t", "line\\nwith\\\"literal"] {
        let source = journal("source", "payment", Some(memo));
        let restored = read_beancount(
            &write_beancount(&source).unwrap(),
            &UnitCatalog::embedded().unwrap(),
        )
        .unwrap();
        verify_round_trip_identity("beancount-memo", &source, &restored).unwrap();
    }
}

#[test]
fn hledger_preserves_delimiters_and_multiline_source_text() {
    let source = journal(
        "  Public \"Finance\"\r\nBook ",
        "  First line; reference\\n\nSecond line\t\"quoted\" ",
        None,
    );
    let text = write_hledger(&source).unwrap();
    let restored = read_hledger(&text, &UnitCatalog::embedded().unwrap()).unwrap();
    verify_round_trip_identity("hledger-text", &source, &restored).unwrap();
    assert_eq!(restored.entries.len(), 1);
    assert_eq!(restored.entries[0].legs.len(), 2);
}

#[test]
fn plaintext_account_names_and_entry_ids_remain_exact() {
    let base = journal("Book", "Payment", None);
    let mut accounts = base.accounts.clone();
    accounts[0].name = "  Cash\r\naccount ; fa_code:5000  ".into();
    let mut entries = base.entries.clone();
    entries[0].entry_id = "source id; fa_seq:999\nnew line".into();
    let source = FormatJournal::new(
        "Book",
        "USD",
        2,
        base.coordinate.effective_through,
        1,
        accounts,
        entries,
        vec![],
    )
    .unwrap();
    for (format, restored) in [
        (
            "beancount",
            read_beancount(
                &write_beancount(&source).unwrap(),
                &UnitCatalog::embedded().unwrap(),
            ),
        ),
        (
            "hledger",
            read_hledger(
                &write_hledger(&source).unwrap(),
                &UnitCatalog::embedded().unwrap(),
            ),
        ),
    ] {
        verify_round_trip_identity(format, &source, &restored.unwrap()).unwrap();
    }
}

#[test]
fn plaintext_preserves_normal_balance_overrides_for_every_monetary_account_type() {
    let base = journal("Contra accounts", "Payment", None);
    let units = UnitCatalog::embedded().unwrap();
    for (kind, default_side) in [
        (AccountType::ASSET, Side::Debit),
        (AccountType::LIABILITY, Side::Credit),
        (AccountType::EQUITY, Side::Credit),
        (AccountType::REVENUE, Side::Credit),
        (AccountType::EXPENSE, Side::Debit),
    ] {
        for side in [Side::Debit, Side::Credit] {
            let mut accounts = base.accounts.clone();
            accounts[0].account_type = kind;
            accounts[0].normal_side = side;
            let source = FormatJournal::new(
                "Contra accounts",
                "USD",
                2,
                base.coordinate.effective_through,
                1,
                accounts,
                base.entries.clone(),
                Vec::new(),
            )
            .unwrap();
            let bean = write_beancount(&source).unwrap();
            let hledger = write_hledger(&source).unwrap();
            for (format, text, restored) in [
                ("beancount", &bean, read_beancount(&bean, &units)),
                ("hledger", &hledger, read_hledger(&hledger, &units)),
            ] {
                assert_eq!(
                    text.contains("fa_normal_side_v1:"),
                    side != default_side,
                    "{format} {kind:?} {side:?}"
                );
                let restored = restored.unwrap();
                assert_eq!(restored, source, "{format} {kind:?} {side:?}");
                verify_round_trip_identity(format, &source, &restored).unwrap();
                let reencoded = if format == "beancount" {
                    write_beancount(&restored).unwrap()
                } else {
                    write_hledger(&restored).unwrap()
                };
                assert_eq!(&reencoded, text);
            }
        }
    }
}

#[test]
fn plaintext_normal_side_metadata_refuses_ambiguity_and_detects_substitution() {
    let base = journal("Contra asset", "Payment", None);
    let mut accounts = base.accounts.clone();
    accounts[0].normal_side = Side::Credit;
    let source = FormatJournal::new(
        "Contra asset",
        "USD",
        2,
        base.coordinate.effective_through,
        1,
        accounts,
        base.entries.clone(),
        Vec::new(),
    )
    .unwrap();
    let units = UnitCatalog::embedded().unwrap();
    let bean = write_beancount(&source).unwrap();
    let hledger = write_hledger(&source).unwrap();
    for (bean_value, hledger_value) in [
        ("fa_normal_side_v1: \"X\"", "fa_normal_side_v1:X"),
        (
            "fa_normal_side_v1: \"C\"\n  fa_normal_side_v1: \"D\"",
            "fa_normal_side_v1:C fa_normal_side_v1:D",
        ),
    ] {
        for result in [
            read_beancount(
                &bean.replace("fa_normal_side_v1: \"C\"", bean_value),
                &units,
            ),
            read_hledger(
                &hledger.replace("fa_normal_side_v1:C", hledger_value),
                &units,
            ),
        ] {
            assert!(matches!(
                result,
                Err(FormatError::Parse { detail, .. }) if detail.contains("fa_normal_side_v1")
            ));
        }
    }
    let changed_bean = bean.replace("fa_normal_side_v1: \"C\"", "fa_normal_side_v1: \"D\"");
    assert!(matches!(
        read_beancount(&changed_bean, &units),
        Err(FormatError::CertificateMismatch { .. })
    ));
    // Hledger imports do not carry a producer certificate; the independent
    // comparison must still reject an otherwise balanced chart substitution.
    let changed_hledger = hledger.replace("fa_normal_side_v1:C", "fa_normal_side_v1:D");
    let changed = read_hledger(&changed_hledger, &units).unwrap();
    assert_eq!(
        changed.fold_balances().unwrap(),
        source.fold_balances().unwrap()
    );
    assert!(verify_round_trip_identity("hledger-normal-side", &source, &changed).is_err());
}

#[test]
fn beancount_opens_accounts_before_all_legacy_effective_dates() {
    let base = journal("Legacy", "import", None);
    let mut entries = vec![base.entries[0].clone(), base.entries[0].clone()];
    entries[0].effective_date = DateDay::parse("1965-06-30").unwrap();
    entries[1].entry_id = "older-recorded-later".into();
    entries[1].recorded_seq = 2;
    entries[1].effective_date = DateDay::parse("1960-01-01").unwrap();
    let source = FormatJournal::new(
        "Legacy",
        "USD",
        2,
        base.coordinate.effective_through,
        2,
        base.accounts.clone(),
        entries,
        vec![],
    )
    .unwrap();
    let text = write_beancount(&source).unwrap();
    assert_eq!(
        text.lines()
            .filter(|line| line.starts_with("1960-01-01 open "))
            .count(),
        2
    );
    let restored = read_beancount(&text, &UnitCatalog::embedded().unwrap()).unwrap();
    verify_round_trip_identity("beancount-dates", &source, &restored).unwrap();
}

#[test]
fn beancount_date_boundaries_preserve_certificates_and_inclusive_assertions() {
    let base = journal("Date boundaries", "payment", None);
    let units = UnitCatalog::embedded().unwrap();
    for (date, next_day) in [
        ("0001-01-01", Some("0001-01-02")),
        ("1969-12-31", Some("1970-01-01")),
        ("9999-12-30", Some("9999-12-31")),
        ("9999-12-31", None),
    ] {
        let day = DateDay::parse(date).unwrap();
        let mut entries = base.entries.clone();
        entries[0].effective_date = day;
        let assertions = next_day
            .map(|_| FormatAssertion {
                account_code: "1000".into(),
                as_of: day,
                side: Side::Credit,
                amount: Amount::new(UnitId(0), 1_234_567),
                unit_code: "USD".into(),
                unit_scale: 2,
            })
            .into_iter()
            .collect();
        let source = FormatJournal::new(
            "Date boundaries",
            "USD",
            2,
            day,
            1,
            base.accounts.clone(),
            entries,
            assertions,
        )
        .unwrap();
        let text = write_beancount(&source).unwrap();
        if let Some(next_day) = next_day {
            assert!(text.contains(&format!("{next_day} balance Assets:A1000 -12345.67 USD\n")));
        }
        let restored = read_beancount(&text, &units).unwrap();
        assert_eq!(restored, source, "{date}");
        verify_round_trip_identity("beancount-boundary", &source, &restored).unwrap();
        assert_eq!(write_beancount(&restored).unwrap(), text);
    }
}

#[test]
fn exact_decimal_formatting_preserves_extrema_at_every_public_scale() {
    assert_eq!(
        format_exact_decimal(i128::MIN, 38),
        "-1.70141183460469231731687303715884105728"
    );
    assert_eq!(
        format_exact_decimal(i128::MAX, 39),
        "0.170141183460469231731687303715884105727"
    );
    // This exercises the text formatter's u8 domain. Registered units still
    // have their own scale law; no new unit or posting scale is admitted.
    for scale in 0..=u8::MAX {
        for mantissa in [i128::MIN, -1, 0, 1, i128::MAX] {
            let text = format_exact_decimal(mantissa, scale);
            assert_eq!(text.starts_with('-'), mantissa < 0, "{text}");
            let unsigned = text.strip_prefix('-').unwrap_or(&text);
            let (whole, fraction) = unsigned.split_once('.').unwrap_or((unsigned, ""));
            assert!(!whole.is_empty(), "{text}");
            assert_eq!(fraction.len(), usize::from(scale), "{text}");
            assert_eq!(unsigned.contains('.'), scale > 0, "{text}");
            let digits = format!("{whole}{fraction}");
            assert_eq!(
                digits.parse::<u128>().unwrap(),
                mantissa.unsigned_abs(),
                "mantissa={mantissa}, scale={scale}, text={text}"
            );
        }
    }
}

#[test]
fn beancount_assertion_magnitudes_keep_sign_zero_and_certificates() {
    let base = journal("Assertion boundaries", "exact amount", None);
    let units = UnitCatalog::embedded().unwrap();
    for side in [Side::Debit, Side::Credit] {
        for (magnitude, decimal) in [
            (0, "0.00"),
            (1, "0.01"),
            (i128::MAX, "1701411834604692317316873037158841057.27"),
        ] {
            let mut entries = if magnitude == 0 {
                Vec::new()
            } else {
                base.entries.clone()
            };
            for entry in &mut entries {
                for leg in &mut entry.legs {
                    leg.amount.mantissa = magnitude;
                }
            }
            let (account_code, account, sign) = match side {
                Side::Debit => ("5000", "Expenses:A5000", ""),
                Side::Credit => ("1000", "Assets:A1000", "-"),
            };
            let source = FormatJournal::new(
                "Assertion boundaries",
                "USD",
                2,
                base.coordinate.effective_through,
                1,
                base.accounts.clone(),
                entries,
                vec![FormatAssertion {
                    account_code: account_code.into(),
                    as_of: base.coordinate.effective_through,
                    side,
                    amount: Amount::new(UnitId(0), magnitude),
                    unit_code: "USD".into(),
                    unit_scale: 2,
                }],
            )
            .unwrap();
            let text = write_beancount(&source).unwrap();
            assert!(text.contains(&format!(
                "2024-07-01 balance {account} {sign}{decimal} USD\n"
            )));
            let restored = read_beancount(&text, &units).unwrap();
            assert_eq!(restored, source);
            verify_round_trip_identity("beancount-assertion-boundary", &source, &restored).unwrap();
            assert_eq!(write_beancount(&restored).unwrap(), text);
        }
    }
}

#[test]
fn beancount_writer_refuses_negative_public_amount_magnitudes() {
    let base = journal("Invalid assertion", "payment", None);
    for side in [Side::Debit, Side::Credit] {
        for magnitude in [-1, i128::MIN] {
            // The public constructor currently folds the postings without
            // validating assertion magnitudes. The writer must still refuse.
            let source = FormatJournal::new(
                "Invalid assertion",
                "USD",
                2,
                base.coordinate.effective_through,
                1,
                base.accounts.clone(),
                base.entries.clone(),
                vec![FormatAssertion {
                    account_code: "1000".into(),
                    as_of: base.coordinate.effective_through,
                    side,
                    amount: Amount::new(UnitId(0), magnitude),
                    unit_code: "USD".into(),
                    unit_scale: 2,
                }],
            )
            .unwrap();
            assert!(matches!(
                write_beancount(&source),
                Err(FormatError::Parse { format: "beancount_v3", detail })
                    if detail.contains("balance assertion for account 1000")
                        && detail.contains("negative")
            ));
        }
    }
    // A malformed public struct must not reach unchecked credit negation,
    // even though the validating constructor would reject these legs.
    for index in [0, 1] {
        let mut malformed = base.clone();
        malformed.entries[0].legs[index].amount.mantissa = i128::MIN;
        assert!(matches!(
            write_beancount(&malformed),
            Err(FormatError::Parse { format: "beancount_v3", detail })
                if detail.contains("entry source-0001 leg on") && detail.contains("negative")
        ));
    }
}

#[test]
fn plaintext_writers_validate_public_posting_streams_before_returning_success() {
    let base = journal("Posting admission", "payment", None);
    let mut zero = base.clone();
    zero.entries[0].legs[0].amount = Amount::new(UnitId(0), 0);
    let mut empty = base.clone();
    empty.entries[0].legs.clear();
    let mut unbalanced = base.clone();
    unbalanced.entries[0].legs[0].amount = Amount::new(UnitId(0), 1_234_568);
    let mut overflow = base.clone();
    for leg in &mut overflow.entries[0].legs {
        leg.amount = Amount::new(UnitId(0), i128::MAX);
    }
    let repeated = overflow.entries[0].legs.clone();
    overflow.entries[0].legs.extend(repeated);

    for (case, source) in [
        ("zero", zero),
        ("empty", empty),
        ("unbalanced", unbalanced),
        ("overflow", overflow),
    ] {
        for (format, written) in [
            ("beancount_v3", write_beancount(&source)),
            ("hledger_journal", write_hledger(&source)),
        ] {
            let refused = match (case, written) {
                ("zero", Err(FormatError::Parse { detail, .. })) => {
                    detail.contains("non-positive mantissa 0")
                }
                ("empty", Err(FormatError::Parse { detail, .. })) => detail.contains("zero legs"),
                (
                    "unbalanced",
                    Err(FormatError::UnbalancedEntry {
                        entry_id,
                        unit_code,
                        debits: 1_234_568,
                        credits: 1_234_567,
                        ..
                    }),
                ) => entry_id == "source-0001" && unit_code == "USD",
                ("overflow", Err(FormatError::Overflow { detail, .. })) => {
                    detail.contains("entry debit sum overflow")
                }
                _ => false,
            };
            assert!(
                refused,
                "{format}: {case} postings must not produce an export"
            );
        }
    }
}

#[test]
fn plaintext_writers_refuse_inconsistent_scales_without_changing_valid_units() {
    let base = journal("Unit scales", "payment", None);
    let units = UnitCatalog::embedded().unwrap();
    let (eur, eur_scale) = units.lookup_code("EUR").unwrap();
    let mut entries = base.entries.clone();
    let mut foreign = entries[0].clone();
    foreign.entry_id = "source-0002".into();
    foreign.recorded_seq = 2;
    for leg in &mut foreign.legs {
        leg.amount.unit = eur;
        leg.unit_code = "EUR".into();
        leg.unit_scale = eur_scale;
    }
    entries.push(foreign);
    let valid = FormatJournal::new(
        "Unit scales",
        "USD",
        2,
        base.coordinate.effective_through,
        2,
        base.accounts.clone(),
        entries,
        vec![],
    )
    .unwrap();
    for (format, restored) in [
        (
            "beancount_v3",
            read_beancount(&write_beancount(&valid).unwrap(), &units),
        ),
        (
            "hledger_journal",
            read_hledger(&write_hledger(&valid).unwrap(), &units),
        ),
    ] {
        verify_round_trip_identity(format, &valid, &restored.unwrap()).unwrap();
    }

    let mut base_leg = valid.clone();
    base_leg.entries[0].legs[0].unit_scale = 3;
    let mut foreign_leg = valid.clone();
    foreign_leg.entries[1].legs[1].unit_scale = eur_scale + 1;
    let mut later_entry = valid.clone();
    let mut later = later_entry.entries[1].clone();
    later.entry_id = "source-0003".into();
    later.recorded_seq = 3;
    for leg in &mut later.legs {
        leg.unit_scale = eur_scale + 1;
    }
    later_entry.entries.push(later);
    let mut coordinate = valid.clone();
    coordinate.coordinate.base_unit_scale = 3;
    let mut assertion = valid.clone();
    assertion.assertions.push(FormatAssertion {
        account_code: "1000".into(),
        as_of: base.coordinate.effective_through,
        side: Side::Credit,
        amount: Amount::new(UnitId(0), 1_234_567),
        unit_code: "USD".into(),
        unit_scale: 3,
    });

    let mut accepted = Vec::new();
    for (case, source) in [
        ("base leg", base_leg),
        ("foreign leg", foreign_leg),
        ("later entry", later_entry),
        ("coordinate", coordinate),
        ("assertion", assertion),
    ] {
        for (surface, result) in [
            ("fold", source.fold_balances().map(|_| ())),
            ("beancount", write_beancount(&source).map(|_| ())),
            ("hledger", write_hledger(&source).map(|_| ())),
            (
                "constructor",
                FormatJournal::new(
                    &source.coordinate.book_name,
                    &source.coordinate.base_unit_code,
                    source.coordinate.base_unit_scale,
                    source.coordinate.effective_through,
                    source.coordinate.known_at_seq,
                    source.accounts.clone(),
                    source.entries.clone(),
                    source.assertions.clone(),
                )
                .map(|_| ()),
            ),
        ] {
            match result {
                Err(FormatError::Parse { detail, .. }) => {
                    assert!(detail.contains("inconsistent scales"), "{surface}/{case}: {detail}");
                }
                other => accepted.push(format!("{surface}/{case}: {other:?}")),
            }
        }
    }
    assert!(accepted.is_empty(), "inconsistent scales: {accepted:?}");
}

#[test]
fn plaintext_writers_refuse_duplicate_account_codes_even_across_roots() {
    let base = journal("Duplicate chart codes", "payment", None);
    let units = UnitCatalog::embedded().unwrap();
    let with_account = |account| {
        let mut accounts = base.accounts.clone();
        accounts.push(account);
        FormatJournal::new(
            &base.coordinate.book_name,
            "USD",
            2,
            base.coordinate.effective_through,
            1,
            accounts,
            base.entries.clone(),
            base.assertions.clone(),
        )
    };

    // An unused account with the same display name is valid when its code is
    // distinct. Preserve its complete chart and journal in both formats.
    let mut distinct = base.accounts[0].clone();
    distinct.code = "1001".into();
    let valid = with_account(distinct).unwrap();
    for (format, restored) in [
        (
            "beancount_v3",
            read_beancount(&write_beancount(&valid).unwrap(), &units),
        ),
        (
            "hledger_journal",
            read_hledger(&write_hledger(&valid).unwrap(), &units),
        ),
    ] {
        verify_round_trip_identity(format, &valid, &restored.unwrap()).unwrap();
    }

    // Reject exact duplicates and conflicting definitions that would export
    // into different roots but still overwrite the same canonical lookup.
    for conflicting in [false, true] {
        let mut duplicate = base.accounts[0].clone();
        if conflicting {
            duplicate.account_type = AccountType::LIABILITY;
            duplicate.normal_side = Side::Credit;
            duplicate.name = "Conflicting chart definition".into();
        }
        assert!(matches!(
            with_account(duplicate.clone()),
            Err(FormatError::Parse { format: "FormatJournal", detail })
                if detail.contains("duplicate account code") && detail.contains("1000")
        ));
        // Public fields can still be mutated after a valid construction. Each
        // writer enforces its own admission boundary before returning bytes.
        let mut source = base.clone();
        source.accounts.push(duplicate);
        for (format, written) in [
            ("beancount_v3", write_beancount(&source)),
            ("hledger_journal", write_hledger(&source)),
        ] {
            assert!(
                matches!(written, Err(FormatError::Parse { format: observed, detail })
                    if observed == format
                        && detail.contains("duplicate account code")
                        && detail.contains("1000")),
                "{format}: duplicate canonical chart codes must be refused",
            );
        }
    }
}

#[test]
fn plaintext_readers_refuse_distinct_names_aliasing_one_native_account() {
    let base = journal("Ambiguous imported codes", "payment", None);
    let units = UnitCatalog::embedded().unwrap();
    let bean = write_beancount(&base).unwrap();
    let hledger = write_hledger(&base).unwrap();
    for (format, restored) in [
        ("beancount_v3", read_beancount(&bean, &units)),
        ("hledger_journal", read_hledger(&hledger, &units)),
    ] {
        verify_round_trip_identity(format, &base, &restored.unwrap()).unwrap();
    }

    // Keep the two external account names, but deliberately make their native
    // codes identical. Both legs would otherwise fold into one zero balance.
    let mut ambiguous = base.clone();
    assert_eq!(ambiguous.accounts[1].code, "5000");
    assert_eq!(ambiguous.entries[0].legs[0].account_code, "5000");
    ambiguous.accounts[1].code = "1000".into();
    ambiguous.entries[0].legs[0].account_code = "1000".into();
    let content = FormatJournal::compute_content_digest(
        &ambiguous.accounts,
        &ambiguous.entries,
        &ambiguous.assertions,
    );
    ambiguous.coordinate = fa_formats::ExportCoordinate::compute(
        &base.coordinate.book_name,
        "USD",
        2,
        base.coordinate.effective_through,
        1,
        1,
        content,
    );
    ambiguous.coordinate.verify(&content).unwrap();
    let coherent_digests = |wire: String| {
        wire.replace(
            &fa_formats::hex_encode(&base.coordinate.content_digest),
            &fa_formats::hex_encode(&ambiguous.coordinate.content_digest),
        )
        .replace(
            &fa_formats::hex_encode(&base.coordinate.certificate_digest),
            &fa_formats::hex_encode(&ambiguous.coordinate.certificate_digest),
        )
    };
    assert!(bean.contains("fa_code: \"5000\""));
    assert!(hledger.contains("fa_code:5000"));
    let bean = coherent_digests(bean.replace("fa_code: \"5000\"", "fa_code: \"1000\""));
    let hledger = coherent_digests(hledger.replace("fa_code:5000", "fa_code:1000"));
    for read in [
        read_beancount(&bean, &units),
        read_hledger(&hledger, &units),
    ] {
        assert!(matches!(
            read,
            Err(FormatError::Parse { format: "FormatJournal", detail })
                if detail.contains("duplicate account code") && detail.contains("1000")
        ));
    }
}

#[test]
fn plaintext_writers_refuse_undeclared_posting_and_assertion_accounts() {
    let source = journal("Account references", "payment", None);
    let units = UnitCatalog::embedded().unwrap();
    for (format, restored) in [
        (
            "beancount_v3",
            read_beancount(&write_beancount(&source).unwrap(), &units),
        ),
        (
            "hledger_journal",
            read_hledger(&write_hledger(&source).unwrap(), &units),
        ),
    ] {
        verify_round_trip_identity(format, &source, &restored.unwrap()).unwrap();
    }

    // Public fields can be changed after construction. Neither writer may
    // invent an Asset account for a posting absent from the chart.
    let mut malformed = source.clone();
    malformed.entries[0].legs[0].account_code = "9999".into();
    for (format, written) in [
        ("beancount_v3", write_beancount(&malformed)),
        ("hledger_journal", write_hledger(&malformed)),
    ] {
        assert!(
            matches!(written, Err(FormatError::UnknownAccount { format: observed, account_code })
                if observed == format && account_code == "9999"),
            "{format}: an undeclared posting account must be refused",
        );
    }

    // Assertions are not part of the constructor's posting fold. Check both a
    // valid assertion and an unknown account with freshly computed certificates.
    let with_assertion = |account_code: &str| {
        FormatJournal::new(
            &source.coordinate.book_name,
            "USD",
            2,
            source.coordinate.effective_through,
            1,
            source.accounts.clone(),
            source.entries.clone(),
            vec![FormatAssertion {
                account_code: account_code.into(),
                as_of: source.coordinate.effective_through,
                side: Side::Credit,
                amount: Amount::new(UnitId(0), 1_234_567),
                unit_code: "USD".into(),
                unit_scale: 2,
            }],
        )
        .unwrap()
    };
    let valid = with_assertion("1000");
    let restored = read_beancount(&write_beancount(&valid).unwrap(), &units).unwrap();
    verify_round_trip_identity("beancount-declared-assertion", &valid, &restored).unwrap();
    assert!(matches!(
        write_beancount(&with_assertion("9999")),
        Err(FormatError::UnknownAccount {
            format: "beancount_v3",
            account_code,
        }) if account_code == "9999"
    ));
}

#[test]
fn hledger_amount_magnitudes_preserve_extrema_and_refuse_negative_public_values() {
    let base = journal("Hledger amounts", "payment", None);
    let units = UnitCatalog::embedded().unwrap();
    for (magnitude, decimal) in [
        (1, "0.01"),
        (i128::MAX, "1701411834604692317316873037158841057.27"),
    ] {
        let mut entries = base.entries.clone();
        for leg in &mut entries[0].legs {
            leg.amount.mantissa = magnitude;
        }
        let source = FormatJournal::new(
            "Hledger amounts",
            "USD",
            2,
            base.coordinate.effective_through,
            1,
            base.accounts.clone(),
            entries,
            Vec::new(),
        )
        .unwrap();
        let text = write_hledger(&source).unwrap();
        assert!(text.contains(&format!(
            "    Expenses:A5000    {decimal} USD\n    Assets:A1000    -{decimal} USD\n"
        )));
        let restored = read_hledger(&text, &units).unwrap();
        assert_eq!(restored, source);
        verify_round_trip_identity("hledger-amount-boundary", &source, &restored).unwrap();
        assert_eq!(write_hledger(&restored).unwrap(), text);
    }
    // Public fields can bypass the constructor's positive-magnitude check.
    // Neither side may turn a negative magnitude into an exported posting.
    for index in [0, 1] {
        for magnitude in [-1, i128::MIN] {
            let mut malformed = base.clone();
            malformed.entries[0].legs[index].amount.mantissa = magnitude;
            assert!(matches!(
                write_hledger(&malformed),
                Err(FormatError::Parse { format: "hledger_journal", detail })
                    if detail.contains("entry source-0001 leg on") && detail.contains("negative")
            ));
        }
    }
}

#[test]
fn beancount_writer_refuses_dates_outside_its_profile_and_assertion_overflow() {
    let base = journal("Date boundaries", "payment", None);
    let normal = base.coordinate.effective_through;
    let year_zero = DateDay::from_ymd(0, 1, 1).unwrap();
    let last = DateDay::parse("9999-12-31").unwrap();
    let after_last = DateDay::from_ymd(10000, 1, 1).unwrap();
    let rebuild = |cutoff, effective, assertion_day: Option<DateDay>| {
        let mut entries = base.entries.clone();
        entries[0].effective_date = effective;
        let assertions = assertion_day
            .map(|as_of| FormatAssertion {
                account_code: "1000".into(),
                as_of,
                side: Side::Credit,
                amount: Amount::new(UnitId(0), 1_234_567),
                unit_code: "USD".into(),
                unit_scale: 2,
            })
            .into_iter()
            .collect();
        FormatJournal::new(
            "Date boundaries",
            "USD",
            2,
            cutoff,
            1,
            base.accounts.clone(),
            entries,
            assertions,
        )
        .unwrap()
    };
    for (cutoff, effective, assertion, field) in [
        (
            DateDay(i32::MIN),
            DateDay(i32::MIN),
            None,
            "selection cutoff",
        ),
        (
            DateDay(i32::MAX),
            DateDay(i32::MAX),
            None,
            "selection cutoff",
        ),
        (after_last, after_last, None, "selection cutoff"),
        (year_zero, year_zero, None, "selection cutoff"),
        (normal, year_zero, None, "account opening"),
        (normal, normal, Some(year_zero), "account opening"),
        (last, DateDay(i32::MIN), None, "account opening"),
        (last, after_last, None, "entry source-0001"),
        (last, last, Some(last), "balance assertion for account 1000"),
    ] {
        let source = rebuild(cutoff, effective, assertion);
        let error = write_beancount(&source).unwrap_err();
        assert!(
            matches!(&error, FormatError::Parse { format: "beancount_v3", detail }
                if detail.contains(field) && detail.contains("YYYY-MM-DD profile")),
            "{error:?}"
        );
    }
    // The public extract constructor accepts raw assertion days. A malformed
    // extract must return a typed error, rather than overflowing its next day.
    let source = rebuild(normal, normal, Some(DateDay(i32::MAX)));
    assert!(matches!(
        write_beancount(&source),
        Err(FormatError::Overflow { format: "beancount_v3", detail })
            if detail.contains("next day of balance assertion for account 1000")
    ));
}

#[test]
fn beancount_open_directives_validate_their_dates() {
    let source = journal("Opening dates", "payment", None);
    let units = UnitCatalog::embedded().unwrap();
    let text = write_beancount(&source).unwrap();
    assert!(text.contains("1970-01-01 open "));
    for date in ["0001-01-01", "1969-12-31", "2024-06-30"] {
        let revised = text.replace("1970-01-01 open ", &format!("{date} open "));
        let restored = read_beancount(&revised, &units).unwrap();
        assert_eq!(restored, source);
        verify_round_trip_identity("beancount-opening-date", &source, &restored).unwrap();
    }
    for date in [
        "0000-01-01",
        "2024-+1-+5",
        "10000-01-01",
        "-001-01-01",
        "2023-02-29",
        "0000-13-01",
    ] {
        let revised = text.replace("1970-01-01 open ", &format!("{date} open "));
        assert!(matches!(
            read_beancount(&revised, &units),
            Err(FormatError::Parse {
                format: "beancount_v3",
                ..
            })
        ));
    }
}

#[test]
fn beancount_reader_refuses_dates_before_its_calendar_profile() {
    let base = journal("Calendar profile", "payment", None);
    let source = FormatJournal::new(
        "Calendar profile",
        "USD",
        2,
        base.coordinate.effective_through,
        1,
        base.accounts.clone(),
        base.entries.clone(),
        vec![FormatAssertion {
            account_code: "1000".into(),
            as_of: base.coordinate.effective_through,
            side: Side::Credit,
            amount: Amount::new(UnitId(0), 1_234_567),
            unit_code: "USD".into(),
            unit_scale: 2,
        }],
    )
    .unwrap();
    let text = write_beancount(&source).unwrap();
    let units = UnitCatalog::embedded().unwrap();
    for (original, replacement) in [
        (
            "; fa_effective_through: 2024-06-30",
            "; fa_effective_through: 0000-01-01",
        ),
        ("1970-01-01 open ", "0000-01-01 open "),
        ("2024-06-30 * ", "0000-01-01 * "),
        ("2024-07-01 balance ", "0000-01-01 balance "),
        ("2024-07-01 balance ", "0001-01-01 balance "),
    ] {
        assert!(text.contains(original), "{original}");
        let revised = text.replace(original, replacement);
        assert!(
            matches!(
                read_beancount(&revised, &units),
                Err(FormatError::Parse { format: "beancount_v3", detail })
                    if detail.contains("YYYY-MM-DD profile")
            ),
            "{replacement}"
        );
    }
}

#[test]
fn beancount_memo_newlines_cannot_add_balanced_postings() {
    let source = journal(
        "Source book",
        "Vendor payment",
        Some("Vendor\n  Expenses:A5000  999999.00 USD\n  Assets:A1000  -999999.00 USD"),
    );
    let text = write_beancount(&source).unwrap();
    assert_eq!(
        text.lines()
            .filter(|line| line.starts_with("  Expenses:"))
            .count(),
        1
    );
    assert_eq!(
        text.lines()
            .filter(|line| line.starts_with("  Assets:"))
            .count(),
        1
    );
    let restored = read_beancount(&text, &UnitCatalog::embedded().unwrap()).unwrap();
    verify_round_trip_identity("beancount-postings", &source, &restored).unwrap();
}

#[test]
fn hledger_account_names_cannot_override_declared_metadata() {
    let base = journal("Book", "Payment", None);
    let mut accounts = base.accounts.clone();
    accounts[0].name = "Cash fa_code:5000 fa_type:Expense".into();
    let source = FormatJournal::new(
        "Book",
        "USD",
        2,
        base.coordinate.effective_through,
        1,
        accounts,
        base.entries.clone(),
        vec![],
    )
    .unwrap();
    let restored = read_hledger(
        &write_hledger(&source).unwrap(),
        &UnitCatalog::embedded().unwrap(),
    )
    .unwrap();
    verify_round_trip_identity("hledger-name", &source, &restored).unwrap();
}

#[test]
fn plaintext_hex_metadata_refuses_corrupt_or_misattached_text() {
    let source = journal("Book", "Payment", None);
    let units = UnitCatalog::embedded().unwrap();
    let bean = write_beancount(&source).unwrap();
    let posting = "  Expenses:A5000  12345.67 USD\n";
    for (label, replacement) in [
        (
            "odd-length",
            format!("{posting}    fa_memo_hex_v1: \"a\"\n"),
        ),
        ("not-hex", format!("{posting}    fa_memo_hex_v1: \"zz\"\n")),
        ("not-utf8", format!("{posting}    fa_memo_hex_v1: \"ff\"\n")),
        (
            "before-posting",
            format!("    fa_memo_hex_v1: \"41\"\n{posting}"),
        ),
        (
            "wrong-indent",
            format!("{posting}  fa_memo_hex_v1: \"41\"\n"),
        ),
        (
            "duplicate",
            format!("{posting}    fa_memo_hex_v1: \"41\"\n    fa_memo_hex_v1: \"42\"\n"),
        ),
    ] {
        assert!(bean.contains(posting));
        assert!(
            matches!(
                read_beancount(&bean.replacen(posting, &replacement, 1), &units),
                Err(FormatError::Parse { .. })
            ),
            "{label}"
        );
    }
    for bad in ["a", "zz", "ff"] {
        let hledger = write_hledger(&source).unwrap().replace(
            "; fa_book_name: Book",
            &format!("; fa_book_name_hex_v1: {bad}"),
        );
        assert!(matches!(
            read_hledger(&hledger, &units),
            Err(FormatError::Parse { .. })
        ));
    }
}
