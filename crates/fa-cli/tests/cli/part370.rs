//! FDIC Part 370 from a real book (plan §15.6 workflow 3, bead fa-p370):
//! deposits are `Deposit` instruments on their own Liability leaves, each
//! with a journaled participant profile; `fa export part370` writes the
//! profile's four files from the book's own parties, balances and holds.

use super::*;

fn ok(book: &Path, step: &str, args: &[&str]) -> String {
    let (code, out, err) = fa(Some(book), args);
    eprintln!(
        "{step}: argv={args:?} exit={code} event={:?} refusal={:?}",
        field(&out, "event"),
        field(&out, "refusal_id")
    );
    assert_eq!(code, 0, "{step}: argv={args:?}\nstdout={out}\nstderr={err}");
    out
}

fn refused(book: &Path, step: &str, args: &[&str]) -> (i32, String) {
    let (code, out, err) = fa(Some(book), args);
    eprintln!(
        "{step}: argv={args:?} exit={code} refusal={:?}",
        field(&out, "refusal_id")
    );
    assert_ne!(code, 0, "{step}: argv={args:?}\nstdout={out}\nstderr={err}");
    (code, format!("{out}\n{err}"))
}

const PARTIES: [(&str, &str); 4] = [
    (
        "bank",
        r#"{"code":"BANK-1","kind":"Bank","name":"First National Hartford"}"#,
    ),
    (
        "alice",
        r#"{"code":"CUST-001","kind":"Customer","name":"Alice M Vance","identifiers":{"given_name":"Alice","middle_name":"M","family_name":"Vance","tax_id":"999-01-0001","tax_id_type":"S","street_address_1":"100 Oak Street","city":"Hartford","state":"CT","postal_code":"06103","country":"US"}}"#,
    ),
    (
        "bob",
        r#"{"code":"CUST-002","kind":"Customer","name":"Bob J Vance","identifiers":{"given_name":"Bob","middle_name":"J","family_name":"Vance","tax_id":"999-01-0002","tax_id_type":"S","street_address_1":"100 Oak Street","city":"Hartford","state":"CT","postal_code":"06103","country":"US"}}"#,
    ),
    (
        "apex",
        r#"{"code":"CUST-003","kind":"Customer","name":"Apex Manufacturing LLC","identifiers":{"tax_id":"99-7000003","tax_id_type":"T","street_address_1":"500 Industrial Way","city":"New Haven","state":"CT","postal_code":"06511","country":"US"}}"#,
    ),
];

/// One deposit of the fixture bank: its leaf, its accrued-interest leaf,
/// funded balance and accrued interest, and its profile's body.
#[derive(Clone, Copy)]
struct Deposit {
    code: &'static str,
    leaf: &'static str,
    interest: Option<&'static str>,
    balance: &'static str,
    accrued: &'static str,
    profile: &'static str,
}

const DEPOSITS: [Deposit; 5] = [
    Deposit {
        code: "DEP-1001",
        leaf: "2810",
        interest: Some("2811"),
        balance: "180000.00",
        accrued: "500.00",
        profile: r#""capacity":"SGL","product":"DDA","primary":"CUST-001","participants":[{"party":"CUST-001","role":"owner","ownership_bps":10000}]"#,
    },
    Deposit {
        code: "DEP-1002",
        leaf: "2820",
        interest: Some("2821"),
        balance: "100000.00",
        accrued: "2000.00",
        profile: r#""capacity":"SGL","product":"CD","primary":"CUST-001","participants":[{"party":"CUST-001","role":"owner","ownership_bps":10000}]"#,
    },
    Deposit {
        code: "DEP-2001",
        leaf: "2830",
        interest: None,
        balance: "400000.00",
        accrued: "0.00",
        profile: r#""capacity":"JNT","product":"MMDA","primary":"CUST-001","participants":[{"party":"CUST-002","role":"owner","ownership_bps":5000},{"party":"CUST-001","role":"owner","ownership_bps":5000}]"#,
    },
    Deposit {
        code: "DEP-3001",
        leaf: "2840",
        interest: Some("2841"),
        balance: "450000.00",
        accrued: "1000.00",
        profile: r#""capacity":"REV","product":"SAV","primary":"CUST-002","participants":[{"party":"CUST-002","role":"owner","ownership_bps":10000,"beneficiaries":2}]"#,
    },
    Deposit {
        code: "DEP-4001",
        leaf: "2850",
        interest: None,
        balance: "310000.00",
        accrued: "0.00",
        profile: r#""capacity":"BUS","product":"DDA","primary":"CUST-003","participants":[{"party":"CUST-003","role":"owner","ownership_bps":10000}]"#,
    },
];

/// The vendored profile fixture's bank, built through the binary: five
/// deposits of three customers (two individuals, one entity), a joint
/// account, a revocable trust naming two beneficiaries, accrued interest on
/// three, and a receivership hold on the business account.
fn bank() -> std::io::Result<(PathBuf, PathBuf, String)> {
    let dir = tmp("part370-bank")?;
    let book = dir.join("book");
    ok(
        &book,
        "book",
        &[
            "book",
            "create",
            "--name",
            "First National Hartford",
            "--json",
        ],
    );
    let mut accounts = vec![
        r#"{"code":"1000","name":"Cash and due from banks","type":"Asset","unit":"USD"}"#
            .to_string(),
        r#"{"code":"1500","name":"Operating account","type":"Asset","unit":"USD"}"#.to_string(),
        r#"{"code":"2890","name":"Holds clearing","type":"Liability","unit":"USD"}"#.to_string(),
        r#"{"code":"6100","name":"Interest expense","type":"Expense","unit":"USD"}"#.to_string(),
    ];
    for Deposit {
        code,
        leaf,
        interest,
        ..
    } in DEPOSITS
    {
        accounts.push(format!(
            r#"{{"code":"{leaf}","name":"Deposits {code}","type":"Liability","unit":"USD"}}"#
        ));
        if let Some(interest) = interest {
            accounts.push(format!(
                r#"{{"code":"{interest}","name":"Accrued interest {code}","type":"Liability","unit":"USD"}}"#
            ));
        }
    }
    let chart = write(
        &dir,
        "chart.json",
        &format!(r#"{{"accounts":[{}]}}"#, accounts.join(",")),
    );
    ok(&book, "chart", &["chart", "import", &chart, "--json"]);
    ok(
        &book,
        "periods",
        &["period", "create", "--fiscal-year", "2026", "--json"],
    );
    ok(&book, "open", &["period", "open", "FY2026-P04", "--json"]);
    let evidence = source_doc(&dir, &book);
    for (name, body) in PARTIES {
        let file = write(&dir, &format!("{name}.json"), body);
        ok(&book, name, &["party", "add", &file, "--json"]);
    }
    for Deposit {
        code,
        leaf,
        interest,
        balance,
        accrued,
        profile,
    } in DEPOSITS
    {
        let instrument = write(
            &dir,
            &format!("{code}.json"),
            &format!(
                r#"{{"code":"{code}","name":"Deposit {code}","kind":"Deposit","unit":"USD","held_at":"BANK-1","mirrors":"{leaf}"}}"#
            ),
        );
        ok(&book, code, &["instrument", "add", &instrument, "--json"]);
        let interest_field =
            interest.map_or_else(|| "null".to_string(), |leaf| format!("\"{leaf}\""));
        let file = write(
            &dir,
            &format!("{code}-profile.json"),
            &format!(
                r#"{{"instrument":"{code}","interest_account":{interest_field},"valid_from":"2026-01-01",{profile}}}"#
            ),
        );
        let recorded = ok(
            &book,
            &format!("{code} profile"),
            &["instrument", "profile", &file, "--json"],
        );
        assert_eq!(field(&recorded, "event"), Some("rea_recorded"));
        assert_eq!(text(&doc(&recorded), "object"), "deposit_profile");
        let mut legs = vec![(leaf, "1000", balance)];
        if let Some(interest) = interest {
            legs.push((interest, "6100", accrued));
        }
        for (n, (credit, debit, amount)) in legs.into_iter().enumerate() {
            let intent = write(
                &dir,
                &format!("{code}-{n}.json"),
                &format!(
                    r#"{{"effective_date":"2026-04-01","idempotency_key":"{code}-{n}","legs":[{{"side":"debit","account":"{debit}","amount":"{amount} USD"}},{{"side":"credit","account":"{credit}","amount":"{amount} USD"}}]}}"#
                ),
            );
            ok(
                &book,
                "fund",
                &[
                    "post",
                    "--intent",
                    &intent,
                    "--evidence",
                    &evidence,
                    "--json",
                ],
            );
        }
    }
    let hold = write(
        &dir,
        "hold.json",
        r#"{"effective_date":"2026-04-10","idempotency_key":"PND-9001","description":"RECEIVERSHIP_HOLD","legs":[{"side":"debit","account":"2850","amount":"15000.00 USD"},{"side":"credit","account":"2890","amount":"15000.00 USD"}]}"#,
    );
    ok(
        &book,
        "hold",
        &[
            "reserve",
            "--intent",
            &hold,
            "--evidence",
            &evidence,
            "--json",
        ],
    );
    Ok((dir, book, evidence))
}

#[test]
fn part370_export_of_a_real_book_equals_the_profile_goldens() -> std::io::Result<()> {
    let (dir, book, _) = bank()?;
    // Pin the coordinate, so a replay is the same package.
    let info = ok(&book, "info", &["book", "info", "--json"]);
    let at = json::parse(info.lines().last().unwrap_or_default())
        .ok()
        .and_then(|line| line.get("coordinate")?.get("known_at").cloned());
    let Some(Json::Int(at)) = at else {
        panic!("no known_at in book info: {info}");
    };
    let at = at.to_string();
    let package = dir.join("p370").display().to_string();
    let out = ok(
        &book,
        "export",
        &[
            "export",
            "part370",
            "--as-of",
            "2026-04-10",
            "--as-known-at",
            &at,
            "--out",
            &package,
            "--json",
        ],
    );
    assert_eq!(field(&out, "event"), Some("part370_exported"));
    let data = doc(&out);
    assert_eq!(text(&data, "effective_date"), "2026-04-10");
    assert_eq!(int(&data, "customers"), Some(3));
    assert_eq!(int(&data, "accounts"), Some(5));
    assert_eq!(int(&data, "participants"), Some(6));
    assert_eq!(int(&data, "pending"), Some(1));
    let read = |name: &str| std::fs::read_to_string(format!("{package}/{name}")).unwrap();
    assert_eq!(
        read("customer.txt"),
        include_str!("../../../fa-formats/corpora/part370_customer_golden.txt")
    );
    assert_eq!(
        read("account.txt"),
        include_str!("../../../fa-formats/corpora/part370_account_golden.txt")
    );
    assert_eq!(
        read("account_participant.txt"),
        include_str!("../../../fa-formats/corpora/part370_account_participant_golden.txt")
    );
    assert_eq!(
        read("pending.txt"),
        include_str!("../../../fa-formats/corpora/part370_pending_golden.txt")
    );
    // Owner-capacity aggregation: CUST-001's two single accounts exceed one
    // standard maximum; the trust's two beneficiaries double CUST-002's.
    let owners: Vec<String> = arr(&data, "owners")
        .iter()
        .map(|o| {
            format!(
                "{} {} {} {} {}",
                text(o, "customer"),
                text(o, "capacity"),
                text(o, "aggregate"),
                text(o, "insured"),
                text(o, "uninsured")
            )
        })
        .collect();
    assert_eq!(
        owners,
        [
            "CUST-001 SGL 282500.00 250000.00 32500.00",
            "CUST-001 JNT 200000.00 200000.00 0.00",
            "CUST-002 JNT 200000.00 200000.00 0.00",
            "CUST-002 REV 451000.00 451000.00 0.00",
            "CUST-003 BUS 310000.00 250000.00 60000.00",
        ]
    );
    let certificate = read("Part370_Certificate.toml");
    let digest = text(&data, "certificate_digest").to_string();
    assert!(
        certificate.contains(&format!("certificate_digest = \"{digest}\"")),
        "{certificate}"
    );
    // The same coordinate replays to the same package, inline this time.
    let again = ok(
        &book,
        "replay",
        &[
            "export",
            "part370",
            "--as-of",
            "2026-04-10",
            "--as-known-at",
            &at,
            "--json",
        ],
    );
    let again = doc(&again);
    assert_eq!(text(&again, "certificate_digest"), digest);
    let inline: Vec<&str> = arr(&again, "files")
        .iter()
        .map(|f| text(f, "content"))
        .collect();
    assert_eq!(inline[0], read("customer.txt"));
    // Before the hold was placed the business account holds nothing and
    // pending.txt lists nothing: the hold is a later record, not a rewrite.
    let earlier = ok(
        &book,
        "before the hold",
        &[
            "export",
            "part370",
            "--as-of",
            "2026-04-09",
            "--as-known-at",
            &at,
            "--json",
        ],
    );
    let earlier = doc(&earlier);
    assert_eq!(int(&earlier, "pending"), Some(0));
    assert!(arr(&earlier, "files").iter().any(|f| {
        text(f, "name") == "account.txt"
            && text(f, "content")
                .contains("DEP-4001|CUST-003|BUS|DDA|310000.00|0.00|310000.00|0.00|USD|2026-04-09")
    }));
    Ok(())
}

#[test]
fn part370_package_verifies_at_its_own_coordinate_and_refuses_an_edit() -> std::io::Result<()> {
    let (dir, book, evidence) = bank()?;
    let package = dir.join("p370").display().to_string();
    let exported = ok(
        &book,
        "export",
        &[
            "export",
            "part370",
            "--as-of",
            "2026-04-10",
            "--out",
            &package,
            "--json",
        ],
    );
    let digest = text(&doc(&exported), "certificate_digest").to_string();
    // A later deposit into DEP-1001 dated before the package's day does
    // not move it: verification reads the book again at the certificate's
    // own known-at.
    let later = write(
        &dir,
        "later.json",
        r#"{"effective_date":"2026-04-05","idempotency_key":"DEP-1001-late","legs":[{"side":"debit","account":"1000","amount":"75000.00 USD"},{"side":"credit","account":"2810","amount":"75000.00 USD"}]}"#,
    );
    ok(
        &book,
        "later deposit",
        &[
            "post",
            "--intent",
            &later,
            "--evidence",
            &evidence,
            "--json",
        ],
    );
    let verified = ok(
        &book,
        "verify",
        &["verify", "export", "part370", &package, "--json"],
    );
    assert_eq!(field(&verified, "event"), Some("export_verified"));
    let data = doc(&verified);
    assert_eq!(text(&data, "format"), "part370");
    assert_eq!(text(&data, "reread"), "package");
    assert_eq!(text(&data, "effective_through"), "2026-04-10");
    assert_eq!(
        text(&data, "certificate_digest"),
        text(&doc(&exported), "journal_certificate_digest")
    );
    let names: Vec<&str> = arr(&data, "files")
        .iter()
        .map(|f| text(f, "name"))
        .collect();
    assert_eq!(
        names,
        [
            "customer.txt",
            "account.txt",
            "account_participant.txt",
            "pending.txt",
            "Part370_Certificate.toml",
        ]
    );
    // The same day exported now is another package: it carries the deposit.
    let now = ok(
        &book,
        "export now",
        &["export", "part370", "--as-of", "2026-04-10", "--json"],
    );
    assert_ne!(text(&doc(&now), "certificate_digest"), digest);
    // Each edit is a verification failure (exit 8) naming what moved.
    let mut flipped = digest.clone();
    flipped.replace_range(0..1, if digest.starts_with('0') { "1" } else { "0" });
    let edits: [(&str, &str, String, String, &str); 5] = [
        (
            "balance",
            "account.txt",
            "|180000.00|500.00|180500.00|".into(),
            "|170000.00|500.00|170500.00|".into(),
            "account.txt differs",
        ),
        (
            "digest",
            "Part370_Certificate.toml",
            format!("certificate_digest = \"{digest}\""),
            format!("certificate_digest = \"{flipped}\""),
            "does not replay from the book",
        ),
        (
            "owner row",
            "Part370_Certificate.toml",
            "uninsured = \"60000.00\"".into(),
            "uninsured = \"0.00\"".into(),
            "does not replay from the book",
        ),
        (
            "maximum",
            "Part370_Certificate.toml",
            "sdia = \"250000.00\"".into(),
            "sdia = \"500000.00\"".into(),
            "Part370_Certificate.toml differs from what fa export part370 writes",
        ),
        (
            "journal",
            "Part370_Certificate.toml",
            "journal_certificate_digest = \"".into(),
            "journal_certificate_digest = \"00".into(),
            "is not this book's",
        ),
    ];
    for (step, target, from, to, expect) in edits {
        let copy = dir.join(format!("edited-{}", step.replace(' ', "-")));
        std::fs::create_dir(&copy)?;
        for name in [
            "customer.txt",
            "account.txt",
            "account_participant.txt",
            "pending.txt",
            "Part370_Certificate.toml",
        ] {
            let mut body = std::fs::read_to_string(format!("{package}/{name}"))?;
            if name == target {
                assert_eq!(body.matches(from.as_str()).count(), 1, "{step}: {from}");
                body = body.replace(from.as_str(), &to);
            }
            std::fs::write(copy.join(name), body)?;
        }
        let copy = copy.display().to_string();
        let (code, out) = refused(
            &book,
            step,
            &["verify", "export", "part370", &copy, "--json"],
        );
        assert_eq!(code, 8, "{step}: {out}");
        assert!(out.contains(expect), "{step}: {out}");
    }
    // A package lacking one of its files is a usage error.
    let partial = dir.join("partial");
    std::fs::create_dir(&partial)?;
    std::fs::copy(
        format!("{package}/customer.txt"),
        partial.join("customer.txt"),
    )?;
    let partial = partial.display().to_string();
    let (code, out) = refused(
        &book,
        "partial package",
        &["verify", "export", "part370", &partial, "--json"],
    );
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("account.txt"), "{out}");
    Ok(())
}

#[test]
fn part370_refuses_incomplete_deposits_naming_what_is_missing() -> std::io::Result<()> {
    let (dir, book, _) = bank()?;
    let profile = |name: &str, body: &str| write(&dir, name, body);
    // A profile without its ownership right and capacity is a usage error
    // naming the field; nothing is recorded.
    let missing = profile(
        "no-capacity.json",
        r#"{"instrument":"DEP-1001","product":"DDA","primary":"CUST-001","valid_from":"2026-02-01","participants":[{"party":"CUST-001","role":"owner","ownership_bps":10000}]}"#,
    );
    let (code, text) = refused(
        &book,
        "no capacity",
        &["instrument", "profile", &missing, "--json"],
    );
    assert_eq!(code, 2, "{text}");
    assert!(text.contains("`capacity`"), "{text}");
    // Owner shares that do not make the whole deposit are refused by the
    // kernel, naming the rule.
    let partial = profile(
        "partial.json",
        r#"{"instrument":"DEP-2001","capacity":"JNT","product":"MMDA","primary":"CUST-001","valid_from":"2026-02-01","participants":[{"party":"CUST-001","role":"owner","ownership_bps":5000},{"party":"CUST-002","role":"owner","ownership_bps":4000}]}"#,
    );
    let (_, text) = refused(
        &book,
        "partial owners",
        &["instrument", "profile", &partial, "--json"],
    );
    assert!(
        text.contains("FA-REF-100") && text.contains("owner_shares"),
        "{text}"
    );
    // A profile describes a deposit: an operating bank account has none.
    let account = write(
        &dir,
        "operating.json",
        r#"{"code":"BA-OPS","name":"Operating","kind":"BankAccount","unit":"USD","held_at":"BANK-1","mirrors":"1500"}"#,
    );
    ok(
        &book,
        "operating",
        &["instrument", "add", &account, "--json"],
    );
    let not_deposit = profile(
        "not-deposit.json",
        r#"{"instrument":"BA-OPS","capacity":"BUS","product":"DDA","primary":"CUST-003","valid_from":"2026-02-01","participants":[{"party":"CUST-003","role":"owner","ownership_bps":10000}]}"#,
    );
    let (_, text) = refused(
        &book,
        "not a deposit",
        &["instrument", "profile", &not_deposit, "--json"],
    );
    assert!(text.contains("not a Deposit"), "{text}");
    // A deposit mirrors a Liability leaf.
    let asset_deposit = write(
        &dir,
        "asset-deposit.json",
        r#"{"code":"DEP-9","name":"Misfiled","kind":"Deposit","unit":"USD","held_at":"BANK-1","mirrors":"1000"}"#,
    );
    let (_, text) = refused(
        &book,
        "deposit on an asset",
        &["instrument", "add", &asset_deposit, "--json"],
    );
    assert!(text.contains("not a Liability"), "{text}");
    // A deposit with no profile valid on the day cannot be exported: its
    // capacity is unknown.
    let unprofiled = write(
        &dir,
        "dep-5001.json",
        r#"{"code":"DEP-5001","name":"New account","kind":"Deposit","unit":"USD","held_at":"BANK-1","mirrors":"2890"}"#,
    );
    ok(
        &book,
        "unprofiled",
        &["instrument", "add", &unprofiled, "--json"],
    );
    let (code, text) = refused(
        &book,
        "export without a profile",
        &["export", "part370", "--as-of", "2026-04-10", "--json"],
    );
    assert_eq!(code, 2, "{text}");
    assert!(
        text.contains("DEP-5001") && text.contains("no participant profile"),
        "{text}"
    );
    Ok(())
}
