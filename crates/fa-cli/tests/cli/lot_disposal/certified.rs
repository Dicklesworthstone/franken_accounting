//! Real process, retained-file and independent outsider paths for lot schedules.

use super::*;

struct CertifiedSchedule {
    path: String,
    handle: String,
    line: String,
    report: Json,
    receipt: Json,
    certificate: fa::LotsCertificate,
}

fn certify(
    book: &Path,
    dir: &Path,
    name: &str,
    through: Option<&str>,
    known_at: &str,
) -> std::io::Result<CertifiedSchedule> {
    let path = dir.join(format!("{name}.cert")).display().to_string();
    let mut args = vec![
        "gl",
        "lots",
        "--account",
        "1400",
        "--as-known-at",
        known_at,
        "--certificate-out",
        &path,
        "--json",
    ];
    if let Some(through) = through {
        args.extend(["--as-of", through]);
    }
    let out = ok(book, "certify lot schedule", &args);
    let lines = out.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 2, "{out}");
    assert_eq!(field(lines[0], "event"), Some("lots"));
    assert_eq!(field(lines[1], "event"), Some("report_certificate"));
    let receipt = doc(lines[1]);
    let bytes = std::fs::read(&path)?;
    let certificate = fa::LotsCertificate::decode(&bytes).unwrap();
    assert_eq!(certificate.canonical_bytes().unwrap(), bytes);
    let artifact = fa::ReportArtifact::decode(&bytes).unwrap();
    assert_eq!(artifact.family(), fa::ReportArtifactFamily::Lots);
    assert_eq!(artifact.digest(), certificate.digest());
    assert_ne!(certificate.digest(), &certificate.source().digest);
    let digest = fa_verify::blake3::hex(certificate.digest());
    assert_eq!(text(&receipt, "oid"), digest);
    assert_eq!(text(&receipt, "file"), path);
    assert_eq!(text(&receipt, "output_format"), "fa:lots:v1");
    assert_eq!(text(&receipt, "bytes"), fa_verify::blake3::hex(&bytes));
    assert_eq!(field(lines[0], "certificate"), Some(digest.as_str()));
    assert_eq!(field(lines[1], "certificate"), Some(digest.as_str()));
    assert_eq!(certificate.source().known_at.0.to_string(), known_at);
    assert_eq!(int(&receipt, "known_at").unwrap().to_string(), known_at);
    assert!(int(&receipt, "recorded_at") > int(&receipt, "known_at"));
    assert!(int(&receipt, "native_inputs").is_some_and(|count| count > 0));
    let report = doc(lines[0]);
    assert_eq!(text(&report, "account"), "1400");
    assert_eq!(text(&report, "base_unit"), "USD");
    assert_eq!(report.get("disposal_plan"), Some(&Json::Null));
    assert_eq!(
        report.get("effective_through"),
        Some(&through.map_or(Json::Null, |day| Json::Str(day.into())))
    );
    let handle = format!("C:{digest}");
    assert!(text(&receipt, "replay_command").contains(&handle));
    assert!(text(&receipt, "replay_command").contains("--expect"));
    assert!(text(&receipt, "replay_command").contains("\"kind\":\"lots\""));
    Ok(CertifiedSchedule {
        path,
        handle,
        line: lines[0].to_string(),
        report,
        receipt,
        certificate,
    })
}

fn replay(book: &Path, dir: &Path, name: &str, saved: &CertifiedSchedule) -> std::io::Result<()> {
    let before = frontier(book);
    // Every invocation starts a new process and reopens the persisted book.
    // The retained object and an independently saved binary file must both
    // preserve the original report and the outer certificate identity.
    for (index, input) in [&saved.handle, &saved.path].into_iter().enumerate() {
        let output = dir
            .join(format!("{name}-{index}.lots"))
            .display()
            .to_string();
        let out = ok(
            book,
            "replay complete lot schedule",
            &["replay", input, "--output", &output, "--json"],
        );
        let lines = out.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 2, "{out}");
        assert_eq!(lines[0], saved.line);
        assert_eq!(field(lines[1], "event"), Some("report_replayed"));
        let receipt = doc(lines[1]);
        assert_eq!(text(&receipt, "family"), "lots");
        assert_eq!(text(&receipt, "file"), output);
        assert_eq!(
            text(&receipt, "output_digest"),
            text(&saved.receipt, "output_digest")
        );
        assert_eq!(
            std::fs::read(output)?,
            saved.certificate.output(),
            "replay reproduces every canonical lot and relief byte"
        );
    }
    assert_eq!(frontier(book), before, "replay is read-only");
    Ok(())
}

fn status(book: &Path, saved: &CertifiedSchedule) -> Json {
    doc(&ok(
        book,
        "lot certificate status",
        &["certificate", "status", &saved.handle, "--json"],
    ))
}

fn dispose(book: &Path, evidence: &str, date: &str, key: &str) -> String {
    let out = ok(
        book,
        "dispose ten shares",
        &[
            "dispose",
            "--account",
            "1400",
            "--quantity",
            "10.000000 SHARE",
            "--quantity-offset",
            "1499",
            "--cost-offset",
            "5100",
            "--date",
            date,
            "--key",
            key,
            "--evidence",
            evidence,
            "--json",
        ],
    );
    assert_eq!(field(&out, "event"), Some("posted"));
    text(&doc(&out), "vid").to_string()
}

fn assert_pool(report: &Json, remaining: bool) {
    let lots = arr(report, "lots");
    assert_eq!(lots.len(), 2);
    for (lot, original_cost) in lots.iter().zip(["100.00 USD", "20.00 USD"]) {
        assert_eq!(text(lot, "original_quantity"), "10.000000 SHARE");
        assert_eq!(text(lot, "original_cost"), original_cost);
    }
    assert_eq!(text(&lots[0], "open_quantity"), "0.000000 SHARE");
    assert_eq!(
        text(&lots[0], "open_cost"),
        if remaining { "40.00 USD" } else { "0.00 USD" }
    );
    assert_eq!(
        text(&lots[1], "open_quantity"),
        if remaining {
            "10.000000 SHARE"
        } else {
            "0.000000 SHARE"
        }
    );
    assert_eq!(
        text(&lots[1], "open_cost"),
        if remaining { "20.00 USD" } else { "0.00 USD" }
    );
}

fn assert_cost_only(report: &Json, last_disposal: &str, live: bool) {
    let relief = arr(&arr(report, "lots")[0], "relieves")
        .iter()
        .find(|relief| {
            text(relief, "disposal_entry") == last_disposal
                && relief.get("qty_ordinal") == Some(&Json::Null)
        })
        .expect("the exhausted first layer retains its separate $40 cost application");
    assert!(int(relief, "cost_ordinal").is_some());
    assert_eq!(text(relief, "quantity"), "0.000000 SHARE");
    assert_eq!(text(relief, "cost"), "40.00 USD");
    assert_eq!(relief.get("live"), Some(&Json::Bool(live)));
}

fn portable(
    book: &Path,
    dir: &Path,
    name: &str,
    saved: &CertifiedSchedule,
    key: [u8; 32],
    base_unit: u32,
    quantity_unit: u32,
) -> std::io::Result<fa_verify::report::VerifiedLots> {
    let output = dir.join(format!("{name}.fab")).display().to_string();
    let receipt = dir.join(format!("{name}.receipt")).display().to_string();
    let before = frontier(book);
    let produced = doc(&ok(
        book,
        "produce portable lot schedule",
        &[
            "bundle",
            "produce",
            "--certificate",
            &saved.handle,
            "--out",
            &output,
            "--receipt-out",
            &receipt,
            "--json",
        ],
    ));
    assert_eq!(frontier(book), before, "bundle production is read-only");
    assert_eq!(text(&produced, "scope"), "report");
    assert_eq!(
        text(&produced, "checkpoint_public_key"),
        fa_verify::blake3::hex(&key)
    );
    let command = text(&produced, "verify");
    assert!(command.starts_with("fa-verify report "), "{command}");
    let words = command.split_whitespace().collect::<Vec<_>>();
    let digest = fa_verify::blake3::hex(saved.certificate.digest());
    let base = base_unit.to_string();
    assert!(
        words
            .windows(2)
            .any(|pair| pair == ["--expect", digest.as_str()])
    );
    assert!(
        words
            .windows(2)
            .any(|pair| pair == ["--base-unit", base.as_str()])
    );
    let bundle = std::fs::read(output)?;
    let receipt = std::fs::read(receipt)?;
    let verified = fa_verify::report::verify_lots_report_expected(
        &bundle,
        &[key],
        None,
        Some(&receipt),
        base_unit,
        Some(saved.certificate.digest()),
    )
    .expect("the dependency-free verifier independently folds the actual CLI bundle");
    assert_eq!(verified.certificate_digest, *saved.certificate.digest());
    assert_eq!(verified.output, saved.certificate.output());
    // A currency premise must come from the recipient, and the recipient's
    // expected object is the whole lot schedule, not its nested OpenItems.
    assert!(
        fa_verify::report::verify_report_expected(
            &bundle,
            &[key],
            None,
            Some(&receipt),
            Some(saved.certificate.digest()),
        )
        .is_err()
    );
    assert!(
        fa_verify::report::verify_lots_report_expected(
            &bundle,
            &[key],
            None,
            Some(&receipt),
            quantity_unit,
            Some(saved.certificate.digest()),
        )
        .is_err()
    );
    assert!(
        fa_verify::report::verify_lots_report_expected(
            &bundle,
            &[key],
            None,
            Some(&receipt),
            base_unit,
            Some(&saved.certificate.source().digest),
        )
        .is_err()
    );
    let lots = verified.lots.expect("lots are independently materialized");
    assert_eq!(lots.base_unit, base_unit);
    assert_eq!(
        lots.source_certificate_digest,
        saved.certificate.source().digest
    );
    Ok(lots)
}

#[test]
fn certified_weighted_lots_replay_and_verify_offline_across_cost_only_relief_and_reversal()
-> std::io::Result<()> {
    let (dir, book, evidence) = setup("WeightedAverage")?;
    // These are independently selected fixture premises, not fields copied
    // from the report or its producer's recommended verifier command.
    let (base_unit, quantity_unit, key) = {
        let keys = fa::BookKeys::load(&book.join("book.keys")).unwrap();
        let reopened = fa::Book::open_dir(&book, keys, fa::Entropy::production()).unwrap();
        (
            reopened.context().units.lookup("USD").unwrap().0,
            reopened.context().units.lookup("SHARE").unwrap().0,
            reopened.checkpoint_public_key(),
        )
    };
    dispose(&book, &evidence, "2026-03-15", "certified-first-disposal");
    let first_at = frontier(&book).render();
    let partial = certify(&book, &dir, "partial", None, &first_at)?;
    assert_eq!(partial.certificate.base_unit().0, base_unit);
    // $120 / 20 shares × 10 shares = $60 total cost relief. Quantity order
    // consumes the first layer but leaves $40 there and $20 in the second.
    assert_pool(&partial.report, true);
    replay(&book, &dir, "partial-before-later-posts", &partial)?;
    assert_eq!(text(&status(&book, &partial), "status"), "Current");
    let expected =
        format!(r#"{{"kind":"lots","account":"1400","through":null,"known_at":{first_at}}}"#);
    let accepted = ok(
        &book,
        "recipient-selected original lot request",
        &["replay", &partial.handle, "--expect", &expected, "--json"],
    );
    assert_eq!(accepted.lines().next().unwrap(), partial.line);
    let before_refusals = frontier(&book);
    let wrong_prefix = first_at.parse::<u64>().unwrap() - 1;
    for (name, request) in [
        (
            "account",
            format!(r#"{{"kind":"lots","account":"1000","through":null,"known_at":{first_at}}}"#),
        ),
        (
            "prefix",
            format!(
                r#"{{"kind":"lots","account":"1400","through":null,"known_at":{wrong_prefix}}}"#
            ),
        ),
        (
            "cutoff",
            format!(
                r#"{{"kind":"lots","account":"1400","through":"2026-03-10","known_at":{first_at}}}"#
            ),
        ),
    ] {
        let rejected_output = dir.join(format!("wrong-{name}.lots")).display().to_string();
        let (code, out, err) = run(
            &book,
            "refuse another recipient question",
            &[
                "replay",
                &partial.handle,
                "--expect",
                &request,
                "--output",
                &rejected_output,
                "--json",
            ],
        );
        assert_eq!(code, 8, "{name}: {out}\n{err}");
        assert_eq!(out.lines().count(), 1);
        assert_eq!(field(&out, "event"), Some("error"));
        assert!(!Path::new(&rejected_output).exists());
        assert_eq!(frontier(&book), before_refusals);
    }
    let before_retry = frontier(&book);
    let repeated = ok(
        &book,
        "repeat exact certificate inline",
        &[
            "gl",
            "lots",
            "--account",
            "1400",
            "--as-known-at",
            &first_at,
            "--certify",
            "--json",
        ],
    );
    assert_eq!(repeated.lines().next().unwrap(), partial.line);
    assert_eq!(text(&doc(&repeated), "oid"), text(&partial.receipt, "oid"));
    assert_eq!(
        int(&doc(&repeated), "recorded_at"),
        int(&partial.receipt, "recorded_at")
    );
    assert_eq!(
        frontier(&book),
        before_retry,
        "retaining the same artifact is idempotent"
    );

    let last = dispose(&book, &evidence, "2026-03-20", "certified-last-disposal");
    let changed = status(&book, &partial);
    assert_eq!(text(&changed, "status"), "SupersededBy");
    assert_eq!(arr(&changed, "later_entries"), &[Json::Str(last.clone())]);
    let exhausted_at = frontier(&book).render();
    let exhausted = certify(&book, &dir, "exhausted", None, &exhausted_at)?;
    let cutoff = certify(&book, &dir, "cutoff", Some("2026-03-20"), &exhausted_at)?;
    assert_pool(&exhausted.report, false);
    assert_cost_only(&exhausted.report, &last, true);
    assert_pool(&cutoff.report, false);

    let undo = doc(&ok(
        &book,
        "reverse final disposal on a later effective date",
        &[
            "reverse",
            &last,
            "--reason",
            "WrongAmount",
            "--effective",
            "2026-03-25",
            "--grant",
            "read",
            "--json",
        ],
    ));
    let reversal = text(&undo, "vid").to_string();
    let changed = status(&book, &exhausted);
    assert_eq!(text(&changed, "status"), "SupersededBy");
    assert_eq!(arr(&changed, "later_entries"), &[Json::Str(reversal)]);
    let still_current = status(&book, &cutoff);
    assert_eq!(text(&still_current, "status"), "Current");
    assert!(arr(&still_current, "later_entries").is_empty());
    let restored_at = frontier(&book).render();
    let restored = certify(&book, &dir, "restored", None, &restored_at)?;
    assert_pool(&restored.report, true);
    assert_cost_only(&restored.report, &last, false);
    // The current source contains the reversal, but the selected historical
    // cutoff must still show the original disposal and its live $40 relief.
    let later_cutoff = certify(
        &book,
        &dir,
        "cutoff-from-later-prefix",
        Some("2026-03-20"),
        &restored_at,
    )?;
    assert_pool(&later_cutoff.report, false);
    assert_cost_only(&later_cutoff.report, &last, true);
    replay(&book, &dir, "partial-after-reversal", &partial)?;
    replay(&book, &dir, "exhausted-after-reversal", &exhausted)?;
    replay(&book, &dir, "restored-after-reopen", &restored)?;
    replay(&book, &dir, "cutoff-after-reopen", &later_cutoff)?;

    ok(
        &book,
        "checkpoint complete history",
        &["checkpoint", "create", "--grant", "witness", "--json"],
    );
    for (name, saved, remaining, live) in [
        ("exhausted", &exhausted, false, true),
        ("restored", &restored, true, false),
        ("later-cutoff", &later_cutoff, false, true),
    ] {
        let independently_folded =
            portable(&book, &dir, name, saved, key, base_unit, quantity_unit)?;
        assert_eq!(independently_folded.lots.len(), 2);
        let first = &independently_folded.lots[0];
        let second = &independently_folded.lots[1];
        assert_eq!(first.open_quantity.mantissa, 0);
        assert_eq!(first.open_cost.mantissa, if remaining { 4_000 } else { 0 });
        assert_eq!(
            second.open_quantity.mantissa,
            if remaining { 10_000_000 } else { 0 }
        );
        assert_eq!(second.open_cost.mantissa, if remaining { 2_000 } else { 0 });
        let cost_only = first
            .relieves
            .iter()
            .find(|relief| relief.qty_ordinal.is_none())
            .unwrap();
        assert_eq!(
            cost_only.disposal_entry,
            u128::from_str_radix(&last, 16).unwrap()
        );
        assert_eq!(cost_only.quantity.mantissa, 0);
        assert_eq!(cost_only.cost.mantissa, 4_000);
        assert_eq!(cost_only.live, live);
    }
    Ok(())
}

#[test]
fn certification_refuses_advisory_relief_and_unbound_report_selectors() -> std::io::Result<()> {
    let (dir, book, _) = setup("WeightedAverage")?;
    let before = frontier(&book);
    let output = dir.join("must-not-be-certified.cert").display().to_string();
    for extra in [
        vec!["--certify"],
        vec!["--certificate-out", output.as_str()],
    ] {
        let mut args = vec![
            "gl",
            "lots",
            "--account",
            "1400",
            "--relieve",
            "10.000000 SHARE",
            "--law",
            "WeightedAverage",
            "--json",
        ];
        args.extend(extra);
        let (code, out, err) = run(&book, "refuse certification of advisory relief", &args);
        assert_eq!(code, 2, "{out}\n{err}");
        assert_eq!(out.lines().count(), 1);
        assert_eq!(field(&out, "event"), Some("error"));
        assert_eq!(field(&out, "certificate"), Some("null"));
        assert_eq!(frontier(&book), before);
        assert!(!Path::new(&output).exists());
    }
    // A certificate must answer the supplied question. Shared GL flags may
    // not be silently discarded, and an instant needs a retained resolution
    // witness that this sequence-only certificate does not carry. The
    // instant refuses before any lookup, without a TimeEvidence fixture.
    for unsupported in [
        vec!["--as-known-at", "2026-03-20T00:00:00Z"],
        vec!["--unit", "USD"],
        vec!["--from", "2026-03-01"],
        vec!["--to", "2026-03-31"],
        vec!["--label", "Selected inventory"],
        vec!["--bucket", "30"],
        vec!["--policy", "must-not-be-read.json"],
        vec!["--income-period", "FY2026-P03"],
        vec!["--reconcile"],
        vec!["--all-posting"],
        vec!["--indirect"],
        vec!["--branch", "scenario:must-not-be-opened"],
    ] {
        let mut args = vec![
            "gl",
            "lots",
            "--account",
            "1400",
            "--certify",
            "--certificate-out",
            &output,
            "--json",
        ];
        args.extend(unsupported);
        let (code, out, err) = run(&book, "refuse unsupported certified selector", &args);
        assert_eq!(code, 2, "argv={args:?}\n{out}\n{err}");
        assert_eq!(out.lines().count(), 1, "{out}");
        assert_eq!(field(&out, "event"), Some("error"));
        assert_eq!(field(&out, "certificate"), Some("null"));
        assert!(!Path::new(&output).exists());
        assert_eq!(frontier(&book), before);
    }
    // Ordinary advisory relief remains useful and read-only.
    let advisory = doc(&ok(
        &book,
        "uncommitted disposal calculation",
        &[
            "gl",
            "lots",
            "--account",
            "1400",
            "--relieve",
            "10.000000 SHARE",
            "--law",
            "WeightedAverage",
            "--json",
        ],
    ));
    assert_eq!(
        text(advisory.get("disposal_plan").unwrap(), "total_cost"),
        "60.00 USD"
    );
    assert_eq!(frontier(&book), before);
    Ok(())
}
