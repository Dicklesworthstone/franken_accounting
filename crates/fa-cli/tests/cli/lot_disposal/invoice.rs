//! A sales invoice and its source-derived inventory relief are one publication.
//!
//! The binary constructs the complete request. Native inspection below checks
//! its accounting effects and retained bytes rather than reproducing its planner.

use super::*;

use fa::{Book, BookKeys, Entropy};
use fa_model::{Entry, account_vid};
use fa_money::{Amount, Side};
use fgdb_types::{CommitSeq, VId};

const FIFO_THREE: &str = "qty=3 unit_price=\"25.00 USD\" inventory=1400 quantity_unit=SHARE quantity_offset=1499 cost_offset=5100 lot_law=FIFO";

fn fixture(law: &str) -> std::io::Result<(PathBuf, PathBuf, String)> {
    let (dir, book, evidence) = sale_fixture(law)?;
    let party = write(
        &dir,
        "invoice-customer.json",
        r#"{"code":"CUSTOMER","kind":"Customer","name":"Inventory customer"}"#,
    );
    ok(
        &book,
        "declare invoice customer",
        &["party", "add", &party, "--json"],
    );
    Ok((dir, book, evidence))
}

fn open(book: &Path) -> Book {
    Book::open_dir(
        book,
        BookKeys::load(&book.join("book.keys")).unwrap(),
        Entropy::production(),
    )
    .unwrap()
}

fn invoice_args(evidence: &str, number: &str, lines: &[&str]) -> Vec<String> {
    let mut args: Vec<String> = [
        "invoice",
        "--party",
        "CUSTOMER",
        "--number",
        number,
        "--date",
        "2026-03-15",
        "--receivable",
        "1100",
        "--revenue",
        "4000",
        "--evidence",
        evidence,
        "--json",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    for line in lines {
        args.extend(["--line".to_string(), (*line).to_string()]);
    }
    args
}

fn invoke(book: &Path, step: &str, args: &[String]) -> String {
    ok(
        book,
        step,
        &args.iter().map(String::as_str).collect::<Vec<_>>(),
    )
}

fn refused(book: &Path, step: &str, args: &[String], exits: &[i32]) -> String {
    let (status, out, err) = run(
        book,
        step,
        &args.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    assert!(
        exits.contains(&status),
        "{step}: exit={status}\n{out}\n{err}"
    );
    assert_eq!(field(&out, "event"), Some("error"), "{out}");
    out
}

fn members(book: &Path, posted: &Json) -> Vec<(Entry, CommitSeq)> {
    let book = open(book);
    arr(posted, "members")
        .iter()
        .map(|member| {
            let vid = VId(u128::from_str_radix(text(member, "vid"), 16).unwrap());
            let (entry, at) = book.read_entry(vid).unwrap().unwrap();
            assert_eq!(int(posted, "recorded_at"), Some(i128::from(at.0)));
            (entry, at)
        })
        .collect()
}

fn member_identities(posted: &Json) -> Vec<(String, String)> {
    arr(posted, "members")
        .iter()
        .map(|member| {
            (
                text(member, "vid").to_string(),
                text(member, "entry_digest").to_string(),
            )
        })
        .collect()
}

fn assert_sale_and_cost(
    book: &Path,
    entries: &[(Entry, CommitSeq)],
    sale: &str,
    cost: &str,
    quantity: &str,
) {
    assert_eq!(entries.len(), 2, "one invoice and one grouped disposal");
    assert_eq!(entries[0].1, entries[1].1, "one atomic publication");
    let book = open(book);
    let units = &book.context().units;
    let expected_sale = Amount::parse(sale, units).unwrap();
    let expected_cost = Amount::parse(cost, units).unwrap();
    let expected_quantity = Amount::parse(quantity, units).unwrap();
    let account = |code| account_vid(book.context().book_id, code);
    let invoice = entries
        .iter()
        .find(|(entry, _)| entry.proposal.lot_disposal_basis().unwrap().is_none())
        .unwrap();
    let control = invoice
        .0
        .proposal
        .legs
        .iter()
        .find(|leg| leg.account_ref == account("1100"))
        .unwrap();
    assert_eq!(control.side, Side::Debit);
    assert_eq!(control.amount, expected_sale);
    let revenue = invoice
        .0
        .proposal
        .legs
        .iter()
        .filter(|leg| leg.account_ref == account("4000"))
        .try_fold(0_i128, |total, leg| {
            assert_eq!(leg.side, Side::Credit);
            assert_eq!(leg.amount.unit, expected_sale.unit);
            total.checked_add(leg.amount.mantissa)
        })
        .unwrap();
    assert_eq!(revenue, expected_sale.mantissa);
    let disposal = entries
        .iter()
        .find(|(entry, _)| entry.proposal.lot_disposal_basis().unwrap().is_some())
        .unwrap();
    let basis = disposal.0.proposal.lot_disposal_basis().unwrap().unwrap();
    assert_eq!(basis.quantity, expected_quantity);
    assert_eq!(basis.account, account("1400"));
    assert_eq!(disposal.0.proposal.legs.len(), 4);
    for (leg, code, side, amount) in [
        (
            &disposal.0.proposal.legs[0],
            "1400",
            Side::Credit,
            expected_quantity,
        ),
        (
            &disposal.0.proposal.legs[1],
            "1499",
            Side::Debit,
            expected_quantity,
        ),
        (
            &disposal.0.proposal.legs[2],
            "1400",
            Side::Credit,
            expected_cost,
        ),
        (
            &disposal.0.proposal.legs[3],
            "5100",
            Side::Debit,
            expected_cost,
        ),
    ] {
        assert_eq!(leg.account_ref, account(code));
        assert_eq!(leg.side, side);
        assert_eq!(leg.amount, amount);
    }
}

fn acquisition(dir: &Path, book: &Path, evidence: &str, key: &str) {
    let input = write(
        dir,
        &format!("{key}.json"),
        &format!(
            r#"{{"effective_date":"2026-03-12","idempotency_key":"{key}","legs":[
            {{"side":"debit","account":"1400","amount":"10.000000 SHARE"}},
            {{"side":"credit","account":"1499","amount":"10.000000 SHARE"}},
            {{"side":"debit","account":"1400","amount":"500.00 USD"}},
            {{"side":"credit","account":"1000","amount":"500.00 USD"}}
            ]}}"#
        ),
    );
    ok(
        book,
        "new acquisition with a different capitalized unit cost",
        &["post", "--intent", &input, "--evidence", evidence, "--json"],
    );
}

#[test]
fn fifo_invoice_uses_capitalized_cost_and_groups_stock_lines_alongside_services()
-> std::io::Result<()> {
    let (_dir, book, evidence) = fixture("FIFO")?;
    let before = frontier(&book);
    let args = invoice_args(
        &evidence,
        "grouped-inventory",
        &[
            "qty=7 unit_price=\"25.00 USD\" inventory=1400 quantity_unit=SHARE quantity_offset=1499 cost_offset=5100 lot_law=FIFO item=WIDGET",
            "qty=5 unit_price=\"25.00 USD\" inventory=1400 quantity_unit=SHARE quantity_offset=1499 cost_offset=5100 lot_law=FIFO item=WIDGET",
            "amount=\"15.00 USD\" description=delivery",
        ],
    );
    let output = invoke(
        &book,
        "invoice goods and services with native FIFO relief",
        &args,
    );
    assert_eq!(field(&output, "event"), Some("batch_posted"));
    let posted = doc(&output);
    let entries = members(&book, &posted);
    // Capitalized acquisition costs are 100/10 and 20/10. Revenue prices
    // never enter relief: 12 units cost 100 + 2*2, despite sales of 300.
    assert_sale_and_cost(
        &book,
        &entries,
        "315.00 USD",
        "104.00 USD",
        "12.000000 SHARE",
    );
    let Json::Int(before) = before else {
        panic!("integer frontier")
    };
    assert_eq!(frontier(&book), Json::Int(before + 1));
    let relief = entries
        .iter()
        .find(|(entry, _)| entry.proposal.lot_disposal_basis().unwrap().is_some())
        .unwrap();
    assert_eq!(relief.0.proposal.legs[0].settles.len(), 2);
    assert_eq!(relief.0.proposal.legs[2].settles.len(), 2);
    assert_eq!(
        remaining_lots(&book, "1400"),
        vec![
            ("0.000000 SHARE".into(), "0.00 USD".into()),
            ("8.000000 SHARE".into(), "16.00 USD".into()),
        ]
    );
    Ok(())
}

#[test]
fn specific_id_invoice_uses_only_the_explicit_lot() -> std::io::Result<()> {
    let (_dir, book, evidence) = fixture("SpecificId")?;
    let owner = open(&book);
    let account = account_vid(owner.context().book_id, "1400");
    let quantity = owner.context().units.lookup("SHARE").unwrap();
    let target = owner
        .open_items(Some(account), None)
        .unwrap()
        .into_iter()
        .find(|item| {
            item.unit_id == quantity.0
                && item.effective_date == fa_time::DateDay::parse("2026-03-10").unwrap()
        })
        .unwrap();
    drop(owner);
    let line = format!(
        "qty=3 unit_price=\"25.00 USD\" inventory=1400 quantity_unit=SHARE quantity_offset=1499 cost_offset=5100 lot_law=SpecificId lots={:032x}:{}",
        target.entry.0, target.ordinal,
    );
    let output = invoke(
        &book,
        "invoice the explicitly selected cheaper lot",
        &invoice_args(&evidence, "selected-lot", &[&line]),
    );
    let entries = members(&book, &doc(&output));
    assert_sale_and_cost(&book, &entries, "75.00 USD", "6.00 USD", "3.000000 SHARE");
    let relief = entries
        .iter()
        .find(|(entry, _)| entry.proposal.lot_disposal_basis().unwrap().is_some())
        .unwrap();
    assert_eq!(relief.0.proposal.legs[0].settles.len(), 1);
    assert_eq!(
        relief.0.proposal.legs[0].settles[0].target.vid,
        target.entry
    );
    assert_eq!(relief.0.proposal.legs[0].settles[0].ordinal, target.ordinal);
    assert_eq!(
        remaining_lots(&book, "1400"),
        vec![
            ("10.000000 SHARE".into(), "100.00 USD".into()),
            ("7.000000 SHARE".into(), "14.00 USD".into()),
        ]
    );
    Ok(())
}

#[test]
fn invalid_inventory_invoice_never_posts_partial_revenue_or_cost() -> std::io::Result<()> {
    let (_dir, book, evidence) = fixture("FIFO")?;
    let before = frontier(&book);
    let lots = remaining_lots(&book, "1400");
    for (number, lines, exits) in [
        (
            "wrong-law",
            vec![
                "qty=3 unit_price=\"25.00 USD\" inventory=1400 quantity_unit=SHARE quantity_offset=1499 cost_offset=5100 lot_law=LIFO",
            ],
            vec![2, 3],
        ),
        (
            "conflicting-routes",
            vec![
                FIFO_THREE,
                "qty=1 unit_price=\"25.00 USD\" inventory=1400 quantity_unit=SHARE quantity_offset=1499 cost_offset=1000 lot_law=FIFO",
            ],
            vec![2, 3],
        ),
        (
            "insufficient-stock",
            vec![
                "qty=21 unit_price=\"25.00 USD\" inventory=1400 quantity_unit=SHARE quantity_offset=1499 cost_offset=5100 lot_law=FIFO",
            ],
            vec![3],
        ),
        (
            "currency-is-not-quantity",
            vec![
                "qty=3 unit_price=\"25.00 USD\" inventory=1400 quantity_unit=USD quantity_offset=1499 cost_offset=5100 lot_law=FIFO",
            ],
            vec![2, 3],
        ),
        (
            "missing-stock-quantity",
            vec![
                "amount=\"75.00 USD\" inventory=1400 quantity_unit=SHARE quantity_offset=1499 cost_offset=5100 lot_law=FIFO",
            ],
            vec![2],
        ),
    ] {
        refused(
            &book,
            number,
            &invoice_args(&evidence, number, &lines),
            &exits,
        );
        assert_eq!(frontier(&book), before, "{number}: refused batch wrote");
        assert_eq!(remaining_lots(&book, "1400"), lots, "{number}");
        let owner = open(&book);
        let account = account_vid(owner.context().book_id, "1100");
        assert!(
            owner.open_items(Some(account), None).unwrap().is_empty(),
            "{number}: revenue companion escaped"
        );
    }
    Ok(())
}

#[test]
fn inventory_invoice_plan_commits_exact_members_and_stale_plan_publishes_nothing()
-> std::io::Result<()> {
    let (dir, book, evidence) = fixture("FIFO")?;
    let path = dir.join("inventory-invoice.plan").display().to_string();
    let mut args = invoice_args(&evidence, "reviewed-inventory", &[FIFO_THREE]);
    args.extend(["--dry-run".into(), "--plan-out".into(), path.clone()]);
    let before = frontier(&book);
    let output = invoke(&book, "review a complete typed inventory invoice", &args);
    assert_eq!(field(&output, "event"), Some("batch_plan"));
    assert_eq!(frontier(&book), before);
    let plan = fa::BatchPlan::decode(&std::fs::read(&path)?).unwrap();
    assert_eq!(plan.prepared_entries().len(), 2);
    let expected = plan.prepared_entries().to_vec();
    let command = suggested_commit(&output);
    let committed = invoke(&book, "commit exact typed invoice plan", &command);
    assert_eq!(field(&committed, "event"), Some("batch_plan_committed"));
    let actual = members(&book, &doc(&committed));
    assert_eq!(
        actual
            .iter()
            .map(|(entry, _)| entry.clone())
            .collect::<Vec<_>>(),
        expected
    );
    assert_sale_and_cost(&book, &actual, "75.00 USD", "30.00 USD", "3.000000 SHARE");

    let stale_path = dir
        .join("stale-inventory-invoice.plan")
        .display()
        .to_string();
    let mut stale = invoice_args(&evidence, "stale-inventory", &[FIFO_THREE]);
    stale.extend(["--dry-run".into(), "--plan-out".into(), stale_path]);
    let review = invoke(
        &book,
        "prepare second invoice before a competing publication",
        &stale,
    );
    acquisition(&dir, &book, &evidence, "new-inventory-invalidates-plan");
    let head = frontier(&book);
    let lots = remaining_lots(&book, "1400");
    let refusal = refused(
        &book,
        "old invoice plan cannot refresh its cost silently",
        &suggested_commit(&review),
        &[6],
    );
    assert_eq!(
        field(&refusal, "refusal_id"),
        Some(fa_journal::refusal::code::PLAN_INVALIDATED)
    );
    assert_eq!(frontier(&book), head);
    assert_eq!(remaining_lots(&book, "1400"), lots);
    Ok(())
}

#[test]
fn raw_inventory_invoice_retry_preserves_original_cost_after_exhaustion_and_new_stock()
-> std::io::Result<()> {
    let (dir, book, evidence) = fixture("FIFO")?;
    let line = "qty=20 unit_price=\"25.00 USD\" inventory=1400 quantity_unit=SHARE quantity_offset=1499 cost_offset=5100 lot_law=FIFO";
    let mut args = invoice_args(&evidence, "exhausted-stock", &[line]);
    // A maximum-length external key must leave room for distinct generated
    // member/outcome identities without truncation or a raw suffix overflow.
    args.extend([
        "--key".into(),
        "x".repeat(fa_model::limits::MAX_IDEMPOTENCY_KEY_BYTES),
    ]);
    let posted = doc(&invoke(&book, "sell all existing inventory", &args));
    let original = members(&book, &posted);
    assert_sale_and_cost(
        &book,
        &original,
        "500.00 USD",
        "120.00 USD",
        "20.000000 SHARE",
    );
    let head = frontier(&book);
    let retry = doc(&invoke(
        &book,
        "retry after the selected lots are exhausted",
        &args,
    ));
    assert_eq!(retry.get("already_recorded"), Some(&Json::Bool(true)));
    assert_eq!(member_identities(&retry), member_identities(&posted));
    assert_eq!(frontier(&book), head);
    acquisition(&dir, &book, &evidence, "later-cost-must-not-reprice-retry");
    let head = frontier(&book);
    let retry = doc(&invoke(
        &book,
        "retry after new higher-cost inventory",
        &args,
    ));
    assert_eq!(retry.get("already_recorded"), Some(&Json::Bool(true)));
    assert_eq!(member_identities(&retry), member_identities(&posted));
    assert_eq!(retry.get("recorded_at"), posted.get("recorded_at"));
    assert_eq!(members(&book, &retry), original);
    assert_eq!(frontier(&book), head);
    let changed_line = line.replace("25.00", "26.00");
    let mut changed = invoice_args(&evidence, "exhausted-stock", &[&changed_line]);
    changed.extend([
        "--key".into(),
        "x".repeat(fa_model::limits::MAX_IDEMPOTENCY_KEY_BYTES),
    ]);
    refused(
        &book,
        "same document key cannot change the sale price",
        &changed,
        &[6],
    );
    assert_eq!(frontier(&book), head);
    Ok(())
}

fn confined_agent(dir: &Path, book: &Path, name: &str) -> String {
    let branch = fa_model::draft_branch(open(book).context().book_id, name).to_hex();
    let token = dir.join(format!("{name}.token")).display().to_string();
    ok(
        book,
        "issue the invoice planner only Post on its draft",
        &[
            "capability",
            "issue",
            "--holder",
            "inventory-invoice-agent",
            "--profile",
            "agent",
            "--op",
            "post",
            "--branch",
            &branch,
            "--out",
            &token,
            "--grant",
            "issue_capability",
            "--grant",
            "post",
            "--json",
        ],
    );
    let issued = fa_policy::CapabilityToken::decode(&std::fs::read(&token).unwrap()).unwrap();
    assert!(!issued.capability().holds(fa_policy::Op::Read));
    ok(
        book,
        "open the confined invoice draft",
        &["--token", &token, "draft", "new", name, "--json"],
    );
    token
}

#[test]
fn post_only_agent_invoice_retries_preserve_reviewed_bytes_and_promotion_checks_current_lots()
-> std::io::Result<()> {
    for stale in [false, true] {
        let (dir, book, evidence) = fixture("FIFO")?;
        let name = if stale {
            "stale-typed-sale"
        } else {
            "reviewed-typed-sale"
        };
        let token = confined_agent(&dir, &book, name);
        let mut args = invoice_args(&evidence, "agent-stock-sale", &[FIFO_THREE]);
        args.extend([
            "--token".into(),
            token.clone(),
            "--draft".into(),
            name.into(),
        ]);
        let before_lots = remaining_lots(&book, "1400");
        let first = invoke(
            &book,
            "agent drafts revenue and native inventory cost together",
            &args,
        );
        assert_eq!(field(&first, "event"), Some("draft_planned"));
        let reviewed = open(&book).draft(name).unwrap().unwrap();
        assert_eq!(reviewed.intents.len(), 2);
        assert_eq!(reviewed.intents[0].record, reviewed.intents[1].record);
        let original: Vec<_> = reviewed
            .intents
            .iter()
            .map(|member| member.resolved_entry.clone().unwrap())
            .collect();
        let head = frontier(&book);
        let again = invoke(
            &book,
            "same draft invoice retains its original lot basis",
            &args,
        );
        assert_eq!(doc(&again).get("already_recorded"), Some(&Json::Bool(true)));
        assert_eq!(frontier(&book), head);
        let repeated = open(&book).draft(name).unwrap().unwrap();
        assert_eq!(repeated.intents.len(), 2);
        assert_eq!(
            repeated
                .intents
                .iter()
                .map(|member| member.resolved_entry.clone().unwrap())
                .collect::<Vec<_>>(),
            original
        );
        assert_eq!(remaining_lots(&book, "1400"), before_lots);
        let mut altered = invoice_args(
            &evidence,
            "agent-stock-sale",
            &[&FIFO_THREE.replace("qty=3", "qty=4")],
        );
        altered.extend([
            "--token".into(),
            token.clone(),
            "--draft".into(),
            name.into(),
        ]);
        refused(
            &book,
            "same draft invoice key cannot substitute another quantity",
            &altered,
            &[6],
        );
        assert_eq!(frontier(&book), head);
        refused(
            &book,
            "source planning grants no general balance read",
            &[
                "--token".into(),
                token.clone(),
                "tb".into(),
                "--period".into(),
                "FY2026-P03".into(),
                "--json".into(),
            ],
            &[7],
        );
        assert_eq!(frontier(&book), head);
        refused(
            &book,
            "Agent cannot promote its own invoice",
            &[
                "--token".into(),
                token.clone(),
                "draft".into(),
                "promote".into(),
                name.into(),
                "--json".into(),
            ],
            &[7],
        );
        assert_eq!(frontier(&book), head);
        if stale {
            ok(
                &book,
                "competing relief changes the selected FIFO layers",
                &[
                    "dispose",
                    "--account",
                    "1400",
                    "--quantity",
                    "1.000000 SHARE",
                    "--quantity-offset",
                    "1499",
                    "--cost-offset",
                    "5100",
                    "--date",
                    "2026-03-15",
                    "--key",
                    "competing-invoice-relief",
                    "--evidence",
                    &evidence,
                    "--json",
                ],
            );
        }
        let head = frontier(&book);
        let lots = remaining_lots(&book, "1400");
        let promote: Vec<String> = [
            "draft",
            "promote",
            name,
            "--as",
            "controller",
            "--yes",
            "--json",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        if stale {
            let failure = refused(
                &book,
                "stale cost refuses the whole invoice promotion",
                &promote,
                &[6],
            );
            assert_eq!(
                field(&failure, "refusal_id"),
                Some(fa_journal::refusal::code::PLAN_INVALIDATED)
            );
            assert_eq!(frontier(&book), head);
            assert_eq!(remaining_lots(&book, "1400"), lots);
            let owner = open(&book);
            assert!(
                owner
                    .open_items(Some(account_vid(owner.context().book_id, "1100")), None)
                    .unwrap()
                    .is_empty()
            );
        } else {
            let result = doc(&invoke(
                &book,
                "independent controller promotes original sale and cost",
                &promote,
            ));
            assert_eq!(arr(&result, "entries").len(), 2);
            let owner = open(&book);
            let mut actual = Vec::new();
            for (reference, expected) in arr(&result, "entries").iter().zip(&original) {
                let vid = VId(u128::from_str_radix(reference.as_str().unwrap(), 16).unwrap());
                let (entry, at) = owner.read_entry(vid).unwrap().unwrap();
                assert_eq!(entry, *expected);
                assert_eq!(Some(i128::from(at.0)), int(&result, "recorded_at"));
                actual.push((entry, at));
            }
            drop(owner);
            assert_sale_and_cost(&book, &actual, "75.00 USD", "30.00 USD", "3.000000 SHARE");
        }
    }
    Ok(())
}
