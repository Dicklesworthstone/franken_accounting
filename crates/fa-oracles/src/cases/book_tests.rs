//! A1b's tests (bead fa-yugf.4): the pilot's native book loads, resolves and
//! balances, round-trips through the parser's canonical bytes, and every
//! planted edit is refused with its named kind at its line.

use super::*;
use crate::cases::{CASE_EXTENSIONS, Case, CaseFiles, LoadError, LoadErrorKind, load_with};

const CASE: &str = include_str!("../../tests/fixtures/pilot/case.toml");
const SOURCES: &str = include_str!("../../tests/fixtures/pilot/sources.toml");
const FACTS: &str = include_str!("../../tests/fixtures/pilot/facts.toml");
const RECEIPTS: &str = include_str!("../../tests/fixtures/pilot/receipts.toml");
const ROLES: &str = include_str!("../../tests/fixtures/pilot/roles.toml");
const NATIVE: &str = include_str!("../../tests/fixtures/pilot/books/native.toml");
const MIGRATION_MIN: &str = include_str!("../../tests/fixtures/migration_min/books/migration.toml");

type Files = Vec<(String, String)>;

/// The pilot's case files with `books` in place of its native book, and
/// `case.toml` declaring exactly their stems.
fn case_with(books: &[(&str, &str)]) -> Files {
    let stems: Vec<String> = books
        .iter()
        .map(|(p, _)| {
            let stem = p
                .strip_prefix("books/")
                .and_then(|p| p.strip_suffix(".toml"))
                .unwrap_or(p);
            format!("\"{stem}\"")
        })
        .collect();
    let case = once(
        CASE,
        "variants = [\"native\"]",
        &format!("variants = [{}]", stems.join(", ")),
    );
    let mut files = vec![
        ("case.toml".to_string(), case),
        ("sources.toml".to_string(), SOURCES.to_string()),
        ("facts.toml".to_string(), FACTS.to_string()),
        ("receipts.toml".to_string(), RECEIPTS.to_string()),
        ("roles.toml".to_string(), ROLES.to_string()),
    ];
    files.extend(
        books
            .iter()
            .map(|(p, t)| ((*p).to_string(), (*t).to_string())),
    );
    files
}

fn load(files: &Files) -> Result<Case, Vec<LoadError>> {
    let refs: Vec<(&str, &str)> = files
        .iter()
        .map(|(p, t)| (p.as_str(), t.as_str()))
        .collect();
    load_with(
        &CaseFiles {
            id: "worldcom",
            files: &refs,
        },
        CASE_EXTENSIONS,
    )
}

/// `text` with `old`, which must occur exactly once, replaced by `new`.
fn once(text: &str, old: &str, new: &str) -> String {
    assert_eq!(text.matches(old).count(), 1, "`{old}` occurs exactly once");
    text.replacen(old, new, 1)
}

/// The pilot's native book with one planted edit.
fn native(old: &str, new: &str) -> String {
    once(NATIVE, old, new)
}

fn refused_native(book: &str) -> Vec<LoadError> {
    load(&case_with(&[("books/native.toml", book)])).expect_err("the planted edit is refused")
}

/// The 1-based line of the one line of `text` containing `needle`.
fn line_of(text: &str, needle: &str) -> usize {
    let hits: Vec<usize> = text
        .lines()
        .enumerate()
        .filter(|(_, l)| l.contains(needle))
        .map(|(n, _)| n + 1)
        .collect();
    assert_eq!(hits.len(), 1, "`{needle}` is on exactly one line");
    hits[0]
}

/// The error of `kind` whose detail contains `part`, in `file`.
#[track_caller]
fn find<'e>(errs: &'e [LoadError], file: &str, kind: LoadErrorKind, part: &str) -> &'e LoadError {
    errs.iter()
        .find(|e| e.file == file && e.kind == kind && e.detail.contains(part))
        .ok_or_else(|| render(errs))
        .expect("an error of the named kind, file and detail")
}

/// Every error, one per line.
fn render(errs: &[LoadError]) -> String {
    errs.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n")
}

/// The files load; when they do not, the rendered errors are the message.
#[track_caller]
fn loads(files: &Files, what: &str) -> Case {
    load(files).map_err(|errs| render(&errs)).expect(what)
}

fn native_err(errs: &[LoadError], kind: LoadErrorKind, part: &str) -> LoadError {
    find(errs, "books/native.toml", kind, part).clone()
}

#[test]
fn pilot_native_book_loads_and_every_intent_balances() {
    let case = loads(
        &case_with(&[("books/native.toml", NATIVE)]),
        "the pilot loads",
    );
    let book = &case.books["native"];
    assert_eq!(book.kind, VariantKind::Native);
    assert_eq!(book.intents.len(), 7);
    assert_eq!(book.legs.len(), 14);
    assert_eq!(book.periods.len(), 6);
    assert_eq!(book.cases.len(), 1);
    // Every declared intent balances per unit, recomputed here from the legs
    // with this test's own sums.
    for intent in &book.intents {
        let (mut dr, mut cr) = (0_i128, 0_i128);
        for leg in book.legs.iter().filter(|l| l.intent == intent.id) {
            let v = super::super::amount::parse_amount(&leg.amount_literal, 2).expect("USD");
            if leg.side == "Dr" { dr += v } else { cr += v }
        }
        assert!(
            dr > 0 && dr == cr,
            "{} balances: Dr {dr} Cr {cr}",
            intent.id
        );
    }
    // Each Δ restates its documented entry.
    for (delta, target) in [("delta-F4", "F4"), ("delta-F9", "F9"), ("delta-F12", "F12")] {
        let d = book.intents.iter().find(|i| i.id == delta).expect("the Δ");
        assert_eq!(d.target.as_deref(), Some(target));
        assert!(d.is_delta());
    }
    // The canonical-bytes round trip.
    assert_eq!(
        book.to_document().canonical_bytes(),
        fa_registry::toml::parse(NATIVE)
            .expect("parses")
            .canonical_bytes(),
        "books/native.toml"
    );
}

#[test]
fn load_book_reloads_a_book_against_a_loaded_case() {
    let case = load(&case_with(&[("books/native.toml", NATIVE)])).expect("the pilot loads");
    let book = load_book(&case, "books/native.toml", NATIVE).expect("loads alone");
    assert_eq!(&book, &case.books["native"]);
    let errs = load_book(
        &case,
        "books/native.toml",
        &native(
            "account = \"6100\"\nside = \"Cr\"\namount_literal = \"560000000.00\"",
            "account = \"6199\"\nside = \"Cr\"\namount_literal = \"560000000.00\"",
        ),
    )
    .expect_err("a dangling account");
    assert!(
        errs.iter()
            .any(|e| e.kind == LoadErrorKind::DanglingKey && e.detail.contains("6199"))
    );
}

#[test]
fn leg_with_unknown_intent_is_refused() {
    let book = native(
        "intent = \"F2\"\nordinal = 0",
        "intent = \"F99\"\nordinal = 0",
    );
    let errs = refused_native(&book);
    let e = native_err(&errs, LoadErrorKind::DanglingKey, "leg 1 names intent F99");
    assert_eq!(e.line, Some(line_of(&book, "intent = \"F99\"")));
    assert!(
        e.to_string().starts_with(&format!(
            "books/native.toml:{}: DanglingKey: leg 1 names intent F99",
            e.line.unwrap()
        )),
        "{e}"
    );
}

#[test]
fn unbalanced_intent_is_refused() {
    let book = native(
        "account = \"1500\"\nside = \"Dr\"\namount_literal = \"560000000.00\"",
        "account = \"1500\"\nside = \"Dr\"\namount_literal = \"559999999.99\"",
    );
    let errs = refused_native(&book);
    let e = native_err(
        &errs,
        LoadErrorKind::Unbalanced,
        "intent F4 USD Dr 559999999.99 Cr 560000000.00 gap 0.01",
    );
    assert_eq!(
        e.line,
        Some(line_of(&book, "id = \"F4\"") - 1),
        "the intent's row"
    );
}

#[test]
fn step_with_unknown_period_is_refused() {
    let book = native(
        "kind = \"period_close\"\nref = \"2001Q3\"",
        "kind = \"period_close\"\nref = \"2001Q9\"",
    );
    let errs = refused_native(&book);
    let e = native_err(&errs, LoadErrorKind::UnknownPeriod, "2001Q9");
    assert_eq!(e.line, Some(line_of(&book, "ref = \"2001Q9\"")));
}

#[test]
fn duplicate_period_label_is_refused() {
    let book = native("code = \"2001Q3\"", "code = \"2001Q2\"");
    let errs = refused_native(&book);
    let e = native_err(
        &errs,
        LoadErrorKind::DuplicateLabel,
        "`2001Q2` is declared twice",
    );
    assert_eq!(e.line, Some(line_of(&book, "start = \"2001-07-01\"") - 2));
}

#[test]
fn amount_with_wrong_scale_is_refused() {
    let book = native(
        "account = \"1500\"\nside = \"Dr\"\namount_literal = \"560000000.00\"",
        "account = \"1500\"\nside = \"Dr\"\namount_literal = \"560000000.0\"",
    );
    let errs = refused_native(&book);
    let e = native_err(
        &errs,
        LoadErrorKind::WrongType,
        "exactly 2 fractional digit",
    );
    assert_eq!(e.line, Some(line_of(&book, "\"560000000.0\"")));
}

#[test]
fn amount_sum_overflow_is_refused() {
    let max = super::super::amount::format_amount(i128::MAX, 2);
    let synthetic = format!(
        "[[intent]]\nid = \"SYN-1\"\nfact = \"synthetic\"\nclass = \"Original\"\nprincipal = \"gen-acct-manager-1\"\neffective_date = \"2001-06-30\"\n\n\
         [[leg]]\nintent = \"SYN-1\"\nordinal = 0\naccount = \"1500\"\nside = \"Dr\"\namount_literal = \"{max}\"\namount_rule = \"synthetic\"\nunit = \"USD\"\n\n\
         [[leg]]\nintent = \"SYN-1\"\nordinal = 1\naccount = \"1510\"\nside = \"Dr\"\namount_literal = \"{max}\"\namount_rule = \"synthetic\"\nunit = \"USD\"\n\n\
         [[leg]]\nintent = \"SYN-1\"\nordinal = 2\naccount = \"6100\"\nside = \"Cr\"\namount_literal = \"1.00\"\namount_rule = \"synthetic\"\nunit = \"USD\"\n"
    );
    let book = format!("{NATIVE}\n{synthetic}");
    let errs = refused_native(&book);
    native_err(
        &errs,
        LoadErrorKind::WrongType,
        "intent SYN-1 USD: the amount overflows i128",
    );
    assert!(
        !errs
            .iter()
            .any(|e| e.kind == LoadErrorKind::Unbalanced && e.detail.contains("SYN-1")),
        "an overflowing sum is reported as overflow, never a wrapped balance"
    );
}

#[test]
fn reclassification_without_target_is_refused() {
    let book = native(
        "fact = \"F2\"\nclass = \"Original\"",
        "fact = \"F2\"\nclass = \"Reclassification\"",
    );
    let errs = refused_native(&book);
    let e = native_err(
        &errs,
        LoadErrorKind::TargetRequired,
        "Reclassification intent reclassifies",
    );
    assert_eq!(e.row.as_deref(), Some("F2"));
}

#[test]
fn unknown_step_kind_is_refused() {
    let book = native(
        "kind = \"intent\"\nref = \"F2\"",
        "kind = \"post\"\nref = \"F2\"",
    );
    let errs = refused_native(&book);
    let e = native_err(
        &errs,
        LoadErrorKind::UnknownValue,
        "`kind = \"post\"` is not a step kind",
    );
    assert_eq!(e.line, Some(line_of(&book, "kind = \"post\"") - 2));
}

#[test]
fn manual_assertion_with_unregistered_reason_is_refused() {
    let book = native(
        "evidence = \"DOC-PH-F4\"",
        "evidence = \"manual_assertion:NotARealCode\"",
    );
    let errs = refused_native(&book);
    let e = native_err(
        &errs,
        LoadErrorKind::DanglingKey,
        "manual_assertion:NotARealCode",
    );
    assert_eq!(e.line, Some(line_of(&book, "NotARealCode")));
    // A registered reason in scope manual_assertion loads.
    load(&case_with(&[(
        "books/native.toml",
        &native(
            "evidence = \"DOC-PH-F4\"",
            "evidence = \"manual_assertion:NoDocumentIssued\"",
        ),
    )]))
    .expect("a registered manual_assertion reason");
}

#[test]
fn role_that_does_not_admit_the_account_type_is_refused() {
    let book = native(
        "type = \"Expense\"\nrole = \"\"",
        "type = \"Expense\"\nrole = \"fixed_asset\"",
    );
    let errs = refused_native(&book);
    native_err(
        &errs,
        LoadErrorKind::UnknownValue,
        "role `fixed_asset` does not admit account type `Expense`",
    );
}

#[test]
fn stem_with_an_unknown_kind_prefix_is_refused() {
    let mut files = case_with(&[("books/native.toml", NATIVE)]);
    files.push(("books/statment-bridge.toml".into(), NATIVE.to_string()));
    let errs = load(&files).expect_err("an unknown stem");
    find(
        &errs,
        "books/statment-bridge.toml",
        LoadErrorKind::BadStem,
        "books/statment-bridge.toml",
    );
    assert_eq!(stem_kind("statement-bridge"), Some(VariantKind::Statement));
    assert_eq!(stem_kind("statement-Bridge"), None);
    assert_eq!(stem_kind("ledger"), Some(VariantKind::Ledger));
}

#[test]
fn variant_differing_from_its_stem_is_refused() {
    let book = native("variant = \"native\"", "variant = \"migration\"");
    let errs = refused_native(&book);
    let e = native_err(
        &errs,
        LoadErrorKind::BadStem,
        "differs from the file's stem `native`",
    );
    assert_eq!(e.line, Some(line_of(&book, "[book]")));
}

#[test]
fn documented_entry_intent_not_named_after_its_fact_is_refused() {
    let extra = "[[intent]]\nid = \"f4-cap\"\nfact = \"F4\"\nclass = \"Original\"\nprincipal = \"gen-acct-manager-1\"\neffective_date = \"2001-06-30\"\n\n\
                 [[leg]]\nintent = \"f4-cap\"\nordinal = 0\naccount = \"1500\"\nside = \"Dr\"\namount_literal = \"1.00\"\namount_rule = \"synthetic\"\nunit = \"USD\"\n\n\
                 [[leg]]\nintent = \"f4-cap\"\nordinal = 1\naccount = \"6100\"\nside = \"Cr\"\namount_literal = \"1.00\"\namount_rule = \"synthetic\"\nunit = \"USD\"\n";
    let book = format!("{NATIVE}\n{extra}");
    let errs = refused_native(&book);
    let e = native_err(&errs, LoadErrorKind::BadId, "documented entry `F4` is `F4`");
    assert_eq!(e.row.as_deref(), Some("f4-cap"));
    // One fact encoded as several intents takes one-letter suffixes (F6a/F6b).
    let ok = format!("{NATIVE}\n{}", extra.replace("f4-cap", "F4b"));
    load(&case_with(&[("books/native.toml", &ok)])).expect("F4b is a lawful id");
}

#[test]
fn negate_delta_not_named_delta_target_is_refused() {
    let book = NATIVE.replace("\"delta-F9\"", "\"undo-F9\"");
    let errs = refused_native(&book);
    let e = native_err(
        &errs,
        LoadErrorKind::BadId,
        "a case Δ of `F9` is `delta-F9`",
    );
    assert_eq!(e.row.as_deref(), Some("undo-F9"));
}

#[test]
fn second_delta_on_one_target_without_its_ordinal_is_refused() {
    let extra = "[[intent]]\nid = \"delta-F4-2\"\nfact = \"derived:negate\"\nclass = \"Restatement\"\nprincipal = \"case-poster-1\"\neffective_date = \"2001-06-30\"\ntarget = \"F4\"\ntarget_kind = \"restates\"\nreason = \"WrongAccount\"\nscenario = \"restate\"\n\n\
                 [[leg]]\nintent = \"delta-F4-2\"\nordinal = 0\naccount = \"1500\"\nside = \"Cr\"\namount_literal = \"560000000.00\"\namount_rule = \"derived:negate\"\nunit = \"USD\"\n\n\
                 [[leg]]\nintent = \"delta-F4-2\"\nordinal = 1\naccount = \"6100\"\nside = \"Dr\"\namount_literal = \"560000000.00\"\namount_rule = \"derived:negate\"\nunit = \"USD\"\n";
    let book = format!("{NATIVE}\n{extra}");
    let errs = refused_native(&book);
    let e = native_err(&errs, LoadErrorKind::BadId, "is `delta-F4-1`");
    assert_eq!(e.row.as_deref(), Some("delta-F4"));
    // Both numbered loads.
    let ok = book.replace("\"delta-F4\"", "\"delta-F4-1\"");
    load(&case_with(&[("books/native.toml", &ok)])).expect("delta-F4-1 and delta-F4-2");
}

#[test]
fn case_poster_who_is_an_approver_is_refused() {
    let book = native("poster = \"case-poster-1\"", "poster = \"case-approver-1\"");
    let errs = refused_native(&book);
    native_err(
        &errs,
        LoadErrorKind::UnknownValue,
        "the poster `case-approver-1` is one of the case's approvers",
    );
}

#[test]
fn period_close_step_without_a_principal_is_refused() {
    let book = native(
        "seq = 21\nkind = \"period_close\"\nref = \"2001Q2\"\nprincipal = \"case-closer-1\"\n",
        "seq = 21\nkind = \"period_close\"\nref = \"2001Q2\"\n",
    );
    let errs = refused_native(&book);
    let e = native_err(
        &errs,
        LoadErrorKind::MissingField,
        "a `period_close` step names the `principal`",
    );
    assert_eq!(e.line, Some(line_of(&book, "seq = 21") - 1));
}

#[test]
fn period_lock_step_approved_by_its_own_principal_is_refused() {
    let book = native(
        "approvers = [\"case-approver-1\"]",
        "approvers = [\"case-closer-1\"]",
    );
    let errs = refused_native(&book);
    let e = native_err(
        &errs,
        LoadErrorKind::UnknownValue,
        "`case-closer-1` approves its own `period_lock` step",
    );
    assert_eq!(
        e.line,
        Some(line_of(&book, "approvers = [\"case-closer-1\"]"))
    );
}

const PARTIES: &str = "[[party]]\nid = \"P1\"\nlabel = \"property-accounting-director-1\"\nkind = \"Employee\"\nrelations = [\"owns:P2;basis=equity_voting;valid_from=1999-06-30;pct=1/2\"]\n\n[[party]]\nid = \"P2\"\nlabel = \"F4\"\nkind = \"RelatedEntity\"\n";

#[test]
fn party_relation_without_basis_or_valid_from_is_refused() {
    let book = format!("{NATIVE}\n{}", PARTIES.replace(";basis=equity_voting", ""));
    let errs = refused_native(&book);
    native_err(
        &errs,
        LoadErrorKind::MissingField,
        "`basis=<code>` is required",
    );
    let book = format!(
        "{NATIVE}\n{}",
        PARTIES.replace(";valid_from=1999-06-30", "")
    );
    let errs = refused_native(&book);
    native_err(
        &errs,
        LoadErrorKind::MissingField,
        "`valid_from=<date>` is required",
    );
    let book = format!("{NATIVE}\n{}", PARTIES.replace("equity_voting", "kinship"));
    let errs = refused_native(&book);
    native_err(
        &errs,
        LoadErrorKind::UnknownValue,
        "basis `kinship` is not in relationship_bases.toml",
    );
}

#[test]
fn leg_naming_an_unknown_party_is_refused() {
    let book = format!(
        "{}\n{PARTIES}",
        native(
            "amount_rule = \"value:F2#1\"\nunit = \"USD\"\n\n[[leg]]\nintent = \"F2\"\nordinal = 1",
            "amount_rule = \"value:F2#1\"\nunit = \"USD\"\nparty = \"P9\"\n\n[[leg]]\nintent = \"F2\"\nordinal = 1",
        )
    );
    let errs = refused_native(&book);
    let e = native_err(&errs, LoadErrorKind::DanglingKey, "leg 1 names party P9");
    assert_eq!(e.line, Some(line_of(&book, "party = \"P9\"")));
    // The same leg naming a declared party loads.
    load(&case_with(&[(
        "books/native.toml",
        &book.replace("party = \"P9\"", "party = \"P1\""),
    )]))
    .expect("a declared party");
}

#[test]
fn authored_key_over_51_bytes_is_refused() {
    let key51 = "k".repeat(51);
    let key52 = "k".repeat(52);
    let ok = native(
        "idempotency_key = \"wc-pilot-F2\"",
        &format!("idempotency_key = \"{key51}\""),
    );
    load(&case_with(&[("books/native.toml", &ok)])).expect("a 51-byte key loads (the boundary)");
    let book = native(
        "idempotency_key = \"wc-pilot-F2\"",
        &format!("idempotency_key = \"{key52}\""),
    );
    let errs = refused_native(&book);
    let e = native_err(
        &errs,
        LoadErrorKind::TooLong,
        "the idempotency key is 52 bytes",
    );
    assert_eq!(e.line, Some(line_of(&book, &key52)));
}

#[test]
fn legacy_tb_stub_on_a_native_stem_is_refused() {
    let book = native("stub_of = \"placeholder:F2\"", "stub_of = \"legacy_tb\"");
    let errs = refused_native(&book);
    native_err(
        &errs,
        LoadErrorKind::UnknownValue,
        "belongs to a migration stem",
    );
}

#[test]
fn leg_ordinals_not_dense_from_zero_are_refused() {
    // F2's legs become ordinals 2 and 1: not 0, 1.
    let book = native(
        "intent = \"F2\"\nordinal = 0",
        "intent = \"F2\"\nordinal = 2",
    );
    let errs = refused_native(&book);
    native_err(
        &errs,
        LoadErrorKind::WrongType,
        "intent F2's leg ordinals are [1, 2]",
    );
}

#[test]
fn bare_derived_rule_name_amount_is_refused() {
    let book = native(
        "amount_literal = \"402000000.00\"\namount_rule = \"value:F2#1\"\nunit = \"USD\"\n\n[[leg]]\nintent = \"F2\"\nordinal = 1",
        "amount_literal = \"402000000.00\"\namount_rule = \"derived:difference\"\nunit = \"USD\"\n\n[[leg]]\nintent = \"F2\"\nordinal = 1",
    );
    let errs = refused_native(&book);
    let e = native_err(
        &errs,
        LoadErrorKind::DanglingKey,
        "`derived:difference` names no derived fact",
    );
    assert_eq!(e.line, Some(line_of(&book, "derived:difference")));
}

#[test]
fn derived_negate_outside_a_delta_is_refused() {
    let book = native(
        "amount_literal = \"402000000.00\"\namount_rule = \"value:F2#1\"\nunit = \"USD\"\n\n[[leg]]\nintent = \"F2\"\nordinal = 1",
        "amount_literal = \"402000000.00\"\namount_rule = \"derived:negate\"\nunit = \"USD\"\n\n[[leg]]\nintent = \"F2\"\nordinal = 1",
    );
    let errs = refused_native(&book);
    native_err(
        &errs,
        LoadErrorKind::UnknownValue,
        "derived:negate belongs to a case Δ",
    );
    // A Δ leg whose side matches its target's is no negation.
    let book = native(
        "intent = \"delta-F9\"\nordinal = 0\naccount = \"1510\"\nside = \"Cr\"",
        "intent = \"delta-F9\"\nordinal = 0\naccount = \"1510\"\nside = \"Dr\"",
    );
    let errs = refused_native(&book);
    native_err(
        &errs,
        LoadErrorKind::DanglingKey,
        "derived:negate needs F9's leg 0",
    );
}

#[test]
fn allocation_without_its_source_or_source_side_is_refused() {
    let alloc = "[[intent]]\nid = \"ALLOC-1\"\nfact = \"synthetic\"\nclass = \"Allocation\"\nprincipal = \"gen-acct-manager-1\"\neffective_date = \"2001-09-30\"\nallocation_law = \"EqualSplitResidualFirst\"\nallocation_total = \"544000000.00\"\nallocation_targets = [\"1510\", \"1520\"]\n";
    let errs = refused_native(&format!("{NATIVE}\n{alloc}"));
    native_err(
        &errs,
        LoadErrorKind::MissingField,
        "names its `allocation_source` account",
    );
    native_err(
        &errs,
        LoadErrorKind::MissingField,
        "needs `allocation_source_side`",
    );
    let full = format!(
        "{NATIVE}\n{}allocation_source = \"1500\"\nallocation_source_side = \"credit\"\n",
        alloc
    );
    load(&case_with(&[("books/native.toml", &full)])).expect("a complete allocation intent");
    let bad_law = full.replace("EqualSplitResidualFirst", "EvenishSplit");
    native_err(
        &refused_native(&bad_law),
        LoadErrorKind::UnknownValue,
        "`allocation_law = \"EvenishSplit\"` is not in allocation_laws.toml",
    );
}

#[test]
fn legacy_attribution_on_a_native_intent_is_refused() {
    let book = native(
        "idempotency_key = \"wc-pilot-F4\"",
        "idempotency_key = \"wc-pilot-F4\"\nsource_entered_by = \"gen-acct-manager-1\"",
    );
    let errs = refused_native(&book);
    let e = native_err(
        &errs,
        LoadErrorKind::UnknownField,
        "unknown field `source_entered_by`",
    );
    assert_eq!(e.row.as_deref(), Some("F4"));
}

#[test]
fn authored_source_recorded_at_ns_is_refused() {
    let book = once(
        MIGRATION_MIN,
        "idempotency_key = \"wc-mig-F9\"",
        "idempotency_key = \"wc-mig-F9\"\nsource_recorded_at_ns = \"1000\"",
    );
    let errs = load(&case_with(&[("books/migration.toml", &book)])).expect_err("refused");
    find(
        &errs,
        "books/migration.toml",
        LoadErrorKind::UnknownField,
        "unknown field `source_recorded_at_ns`",
    );
}

const ENTITIES: &str = "posture = \"embedded-owner\"\nentities = [\"ACQ:Acquirer Co\", \"TGT:Target Co\"]\nentity_relations = [\"ACQ|owns:TGT;basis=equity_voting;valid_from=2016-12-08;pct=10000/10000\"]";

#[test]
fn entity_relation_naming_a_non_entity_is_refused() {
    let book = native(
        "posture = \"embedded-owner\"",
        &ENTITIES.replace("ACQ|owns:TGT", "ACQ|owns:XYZ"),
    );
    let errs = refused_native(&book);
    native_err(
        &errs,
        LoadErrorKind::DanglingKey,
        "names `XYZ`, which is not a `[book] entities` code",
    );
}

#[test]
fn owns_entity_relation_with_a_fractional_basis_point_stake_is_refused() {
    let book = native(
        "posture = \"embedded-owner\"",
        &ENTITIES.replace("pct=10000/10000", "pct=1/3"),
    );
    let errs = refused_native(&book);
    native_err(&errs, LoadErrorKind::UnknownValue, "whole basis points");
}

#[test]
fn party_id_equal_to_an_entity_code_is_refused() {
    let book = format!(
        "{}\n{}",
        native("posture = \"embedded-owner\"", ENTITIES),
        PARTIES
            .replace("id = \"P2\"", "id = \"TGT\"")
            .replace("owns:P2", "owns:TGT"),
    );
    let errs = refused_native(&book);
    native_err(
        &errs,
        LoadErrorKind::DuplicateLabel,
        "party id `TGT` equals a `[book] entities` code",
    );
}

#[test]
fn params_on_a_period_step_is_refused() {
    let book = native(
        "seq = 21\nkind = \"period_close\"\nref = \"2001Q2\"\nprincipal = \"case-closer-1\"",
        "seq = 21\nkind = \"period_close\"\nref = \"2001Q2\"\nprincipal = \"case-closer-1\"\nparams = [\"window_days=4\"]",
    );
    let errs = refused_native(&book);
    let e = native_err(
        &errs,
        LoadErrorKind::UnknownField,
        "`params` belongs to finding_record / rule_backtest steps",
    );
    assert_eq!(e.line, Some(line_of(&book, "params = [\"window_days=4\"]")));
}

fn period_end_timing() -> String {
    let procedures = fa_registry::procedures::Procedures::embedded().expect("procedures.toml");
    let p = procedures.get("jet.period_end_timing").expect("registered");
    format!("jet.period_end_timing@{}", p.version)
}

fn with_finding_params(params: &str) -> String {
    let record = format!(
        "[[step]]\nseq = 53\nkind = \"finding_record\"\nref = \"{}\"\nknown_at = \"pre_case\"\nprincipal = \"examiner-1\"\nparams = [{params}]\n\n[[step]]\nseq = 60\nkind = \"case_open\"",
        period_end_timing()
    );
    native("[[step]]\nseq = 60\nkind = \"case_open\"", &record)
}

#[test]
fn finding_record_param_not_registered_for_its_procedure_is_refused() {
    load(&case_with(&[(
        "books/native.toml",
        &with_finding_params("\"window_days=4\""),
    )]))
    .expect("a registered integer parameter");
    let errs = refused_native(&with_finding_params("\"lookback=4\""));
    native_err(
        &errs,
        LoadErrorKind::UnknownValue,
        "`lookback` is not a registered parameter",
    );
}

#[test]
fn finding_record_param_that_is_not_an_integer_is_refused() {
    let errs = refused_native(&with_finding_params("\"window_days=four\""));
    native_err(
        &errs,
        LoadErrorKind::UnknownValue,
        "a finding_record parameter value is an integer",
    );
}

#[test]
fn assert_balance_without_evidence_is_refused() {
    let step = "[[step]]\nseq = 72\nkind = \"assert_balance\"\nref = \"W-T-02\"\nprincipal = \"examiner-1\"\n";
    let errs = refused_native(&format!("{NATIVE}\n{step}"));
    native_err(
        &errs,
        LoadErrorKind::MissingField,
        "names the filing stub its --evidence cites",
    );
    let ok = format!("{NATIVE}\n{step}evidence = \"DOC-406\"\nasserts = \"W406-TA-2000\"\n");
    load(&case_with(&[("books/native.toml", &ok)])).expect("with evidence and asserts");
}

#[test]
fn issue_step_without_its_filing_document_is_refused() {
    let step = "[[step]]\nseq = 72\nkind = \"issue\"\nref = \"2002Q1\"\nprincipal = \"case-closer-1\"\napprovers = [\"case-approver-1\"]\n";
    let errs = refused_native(&format!("{NATIVE}\n{step}"));
    native_err(
        &errs,
        LoadErrorKind::MissingField,
        "names the filing stub its issuance cites",
    );
}

#[test]
fn issue_document_that_is_not_a_source_stub_is_refused() {
    let step = "[[step]]\nseq = 72\nkind = \"issue\"\nref = \"2002Q1\"\nprincipal = \"case-closer-1\"\napprovers = [\"case-approver-1\"]\ndocument = \"DOC-PH-F4\"\n";
    let errs = refused_native(&format!("{NATIVE}\n{step}"));
    native_err(
        &errs,
        LoadErrorKind::DanglingKey,
        "whose stub_of is a source id",
    );
    let ok = format!("{NATIVE}\n{}", step.replace("DOC-PH-F4", "DOC-406"));
    load(&case_with(&[("books/native.toml", &ok)])).expect("a filing stub");
}

#[test]
fn engagement_file_finding_ref_without_a_finding_record_step_is_refused() {
    let book = native(
        "[[step]]\nseq = 10\nkind = \"intent\"",
        "[[step]]\nseq = 9\nkind = \"engagement_file\"\nref = \"finding:W-D-01\"\nprincipal = \"examiner-1\"\n\n[[step]]\nseq = 10\nkind = \"intent\"",
    );
    let errs = refused_native(&book);
    native_err(
        &errs,
        LoadErrorKind::UnknownValue,
        "no earlier finding_record step recorded",
    );
}

#[test]
fn filler_batch_on_a_statement_stem_is_refused() {
    let book = statement_book()
        + "\n[[step]]\nseq = 9\nkind = \"filler_batch\"\nref = \"K1\"\nprincipal = \"case-closer-1\"\n";
    let errs = load(&case_with(&[("books/statement-bridge.toml", &book)])).expect_err("refused");
    find(
        &errs,
        "books/statement-bridge.toml",
        LoadErrorKind::UnknownValue,
        "a statement stem carries no filler",
    );
}

#[test]
fn ledger_map_on_a_native_stem_is_refused() {
    let map = "[[ledger_map]]\nsource = \"F4\"\naccount = \"1ZR176\"\nbook_account = \"1500\"\nparty = \"P1\"\ncash_account = \"1400\"\ntransfer_account = \"1510\"\namount_columns = [\"AMOUNT\"]\n";
    let errs = refused_native(&format!("{NATIVE}\n{PARTIES}\n{map}"));
    native_err(
        &errs,
        LoadErrorKind::UnknownField,
        "`[[ledger_map]]` belongs to a ledger stem",
    );
}

#[test]
fn ledger_map_transfer_account_with_the_cash_role_is_refused() {
    let book = ledger_book().replace(
        "code = \"2900\"\nname_fact = \"F2\"\ntype = \"Asset\"\nrole = \"\"",
        "code = \"2900\"\nname_fact = \"F2\"\ntype = \"Asset\"\nrole = \"cash\"",
    );
    let errs = load(&case_with(&[("books/ledger.toml", &book)])).expect_err("refused");
    find(
        &errs,
        "books/ledger.toml",
        LoadErrorKind::UnknownValue,
        "the transfer account holds the `cash` role",
    );
}

fn statement_book() -> String {
    "[book]\nvariant = \"statement-bridge\"\nopening_date = \"1999-12-31\"\ncalendar = \"custom\"\nbase_unit = \"USD\"\nposture = \"embedded-owner\"\n\n\
     [[period]]\ncode = \"2000Q4\"\nstart = \"2000-10-01\"\nend = \"2000-12-31\"\nfiscal_year = 2000\nkind = \"Normal\"\n\n\
     [[principal]]\nlabel = \"case-closer-1\"\nprofile = \"Human\"\ngrants = [\"read\", \"post\", \"close\"]\n\n\
     [[principal]]\nlabel = \"case-approver-1\"\nprofile = \"Human\"\ngrants = [\"read\", \"approve\"]\n\n\
     [[account]]\ncode = \"1000\"\nname_fact = \"W406-TA-2000\"\ntype = \"Asset\"\nopened = \"1999-12-31\"\n\n\
     [[account]]\ncode = \"3900\"\nname_fact = \"W406-TA-2000\"\ntype = \"Equity\"\nopened = \"1999-12-31\"\n\n\
     [[document]]\nid = \"DOC-401\"\nstub_of = \"SRC-WC-401\"\ngrade = \"AgentUpload\"\n\n\
     [[intent]]\nid = \"W406-TA-2000\"\nfact = \"W406-TA-2000\"\nclass = \"Original\"\nprincipal = \"case-closer-1\"\neffective_date = \"2000-12-31\"\nevidence = \"DOC-401\"\n\n\
     [[leg]]\nintent = \"W406-TA-2000\"\nordinal = 0\naccount = \"1000\"\nside = \"Dr\"\namount_literal = \"98727000000.00\"\namount_rule = \"synthetic\"\nunit = \"USD\"\n\n\
     [[leg]]\nintent = \"W406-TA-2000\"\nordinal = 1\naccount = \"3900\"\nside = \"Cr\"\namount_literal = \"98727000000.00\"\namount_rule = \"synthetic\"\nunit = \"USD\"\n\n\
     [[step]]\nseq = 1\nkind = \"period_open\"\nref = \"2000Q4\"\nprincipal = \"case-closer-1\"\n\n\
     [[step]]\nseq = 2\nkind = \"intent\"\nref = \"W406-TA-2000\"\n\n\
     [[step]]\nseq = 3\nkind = \"issue\"\nref = \"2000Q4\"\nprincipal = \"case-closer-1\"\napprovers = [\"case-approver-1\"]\ndocument = \"DOC-401\"\n"
        .to_string()
}

fn ledger_book() -> String {
    format!(
        "[book]\nvariant = \"ledger\"\nopening_date = \"1999-12-31\"\ncalendar = \"custom\"\nbase_unit = \"USD\"\nposture = \"embedded-owner\"\n\n\
         [[period]]\ncode = \"2001Q3\"\nstart = \"2001-07-01\"\nend = \"2001-09-30\"\nfiscal_year = 2001\nkind = \"Normal\"\n\n\
         [[principal]]\nlabel = \"case-closer-1\"\nprofile = \"Human\"\ngrants = [\"read\", \"post\"]\n\n\
         [[account]]\ncode = \"1000\"\nname_fact = \"F2\"\ntype = \"Asset\"\nrole = \"cash\"\nopened = \"1999-12-31\"\n\n\
         [[account]]\ncode = \"2000\"\nname_fact = \"F2\"\ntype = \"Liability\"\nrole = \"investor_capital\"\nopened = \"1999-12-31\"\n\n\
         [[account]]\ncode = \"2900\"\nname_fact = \"F2\"\ntype = \"Asset\"\nrole = \"\"\nopened = \"1999-12-31\"\n\n\
         {PARTIES}\n\
         [[ledger_map]]\nsource = \"F2\"\naccount = \"1ZR176\"\nbook_account = \"2000\"\nparty = \"P1\"\ncash_account = \"1000\"\ntransfer_account = \"2900\"\namount_columns = [\"CASH DEPOSITS\", \"CASH WITHDRAWALS\"]\n\n\
         [[ledger_map]]\nsource = \"F4\"\naccount = \"1FN025\"\nbook_account = \"2000\"\nparty = \"P2\"\ncash_account = \"1000\"\ntransfer_account = \"2900\"\namount_columns = [\"CASH DEPOSITS\"]\n\n\
         [[default]]\nattribute = \"sign\"\nrule = \"deposits_debit_cash\"\nrationale = \"a deposit raises the cash account and the investor's capital\"\n\n\
         [[step]]\nseq = 1\nkind = \"period_open\"\nref = \"2001Q3\"\nprincipal = \"case-closer-1\"\n\n\
         [[step]]\nseq = 2\nkind = \"batch\"\nref = \"1ZR176\"\n"
    )
}

#[test]
fn statement_and_ledger_stems_load_with_their_kind() {
    let case = loads(
        &case_with(&[
            ("books/statement-bridge.toml", &statement_book()),
            ("books/ledger.toml", &ledger_book()),
        ]),
        "statement and ledger stems load",
    );
    assert_eq!(case.books["statement-bridge"].kind, VariantKind::Statement);
    let ledger = &case.books["ledger"];
    assert_eq!(ledger.kind, VariantKind::Ledger);
    assert_eq!(ledger.ledger_maps.len(), 2);
    let p1 = ledger.parties.iter().find(|p| p.id == "P1").expect("P1");
    assert_eq!(
        p1.relations,
        vec![Relation {
            kind: RelationKind::Owns,
            to: "P2".into(),
            basis: "equity_voting".into(),
            valid_from: "1999-06-30".into(),
            valid_to: None,
            pct: Some((1, 2)),
        }]
    );
    for (stem, text) in [
        ("statement-bridge", statement_book()),
        ("ledger", ledger_book()),
    ] {
        assert_eq!(
            case.books[stem].to_document().canonical_bytes(),
            fa_registry::toml::parse(&text)
                .expect("parses")
                .canonical_bytes(),
            "{stem} round-trips"
        );
    }
}

#[test]
fn migration_fixture_loads_with_migrate_step_kinds() {
    let case = loads(
        &case_with(&[("books/migration.toml", MIGRATION_MIN)]),
        "the migration fixture loads",
    );
    let book = &case.books["migration"];
    let kinds: Vec<_> = book.steps.iter().filter_map(StepDef::step_kind).collect();
    assert_eq!(
        kinds,
        [
            StepKind::MigrateOpen,
            StepKind::MigrateStage,
            StepKind::MigrateFinalize
        ]
    );
    assert_eq!(
        book.intents[0].source_entered_by.as_deref(),
        Some("property-accounting-director-1")
    );
    // A second copy with one import: a prepare step and two stage steps.
    let import = "[[document]]\nid = \"DOC-IMPORT\"\nstub_of = \"SRC-WC-001\"\ngrade = \"AgentUpload\"\n\n\
                  [[migration_import]]\nid = \"imp-1\"\nrun = 1\nsource = \"DOC-IMPORT\"\nformat = \"csv\"\naccount_map = [\"LEGACY-1510=1510\", \"LEGACY-6100=6100\"]\ncolumn_map = \"rows/columns.toml\"\ndefault_unit = \"USD\"\nentry_periods = [\"JE-1=2001Q3\"]\n\n\
                  [[step]]\nseq = 4\nkind = \"migrate_import\"\nref = \"imp-1\"\nprincipal = \"case-closer-1\"\n\n\
                  [[step]]\nseq = 5\nkind = \"migrate_import\"\nref = \"imp-1#0\"\nprincipal = \"case-closer-1\"\napprovers = [\"case-approver-1\", \"case-approver-2\"]\n\n\
                  [[step]]\nseq = 6\nkind = \"migrate_import\"\nref = \"imp-1#1\"\nprincipal = \"case-closer-1\"\napprovers = [\"case-approver-1\", \"case-approver-2\"]\n";
    let with_import = format!("{MIGRATION_MIN}\n{import}");
    let case = loads(
        &case_with(&[("books/migration.toml", &with_import)]),
        "the import copy loads",
    );
    assert_eq!(case.books["migration"].migration_imports.len(), 1);
}

#[test]
fn migrate_import_stage_before_its_prepare_is_refused() {
    let import = "[[document]]\nid = \"DOC-IMPORT\"\nstub_of = \"SRC-WC-001\"\ngrade = \"AgentUpload\"\n\n\
                  [[migration_import]]\nid = \"imp-1\"\nrun = 1\nsource = \"DOC-IMPORT\"\nformat = \"beancount\"\naccount_map = [\"Assets:PPE=1510\"]\n\n\
                  [[step]]\nseq = 5\nkind = \"migrate_import\"\nref = \"imp-1#0\"\nprincipal = \"case-closer-1\"\napprovers = [\"case-approver-1\", \"case-approver-2\"]\n";
    let errs = load(&case_with(&[(
        "books/migration.toml",
        &format!("{MIGRATION_MIN}\n{import}"),
    )]))
    .expect_err("refused");
    find(
        &errs,
        "books/migration.toml",
        LoadErrorKind::UnknownValue,
        "stages a chunk before its import's prepare step",
    );
}

#[test]
fn migrate_import_stage_with_one_approver_is_refused() {
    let import = "[[document]]\nid = \"DOC-IMPORT\"\nstub_of = \"SRC-WC-001\"\ngrade = \"AgentUpload\"\n\n\
                  [[migration_import]]\nid = \"imp-1\"\nrun = 1\nsource = \"DOC-IMPORT\"\nformat = \"beancount\"\naccount_map = [\"Assets:PPE=1510\"]\n\n\
                  [[step]]\nseq = 4\nkind = \"migrate_import\"\nref = \"imp-1\"\nprincipal = \"case-closer-1\"\n\n\
                  [[step]]\nseq = 5\nkind = \"migrate_import\"\nref = \"imp-1#0\"\nprincipal = \"case-closer-1\"\napprovers = [\"case-approver-1\"]\n";
    let errs = load(&case_with(&[(
        "books/migration.toml",
        &format!("{MIGRATION_MIN}\n{import}"),
    )]))
    .expect_err("refused");
    find(
        &errs,
        "books/migration.toml",
        LoadErrorKind::MissingField,
        "names two approver(s); it names 1",
    );
}

const EVENT: &str = "[[event]]\nid = \"EV-1\"\nkind = \"sale\"\noccurred_on = \"2001-08-22\"\nevidence = [\"DOC-406\"]\nparticipants = [\"P1\"]\nresource_label = \"line capacity\"\nresource_amount_literal = \"544000000.00\"\nresource_amount_rule = \"synthetic\"\nresource_unit = \"USD\"\n";

#[test]
fn event_without_evidence_is_refused() {
    let errs = refused_native(&format!(
        "{NATIVE}\n{PARTIES}\n{}",
        EVENT.replace("evidence = [\"DOC-406\"]", "evidence = []")
    ));
    native_err(
        &errs,
        LoadErrorKind::MissingField,
        "at least one evidence citation",
    );
}

#[test]
fn rule_step_naming_a_file_outside_rules_is_refused() {
    let step = "[[step]]\nseq = 72\nkind = \"rule_check\"\nref = \"../registries/verbs.toml\"\nprincipal = \"examiner-1\"\n";
    let errs = refused_native(&format!("{NATIVE}\n{step}"));
    native_err(
        &errs,
        LoadErrorKind::UnknownValue,
        "is a rule source `rules/<name>.rule` of the case",
    );
    let step = step.replace("../registries/verbs.toml", "rules/missing.rule");
    let errs = refused_native(&format!("{NATIVE}\n{step}"));
    native_err(
        &errs,
        LoadErrorKind::DanglingKey,
        "`rules/missing.rule` is not among the case's files",
    );
}

#[test]
fn extension_tables_load() {
    let alloc = "[[intent]]\nid = \"ALLOC-1\"\nfact = \"synthetic\"\nclass = \"Allocation\"\nprincipal = \"gen-acct-manager-1\"\neffective_date = \"2001-09-30\"\nallocation_law = \"EqualSplitResidualFirst\"\nallocation_total = \"544000000.00\"\nallocation_targets = [\"1510\", \"1520\"]\nallocation_source = \"1500\"\nallocation_source_side = \"credit\"\n";
    let steps = format!(
        "[[step]]\nseq = 72\nkind = \"allocate\"\nref = \"ALLOC-1\"\n\n\
         [[step]]\nseq = 73\nkind = \"assert_balance\"\nref = \"W-T-02#W406-TA-2000\"\nprincipal = \"examiner-1\"\nevidence = \"DOC-406\"\nasserts = \"W406-TA-2000\"\n\n\
         [[step]]\nseq = 74\nkind = \"issue\"\nref = \"2002Q1\"\nprincipal = \"case-closer-1\"\napprovers = [\"case-approver-1\"]\ndocument = \"DOC-406\"\n\n\
         [[step]]\nseq = 75\nkind = \"issue\"\nref = \"2002Q1\"\nprincipal = \"case-closer-1\"\napprovers = [\"case-approver-2\"]\ndocument = \"DOC-406\"\n\n\
         [[step]]\nseq = 76\nkind = \"finding_record\"\nref = \"{}\"\nknown_at = \"head\"\nprincipal = \"examiner-1\"\nparams = [\"window_days=4\"]\n\n\
         [[step]]\nseq = 77\nkind = \"event_record\"\nref = \"EV-1\"\nprincipal = \"case-closer-1\"\n\n\
         [[step]]\nseq = 78\nkind = \"rule_check\"\nref = \"rules/sales.rule\"\nprincipal = \"examiner-1\"\n\n\
         [[step]]\nseq = 79\nkind = \"rule_propose\"\nref = \"rules/sales.rule\"\nprincipal = \"examiner-1\"\n\n\
         [[step]]\nseq = 80\nkind = \"rule_backtest\"\nref = \"rules/sales.rule\"\nprincipal = \"examiner-1\"\nparams = [\"compare=79\", \"from=2001-07-01\", \"to=2001-09-30\"]\n",
        period_end_timing()
    );
    let book = format!(
        "{}\n{PARTIES}\n{EVENT}\n{alloc}\n{steps}",
        native("posture = \"embedded-owner\"", ENTITIES)
    );
    let mut files = case_with(&[("books/native.toml", &book)]);
    files.push(("rules/sales.rule".into(), "rule sales {}\n".into()));
    let case = loads(&files, "the extension tables load");
    let b = &case.books["native"];
    assert_eq!(b.book.relations.len(), 1);
    assert_eq!(b.book.relations[0].relation.pct, Some((10_000, 10_000)));
    assert_eq!(b.book.entity_codes(), ["ACQ", "TGT"]);
    assert_eq!(b.events.len(), 1);
    assert!(b.intents.iter().any(IntentDef::is_allocation));
    assert_eq!(
        b.to_document().canonical_bytes(),
        fa_registry::toml::parse(&book)
            .expect("parses")
            .canonical_bytes()
    );
}

#[test]
fn every_declared_variant_has_its_book_and_every_book_is_declared() {
    let mut files = case_with(&[("books/native.toml", NATIVE)]);
    files.retain(|(p, _)| p != "books/native.toml");
    let errs = load(&files).expect_err("a declared variant without its file");
    find(
        &errs,
        "case.toml",
        LoadErrorKind::MissingField,
        "variant `native` has no books/native.toml",
    );
    let mut files = case_with(&[("books/native.toml", NATIVE)]);
    files.push(("books/migration.toml".into(), MIGRATION_MIN.to_string()));
    let errs = load(&files).expect_err("an undeclared book");
    find(
        &errs,
        "books/migration.toml",
        LoadErrorKind::DanglingKey,
        "does not declare `migration`",
    );
}
