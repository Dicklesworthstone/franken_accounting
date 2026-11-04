//! fa-kxc4 acceptance: Lantern selects every account population by the
//! journaled account role, never by what the account is called. Over the
//! Ponzi and shell-network corpora, renaming every account to a neutral code
//! and name leaves every procedure's findings identical; an account named
//! "Cash" without the cash role is outside the cash population; a procedure
//! whose role no account holds refuses with the `fa chart role` fix.

use super::*;
use fa_gen::{GenConfig, GeneratedCorpus, ScenarioKind, generate};

/// `corpus` with every account renamed to a neutral code (`N-00`, `N-01`, …
/// in chart order) and a neutral name, the legs and labels following. The
/// roles stay with the accounts, as a chart template carries them. Returns
/// the renamed corpus and each neutral code's original code and name.
fn renamed(corpus: &GeneratedCorpus) -> (GeneratedCorpus, BTreeMap<String, (String, String)>) {
    let mut renamed = corpus.clone();
    let mut neutral_of = BTreeMap::new();
    let mut original_of = BTreeMap::new();
    for (i, account) in renamed.accounts.iter_mut().enumerate() {
        let code = format!("N-{i:02}");
        neutral_of.insert(account.code.clone(), code.clone());
        original_of.insert(code.clone(), (account.code.clone(), account.name.clone()));
        account.code = code;
        account.name = format!("Ledger account {i:02}");
    }
    let neutral = |code: &mut String| {
        *code = neutral_of
            .get(code.as_str())
            .expect("every leg and label names an account of the corpus chart")
            .clone();
    };
    for entry in &mut renamed.entries {
        for leg in &mut entry.legs {
            neutral(&mut leg.account_code);
        }
    }
    for label in &mut renamed.labels {
        for code in &mut label.account_codes {
            neutral(code);
        }
    }
    (renamed, original_of)
}

/// `text` with every CGSE determinism witness (`cgse_witness=<hex>`)
/// masked. The witness digests the graph a ranking ran over, vertex ids
/// included, so renaming an account changes it by construction; the
/// finding it accompanies must not change.
fn masked_witness(text: &str) -> String {
    const TAG: &str = "cgse_witness=";
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(TAG) {
        let (head, tail) = rest.split_at(at + TAG.len());
        out.push_str(head);
        out.push_str("<digest>");
        rest = tail.trim_start_matches(|c: char| c.is_ascii_hexdigit());
    }
    out.push_str(rest);
    out
}

/// Version 2 declares an undirected pair, serialized in native vid order.
/// After mapping handles back to the original accounts, compare that pair as
/// an unordered value, just as citations are compared below. Retain every
/// member, word and numeric value; other procedures and versions are unchanged.
fn canonical_pair_narrative(procedure: &str, version: u16, text: &str) -> String {
    const PREFIX: &str = "debit/credit account pair (";
    if procedure != "jet.unusual_accounts" || version != 2 {
        return text.to_owned();
    }
    let Some(rest) = text.strip_prefix(PREFIX) else {
        return text.to_owned();
    };
    let Some((pair, suffix)) = rest.split_once(") occurs ") else {
        return text.to_owned();
    };
    let Some((a, b)) = pair.split_once(", ") else {
        return text.to_owned();
    };
    let account =
        |part: &str| part.starts_with("account(") && part.ends_with(')') && !part.contains(", ");
    if !account(a) || !account(b) {
        return text.to_owned();
    }
    let (a, b) = if a <= b { (a, b) } else { (b, a) };
    format!("{PREFIX}{a}, {b}) occurs {suffix}")
}

/// A run's outcome over one book, with every book-specific handle mapped to
/// what it stands for in the original corpus: entries by corpus index,
/// accounts by original code, and in narratives and statistic names the
/// neutral codes and names (and any account vid) by the original. Findings
/// are sorted, so only their content counts.
fn outcome(
    run: Result<ProcedureRun, LanternError>,
    book: &BookContext,
    posted_vids: &[VId],
    chart: &[(String, String)],
    original_of: &BTreeMap<String, (String, String)>,
) -> Result<Vec<String>, String> {
    let mut account_code = BTreeMap::new();
    let mut replacements: Vec<(String, String)> = Vec::new();
    for (code, name) in chart {
        let (original_code, original_name) = original_of
            .get(code)
            .cloned()
            .unwrap_or_else(|| (code.clone(), name.clone()));
        let vid = account_vid(book.book_id, code);
        account_code.insert(vid, original_code.clone());
        let handle = format!("account({original_code})");
        replacements.push((format!("{:032x}", vid.0), handle.clone()));
        replacements.push((format!("{:x}", vid.0), handle.clone()));
        replacements.push((vid.0.to_string(), handle));
        if original_of.contains_key(code) {
            replacements.push((code.clone(), original_code));
            replacements.push((name.clone(), original_name));
        }
    }
    let text = |s: &str| {
        masked_witness(
            &replacements
                .iter()
                .fold(s.to_string(), |s, (from, to)| s.replace(from, to)),
        )
    };
    let entry = |vid: &VId| match posted_vids.iter().position(|v| v == vid) {
        Some(index) => format!("entry#{index}"),
        None => format!("entry{vid:?}"),
    };
    let run = run.map_err(|e| text(&e.to_string()))?;
    let mut findings: Vec<String> = run
        .findings
        .iter()
        .map(|f| {
            // Citations follow vid order, which renaming changes by
            // construction (an account's vid hashes its code): compare them
            // as a sorted list.
            let mut cites: Vec<String> = f
                .cites
                .iter()
                .map(|c| match c {
                    Cite::Entry(vid) => entry(vid),
                    Cite::Leg {
                        entry: vid,
                        ordinal,
                    } => format!("{}/leg{ordinal}", entry(vid)),
                    Cite::Account(vid) => account_code
                        .get(vid)
                        .map_or_else(|| format!("account{vid:?}"), |c| format!("account({c})")),
                    other => format!("{other:?}"),
                })
                .collect();
            cites.sort();
            format!(
                "{} v{} {:?} {}={}e-{} of {} cites={cites:?} {}",
                f.procedure,
                f.version,
                f.severity,
                text(&f.statistic.name),
                f.statistic.value,
                f.statistic.scale,
                f.statistic.population,
                canonical_pair_narrative(&f.procedure, f.version, &text(&f.narrative)),
            )
        })
        .collect();
    findings.sort();
    Ok(findings)
}

/// The oracle admits only the declared undirected pair's presentation order.
/// Mutating actual findings' membership, values, citations or other content
/// must still change the compared outcome.
#[test]
fn role_outcome_preserves_membership_and_all_nonordering_fields() {
    let corpus = generate(GenConfig::new(ScenarioKind::Ponzi, 7));
    let (book, snapshot, posted_vids) = corpus_snapshot(&corpus);
    let chart: Vec<_> = corpus
        .accounts
        .iter()
        .map(|account| (account.code.clone(), account.name.clone()))
        .collect();
    let procedure = fa_lantern::jet::UnusualAccounts::new().unwrap();
    let mut run = run_over(&snapshot, &book, &procedure).unwrap();
    assert_eq!(run.procedure, "jet.unusual_accounts");
    assert_eq!(run.version, 2);
    assert!(
        !run.findings.is_empty(),
        "the native run must report a pair"
    );
    let compared = |run| outcome(Ok(run), &book, &posted_vids, &chart, &BTreeMap::new()).unwrap();
    let accounts: Vec<_> = run.findings[0]
        .cites
        .iter()
        .filter_map(|cite| match cite {
            Cite::Account(vid) => Some(*vid),
            _ => None,
        })
        .collect();
    assert_eq!(accounts.len(), 2);
    let (a, b) = (accounts[0], accounts[1]);
    let prefix = format!("debit/credit account pair ({:032x}, {:032x})", a.0, b.0);
    let suffix = run.findings[0]
        .narrative
        .strip_prefix(&prefix)
        .unwrap()
        .to_owned();
    let code = |vid| {
        chart
            .iter()
            .find(|(code, _)| account_vid(book.book_id, code) == vid)
            .map(|(code, _)| code.as_str())
            .unwrap()
    };
    let (first, second) = if code(a) <= code(b) { (a, b) } else { (b, a) };
    // Start semantic mutants from an already canonical pair presentation.
    // Changing version or procedure then cannot differ merely because it
    // disables pair sorting; each mutant must preserve its own changed field.
    run.findings[0].narrative = format!(
        "debit/credit account pair ({:032x}, {:032x}){suffix}",
        first.0, second.0
    );
    let expected = compared(run.clone());
    let mut permuted = run.clone();
    permuted.findings[0].narrative = format!(
        "debit/credit account pair ({:032x}, {:032x}){suffix}",
        second.0, first.0
    );
    assert_eq!(
        compared(permuted),
        expected,
        "an undirected pair has no order"
    );

    let other = chart
        .iter()
        .map(|(code, _)| account_vid(book.book_id, code))
        .find(|vid| !accounts.contains(vid))
        .unwrap();
    let mut wrong_member = run.clone();
    wrong_member.findings[0].narrative = wrong_member.findings[0]
        .narrative
        .replace(&format!("{:032x}", a.0), &format!("{:032x}", other.0));
    assert_ne!(
        compared(wrong_member),
        expected,
        "pair membership is retained"
    );

    for field in 0..9 {
        let mut changed = run.clone();
        let finding = &mut changed.findings[0];
        match field {
            0 => finding.statistic.value += 1,
            1 => finding.statistic.scale += 1,
            2 => finding.statistic.population += 1,
            3 => finding.severity = Severity::Info,
            4 => {
                finding.cites.pop();
            }
            5 => finding.version += 1,
            6 => finding.narrative.push_str(" changed"),
            7 => finding.statistic.name.push_str("_changed"),
            8 => finding.procedure.push_str("_changed"),
            _ => unreachable!(),
        }
        assert_ne!(
            compared(changed),
            expected,
            "semantic field {field} was lost"
        );
    }
}

/// Every registered procedure that builds from its default parameters, run
/// over `corpus` journaled into a book: its outcome by procedure id.
fn outcomes(
    corpus: &GeneratedCorpus,
    original_of: &BTreeMap<String, (String, String)>,
) -> BTreeMap<String, Result<Vec<String>, String>> {
    let (book, snapshot, posted_vids) = corpus_snapshot(corpus);
    let chart: Vec<(String, String)> = corpus
        .accounts
        .iter()
        .map(|a| (a.code.clone(), a.name.clone()))
        .collect();
    let mut outcomes = BTreeMap::new();
    for row in fa_lantern::catalog::registered().unwrap() {
        let Ok(procedure) = fa_lantern::catalog::build(
            &row.id,
            Params::defaults(&row.id).unwrap(),
            fa_lantern::catalog::Inputs::default(),
        ) else {
            continue;
        };
        let run = run_over(&snapshot, &book, procedure.as_ref());
        outcomes.insert(
            row.id.clone(),
            outcome(run, &book, &posted_vids, &chart, original_of),
        );
    }
    outcomes
}

/// Acceptance positive: renaming every account in the Ponzi and
/// shell-network corpora to neutral codes and names, with the roles carried
/// as the templates carry them, leaves every procedure's findings (and every
/// refusal) identical. Not vacuous: each corpus yields findings, including
/// from role-selected procedures.
#[test]
fn findings_invariant_under_account_renaming() {
    let role_selected: BTreeSet<&str> = fa_lantern::ROLE_POPULATIONS
        .iter()
        .map(|(procedure, _)| *procedure)
        .collect();
    for scenario in [ScenarioKind::Ponzi, ScenarioKind::ShellNetwork] {
        let corpus = generate(GenConfig::new(scenario, 7));
        let (neutral, original_of) = renamed(&corpus);
        assert!(neutral.accounts.iter().all(|a| a.code.starts_with("N-")));
        let named = outcomes(&corpus, &BTreeMap::new());
        let renamed = outcomes(&neutral, &original_of);
        assert_eq!(
            named.keys().collect::<Vec<_>>(),
            renamed.keys().collect::<Vec<_>>()
        );
        let changed: Vec<String> = named
            .iter()
            .filter(|(procedure, outcome)| *outcome != &renamed[*procedure])
            .map(|(procedure, outcome)| {
                format!(
                    "{procedure}:\n  named:   {outcome:?}\n  renamed: {:?}",
                    renamed[procedure]
                )
            })
            .collect();
        assert!(
            changed.is_empty(),
            "{scenario:?}: renaming the accounts changed {} outcome(s):\n{}",
            changed.len(),
            changed.join("\n")
        );
        let finding = |procedure: &&String| named[*procedure].as_ref().is_ok_and(|f| !f.is_empty());
        let reporting: Vec<&String> = named.keys().filter(finding).collect();
        assert!(
            reporting
                .iter()
                .any(|procedure| role_selected.contains(procedure.as_str())),
            "{scenario:?}: no role-selected procedure reported, so the comparison is vacuous; reporting: {reporting:?}"
        );
        println!(
            "{scenario:?}: {} procedures compared, {} reporting",
            named.len(),
            reporting.len()
        );
    }
}

/// Planted negative: in the Ponzi corpus, account 1000 is renamed "Cash" and
/// stripped of the cash role. It is outside every cash population while the
/// accounts holding the role are inside; and once no account holds the role,
/// a procedure requiring it refuses instead of falling back to the account
/// called "Cash".
#[test]
fn name_without_role_is_not_selected() {
    let mut corpus = generate(GenConfig::new(ScenarioKind::Ponzi, 7));
    let named_cash = corpus
        .accounts
        .iter_mut()
        .find(|a| a.code == "1000")
        .expect("the standard chart has 1000");
    named_cash.name = "Cash".to_string();
    named_cash.roles.clear();
    let (book, snapshot, _) = corpus_snapshot(&corpus);
    let cash_vid = account_vid(book.book_id, "1000");
    assert_eq!(snapshot.accounts[&cash_vid].name, "Cash");
    let holders: BTreeSet<VId> = corpus
        .accounts
        .iter()
        .filter(|a| a.roles.iter().any(|r| r == "cash"))
        .map(|a| account_vid(book.book_id, &a.code))
        .collect();
    assert!(!holders.is_empty());
    for (procedure, role) in fa_lantern::ROLE_POPULATIONS {
        if *role != "cash" {
            continue;
        }
        let cash = snapshot.role_accounts(procedure, "cash").unwrap();
        assert_eq!(cash, holders, "{procedure}");
        let population = snapshot.role_population(procedure).unwrap();
        assert!(!population.contains(&cash_vid), "{procedure}");
    }

    // No account holds the cash role; one is still called "Cash".
    for account in &mut corpus.accounts {
        account.roles.retain(|r| r != "cash");
    }
    let (book, snapshot, _) = corpus_snapshot(&corpus);
    for procedure in [
        "solvency.cash_flow_test",
        "lookback.preferences",
        "ponzi.net_investment",
        "distribution.rising_tide",
        "distribution.pro_rata",
    ] {
        let built = fa_lantern::catalog::build(
            procedure,
            Params::defaults(procedure).unwrap(),
            fa_lantern::catalog::Inputs::default(),
        )
        .unwrap();
        let refused = run_over(&snapshot, &book, built.as_ref()).unwrap_err();
        assert!(
            matches!(&refused, LanternError::RoleUnassigned { procedure: p, role } if p == procedure && role == "cash"),
            "{procedure}: {refused:?}"
        );
    }
}

/// Planted negative: with no account role journaled at all, every
/// role-selected procedure refuses, naming itself and the role, with the
/// exact `fa chart role` fix; none reports "nothing found".
#[test]
fn missing_role_refuses_with_fix() {
    let mut corpus = generate(GenConfig::new(ScenarioKind::Ponzi, 7));
    for account in &mut corpus.accounts {
        account.roles.clear();
    }
    let (book, snapshot, _) = corpus_snapshot(&corpus);
    let procedures: BTreeSet<&str> = fa_lantern::ROLE_POPULATIONS
        .iter()
        .map(|(procedure, _)| *procedure)
        .collect();
    for procedure in procedures {
        let built = fa_lantern::catalog::build(
            procedure,
            Params::defaults(procedure).unwrap(),
            fa_lantern::catalog::Inputs::default(),
        )
        .unwrap();
        let refused = run_over(&snapshot, &book, built.as_ref()).unwrap_err();
        let LanternError::RoleUnassigned { procedure: p, role } = &refused else {
            panic!("{procedure}: {refused:?}");
        };
        assert_eq!(p, procedure);
        assert!(
            fa_lantern::ROLE_POPULATIONS
                .iter()
                .any(|(id, r)| *id == procedure && role.split(" or ").any(|named| named == *r)),
            "{procedure}: refused for {role}, which it does not read"
        );
        assert_eq!(
            refused.fix_hint().unwrap(),
            format!(
                "fa chart role <account> {role} assigns the role to each account it describes (fa chart roles lists what is assigned)"
            )
        );
    }
}
