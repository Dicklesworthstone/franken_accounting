//! Branch-class property tests through the real binary
//! (docs/FORENSIC_CASE_STUDIES_PLAN.md §2.6 rule 5, §3.7 item 5; bead
//! fa-yugf.12, A5a): every seeded witness of a class, posted on a micro-book
//! and read by its rule's reader, gives the class's verdict.
//!
//! A class's witnesses co-reside on one micro-book and post as one batch:
//! the readers tested here (tier C `jet.round_amounts`, tier L
//! `jet.period_end_timing`) read each entry alone, so each witness is the
//! others' filler (§3.3). The verdict is predicted from the class, never
//! from a witness: a witness from outside its class disagrees and fails,
//! naming the rule, the class, the seed and the witness.

use fa_oracles::cases::amount::format_amount;
use fa_oracles::cases::branch::{Cell, CellPart, Witness, WitnessValue, witness_seed};
use fa_oracles::cases::date::Day;
use fa_oracles::cases::{CaseFiles, load};
use fa_oracles::json::Json;

use super::run::{BookRun, build_book, reproduce};

/// One class's outcome: a `PROPERTY` line, then a `FAIL property` line and
/// its `REPRODUCE` argv per witness that disagrees with the class.
pub struct ClassOutcome {
    pub lines: Vec<String>,
    pub witnesses: usize,
    pub agree: usize,
}

/// One witness entry of a micro-book: its day and its legs (account, side,
/// amount text).
struct Entry {
    day: Day,
    legs: Vec<(&'static str, &'static str, String)>,
}

const PRINCIPALS: [(&str, &str); 4] = [
    ("selftest-preparer-1", r#"["read", "post"]"#),
    ("case-closer-1", r#"["read", "close"]"#),
    ("case-second-reader", r#"["read", "approve"]"#),
    ("examiner-1", r#"["read", "produce"]"#),
];

/// The micro-case's files: one quarter (2026Q1), the fixture roles, one
/// synthetic fact and its reviewed placeholder, each witness an intent
/// `W-<n>` posted in one batch, then one run of `reader`.
fn micro_case(
    accounts: &[(&str, &str)],
    entries: &[Entry],
    reader: &str,
) -> Vec<(&'static str, String)> {
    let case = format!(
        "id = \"property\"\ntitle = \"Branch-class property micro-book\"\nversion = 1\nkind = \"harness_selftest\"\nscope = \"the witnesses of one branch class through its reader\"\nclaims = []\ncapabilities = [\"verb:batch\", \"procedure:{reader}\"]\npinned_commit = \"09ef3bcb4\"\nvariants = [\"native\"]\n"
    );
    let mut roles = String::new();
    for (label, _) in PRINCIPALS {
        roles.push_str(&format!(
            "[[role]]\nlabel = \"{label}\"\nkind = \"harness\"\ndescription = \"a property-test principal\"\n\n"
        ));
    }
    let facts = "[[fact]]\nid = \"PW\"\nprovenance = \"synthetic\"\nreason = \"a branch-class witness\"\ndiscipline = \"never cited by a case\"\n".to_string();
    let mut book = String::from(
        "[book]\nvariant = \"native\"\nopening_date = \"2026-01-01\"\ncalendar = \"custom\"\nbase_unit = \"USD\"\nposture = \"embedded-owner\"\n\n[[period]]\ncode = \"2026Q1\"\nstart = \"2026-01-01\"\nend = \"2026-03-31\"\nfiscal_year = 2026\nkind = \"Normal\"\n\n",
    );
    for (label, grants) in PRINCIPALS {
        book.push_str(&format!(
            "[[principal]]\nlabel = \"{label}\"\nprofile = \"Human\"\ngrants = {grants}\n\n"
        ));
    }
    for (code, kind) in accounts {
        book.push_str(&format!(
            "[[account]]\ncode = \"{code}\"\nname_fact = \"PW\"\ntype = \"{kind}\"\nrole = \"\"\nopened = \"2026-01-01\"\nrole_map_rule = \"role_map\"\n\n"
        ));
    }
    book.push_str("[[document]]\nid = \"DOC-PH-PW\"\nstub_of = \"placeholder:PW\"\ngrade = \"AgentUpload\"\nreviewed_by = \"case-second-reader\"\n\n");
    for (n, e) in entries.iter().enumerate() {
        book.push_str(&format!(
            "[[intent]]\nid = \"W-{n}\"\nfact = \"PW\"\nclass = \"Original\"\nprincipal = \"selftest-preparer-1\"\neffective_date = \"{}\"\nmemo = \"witness {n} (property test)\"\nevidence = \"DOC-PH-PW\"\nidempotency_key = \"property-W-{n}\"\n\n",
            e.day
        ));
        for (o, (account, side, amount)) in e.legs.iter().enumerate() {
            book.push_str(&format!(
                "[[leg]]\nintent = \"W-{n}\"\nordinal = {o}\naccount = \"{account}\"\nside = \"{side}\"\namount_literal = \"{amount}\"\namount_rule = \"synthetic\"\nunit = \"USD\"\n\n"
            ));
        }
    }
    let last = entries.len().saturating_sub(1);
    book.push_str(&format!(
        "[[step]]\nseq = 1\nkind = \"period_open\"\nref = \"2026Q1\"\nprincipal = \"case-closer-1\"\n\n[[step]]\nseq = 2\nkind = \"batch\"\nref = \"W-0..W-{last}\"\n\n[[step]]\nseq = 3\nkind = \"finding_record\"\nref = \"{reader}\"\nprincipal = \"examiner-1\"\n\n"
    ));
    book.push_str("[[default]]\nattribute = \"evidence_attached\"\nrule = \"placeholder_reviewed\"\nrationale = \"a placeholder reviewed by case-second-reader stands in (plan §2.6)\"\n");
    vec![
        ("case.toml", case),
        ("roles.toml", roles),
        ("facts.toml", facts),
        ("books/native.toml", book),
    ]
}

/// What `reader`'s run shows of entry `W-<n>`: `none`, or its findings'
/// severity, statistic and leg cites (`W-<n>#<ordinal>`, the native ordinal
/// being the fixture's: a batch posts each intent's legs in ordinal order).
fn observed(run: &BookRun<'_>, procedure: &str, n: usize) -> String {
    let intent = format!("W-{n}");
    let Some(found) = run.runs.get(procedure) else {
        return format!("no recorded run of {procedure}");
    };
    let Some(vid) = run.vids.get(&intent) else {
        return format!("{intent} not posted");
    };
    let mut parts: Vec<String> = found
        .findings
        .iter()
        .filter_map(|f| {
            let cites = f.get("cites").and_then(Json::as_array).unwrap_or(&[]);
            let is = |c: &Json, kind: &str| {
                c.get("kind").and_then(Json::as_str) == Some(kind)
                    && c.get("entry").and_then(Json::as_str) == Some(vid.as_str())
            };
            if !cites.iter().any(|c| is(c, "entry")) {
                return None;
            }
            let legs: Vec<String> = cites
                .iter()
                .filter(|c| is(c, "leg"))
                .filter_map(|c| c.get("ordinal").and_then(Json::as_int))
                .map(|o| format!("{intent}#{o}"))
                .collect();
            let stat = f
                .get("statistic")
                .and_then(|s| s.get("value"))
                .and_then(Json::as_int)
                .map_or_else(|| "-".into(), |v| v.to_string());
            Some(format!(
                "severity={} statistic={stat} legs=[{}]",
                f.get("severity").and_then(Json::as_str).unwrap_or("-"),
                legs.join(",")
            ))
        })
        .collect();
    parts.sort();
    if parts.is_empty() {
        "none".into()
    } else {
        parts.join("; ")
    }
}

/// Builds the class's micro-book, runs `procedure`, and compares each
/// witness's entry with `predict`.
fn run_class(
    rule: &str,
    cell: &Cell,
    seed: [u8; 32],
    procedure: &str,
    accounts: &[(&str, &str)],
    entries: &[Entry],
    predict: &dyn Fn(usize) -> String,
) -> ClassOutcome {
    let class = cell.key.join("/");
    let seed_hex: String = seed.iter().map(|b| format!("{b:02x}")).collect();
    let files = micro_case(accounts, entries, &format!("{procedure}@1"));
    let refs: Vec<(&str, &str)> = files.iter().map(|(p, t)| (*p, t.as_str())).collect();
    let mut lines = vec![];
    let case = match load(&CaseFiles {
        id: "property",
        files: &refs,
    }) {
        Ok(case) => case,
        Err(errs) => {
            lines.push(format!(
                "FAIL property {rule} class={class} seed={seed_hex} the micro-book does not load: {errs:?}"
            ));
            return ClassOutcome {
                lines,
                witnesses: entries.len(),
                agree: 0,
            };
        }
    };
    let run = build_book(&case, "native", &format!("{rule}:{class}"), &refs);
    if let Some(why) = &run.failure {
        lines.push(format!(
            "FAIL property {rule} class={class} seed={seed_hex} the micro-book did not build: {why}"
        ));
    }
    let mut agree = 0;
    for n in 0..entries.len() {
        let (want, got) = (predict(n), observed(&run, procedure, n));
        if want == got {
            agree += 1;
            continue;
        }
        lines.push(format!(
            "FAIL property {rule} class={class} seed={seed_hex} witness={n} expected {want} observed {got}"
        ));
        if let Some(c) = run.posts.get(&format!("W-{n}")) {
            lines.push(reproduce(c));
        }
    }
    lines.insert(
        0,
        format!(
            "PROPERTY {rule} class={class} seed={seed_hex} witnesses={} agree={agree}",
            entries.len()
        ),
    );
    ClassOutcome {
        lines,
        witnesses: entries.len(),
        agree,
    }
}

/// `round_residue_legs` through `jet.round_amounts`@1: each witness posts
/// the CIP debit (the sourced total) against its three credit amounts. A
/// leg is cited round iff it is a whole multiple of 10^3 units, so the
/// class predicts the cited legs (the debit, if the total is round, and each
/// `m` leg), the count and the severity (Medium when every leg is round).
/// `plant` replaces a witness's amounts before posting (the out-of-class
/// negative).
pub fn residue_class(
    case_id: &str,
    expectation_id: &str,
    cell: &Cell,
    witnesses: &[Witness],
    plant: Option<(usize, Vec<i128>)>,
) -> ClassOutcome {
    let Some(CellPart::Legs {
        letters,
        total,
        modulus,
        ..
    }) = cell.parts.first()
    else {
        return ClassOutcome {
            lines: vec![format!(
                "FAIL property round_residue_legs class={:?} is not a per-leg cell",
                cell.key
            )],
            witnesses: 0,
            agree: 0,
        };
    };
    let day = Day::parse("2026-02-10").expect("a fixture day");
    let usd = |minor: i128| format_amount(minor, 2);
    let entries: Vec<Entry> = witnesses
        .iter()
        .enumerate()
        .map(|(n, w)| {
            let mut credits: Vec<i128> = w
                .values
                .iter()
                .filter_map(|v| match v {
                    WitnessValue::Legs(legs) => {
                        Some(legs.iter().map(|(_, a)| *a).collect::<Vec<_>>())
                    }
                    _ => None,
                })
                .flatten()
                .collect();
            if let Some((at, amounts)) = &plant
                && *at == n
            {
                credits.clone_from(amounts);
            }
            let mut legs = vec![("1500", "Dr", usd(*total))];
            for (account, a) in ["6100", "6110", "6120"].into_iter().zip(&credits) {
                legs.push((account, "Cr", usd(*a)));
            }
            Entry { day, legs }
        })
        .collect();
    let debit_round = total % modulus == 0;
    let predict = |n: usize| {
        let mut round: Vec<String> = Vec::new();
        if debit_round {
            round.push(format!("W-{n}#0"));
        }
        for (i, c) in letters.chars().enumerate() {
            if c == 'm' {
                round.push(format!("W-{n}#{}", i + 1));
            }
        }
        if round.is_empty() {
            return "none".to_string();
        }
        let severity = if round.len() == letters.len() + 1 {
            "Medium"
        } else {
            "Low"
        };
        format!(
            "severity={severity} statistic={} legs=[{}]",
            round.len(),
            round.join(",")
        )
    };
    run_class(
        "round_residue_legs",
        cell,
        witness_seed(case_id, expectation_id, cell),
        "jet.round_amounts",
        &[
            ("1500", "Asset"),
            ("6100", "Expense"),
            ("6110", "Expense"),
            ("6120", "Expense"),
        ],
        &entries,
        &predict,
    )
}

/// `period_end_window` through `jet.period_end_timing`@1: each witness
/// posts one 100.00 entry on its day. Inside the window the entry is flagged
/// (severity Low, its days to the period's last day); outside it is not.
pub fn window_class(
    case_id: &str,
    expectation_id: &str,
    cell: &Cell,
    witnesses: &[Witness],
) -> ClassOutcome {
    let Some(CellPart::Window { inside, last, .. }) = cell.parts.first() else {
        return ClassOutcome {
            lines: vec![format!(
                "FAIL property period_end_window class={:?} is not a window cell",
                cell.key
            )],
            witnesses: 0,
            agree: 0,
        };
    };
    let days: Vec<Day> = witnesses
        .iter()
        .map(|w| match w.values.first() {
            Some(WitnessValue::Day(d)) => *d,
            _ => *last,
        })
        .collect();
    let entries: Vec<Entry> = days
        .iter()
        .map(|d| Entry {
            day: *d,
            legs: vec![
                ("6000", "Dr", "100.00".to_string()),
                ("1000", "Cr", "100.00".to_string()),
            ],
        })
        .collect();
    let predict = |n: usize| {
        if *inside {
            format!(
                "severity=Low statistic={} legs=[]",
                last.to_days() - days[n].to_days()
            )
        } else {
            "none".to_string()
        }
    };
    run_class(
        "period_end_window",
        cell,
        witness_seed(case_id, expectation_id, cell),
        "jet.period_end_timing",
        &[("1000", "Asset"), ("6000", "Expense")],
        &entries,
        &predict,
    )
}
