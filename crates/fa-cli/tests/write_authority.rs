//! The write-authority matrix (fa-mg2j, plan §14, doctrine 8 "authorization
//! precedes observation").
//!
//! Every command a launch-bound session (MCP, `fa --token`, fad tokens) can
//! name to write is a row stating, independently of the code, the
//! operations it requires, and the CLI's bound-route table must name
//! exactly those operations.
//!
//! A token-bound session never holds more than the Preparer launch ceiling
//! (read, post, post_softclosed, verify, reconcile, produce, partial_view):
//! a row needing any other operation (approve, witness, schema_change,
//! hold, erase, privileged, migrate, close, issue_capability) can never be
//! run by one, and a token with exactly its operations is refused when the
//! session is bound. Every other row is run in process over an in-memory
//! book with an issued holder-bound token, and must refuse with exit 7, the
//! named refusal, an unchanged book head and no host file written when the
//! token lacks any one of its operations (FA-REF-011), has expired
//! (FA-REF-014), was revoked (FA-REF-023) or was issued by another book
//! (FA-REF-156). With exactly its operations the command is admitted: rows
//! with complete inputs succeed, and the rest fail, if at all, for a reason
//! other than authority.
//!
//! Coverage: every subcommand of a verb the registry marks as writing is a
//! row, a read-only variant, or a named host-only command, so a new
//! writing command without a row fails here.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fa::{Book, BookKeys, Entropy};
use fa_cli::authority::{LaunchAuthority, LaunchProfile};
use fa_cli::cli::{Books, Captured, Files, Stdin, bound_command_ops, run, run_with_authority};
use fa_cli::json::{self, Json};
use fa_cli::verbs::registry;
use fa_journal::BookSpec;
use fa_model::{Id128, principal_vid};
use fa_money::UnitRegistry;
use fa_policy::{Capability, CapabilityToken, Op, Profile, possession_digest};
use fa_time::{DateDay, FiscalCalendar};
use fgdb_types::CommitSeq;

const ISSUER: &str = "matrix-issuer";
const HOLDER: &str = "matrix-holder";
const DAY: &str = "2026-03-14";
const ZERO_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// What a command with exactly its operations must do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Admitted {
    /// Its inputs are complete: it succeeds (exit 0).
    Succeeds,
    /// Its inputs are placeholders: it may fail, but never on authority.
    Reaches,
}

struct Row {
    argv: Vec<String>,
    ops: Vec<Op>,
    admitted: Admitted,
    /// A host file the command would create; it must not exist after any
    /// refusal.
    output: Option<&'static str>,
}

fn row(argv: &[&str], ops: &[Op], admitted: Admitted) -> Row {
    Row {
        argv: argv.iter().map(|a| (*a).to_string()).collect(),
        ops: ops.to_vec(),
        admitted,
        output: None,
    }
}

/// Commands that write but are never a launch-bound session's: the bound
/// route has no row for them, so it refuses them before the book.
const HOST_ONLY: &[(&str, Option<&str>, &str)] = &[
    ("book", Some("create"), "creates the book itself"),
    (
        "chart",
        Some("import"),
        "installs the chart (schema genesis)",
    ),
    ("period", Some("create"), "births fiscal periods"),
    (
        "period",
        Some("open"),
        "period transitions are host-confirmed",
    ),
    (
        "period",
        Some("soft-close"),
        "period transitions are host-confirmed",
    ),
    (
        "period",
        Some("close"),
        "period transitions are host-confirmed",
    ),
    (
        "period",
        Some("lock"),
        "period transitions are host-confirmed",
    ),
    (
        "period",
        Some("reopen"),
        "period transitions are host-confirmed",
    ),
    (
        "capability",
        Some("issue"),
        "issuance runs as the issuer on the host or with --issuer-token",
    ),
    (
        "party",
        Some("identifiers"),
        "a bank-detail change is host-only (plan §14.4)",
    ),
    (
        "bank",
        Some("unmatch"),
        "always dangerous: confirmed on the host",
    ),
    (
        "bank",
        Some("reconcile"),
        "always dangerous: a statement close is confirmed on the host",
    ),
    (
        "recover",
        Some("projections"),
        "needs schema_change on trunk and --yes, outside every launch ceiling",
    ),
    (
        "recover",
        Some("outcomes"),
        "rebuilds the idempotency namespace: schema_change on trunk and --yes after a dry-run preview, outside every launch ceiling",
    ),
    ("demo", Some("init"), "creates a sandbox book"),
];

fn fixture() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("fa-write-authority-{}-{id}", std::process::id()));
        let created = std::fs::create_dir(&path);
        if created
            .as_ref()
            .is_err_and(|error| error.kind() == std::io::ErrorKind::AlreadyExists)
        {
            continue;
        }
        created.expect("create the fixture directory");
        return path;
    }
}

fn spec(book_id: Id128, name: &str) -> BookSpec {
    let units = UnitRegistry::embedded().expect("units");
    BookSpec {
        book_id,
        name: name.into(),
        base_unit: units.lookup("USD").expect("USD"),
        calendar: FiscalCalendar::monthly("matrix", 1, 1).expect("calendar"),
        time_zone_policy: None,
        entities: Vec::new(),
        opening_date: None,
    }
}

fn argv(args: &[&str]) -> Vec<String> {
    args.iter().map(|a| (*a).to_string()).collect()
}

fn parse_line(out: &Captured) -> Json {
    let lines: Vec<&str> = out.stdout.lines().collect();
    assert_eq!(lines.len(), 1, "{out:?}");
    registry()
        .expect("verbs.toml")
        .check_line(lines[0])
        .map_err(|error| format!("{error}\n{out:?}"))
        .expect("the robot line matches its registered schema");
    json::parse(lines[0]).expect("robot JSON")
}

fn refusal_id(event: &Json) -> Option<&str> {
    event
        .get("data")
        .and_then(|data| data.get("refusal_id"))
        .and_then(Json::as_str)
}

/// The owner's embedded posture, for setup.
fn owner(book: &mut Book, dir: &Path, args: &[&str]) -> Json {
    let mut argv = argv(args);
    argv.push("--json".to_string());
    let (exit, out) = run(
        &argv,
        Books::Held {
            book,
            dir: dir.join("book"),
        },
        Files {
            cwd: Some(dir.to_path_buf()),
            stdin: Stdin::Missing,
        },
        true,
    );
    assert_eq!(exit, 0, "owner {args:?}: {out:?}");
    parse_line(&out)
}

struct Matrix {
    dir: PathBuf,
    book: Book,
    issuer: Capability,
    day: DateDay,
    seed: u8,
}

impl Matrix {
    fn issue(
        &mut self,
        ops: &[Op],
        expires_at: Option<CommitSeq>,
    ) -> (Capability, CapabilityToken) {
        self.seed = self.seed.checked_add(1).expect("fewer than 256 tokens");
        let secret = [self.seed; 32];
        let mut issued = Capability::new(
            principal_vid(HOLDER),
            Profile::Human,
            ops,
            self.issuer.holder(),
        )
        .expect("issued capability");
        if let Some(at) = expires_at {
            issued = issued.expiring_at(at);
        }
        let issued = issued.holder_bound(possession_digest(&secret));
        let key = format!("matrix-issue-{}", self.seed);
        self.book
            .issue_capability(
                self.issuer.clone(),
                issued.clone(),
                self.day,
                key.as_bytes(),
                "write-authority matrix",
            )
            .expect("kernel")
            .expect("issued");
        let token = CapabilityToken::new(HOLDER, issued.clone(), secret).expect("token");
        (issued, token)
    }

    fn authority(&self, token: &CapabilityToken) -> LaunchAuthority {
        LaunchAuthority::from_token(self.dir.join("book"), None, token)
            .expect("token authority")
            .with_files(Some(self.dir.clone()))
            .expect("files root")
    }

    fn bound(&mut self, authority: &LaunchAuthority, args: &[String]) -> (u8, Captured) {
        let mut argv = args.to_vec();
        argv.push("--json".to_string());
        run_with_authority(
            &argv,
            Books::Held {
                book: &mut self.book,
                dir: self.dir.join("book"),
            },
            Files {
                cwd: None,
                stdin: Stdin::Missing,
            },
            authority,
            true,
        )
    }

    /// Run `row` under `authority` and require the named refusal with an
    /// unchanged head and no host output.
    fn refused(&mut self, authority: &LaunchAuthority, row: &Row, want: &str, case: &str) {
        let before = self.book.head().expect("head");
        let (exit, out) = self.bound(authority, &row.argv);
        assert_eq!(exit, 7, "{case} {:?}: {out:?}", row.argv);
        let event = parse_line(&out);
        assert_eq!(event.get("event").and_then(Json::as_str), Some("error"));
        assert_eq!(
            refusal_id(&event),
            Some(want),
            "{case} {:?}: {out:?}",
            row.argv
        );
        assert_eq!(
            self.book.head().expect("head"),
            before,
            "{case} {:?} moved the book",
            row.argv
        );
        if let Some(file) = row.output {
            assert!(
                !self.dir.join(file).exists(),
                "{case} {:?} wrote {file}",
                row.argv
            );
        }
    }
}

/// The ops a token missing `op` from `ops` holds: the others, or an
/// unrelated op when `op` was the only one.
fn without(ops: &[Op], op: Op) -> Vec<Op> {
    let rest: Vec<Op> = ops.iter().copied().filter(|o| *o != op).collect();
    if !rest.is_empty() {
        return rest;
    }
    vec![if op == Op::Verify {
        Op::Read
    } else {
        Op::Verify
    }]
}

fn names(ops: &[Op]) -> BTreeSet<&'static str> {
    ops.iter().map(|op| op.name()).collect()
}

/// The bound-route table's ops for `argv`, as the CLI parses it.
fn table_ops(row_argv: &[String]) -> Option<BTreeSet<&'static str>> {
    let reg = registry().expect("verbs.toml");
    let verb = reg.verb(&row_argv[0]).expect("a registered verb");
    let flags: Vec<&str> = verb.flags.iter().map(String::as_str).collect();
    let switches: Vec<&str> = verb.switches.iter().map(String::as_str).collect();
    let args = fa_cli::args::parse(row_argv, &flags, &switches).expect("row argv parses");
    bound_command_ops(&row_argv[0], &args).map(names)
}

fn write_files(dir: &Path, files: &[(&str, &str)]) {
    for (name, text) in files {
        std::fs::write(dir.join(name), text).expect("fixture file");
    }
}

fn rows(document: &str, entry: &str) -> Vec<Row> {
    use Admitted::{Reaches, Succeeds};
    let mut rows = vec![
        row(
            &["post", "--intent", "post.json", "--evidence", document],
            &[Op::Post],
            Succeeds,
        ),
        row(&["commit", "--plan", "junk.plan"], &[Op::Post], Reaches),
        row(
            &["reverse", entry, "--reason", "WrongAccount"],
            &[Op::Post],
            Succeeds,
        ),
        row(
            &[
                "reclass",
                entry,
                "--from",
                "4000",
                "--to",
                "3000",
                "--amount",
                "1.00 USD",
                "--reason",
                "WrongAccount",
            ],
            &[Op::Post],
            Reaches,
        ),
        row(
            &["reserve", "--intent", "hold.json", "--evidence", document],
            &[Op::Post],
            Succeeds,
        ),
        row(&["resolve", "--intent", "junk.json"], &[Op::Post], Reaches),
        row(
            &[
                "invoice",
                "--party",
                "C-1",
                "--number",
                "INV-1",
                "--date",
                DAY,
                "--receivable",
                "1200",
                "--revenue",
                "4000",
                "--line",
                "qty=1 unit_price=\"1.00 USD\" item=X product=Y",
                "--evidence",
                document,
            ],
            &[Op::Post],
            Reaches,
        ),
        row(
            &[
                "bill",
                "--party",
                "V-1",
                "--number",
                "B-1",
                "--date",
                DAY,
                "--payable",
                "2000",
                "--line",
                "amount=\"1.00 USD\" account=6000 item=hosting",
                "--evidence",
                document,
            ],
            &[Op::Post],
            Reaches,
        ),
        row(
            &[
                "receipt",
                "--party",
                "C-1",
                "--number",
                "R-1",
                "--date",
                DAY,
                "--cash",
                "1000",
                "--receivable",
                "1200",
                "--amount",
                "1.00 USD",
                "--evidence",
                document,
            ],
            &[Op::Post],
            Reaches,
        ),
        row(
            &[
                "payment",
                "--party",
                "V-1",
                "--number",
                "P-1",
                "--date",
                DAY,
                "--cash",
                "1000",
                "--payable",
                "2000",
                "--amount",
                "1.00 USD",
                "--evidence",
                document,
            ],
            &[Op::Post],
            Reaches,
        ),
        row(
            &["allocate", "--intent", "junk.json"],
            &[Op::Read, Op::Post],
            Reaches,
        ),
        row(
            &["settle", "--intent", "junk.json"],
            &[Op::Read, Op::Post],
            Reaches,
        ),
        row(
            &["approve", "--proposal", ZERO_DIGEST],
            &[Op::Approve],
            Reaches,
        ),
        row(&["checkpoint", "create"], &[Op::Witness], Reaches),
        row(
            &[
                "case",
                "open",
                "--kind",
                "Restatement",
                "--periods",
                "FY2026-P03",
            ],
            &[Op::Read, Op::Restate],
            Reaches,
        ),
        row(
            &[
                "case",
                "determine",
                "1",
                "--on",
                DAY,
                "--authority",
                document,
            ],
            &[Op::Read, Op::Restate],
            Reaches,
        ),
        row(
            &["case", "rehearse", "1", "--certificate", "rehearsal.cert"],
            &[Op::Read, Op::Restate, Op::Produce],
            Reaches,
        ),
        row(
            &["case", "approve", "1", "--approval", ZERO_DIGEST],
            &[Op::Read, Op::Restate],
            Reaches,
        ),
        row(
            &["case", "post", "1"],
            &[Op::Read, Op::Restate, Op::Post],
            Reaches,
        ),
        row(
            &["case", "disclose", "1", "--document", ZERO_DIGEST],
            &[Op::Read, Op::Restate],
            Reaches,
        ),
        row(&["case", "close", "1"], &[Op::Read, Op::Restate], Reaches),
        row(
            &[
                "statement",
                "issue",
                "--certificate",
                ZERO_DIGEST,
                "--issued-to",
                "auditor",
                "--dry-run",
            ],
            &[Op::Read, Op::Close],
            Reaches,
        ),
        row(
            &["statement", "issue", "--plan", "junk.plan"],
            &[Op::Read, Op::Close],
            Reaches,
        ),
        row(
            &[
                "production",
                "open",
                "matrix-matter",
                "--bates-prefix",
                "MTX",
            ],
            &[Op::Produce],
            Succeeds,
        ),
        row(
            &[
                "produce",
                "--matter",
                "no-such-matter",
                "--document",
                document,
                "--out",
                "matrix-volume",
            ],
            &[Op::Read, Op::Produce],
            Reaches,
        ),
        row(
            &[
                "engagement",
                "open",
                "matrix-engagement",
                "--kind",
                "audit",
                "--period",
                "FY2026-P03",
                "--overall",
                "100.00 USD",
                "--performance",
                "50.00 USD",
                "--clearly-trivial",
                "5.00 USD",
            ],
            &[Op::Produce],
            Succeeds,
        ),
        row(
            &[
                "engagement",
                "file",
                "no-such-engagement",
                "--document",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ],
            &[Op::Produce],
            Reaches,
        ),
        row(
            &[
                "engagement",
                "complete",
                "no-such-engagement",
                "--completion-date",
                "2026-04-30",
                "--report-release",
                "2026-04-15",
            ],
            &[Op::Produce],
            Reaches,
        ),
        row(
            &[
                "engagement",
                "carry-forward",
                "no-such-engagement",
                "--from",
                "no-such-prior",
            ],
            &[Op::Produce],
            Reaches,
        ),
        row(
            &[
                "adjustment",
                "propose",
                "--engagement",
                "no-such-engagement",
                "--intent",
                "-",
            ],
            &[Op::Produce],
            Reaches,
        ),
        row(
            &[
                "adjustment",
                "book",
                "--engagement",
                "no-such-engagement",
                "--proposal",
                "1",
                "--entry",
                "E:00000000000000000000000000000000",
            ],
            &[Op::Read, Op::Produce],
            Reaches,
        ),
        row(
            &[
                "adjustment",
                "pass",
                "--engagement",
                "no-such-engagement",
                "--proposal",
                "1",
                "--reason",
                "Other",
            ],
            &[Op::Produce],
            Reaches,
        ),
        row(&["draft", "new", "matrix-draft"], &[Op::Post], Succeeds),
        row(
            &["draft", "plan", "matrix-draft", "--intent", "junk.json"],
            &[Op::Post],
            Reaches,
        ),
        row(&["draft", "discard", "no-such-draft"], &[Op::Post], Reaches),
        row(
            &["draft", "promote", "no-such-draft"],
            &[Op::Approve],
            Reaches,
        ),
        row(
            &["scenario", "fork", "matrix-scenario"],
            &[Op::Post],
            Reaches,
        ),
        row(
            &[
                "scenario",
                "run",
                "no-such-scenario",
                "--intent",
                "junk.json",
            ],
            &[Op::Post],
            Reaches,
        ),
        row(
            &["scenario", "discard", "no-such-scenario"],
            &[Op::Post],
            Reaches,
        ),
        row(
            &["document", "add", "receipt.txt", "--kind", "Receipt"],
            &[Op::Post],
            Succeeds,
        ),
        row(
            &["document", "redact", document],
            &[Op::Privileged],
            Reaches,
        ),
        row(
            &["document", "custody", document, "--to", "custodian"],
            &[Op::Post],
            Reaches,
        ),
        row(&["document", "erase", document], &[Op::Erase], Reaches),
        row(
            &[
                "document",
                "hold",
                "place",
                "--authority",
                document,
                "--subject",
                document,
            ],
            &[Op::Hold],
            Reaches,
        ),
        row(
            &["document", "attest", "review", document],
            &[Op::Approve],
            Reaches,
        ),
        row(
            &[
                "document",
                "attest",
                "confirmed",
                document,
                "--party",
                "no-such-party",
                "--balance",
                "1.00 USD",
                "--as-of",
                "2026-03-31",
            ],
            &[Op::Produce],
            Reaches,
        ),
        row(
            &[
                "document",
                "attest",
                "represented",
                document,
                "--claim",
                "all transactions are recorded",
                "--as-of",
                "2026-03-31",
            ],
            &[Op::Approve],
            Reaches,
        ),
        row(
            &["document", "attach", entry, "--evidence", document],
            &[Op::Read, Op::Post],
            Succeeds,
        ),
        row(
            &["document", "import", "run", "junk.json"],
            &[Op::Post],
            Reaches,
        ),
        row(
            &[
                "event",
                "record",
                "--code",
                "EV-1",
                "--kind",
                "sale",
                "--occurred-on",
                DAY,
                "--evidence",
                document,
            ],
            &[Op::Post],
            Reaches,
        ),
        row(
            &["migrate", "open", "--intent", "junk.json"],
            &[Op::Read, Op::Post, Op::Migrate],
            Reaches,
        ),
        row(
            &["migrate", "stage", "no-such-run", "--intent", "junk.json"],
            &[Op::Read, Op::Post, Op::Migrate],
            Reaches,
        ),
        row(
            &["migrate", "finalize", "no-such-run"],
            &[Op::Read, Op::Post, Op::Migrate],
            Reaches,
        ),
        row(
            &["migrate", "abandon", "no-such-run"],
            &[Op::Read, Op::Post, Op::Migrate],
            Reaches,
        ),
        row(
            &[
                "migrate",
                "import",
                "--action",
                "prepare",
                "--intent",
                "junk.json",
            ],
            &[Op::Read, Op::Post, Op::Migrate],
            Reaches,
        ),
        row(
            &["capability", "revoke", "--commitment", ZERO_DIGEST],
            &[Op::Read, Op::IssueCapability],
            Reaches,
        ),
        row(
            &["chart", "open", "account.json", "--opened", "2026-03-01"],
            &[Op::SchemaChange],
            Reaches,
        ),
        row(
            &["chart", "close", "6100", "--on", "2026-03-31"],
            &[Op::SchemaChange],
            Reaches,
        ),
        row(
            &["chart", "promote", "6100", "--on", "2026-03-31"],
            &[Op::SchemaChange],
            Reaches,
        ),
        row(
            &["party", "add", "party.json"],
            &[Op::SchemaChange],
            Reaches,
        ),
        row(
            &[
                "party",
                "relate",
                "V-17",
                "V-18",
                "--kind",
                "related",
                "--basis",
                "common_control",
                "--valid-from",
                "2026-01-01",
            ],
            &[Op::SchemaChange],
            Reaches,
        ),
        row(
            &["party", "bind", "V-17", "--external-id", "qbo:55"],
            &[Op::SchemaChange],
            Reaches,
        ),
        row(
            &["instrument", "add", "junk.json"],
            &[Op::SchemaChange],
            Reaches,
        ),
        row(
            &["entity", "add", "junk.json"],
            &[Op::SchemaChange],
            Reaches,
        ),
        row(
            &["finding", "record", "jet.round_amounts"],
            &[Op::Read, Op::Produce],
            Reaches,
        ),
        row(
            &[
                "finding",
                "review",
                "F:00000000000000000000000000000001",
                "--action",
                "acknowledge",
                "--note",
                "matrix",
            ],
            &[Op::Read, Op::Approve],
            Reaches,
        ),
        row(
            &[
                "bank",
                "import",
                "statement.csv",
                "--bank-format",
                "csv",
                "--account",
                "1000",
            ],
            &[Op::Read, Op::Post, Op::Reconcile],
            Reaches,
        ),
        row(
            &["bank", "match", "--import", ZERO_DIGEST],
            &[Op::Read, Op::Reconcile],
            Reaches,
        ),
        row(
            &[
                "bank",
                "confirm",
                "--import",
                ZERO_DIGEST,
                "--line-ordinal",
                "1",
                "--proposal-digest",
                ZERO_DIGEST,
                "--source-known-at",
                "1",
                "--proposer",
                "00000000000000000000000000000001",
            ],
            &[Op::Read, Op::Reconcile],
            Reaches,
        ),
        row(
            &["bank", "status", "--import", ZERO_DIGEST],
            &[Op::Read, Op::Reconcile],
            Reaches,
        ),
        row(
            &["bank", "history", "--account", "1000"],
            &[Op::Read, Op::Reconcile],
            Reaches,
        ),
        row(
            &["bank", "reconciliation", "--import", ZERO_DIGEST],
            &[Op::Read, Op::Reconcile],
            Reaches,
        ),
        row(
            &["fx", "rate", "add", "--from-json", "rate.json"],
            &[Op::Post],
            Reaches,
        ),
        row(
            &[
                "fx",
                "routes",
                "set",
                "--route",
                "1000:1010:4010",
                "--effective-from",
                "2026-01-01",
                "--key",
                "matrix-routes",
            ],
            &[Op::Read, Op::SchemaChange],
            Reaches,
        ),
        row(
            &[
                "fx",
                "revalue",
                "--period",
                "FY2026-P03",
                "--account",
                "1000",
                "--rate",
                "D:0000000000000000000000000000000000000000000000000000000000000000",
                "--key",
                "matrix-revalue",
                "--review-only",
            ],
            &[Op::Read, Op::Post],
            Reaches,
        ),
        row(
            &["registers", "materialize", "--period", "FY2026-P03"],
            &[Op::Read, Op::Verify],
            Succeeds,
        ),
        row(
            &["registers", "advance", "--period", "FY2026-P03"],
            &[Op::Read, Op::Verify],
            Succeeds,
        ),
        row(
            &[
                "close",
                "map",
                "--route",
                "4000:3000",
                "--effective-from",
                "2026-01-01",
                "--key",
                "matrix-map",
            ],
            &[Op::Read, Op::SchemaChange],
            Reaches,
        ),
        row(
            &[
                "close",
                "year-end",
                "--fiscal-year",
                "2026",
                "--period",
                "FY2026-CLOSE",
                "--key",
                "matrix-close",
                "--review-only",
            ],
            &[Op::Read, Op::Post, Op::Close],
            Reaches,
        ),
    ];
    let mut produce = row(
        &[
            "finding",
            "export",
            "--certificate",
            "C:00",
            "--out",
            "finding.md",
        ],
        &[Op::Read, Op::Produce],
        Reaches,
    );
    produce.output = Some("finding.md");
    rows.push(produce);
    let mut disclose = row(
        &["document", "disclose", document, "--out", "disclosure.bin"],
        &[Op::Read, Op::Produce],
        Reaches,
    );
    disclose.output = Some("disclosure.bin");
    rows.push(disclose);
    let mut proof = row(
        &["proof", "checkpoint", "--out", "matrix.checkpoint"],
        &[Op::Read, Op::Produce],
        Reaches,
    );
    proof.output = Some("matrix.checkpoint");
    rows.push(proof);
    let mut bundle = row(
        &[
            "bundle",
            "produce",
            "--out",
            "matrix.fab",
            "--receipt-out",
            "matrix.receipt",
        ],
        &[Op::Read, Op::Produce],
        Reaches,
    );
    bundle.output = Some("matrix.fab");
    rows.push(bundle);
    rows
}

/// The authority refusals; an admitted command never reports one.
const AUTHORITY: &[&str] = &["FA-REF-011", "FA-REF-014", "FA-REF-023", "FA-REF-156"];

#[test]
fn every_bound_writing_command_is_admitted_on_exactly_its_operations() {
    let dir = fixture();
    write_files(
        &dir,
        &[
            (
                "chart.json",
                r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"1200","name":"Receivables","type":"Asset","unit":"USD"},{"code":"2000","name":"Payables","type":"Liability","unit":"USD"},{"code":"3000","name":"Retained earnings","type":"Equity","unit":"USD"},{"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"},{"code":"6000","name":"Rent","type":"Expense","unit":"USD"}]}"#,
            ),
            ("invoice.txt", "Invoice 1: 100.00 USD for services."),
            ("receipt.txt", "Receipt 1: 1.00 USD received."),
            (
                "sale.json",
                r#"{"effective_date":"2026-03-14","idempotency_key":"matrix-sale","legs":[{"side":"debit","account":"1200","amount":"100.00 USD"},{"side":"credit","account":"4000","amount":"100.00 USD"}]}"#,
            ),
            (
                "post.json",
                r#"{"effective_date":"2026-03-14","idempotency_key":"matrix-post","legs":[{"side":"debit","account":"1000","amount":"5.00 USD"},{"side":"credit","account":"4000","amount":"5.00 USD"}]}"#,
            ),
            (
                "hold.json",
                r#"{"effective_date":"2026-03-14","idempotency_key":"matrix-hold","legs":[{"side":"debit","account":"6000","amount":"1.00 USD"},{"side":"credit","account":"1000","amount":"1.00 USD"}]}"#,
            ),
            (
                "account.json",
                r#"{"code":"6100","name":"Office supplies","type":"Expense","unit":"USD"}"#,
            ),
            (
                "party.json",
                r#"{"code":"V-17","kind":"Vendor","name":"Acme Supplies"}"#,
            ),
            ("junk.json", "{}"),
            ("junk.plan", "not a plan"),
            ("statement.csv", "date,amount,reference\n"),
        ],
    );
    let mut book = Book::create_memory(
        BookKeys::for_development(0x4d),
        spec(Id128([0x4d; 16]), "Write authority matrix"),
        Entropy::deterministic(0x4d),
    )
    .expect("book");
    owner(&mut book, &dir, &["chart", "import", "chart.json"]);
    owner(
        &mut book,
        &dir,
        &["period", "create", "--fiscal-year", "2026"],
    );
    owner(&mut book, &dir, &["period", "open", "FY2026-P03"]);
    let document = owner(
        &mut book,
        &dir,
        &[
            "document",
            "add",
            "invoice.txt",
            "--kind",
            "Invoice",
            "--grade",
            "HumanUpload",
        ],
    );
    let document = document
        .get("data")
        .and_then(|d| d.get("oid"))
        .and_then(Json::as_str)
        .expect("document oid")
        .to_string();
    let entry = owner(
        &mut book,
        &dir,
        &["post", "--intent", "sale.json", "--evidence", &document],
    );
    let entry = entry
        .get("data")
        .and_then(|d| d.get("vid"))
        .and_then(Json::as_str)
        .expect("entry vid")
        .to_string();

    let rows = rows(&document, &entry);
    let ceiling: BTreeSet<Op> = LaunchProfile::Preparer.ceiling().iter().copied().collect();
    let (bound_rows, host_rows): (Vec<&Row>, Vec<&Row>) = rows
        .iter()
        .partition(|r| r.ops.iter().all(|op| ceiling.contains(op)));
    let all: Vec<Op> = bound_rows
        .iter()
        .flat_map(|r| r.ops.iter().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let beyond: Vec<Op> = host_rows
        .iter()
        .flat_map(|r| r.ops.iter().copied())
        .filter(|op| !ceiling.contains(op))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut issuer_ops: Vec<&str> = all.iter().chain(&beyond).map(|op| op.name()).collect();
    issuer_ops.push(Op::IssueCapability.name());
    let issuer = Capability::embedded(principal_vid(ISSUER), &issuer_ops).expect("issuer");
    let mut m = Matrix {
        dir: dir.clone(),
        book,
        issuer,
        day: DateDay::parse(DAY).expect("day"),
        seed: 0,
    };

    // The bound-route table names exactly each row's operations.
    for row in &rows {
        assert_eq!(
            table_ops(&row.argv),
            Some(names(&row.ops)),
            "bound_command_ops disagrees with the matrix for {:?}",
            row.argv
        );
    }

    // Tokens: one that expires at the next commit, one revoked, one from
    // another book, then every missing-op and exact-op token.
    let head = m.book.head().expect("head");
    let (_, expired) = m.issue(&all, Some(CommitSeq(head.0 + 2)));
    let (revoked_cap, revoked) = m.issue(&all, None);
    m.book
        .revoke_capability(
            m.issuer.clone(),
            revoked_cap.commitment().expect("commitment"),
            m.day,
            b"matrix-revoke",
            "write-authority matrix",
        )
        .expect("kernel")
        .expect("revoked");
    let mut foreign_book = Book::create_memory(
        BookKeys::for_development(0x4e),
        spec(Id128([0x4e; 16]), "Another book"),
        Entropy::deterministic(0x4e),
    )
    .expect("another book");
    let schema = Capability::embedded(principal_vid(ISSUER), &["schema_change"]).expect("schema");
    foreign_book
        .create_periods(2026, schema.holder(), &schema)
        .expect("kernel")
        .expect("periods");
    let foreign_secret = [0xf0; 32];
    let foreign_cap = Capability::new(
        principal_vid(HOLDER),
        Profile::Human,
        &all,
        m.issuer.holder(),
    )
    .expect("foreign capability")
    .holder_bound(possession_digest(&foreign_secret));
    foreign_book
        .issue_capability(
            m.issuer.clone(),
            foreign_cap.clone(),
            m.day,
            b"matrix-foreign",
            "write-authority matrix",
        )
        .expect("kernel")
        .expect("issued in the other book");
    let foreign = CapabilityToken::new(HOLDER, foreign_cap, foreign_secret).expect("token");

    let mut by_ops: BTreeMap<BTreeSet<&'static str>, CapabilityToken> = BTreeMap::new();
    let mut tokens = |m: &mut Matrix, ops: &[Op]| -> LaunchAuthority {
        let key = names(ops);
        if !by_ops.contains_key(&key) {
            let (_, token) = m.issue(ops, None);
            by_ops.insert(key.clone(), token);
        }
        m.authority(&by_ops[&key])
    };
    assert!(
        m.book.head().expect("head").0 >= head.0 + 2,
        "the expiry has passed"
    );

    // No session binds a token beyond the ceiling, so these rows are the
    // operator's even though the table names their operations.
    for row in &host_rows {
        let (_, token) = m.issue(&row.ops, None);
        let refused = LaunchAuthority::from_token(dir.join("book"), None, &token)
            .expect_err("a token beyond the Preparer ceiling binds no session");
        assert!(
            refused.contains("beyond the preparer session ceiling"),
            "{:?}: {refused}",
            row.argv
        );
    }

    for row in &bound_rows {
        for op in &row.ops {
            let authority = tokens(&mut m, &without(&row.ops, *op));
            m.refused(
                &authority,
                row,
                "FA-REF-011",
                &format!("missing {}", op.name()),
            );
        }
        for (case, token, code) in [
            ("expired", &expired, "FA-REF-014"),
            ("revoked", &revoked, "FA-REF-023"),
            ("another book's", &foreign, "FA-REF-156"),
        ] {
            let authority = m.authority(token);
            m.refused(&authority, row, code, case);
        }

        let authority = tokens(&mut m, &row.ops);
        let (exit, out) = m.bound(&authority, &row.argv);
        match row.admitted {
            Admitted::Succeeds => {
                assert_eq!(exit, 0, "exact ops {:?}: {out:?}", row.argv);
                parse_line(&out);
            }
            Admitted::Reaches => {
                if exit != 0 {
                    let event = parse_line(&out);
                    assert!(
                        !refusal_id(&event).is_some_and(|code| AUTHORITY.contains(&code)),
                        "exact ops {:?} was refused on authority: {out:?}",
                        row.argv
                    );
                }
            }
        }
    }
}

/// Every subcommand of a verb the registry marks as writing is a matrix
/// row, a variant the bound route admits on read alone, or a named
/// host-only command; nothing that writes is unaccounted for.
#[test]
fn every_writing_command_is_in_the_matrix_or_named_host_only() {
    let reg = registry().expect("verbs.toml");
    let covered: BTreeSet<(String, Option<String>)> = rows("D", "E")
        .iter()
        .map(|r| {
            let sub = reg
                .verb(&r.argv[0])
                .filter(|v| !v.subcommands.is_empty())
                .map(|_| r.argv[1].clone());
            (r.argv[0].clone(), sub)
        })
        .collect();
    let host_only: BTreeSet<(String, Option<String>)> = HOST_ONLY
        .iter()
        .map(|(verb, sub, _)| ((*verb).to_string(), sub.map(str::to_string)))
        .collect();
    let read_only = names(&[Op::Read]);
    let mut missing = Vec::new();
    for verb in reg.verbs.iter().filter(|v| v.writes) {
        let subs: Vec<Option<String>> = if verb.subcommands.is_empty() {
            vec![None]
        } else {
            verb.subcommands.iter().cloned().map(Some).collect()
        };
        for sub in subs {
            let key = (verb.name.clone(), sub.clone());
            if covered.contains(&key) || host_only.contains(&key) {
                continue;
            }
            let mut base = vec![verb.name.clone()];
            base.extend(sub.clone());
            let args = fa_cli::args::parse(&base, &[], &[]).expect("bare argv parses");
            match bound_command_ops(&verb.name, &args).map(names) {
                Some(ops) if ops.is_subset(&read_only) => {}
                other => missing.push(format!("{key:?} -> {other:?}")),
            }
        }
    }
    assert!(
        missing.is_empty(),
        "writing commands with no matrix row and no host-only reason: {missing:#?}"
    );
    for (verb, sub, why) in HOST_ONLY {
        let mut base = vec![(*verb).to_string()];
        base.extend(sub.map(str::to_string));
        let args = fa_cli::args::parse(&base, &[], &[]).expect("bare argv parses");
        assert_eq!(
            bound_command_ops(verb, &args),
            None,
            "{verb} {sub:?} is named host-only ({why}) but the bound route admits it"
        );
    }
}
