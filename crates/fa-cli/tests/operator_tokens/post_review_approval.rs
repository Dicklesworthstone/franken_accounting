//! A scoped approver receives the complete sealed entry, not scope claimed
//! alongside an opaque digest. Exercise the actual client binary,
//! issued token files, native approval publication and eventual posting.

use super::*;
use std::io::Write;
use std::process::Stdio;

use fa::PostIntent;
use fa_model::{ApprovalRef, EntryClass};
use fgdb_types::VId;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct Review {
    event: Json,
    bytes: Vec<u8>,
    path: String,
}

struct Client {
    dir: PathBuf,
    evidence: String,
}

impl Client {
    fn new() -> Self {
        let mut client = Self {
            dir: directory(),
            evidence: String::new(),
        };
        client.ok(&["book", "create", "--name", "Payload approval CLI"], None);
        std::fs::write(
            client.dir.join("chart.json"),
            r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"}]}"#,
        )
        .unwrap();
        client.ok(&["chart", "import", "chart.json"], None);
        client.ok(&["period", "create", "--fiscal-year", "2026"], None);
        client.ok(&["period", "open", PERIOD], None);
        std::fs::write(
            client.dir.join("invoice.txt"),
            "Reviewed invoice for USD 1.00",
        )
        .unwrap();
        let evidence = client.ok(
            &[
                "document",
                "add",
                "invoice.txt",
                "--kind",
                "Invoice",
                "--grade",
                "HumanUpload",
            ],
            None,
        );
        client.evidence = text(&evidence, "oid").to_owned();
        client
    }

    fn run(&self, words: &[&str], input: Option<&[u8]>) -> (i32, Json) {
        let mut child = Command::new(env!("CARGO_BIN_EXE_fa"))
            .current_dir(&self.dir)
            .args(["--book", "book", "--via", "direct", "--json"])
            .args(words)
            .env_remove("FA_BOOK")
            .env_remove("FA_TOKEN")
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        if let Some(input) = input {
            child.stdin.take().unwrap().write_all(input).unwrap();
        }
        let output = child.wait_with_output().unwrap();
        let captured = Captured {
            stdout: String::from_utf8(output.stdout).unwrap(),
            stderr: String::from_utf8(output.stderr).unwrap(),
        };
        (output.status.code().unwrap_or(-1), event(&captured))
    }

    fn ok(&self, words: &[&str], input: Option<&[u8]>) -> Json {
        let (exit, event) = self.run(words, input);
        assert_eq!(exit, 0, "{words:?}: {}", event.render());
        event
    }

    fn book(&self) -> Book {
        let path = self.dir.join("book");
        Book::open_dir(
            &path,
            BookKeys::load(&path.join("book.keys")).unwrap(),
            Entropy::production(),
        )
        .unwrap()
    }

    fn head(&self) -> CommitSeq {
        self.book().head().unwrap()
    }

    fn refused(
        &self,
        words: &[&str],
        input: Option<&[u8]>,
        expected_exit: i32,
        message: &str,
    ) -> Json {
        let before = self.head();
        let (exit, refusal) = self.run(words, input);
        assert_eq!(exit, expected_exit, "{words:?}: {}", refusal.render());
        assert!(
            text(&refusal, "message").contains(message),
            "expected {message}: {}",
            refusal.render()
        );
        assert_eq!(self.head(), before, "a refused approval publishes nothing");
        refusal
    }

    fn issue(&self, holder: &str, class: &str, extra: &[&str]) -> String {
        let path = format!("{holder}.token");
        let mut words = vec![
            "capability",
            "issue",
            "--holder",
            holder,
            "--profile",
            "human",
            "--op",
            "read",
            "--op",
            "approve",
            "--class",
            class,
            "--out",
            path.as_str(),
            "--grant",
            "issue_capability",
            "--grant",
            "read",
            "--grant",
            "approve",
        ];
        words.extend_from_slice(extra);
        let issued = self.ok(&words, None);
        assert_eq!(text(&issued, "event"), "capability_issued");
        let token = CapabilityToken::decode(&std::fs::read(self.dir.join(&path)).unwrap()).unwrap();
        assert_eq!(token.capability().profile(), Profile::Human);
        assert_eq!(
            token.capability().classes(),
            Some(&std::collections::BTreeSet::from([EntryClass::from_name(
                class
            )
            .unwrap()]))
        );
        path
    }

    fn review(&self, class: &str, key: &str) -> Review {
        let input = format!("{key}.json");
        let path = format!("{key}.review");
        std::fs::write(
            self.dir.join(&input),
            format!(
                r#"{{"class":"{class}","effective_date":"2026-03-12","idempotency_key":"{key}","description":"Review this exact sealed proposal","legs":[{{"side":"debit","account":"1000","amount":"1.00 USD"}},{{"side":"credit","account":"4000","amount":"1.00 USD"}}]}}"#
            ),
        )
        .unwrap();
        let before = self.head();
        let event = self.ok(
            &[
                "post",
                "--intent",
                &input,
                "--evidence",
                &self.evidence,
                "--review-out",
                &path,
            ],
            None,
        );
        assert_eq!(text(&event, "event"), "post_reviewed");
        assert_eq!(self.head(), before);
        let bytes = std::fs::read(self.dir.join(&path)).unwrap();
        assert_eq!(hex(&bytes), text(&event, "bytes"));
        Review { event, bytes, path }
    }
}

#[test]
fn class_scoped_review_approval_completes_a_closed_period_post_through_the_binary() {
    let client = Client::new();
    let reviewer = client.issue("adjustment-reviewer", "Adjusting", &[]);
    let wrong_class = client.issue("original-reviewer", "Original", &[]);
    client.ok(
        &["period", "close", PERIOD, "--reason", "Scheduled", "--yes"],
        None,
    );
    let review = client.review("Adjusting", "closed-adjustment");
    let digest = text(&review.event, "review_digest");
    let proposal_digest = text(&review.event, "proposal_digest");
    let post = [
        "post",
        "--review",
        review.path.as_str(),
        "--digest",
        digest,
        "--grant",
        "post_closed",
        "--yes",
    ];
    let missing = client.refused(&post, None, 7, "approval");
    assert_eq!(text(&missing, "refusal_id"), "FA-REF-012");

    let denied = client.refused(
        &[
            "--token",
            &wrong_class,
            "approve",
            "--review",
            text(&review.event, "bytes"),
            "--digest",
            digest,
        ],
        None,
        7,
        "`classes`",
    );
    assert_eq!(text(&denied, "refusal_id"), "FA-REF-011");
    assert_eq!(
        field(&denied, "authority")
            .get("profile")
            .and_then(Json::as_str),
        Some("Human")
    );
    client.refused(
        &[
            "--token",
            &reviewer,
            "approve",
            "--proposal",
            proposal_digest,
        ],
        None,
        7,
        "`classes`",
    );

    // Raw binary stdin and complete inline hex identify the same original
    // sealed review. The returned approval binds its proposal, not its container.
    let before = client.head();
    let approved = client.ok(
        &[
            "--token", &reviewer, "approve", "--review", "-", "--digest", digest,
        ],
        Some(&review.bytes),
    );
    assert_eq!(text(&approved, "event"), "approved");
    assert_eq!(text(&approved, "approved_digest"), proposal_digest);
    assert_ne!(text(&approved, "approved_digest"), digest);
    assert_eq!(field(&approved, "already_recorded"), &Json::Bool(false));
    assert!(client.head() > before);
    let approved_at = client.head();
    let retry = client.ok(
        &[
            "--token",
            &reviewer,
            "approve",
            "--review",
            text(&review.event, "bytes"),
            "--digest",
            digest,
        ],
        None,
    );
    assert_eq!(
        text(&retry, "approval_vid"),
        text(&approved, "approval_vid")
    );
    assert_eq!(field(&retry, "already_recorded"), &Json::Bool(true));
    assert_eq!(client.head(), approved_at);

    let mut post = post.to_vec();
    post.extend(["--approval", text(&approved, "approval_vid")]);
    let posted = client.ok(&post, None);
    assert_eq!(text(&posted, "event"), "posted");
    let vid = VId(u128::from_str_radix(text(&posted, "vid"), 16).unwrap());
    let (entry, _) = client.book().read_entry(vid).unwrap().unwrap();
    assert_eq!(
        entry.proposal,
        *PostIntent::decode(&review.bytes).unwrap().proposal()
    );
    assert_eq!(entry.approvals.len(), 1);
    assert_eq!(
        format!("{:032x}", entry.approvals[0].approval_vid.0),
        text(&approved, "approval_vid")
    );
}

#[test]
fn entry_review_approval_refuses_substitution_and_preserves_other_scope_boundaries() {
    let client = Client::new();
    let reviewer = client.issue("original-reviewer", "Original", &[]);
    let review = client.review("Original", "unchanged-review");
    let original = PostIntent::decode(&review.bytes).unwrap();
    let digest = text(&review.event, "review_digest");
    let request = [
        "--token",
        reviewer.as_str(),
        "approve",
        "--review",
        "-",
        "--digest",
        digest,
    ];

    client.refused(
        &[
            "--token",
            &reviewer,
            "approve",
            "--review",
            text(&review.event, "bytes"),
            "--digest",
            text(&review.event, "proposal_digest"),
        ],
        None,
        2,
        "digest does not match",
    );
    let mut changed = original.proposal().clone();
    changed.idempotency_key = b"substituted-proposal".to_vec();
    let changed = PostIntent::new(changed, Vec::new()).unwrap();
    client.refused(
        &request,
        Some(&changed.canonical_bytes().unwrap()),
        2,
        "digest does not match",
    );

    for bytes in [
        review.bytes[..10].to_vec(),
        {
            let mut bytes = review.bytes.clone();
            bytes[10] ^= 0x80;
            bytes
        },
        {
            let mut bytes = review.bytes.clone();
            bytes.push(0);
            bytes
        },
    ] {
        client.refused(&request, Some(&bytes), 2, "invalid entry approval review");
    }

    let approved_review = PostIntent::new(
        original.proposal().clone(),
        vec![ApprovalRef {
            approval_vid: VId(99),
            approved_digest: original.proposal().proposal_digest().unwrap(),
        }],
    )
    .unwrap();
    client.refused(
        &[
            "--token",
            &reviewer,
            "approve",
            "--review",
            "-",
            "--digest",
            &hex(&approved_review.digest().unwrap()),
        ],
        Some(&approved_review.canonical_bytes().unwrap()),
        2,
        "must contain no prior approvals",
    );
    let mut foreign = original.proposal().clone();
    foreign.book_id.0[0] ^= 0x80;
    let foreign = PostIntent::new(foreign, Vec::new()).unwrap();
    let denied = client.refused(
        &[
            "--token",
            &reviewer,
            "approve",
            "--review",
            "-",
            "--digest",
            &hex(&foreign.digest().unwrap()),
        ],
        Some(&foreign.canonical_bytes().unwrap()),
        2,
        "this book's trunk target",
    );
    assert_eq!(
        text(&denied, "refusal_id"),
        fa_journal::refusal::code::COORDINATE
    );

    client.refused(
        &[
            "--token",
            &reviewer,
            "approve",
            "--review",
            &review.path,
            "--digest",
            digest,
        ],
        None,
        2,
        "host filesystem path",
    );
    for (holder, extra, caveat) in [
        (
            "period-reviewer",
            vec!["--period", "FY2026-P02"],
            "`periods`",
        ),
        (
            "rehearsal-reviewer",
            vec!["--requires-dry-run"],
            "`requires_dry_run`",
        ),
    ] {
        let scoped = client.issue(holder, "Original", &extra);
        let denied = client.refused(
            &[
                "--token",
                &scoped,
                "approve",
                "--review",
                text(&review.event, "bytes"),
                "--digest",
                digest,
            ],
            None,
            7,
            caveat,
        );
        assert_eq!(text(&denied, "refusal_id"), "FA-REF-011");
    }
    // Enabling the typed review route does not make other review containers
    // class-aware or skip their existing whole-book boundary.
    let denied = client.refused(&request, Some(b"FA-ALLOC-REVIEW\0invalid"), 7, "`classes`");
    assert_eq!(text(&denied, "refusal_id"), "FA-REF-011");
    client.ok(&request, Some(text(&review.event, "bytes").as_bytes()));
}

#[test]
fn a_departmental_reviewer_signs_only_complete_in_scope_adjustments() {
    let client = Client::new();
    client.ok(
        &["principal", "key", "new", "--out", "department.key"],
        None,
    );
    client.ok(
        &[
            "principal",
            "key",
            "add",
            "--as",
            "department-reviewer",
            "--sign-key",
            "department.key",
        ],
        None,
    );
    let reviewer = client.issue(
        "department-reviewer",
        "Adjusting",
        &[
            "--account",
            "1000",
            "--account",
            "4000",
            "--period",
            PERIOD,
            "--effective-through",
            "2026-03-12",
            "--ceiling",
            "1.00 USD",
        ],
    );
    let restricted = [
        (
            client.issue("cash-only", "Adjusting", &["--account", "1000"]),
            "`accounts`",
        ),
        (
            client.issue("february-only", "Adjusting", &["--period", "FY2026-P02"]),
            "`periods`",
        ),
        (
            client.issue(
                "earlier-only",
                "Adjusting",
                &["--effective-through", "2026-03-11"],
            ),
            "`effective`",
        ),
        (
            client.issue("smaller-only", "Adjusting", &["--ceiling", "0.99 USD"]),
            "ceiling",
        ),
    ];
    client.ok(
        &["period", "close", PERIOD, "--reason", "Scheduled", "--yes"],
        None,
    );
    let review = client.review("Adjusting", "department-adjustment");
    let digest = text(&review.event, "review_digest");
    for (token, caveat) in &restricted {
        // Full scope admission precedes the host's signing-key file read.
        // The in-scope debit alone must not authorize the hidden credit.
        client.refused(
            &[
                "--token",
                token,
                "approve",
                "--review",
                text(&review.event, "bytes"),
                "--digest",
                digest,
                "--sign-key",
                "must-not-read.key",
            ],
            None,
            7,
            caveat,
        );
    }
    client.refused(
        &[
            "--token",
            &reviewer,
            "approve",
            "--proposal",
            text(&review.event, "proposal_digest"),
        ],
        None,
        7,
        "`classes`",
    );
    let unsigned = client.refused(
        &[
            "--token",
            &reviewer,
            "approve",
            "--review",
            text(&review.event, "bytes"),
            "--digest",
            digest,
        ],
        None,
        7,
        "must be signed",
    );
    assert_eq!(text(&unsigned, "refusal_id"), "FA-REF-205");
    let approved = client.ok(
        &[
            "--token",
            &reviewer,
            "approve",
            "--review",
            "-",
            "--digest",
            digest,
            "--sign-key",
            "department.key",
        ],
        Some(&review.bytes),
    );
    assert_eq!(text(&approved, "event"), "approved");
    assert_eq!(
        text(&approved, "approved_digest"),
        text(&review.event, "proposal_digest")
    );
    let approved_at = client.head();
    let retry = client.ok(
        &[
            "--token",
            &reviewer,
            "approve",
            "--review",
            text(&review.event, "bytes"),
            "--digest",
            digest,
            "--sign-key",
            "department.key",
        ],
        None,
    );
    assert_eq!(
        text(&retry, "approval_vid"),
        text(&approved, "approval_vid")
    );
    assert_eq!(field(&retry, "already_recorded"), &Json::Bool(true));
    assert_eq!(client.head(), approved_at);
    let posted = client.ok(
        &[
            "post",
            "--review",
            &review.path,
            "--digest",
            digest,
            "--approval",
            text(&approved, "approval_vid"),
            "--grant",
            "post_closed",
            "--yes",
        ],
        None,
    );
    assert_eq!(text(&posted, "event"), "posted");
    let vid = VId(u128::from_str_radix(text(&posted, "vid"), 16).unwrap());
    let (entry, _) = client.book().read_entry(vid).unwrap().unwrap();
    assert_eq!(
        entry.proposal,
        *PostIntent::decode(&review.bytes).unwrap().proposal()
    );
    assert_eq!(entry.approvals.len(), 1);
    assert_eq!(
        format!("{:032x}", entry.approvals[0].approval_vid.0),
        text(&approved, "approval_vid")
    );
}

#[test]
fn a_class_scoped_review_approval_requires_the_registered_signing_key_in_the_binary() {
    let client = Client::new();
    let reviewer = client.issue("signed-reviewer", "Original", &[]);
    for path in ["reviewer.key", "unrelated.key"] {
        client.ok(&["principal", "key", "new", "--out", path], None);
    }
    client.ok(
        &[
            "principal",
            "key",
            "add",
            "--as",
            "signed-reviewer",
            "--sign-key",
            "reviewer.key",
        ],
        None,
    );
    let review = client.review("Original", "signed-entry");
    let request = [
        "--token",
        reviewer.as_str(),
        "approve",
        "--review",
        text(&review.event, "bytes"),
        "--digest",
        text(&review.event, "review_digest"),
    ];
    let unsigned = client.refused(&request, None, 7, "must be signed");
    assert_eq!(text(&unsigned, "refusal_id"), "FA-REF-205");
    let mut request = request.to_vec();
    request.extend(["--sign-key", "unrelated.key"]);
    let wrong_key = client.refused(&request, None, 7, "signature");
    assert_eq!(text(&wrong_key, "refusal_id"), "FA-REF-205");
    *request.last_mut().unwrap() = "reviewer.key";
    let approved = client.ok(&request, None);
    assert_eq!(
        text(&approved, "approved_digest"),
        text(&review.event, "proposal_digest")
    );
    let before = client.head();
    let retry = client.ok(&request, None);
    assert_eq!(
        text(&retry, "approval_vid"),
        text(&approved, "approval_vid")
    );
    assert_eq!(field(&retry, "already_recorded"), &Json::Bool(true));
    assert_eq!(client.head(), before);
    let posted = client.ok(
        &[
            "post",
            "--review",
            &review.path,
            "--digest",
            text(&review.event, "review_digest"),
            "--approval",
            text(&approved, "approval_vid"),
        ],
        None,
    );
    assert_eq!(text(&posted, "event"), "posted");
}

#[test]
fn entry_review_approval_uses_a_configured_book_signing_key_without_an_explicit_flag() {
    let mut f = Fixture::new(0xf1);
    std::fs::write(
        f.dir.join("chart.json"),
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"}]}"#,
    )
    .unwrap();
    f.owner(&["chart", "import", "chart.json"]);
    std::fs::write(f.dir.join("intent.json"), r#"{"effective_date":"2026-03-12","idempotency_key":"configured-signing","legs":[{"side":"debit","account":"1000","amount":"1.00 USD"},{"side":"credit","account":"4000","amount":"1.00 USD"}]}"#).unwrap();
    let review = f.owner(&["post", "--intent", "intent.json", "--review-only"]);
    let base = token("configured-reviewer", &[Op::Read, Op::Approve], 0xf2);
    let token = CapabilityToken::new(
        base.principal(),
        base.capability()
            .clone()
            .for_classes(&[EntryClass::ORIGINAL])
            .unwrap(),
        [0xf2; 32],
    )
    .unwrap();
    let authority = f.issue(&token);
    let key = fa::SigningKey::from_seed(&[0xf3; 32]);
    f.book
        .register_principal_key(
            Capability::embedded(token.capability().holder(), &["approve"]).unwrap(),
            &key,
            None,
            DateDay::parse("2026-03-12").unwrap(),
            b"configured-reviewer-key",
            "Registered key for held-book review approval",
        )
        .unwrap()
        .unwrap();
    let words = [
        "approve",
        "--review",
        text(&review, "bytes"),
        "--digest",
        text(&review, "review_digest"),
    ];
    f.refused(&authority, &words, "FA-REF-205");
    f.book.sign_with_principal_key(key);
    let approved = f.ok(&authority, &words, None);
    assert_eq!(
        text(&approved, "approved_digest"),
        text(&review, "proposal_digest")
    );
    assert_eq!(field(&approved, "already_recorded"), &Json::Bool(false));
    let before = f.book.head().unwrap();
    let retry = f.ok(&authority, &words, None);
    assert_eq!(
        text(&retry, "approval_vid"),
        text(&approved, "approval_vid")
    );
    assert_eq!(field(&retry, "already_recorded"), &Json::Bool(true));
    assert_eq!(f.book.head().unwrap(), before);
}
