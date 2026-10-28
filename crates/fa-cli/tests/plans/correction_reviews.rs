//! Complete correction proposals survive approval publications without resealing.

use super::correction_drafts::{agent, bound, corrected, original};
use super::*;
use fa::{PostIntent, ReplacementReview};

fn unhex(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2));
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn member(review: &Json, index: usize) -> &Json {
    &get(review, "members").as_arr().unwrap()[index]
}

fn retained(f: &Fixture, target: &str, verb: &str) -> Json {
    let input = write(
        &f.dir,
        "replacement.json",
        &corrected("replacement", "12.00"),
    );
    let before = head(&f.book);
    let output = f.dir.join("prepared-correction.review");
    let mut args = vec![
        verb,
        target,
        "--reason",
        "WrongAmount",
        if verb == "replace" {
            "--intent"
        } else {
            "--replace-with"
        },
        &input,
        "--evidence",
        &f.evidence,
        "--grant",
        "post_closed",
    ];
    if verb == "reverse" {
        args.extend(["--review-out", output.to_str().unwrap()]);
    } else {
        args.push("--review-only");
    }
    let review = ok(&f.book, &args);
    assert_eq!(text(&review, "event"), "replacement_reviewed");
    assert_eq!(head(&f.book), before, "unapproved review cannot publish");
    if verb == "reverse" {
        assert_eq!(
            std::fs::read(output).unwrap(),
            unhex(text(&review, "bytes")),
            "the private review file preserves the exact emitted pair"
        );
    }
    review
}

fn approve(f: &Fixture, proposal: &str, who: &str) -> String {
    text(
        &ok(&f.book, &["approve", "--proposal", proposal, "--as", who]),
        "approval_vid",
    )
    .to_owned()
}

fn assert_absent(f: &Fixture, target: &str) {
    let target = fgdb_types::VId(u128::from_str_radix(target, 16).unwrap());
    for vid in [
        fa_journal::rows::reversal_vid(target),
        fa_journal::rows::replacement_vid(target),
    ] {
        assert_eq!(
            get(
                &ok(&f.book, &["entry", "show", &format!("{:032x}", vid.0)]),
                "found"
            ),
            &Json::Bool(false),
        );
    }
}

fn assert_review_receipt(f: &Fixture, authority: &LaunchAuthority, before: i128, review: &Json) {
    assert_eq!(
        head(&f.book),
        before + 1,
        "bound review delivery publishes exactly its required access receipt"
    );
    let log = ok(&f.book, &["access", "log", "--since", &before.to_string()]);
    assert_eq!(integer(&log, "count"), 1);
    let receipts = get(&log, "events").as_arr().unwrap();
    assert_eq!(receipts.len(), 1);
    let receipt = &receipts[0];
    assert_eq!(text(receipt, "command"), "replace");
    assert_eq!(text(receipt, "principal_name"), authority.principal());
    assert_eq!(
        text(receipt, "principal"),
        format!("{:032x}", authority.principal_vid().0)
    );
    assert_eq!(
        text(receipt, "capability"),
        hex(&authority.capability().commitment().unwrap())
    );
    assert_eq!(integer(receipt, "observed_at"), before);
    assert_eq!(integer(receipt, "recorded_at"), before + 1);
    assert_eq!(integer(get(review, "coordinate"), "known_at"), before + 1);
    assert_absent(f, text(review, "target"));
}

#[test]
fn retained_correction_review_completes_closed_pair_after_independent_approvals() {
    for verb in ["replace", "reverse"] {
        let f = Fixture::new();
        let posted = original(&f);
        let target = text(&posted, "vid");
        ok(
            &f.book,
            &[
                "period",
                "close",
                "FY2026-P03",
                "--reason",
                "AuditComplete",
                "--yes",
            ],
        );
        let review = retained(&f, target, verb);
        let raw = unhex(text(&review, "bytes"));
        let decoded = ReplacementReview::decode(&raw).unwrap();
        assert_eq!(
            decoded.digest().unwrap(),
            unhex(text(&review, "review_digest")).as_slice()
        );
        assert_eq!(
            decoded.target().entry_digest,
            unhex(text(&posted, "entry_digest")).as_slice()
        );

        let before = head(&f.book);
        let missing = run(
            &f.book,
            &[
                verb,
                "--review",
                text(&review, "bytes"),
                "--digest",
                text(&review, "review_digest"),
                "--grant",
                "post_closed",
                "--dry-run",
            ],
            None,
        );
        assert_eq!(missing.0, 7, "{}", missing.1.render());
        assert_eq!(text(&missing.1, "refusal_id"), "FA-REF-012");
        assert_eq!(head(&f.book), before);
        assert_absent(&f, target);

        let reversal_approval = approve(
            &f,
            text(member(&review, 0), "proposal_digest"),
            "reversal-reviewer",
        );
        let replacement_approval = approve(
            &f,
            text(member(&review, 1), "proposal_digest"),
            "replacement-reviewer",
        );
        let self_approval = approve(&f, text(member(&review, 1), "proposal_digest"), "operator");
        let container_approval = approve(&f, text(&review, "review_digest"), "container-reviewer");
        let before = head(&f.book);
        for (approval, reversal, expected) in [
            (
                self_approval.as_str(),
                reversal_approval.as_str(),
                "FA-REF-008",
            ),
            (
                container_approval.as_str(),
                reversal_approval.as_str(),
                "FA-REF-016",
            ),
            (
                replacement_approval.as_str(),
                replacement_approval.as_str(),
                "FA-REF-016",
            ),
        ] {
            let (exit, error) = run(
                &f.book,
                &[
                    verb,
                    "--review",
                    text(&review, "bytes"),
                    "--digest",
                    text(&review, "review_digest"),
                    "--approval",
                    approval,
                    "--reversal-approval",
                    reversal,
                    "--grant",
                    "post_closed",
                    "--dry-run",
                ],
                None,
            );
            assert_eq!(exit, 7, "{}", error.render());
            assert_eq!(text(&error, "refusal_id"), expected, "{}", error.render());
            assert_eq!(head(&f.book), before);
            assert_absent(&f, target);
        }

        // A binary file and forwarded hex both restore exactly the same seals.
        let file = f.dir.join("approved-correction.review");
        std::fs::write(&file, &raw).unwrap();
        let file_arg = file.display().to_string();
        let (posted, retry) = if verb == "replace" {
            let command = [
                verb,
                "--review",
                file_arg.as_str(),
                "--digest",
                text(&review, "review_digest"),
                "--approval",
                replacement_approval.as_str(),
                "--reversal-approval",
                reversal_approval.as_str(),
                "--grant",
                "post_closed",
                "--yes",
            ];
            let posted = ok(&f.book, &command);
            let retry = ok(&f.book, &command);
            (posted, retry)
        } else {
            let (exit, plan) = run(
                &f.book,
                &[
                    verb,
                    "--review",
                    "-",
                    "--digest",
                    text(&review, "review_digest"),
                    "--approval",
                    &replacement_approval,
                    "--reversal-approval",
                    &reversal_approval,
                    "--grant",
                    "post_closed",
                    "--dry-run",
                ],
                Some(text(&review, "bytes").as_bytes()),
            );
            assert_eq!(exit, 0, "{}", plan.render());
            assert_eq!(text(&plan, "event"), "replacement_plan");
            assert_eq!(head(&f.book), before, "native rehearsal still aborts");
            let (exit, posted) = run(
                &f.book,
                &["commit", "--plan", "-", "--grant", "post_closed"],
                Some(text(&plan, "bytes").as_bytes()),
            );
            assert_eq!(exit, 0, "{}", posted.render());
            let (exit, retry) = run(
                &f.book,
                &["commit", "--plan", "-", "--grant", "post_closed"],
                Some(text(&plan, "bytes").as_bytes()),
            );
            assert_eq!(exit, 0, "{}", retry.render());
            (posted, retry)
        };
        assert_eq!(
            head(&f.book),
            before + 1,
            "both entries have one publication"
        );
        assert_eq!(get(&retry, "already_recorded"), &Json::Bool(true));
        for (index, field) in ["reversal", "replacement"].into_iter().enumerate() {
            let stored = ok(&f.book, &["entry", "show", text(&posted, field)]);
            assert_eq!(
                text(&stored, "proposal_digest"),
                text(member(&review, index), "proposal_digest")
            );
            assert_eq!(
                integer(&stored, "recorded_at"),
                integer(&posted, "recorded_at")
            );
        }
    }
}

#[test]
fn correction_review_codec_pins_both_seals_and_member_specific_approvals() {
    let f = Fixture::new();
    let posted = original(&f);
    let review = retained(&f, text(&posted, "vid"), "replace");
    let bytes = unhex(text(&review, "bytes"));
    let review = ReplacementReview::decode(&bytes).unwrap();
    let digest = review.digest().unwrap();

    // Independent framing pins the additive v1 wire order, beyond a codec roundtrip.
    let mut expected = b"FA-REPLACE-REVIEW\0".to_vec();
    expected.extend_from_slice(&[1, 0, 0, 0]);
    for member in [review.reversal(), review.replacement()] {
        let body = member.canonical_bytes().unwrap();
        expected.extend_from_slice(&u32::try_from(body.len()).unwrap().to_le_bytes());
        expected.extend_from_slice(&body);
    }
    assert_eq!(bytes, expected);
    assert_eq!(review.canonical_bytes().unwrap(), bytes);
    for end in [0, 17, 18, 20, 22, 26, bytes.len() / 2, bytes.len() - 1] {
        assert!(
            ReplacementReview::decode(&bytes[..end]).is_err(),
            "prefix {end}"
        );
    }
    for offset in [0, 18, 20] {
        let mut bad = bytes.clone();
        bad[offset] = 255;
        assert!(ReplacementReview::decode(&bad).is_err(), "offset {offset}");
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(ReplacementReview::decode(&trailing).is_err());

    let rev_approval = fa_model::ApprovalRef {
        approval_vid: fgdb_types::VId(7),
        approved_digest: review.reversal().proposal().proposal_digest().unwrap(),
    };
    let rep_approval = fa_model::ApprovalRef {
        approval_vid: fgdb_types::VId(8),
        approved_digest: review.replacement().proposal().proposal_digest().unwrap(),
    };
    let (rev, rep) = review
        .with_approvals(digest, vec![rev_approval], vec![rep_approval])
        .unwrap();
    assert_eq!(rev.proposal(), review.reversal().proposal());
    assert_eq!(rep.proposal(), review.replacement().proposal());
    assert_eq!(rev.approvals(), &[rev_approval]);
    assert_eq!(rep.approvals(), &[rep_approval]);
    assert!(
        review
            .with_approvals([0; 32], Vec::new(), Vec::new())
            .is_err()
    );
    assert!(
        review
            .with_approvals(digest, vec![rep_approval], vec![rev_approval])
            .is_err()
    );
    assert!(
        ReplacementReview::new(rev, rep).is_err(),
        "reviews cannot carry approvals"
    );
    assert!(
        ReplacementReview::new(review.replacement().clone(), review.reversal().clone()).is_err()
    );

    for field in ["target", "reason", "book", "branch", "principal"] {
        let mut changed = review.replacement().proposal().clone();
        match field {
            "target" => changed.supersession[0].target.vid = fgdb_types::VId(91),
            "reason" => changed.supersession[0].reason_code += 1,
            "book" => changed.book_id = fa_model::Id128([4; 16]),
            "branch" => changed.branch_id = fa_model::Id128([5; 16]),
            "principal" => changed.principal_ref = fgdb_types::VId(92),
            _ => unreachable!(),
        }
        let changed = PostIntent::new(changed, Vec::new()).unwrap();
        assert!(
            ReplacementReview::new(review.reversal().clone(), changed).is_err(),
            "{field}"
        );
    }
    for field in ["date", "key", "amount"] {
        let mut changed = review.replacement().proposal().clone();
        match field {
            "date" => changed.effective_date = fa_time::DateDay::parse("2026-03-11").unwrap(),
            "key" => changed.idempotency_key = b"another-replacement".to_vec(),
            "amount" => {
                for leg in &mut changed.legs {
                    leg.amount.mantissa += 100;
                }
                for total in &mut changed.unit_totals {
                    total.debits += 100;
                    total.credits += 100;
                }
            }
            _ => unreachable!(),
        }
        let changed = ReplacementReview::new(
            review.reversal().clone(),
            PostIntent::new(changed, Vec::new()).unwrap(),
        )
        .unwrap();
        assert_ne!(changed.digest().unwrap(), digest, "{field}");
        assert!(
            changed
                .with_approvals(digest, Vec::new(), Vec::new())
                .is_err(),
            "{field}"
        );
    }
}

#[test]
fn correction_review_restoration_refuses_overrides_modes_and_other_principals() {
    let f = Fixture::new();
    let posted = original(&f);
    let review = retained(&f, text(&posted, "vid"), "replace");
    let before = head(&f.book);
    for extra in [
        vec!["--intent", "/missing/corrected.json"],
        vec!["--reason", "WrongAccount"],
        vec!["--effective", "2026-03-11"],
        vec!["--period", "FY2026-P04"],
        vec!["--key", "changed"],
        vec!["--description", "changed"],
        vec!["--evidence", "not-a-document"],
        vec!["--review-only"],
        vec!["--review-out", "/missing/output.review"],
        vec!["--draft", "missing", "--yes"],
        vec!["--draft", "missing", "--dry-run"],
        vec!["--draft", "missing", "--plan-out", "/missing/output.plan"],
        vec!["--draft", "missing", "--commit-mode", "commit"],
        vec!["--digest", text(&review, "review_digest")],
    ] {
        let mut command = vec![
            "replace",
            "--review",
            text(&review, "bytes"),
            "--digest",
            text(&review, "review_digest"),
        ];
        command.extend(extra);
        let (exit, error) = run(&f.book, &command, None);
        assert_eq!(exit, 2, "{command:?}: {}", error.render());
        assert_eq!(head(&f.book), before);
    }
    let (exit, error) = run(
        &f.book,
        &[
            "replace",
            "00000000000000000000000000000001",
            "--review",
            text(&review, "bytes"),
            "--digest",
            text(&review, "review_digest"),
        ],
        None,
    );
    assert_eq!(exit, 2, "{}", error.render());
    let (exit, error) = run(
        &f.book,
        &[
            "replace",
            "--review",
            text(&review, "bytes"),
            "--digest",
            &"00".repeat(32),
        ],
        None,
    );
    assert_eq!(exit, 2, "{}", error.render());
    let (exit, error) = run(
        &f.book,
        &[
            "replace",
            "--review",
            text(&review, "bytes"),
            "--digest",
            text(&review, "review_digest"),
            "--as",
            "different-preparer",
            "--dry-run",
        ],
        None,
    );
    assert_eq!(exit, 7, "{}", error.render());
    assert_eq!(text(&error, "refusal_id"), "FA-REF-011");
    assert_eq!(head(&f.book), before);
    assert_absent(&f, text(&posted, "vid"));

    let other = Fixture::new();
    let other_before = head(&other.book);
    let (exit, error) = run(
        &other.book,
        &[
            "replace",
            "--review",
            text(&review, "bytes"),
            "--digest",
            text(&review, "review_digest"),
            "--dry-run",
        ],
        None,
    );
    assert_eq!(exit, 2, "{}", error.render());
    assert_eq!(text(&error, "refusal_id"), "FA-REF-103");
    assert_eq!(head(&other.book), other_before);

    // Conflicting creation modes refuse before trying to open the input.
    for extra in [
        vec!["--review-only", "--draft", "missing"],
        vec![
            "--review-out",
            "/missing/output.review",
            "--draft",
            "missing",
        ],
        vec!["--review-only", "--yes"],
        vec!["--review-out", "/missing/output.review", "--yes"],
        vec!["--review-only", "--commit-mode", "commit"],
        vec![
            "--review-only",
            "--dry-run",
            "--plan-out",
            "/missing/output.plan",
        ],
    ] {
        let mut command = vec![
            "replace",
            text(&posted, "vid"),
            "--intent",
            "/missing/corrected.json",
            "--reason",
            "WrongAmount",
        ];
        command.extend(extra);
        let (exit, error) = run(&f.book, &command, None);
        assert_eq!(exit, 2, "{command:?}: {}", error.render());
        assert!(
            !text(&error, "message").contains("No such file"),
            "{}",
            error.render()
        );
        assert_eq!(head(&f.book), before);
    }
}

#[test]
fn agent_correction_review_retains_exact_approved_pair_for_independent_promotion() {
    let f = Fixture::new();
    let original = original(&f);
    let target = text(&original, "vid");
    let authority = agent(&f, "review-agent", &["read", "post"]);
    assert_eq!(bound(&authority, &["draft", "new", "reviewed"], None).0, 0);
    let before = head(&f.book);
    let (exit, review) = bound(
        &authority,
        &[
            "replace",
            target,
            "--intent",
            "-",
            "--reason",
            "WrongAmount",
            "--evidence",
            &f.evidence,
            "--review-only",
        ],
        Some(&corrected("agent-replacement", "12.00")),
    );
    assert_eq!(exit, 0, "{review:?}");
    assert_eq!(review.len(), 1);
    let review = &review[0];
    assert_eq!(text(review, "event"), "replacement_reviewed");
    assert_review_receipt(&f, &authority, before, review);
    let approval = approve(
        &f,
        text(member(review, 1), "proposal_digest"),
        "replacement-reviewer",
    );
    let before = head(&f.book);
    for extra in [
        vec![],
        vec!["--yes"],
        vec!["--review-only", "--yes"],
        vec!["--draft", "reviewed", "--yes"],
        vec!["--draft", "reviewed", "--commit-mode", "commit"],
        vec![
            "--draft",
            "reviewed",
            "--dry-run",
            "--plan-out",
            "forbidden.plan",
        ],
    ] {
        let mut command = vec![
            "replace",
            "--review",
            text(review, "bytes"),
            "--digest",
            text(review, "review_digest"),
            "--approval",
            &approval,
        ];
        command.extend(extra);
        let (exit, result) = bound(&authority, &command, None);
        assert!(
            exit != 0
                || result
                    .iter()
                    .all(|event| text(event, "event") == "replacement_plan"),
            "{result:?}"
        );
        assert_eq!(head(&f.book), before);
        assert_absent(&f, target);
    }
    let (exit, planned) = bound(
        &authority,
        &[
            "replace",
            "--review",
            "-",
            "--digest",
            text(review, "review_digest"),
            "--approval",
            &approval,
            "--draft",
            "reviewed",
        ],
        Some(text(review, "bytes")),
    );
    assert_eq!(exit, 0, "{planned:?}");
    assert_eq!(planned.len(), 2);
    assert_eq!(head(&f.book), before + 1);
    for (index, entry) in planned.iter().enumerate() {
        assert_eq!(text(entry, "event"), "draft_planned");
        assert_eq!(
            text(entry, "proposal_digest"),
            text(member(review, index), "proposal_digest")
        );
    }
    assert_absent(&f, target);
    let promoted = ok(
        &f.book,
        &[
            "draft",
            "promote",
            "reviewed",
            "--as",
            "controller",
            "--yes",
        ],
    );
    assert_eq!(head(&f.book), before + 2);
    for (index, entry) in planned.iter().enumerate() {
        let stored = ok(&f.book, &["entry", "show", text(entry, "entry")]);
        assert_eq!(
            text(&stored, "proposal_digest"),
            text(member(review, index), "proposal_digest")
        );
        assert_eq!(
            integer(&stored, "recorded_at"),
            integer(&promoted, "recorded_at")
        );
    }
    let after = head(&f.book);
    let (exit, retry) = bound(
        &authority,
        &[
            "replace",
            "--review",
            text(review, "bytes"),
            "--digest",
            text(review, "review_digest"),
            "--approval",
            &approval,
            "--draft",
            "reviewed",
        ],
        None,
    );
    assert_eq!(exit, 0, "{retry:?}");
    assert!(
        retry
            .iter()
            .all(|event| get(event, "already_recorded") == &Json::Bool(true))
    );
    assert_eq!(head(&f.book), after);
}

#[test]
fn correction_review_current_authority_precedes_input_and_target_observation() {
    for expired in [false, true] {
        let f = Fixture::new();
        let original = original(&f);
        let target = text(&original, "vid");
        // Issuance, opening the draft, the review's required access receipt,
        // and the independent approval each publish one distinct marker.
        let expires = (head(&f.book) + 4).to_string();
        let path = f.dir.join("holder.token");
        let path_arg = path.display().to_string();
        let mut issue = vec![
            "capability",
            "issue",
            "--holder",
            "review-holder",
            "--profile",
            "agent",
            "--op",
            "read",
            "--op",
            "post",
            "--out",
            path_arg.as_str(),
            "--as",
            "steward",
            "--grant",
            "issue_capability",
            "--grant",
            "read",
            "--grant",
            "post",
        ];
        if expired {
            issue.extend(["--expires-at", expires.as_str()]);
        }
        let issued = ok(&f.book, &issue);
        let token = fa_policy::CapabilityToken::decode(&std::fs::read(&path).unwrap()).unwrap();
        let authority = LaunchAuthority::from_token(f.book.clone(), None, &token)
            .unwrap()
            .with_files(Some(f.dir.clone()))
            .unwrap();
        assert_eq!(bound(&authority, &["draft", "new", "reviewed"], None).0, 0);
        let before = head(&f.book);
        let (exit, review) = bound(
            &authority,
            &[
                "replace",
                target,
                "--intent",
                "-",
                "--reason",
                "WrongAmount",
                "--evidence",
                &f.evidence,
                "--review-only",
            ],
            Some(&corrected("token-replacement", "12.00")),
        );
        assert_eq!(exit, 0, "{review:?}");
        let review = &review[0];
        assert_review_receipt(&f, &authority, before, review);
        let approval = approve(
            &f,
            text(member(review, 1), "proposal_digest"),
            "replacement-reviewer",
        );
        if expired {
            assert_eq!(head(&f.book).to_string(), expires);
        } else {
            ok(
                &f.book,
                &[
                    "capability",
                    "revoke",
                    "--commitment",
                    text(&issued, "commitment"),
                    "--as",
                    "steward",
                    "--grant",
                    "issue_capability",
                    "--yes",
                ],
            );
        }
        let before = head(&f.book);
        let expected = if expired { "FA-REF-014" } else { "FA-REF-023" };
        for review_input in ["missing.review", text(review, "bytes")] {
            let (exit, refusal) = bound(
                &authority,
                &[
                    "replace",
                    "--review",
                    review_input,
                    "--digest",
                    text(review, "review_digest"),
                    "--approval",
                    &approval,
                    "--draft",
                    "reviewed",
                ],
                None,
            );
            assert_eq!(exit, 7, "{refusal:?}");
            assert_eq!(text(&refusal[0], "refusal_id"), expected);
            assert_eq!(refusal[0].get("book"), Some(&Json::Null));
            assert_eq!(refusal[0].get("coordinate"), Some(&Json::Null));
        }
        // Even a well-formed artifact with a nonexistent target must refuse
        // current authority before its target can be observed by the kernel.
        let retained = ReplacementReview::decode(&unhex(text(review, "bytes"))).unwrap();
        let mut reversal = retained.reversal().proposal().clone();
        let mut replacement = retained.replacement().proposal().clone();
        reversal.supersession[0].target.vid = fgdb_types::VId(0xdead);
        replacement.supersession[0].target = reversal.supersession[0].target;
        let unknown = ReplacementReview::new(
            PostIntent::new(reversal, Vec::new()).unwrap(),
            PostIntent::new(replacement, Vec::new()).unwrap(),
        )
        .unwrap();
        let (exit, refusal) = bound(
            &authority,
            &[
                "replace",
                "--review",
                &hex(&unknown.canonical_bytes().unwrap()),
                "--digest",
                &hex(&unknown.digest().unwrap()),
                "--draft",
                "reviewed",
            ],
            None,
        );
        assert_eq!(exit, 7, "{refusal:?}");
        assert_eq!(text(&refusal[0], "refusal_id"), expected);
        assert_eq!(head(&f.book), before);
        assert_absent(&f, target);
    }
}
