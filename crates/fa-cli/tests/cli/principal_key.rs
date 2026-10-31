//! Signed approvals (plan §14.5 non-repudiation, bead fa-kae): a principal
//! registers its own Ed25519 key, after which its approvals carry the key's
//! signature, its unsigned ones are refused, a rotation needs the current
//! key's endorsement, and a signed approval admits the period transition it
//! approves exactly as an unsigned one did.

use super::*;

fn run(book: &Path, step: &str, args: &[&str]) -> (i32, String) {
    let mut argv = args.to_vec();
    argv.push("--json");
    let (code, out, err) = fa(Some(book), &argv);
    eprintln!(
        "{step}: argv={argv:?} exit={code} event={:?} refusal={:?}",
        field(&out, "event"),
        field(&out, "refusal_id")
    );
    (code, format!("{out}\n{err}"))
}

fn ok(book: &Path, step: &str, args: &[&str]) -> Json {
    let (code, out) = run(book, step, args);
    assert_eq!(code, 0, "{step}: {out}");
    doc(out.lines().next().unwrap_or_default())
}

fn refused(book: &Path, step: &str, args: &[&str], exit: i32, refusal: &str) {
    let (code, out) = run(book, step, args);
    assert_eq!(code, exit, "{step}: {out}");
    assert!(out.contains(refusal), "{step}: expected {refusal}: {out}");
}

#[test]
fn a_keyed_principal_signs_its_approvals_and_rotates_only_with_endorsement() -> std::io::Result<()>
{
    let dir = tmp("principal-key")?;
    let book = dir.join("book");
    ok(&book, "book", &["book", "create", "--name", "Signed Co"]);
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"}]}"#,
    );
    ok(&book, "chart", &["chart", "import", &chart]);
    ok(
        &book,
        "periods",
        &["period", "create", "--fiscal-year", "2026"],
    );
    ok(&book, "open", &["period", "open", "FY2026-P01"]);
    let key = |name: &str| -> String {
        let path = dir.join(name).display().to_string();
        let created = ok(&book, name, &["principal", "key", "new", "--out", &path]);
        assert_eq!(text(&created, "out"), path);
        path
    };
    let (first, second, stranger) = (key("c1.key"), key("c2.key"), key("x.key"));

    // No key yet: a signed approval has nothing to verify against, and an
    // unsigned one is admitted as it always was.
    let digest = |n: u8| format!("{n:02x}").repeat(32);
    refused(
        &book,
        "signed before registration",
        &[
            "approve",
            "--proposal",
            &digest(1),
            "--as",
            "controller",
            "--sign-key",
            &first,
        ],
        7,
        "FA-REF-205",
    );
    ok(
        &book,
        "unsigned before registration",
        &["approve", "--proposal", &digest(1), "--as", "controller"],
    );

    // Generation 0, proved by the key itself; a retry writes nothing.
    let added = ok(
        &book,
        "register",
        &[
            "principal",
            "key",
            "add",
            "--sign-key",
            &first,
            "--as",
            "controller",
        ],
    );
    assert_eq!(int(&added, "generation"), Some(0));
    assert_eq!(added.get("already_recorded"), Some(&Json::Bool(false)));
    let again = ok(
        &book,
        "register again",
        &[
            "principal",
            "key",
            "add",
            "--sign-key",
            &first,
            "--as",
            "controller",
        ],
    );
    assert_eq!(again.get("already_recorded"), Some(&Json::Bool(true)));
    assert_eq!(text(&again, "control_entry"), text(&added, "control_entry"));

    // Keyed: unsigned or wrongly signed approvals are refused.
    refused(
        &book,
        "unsigned after registration",
        &["approve", "--proposal", &digest(2), "--as", "controller"],
        7,
        "FA-REF-205",
    );
    refused(
        &book,
        "another key",
        &[
            "approve",
            "--proposal",
            &digest(2),
            "--as",
            "controller",
            "--sign-key",
            &stranger,
        ],
        7,
        "FA-REF-205",
    );
    ok(
        &book,
        "signed",
        &[
            "approve",
            "--proposal",
            &digest(2),
            "--as",
            "controller",
            "--sign-key",
            &first,
        ],
    );
    // A review approval takes the key too; here the review itself is judged
    // (signed review approvals: allocation_dimensions.rs).
    refused(
        &book,
        "a signed approval of no review",
        &[
            "approve",
            "--review",
            &digest(3),
            "--digest",
            &digest(3),
            "--sign-key",
            &first,
        ],
        2,
        "unrecognized review artifact format",
    );

    // Rotation: the current key must endorse the next one.
    let (code, out) = run(
        &book,
        "rotation unendorsed",
        &[
            "principal",
            "key",
            "add",
            "--sign-key",
            &second,
            "--as",
            "controller",
        ],
    );
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("--endorse-key"), "{out}");
    refused(
        &book,
        "rotation endorsed by a stranger",
        &[
            "principal",
            "key",
            "add",
            "--sign-key",
            &second,
            "--endorse-key",
            &stranger,
            "--as",
            "controller",
        ],
        2,
        "FA-REF-204",
    );
    let rotated = ok(
        &book,
        "rotation",
        &[
            "principal",
            "key",
            "add",
            "--sign-key",
            &second,
            "--endorse-key",
            &first,
            "--as",
            "controller",
        ],
    );
    assert_eq!(int(&rotated, "generation"), Some(1));
    // Its retry answers with the recorded generation, even without the
    // endorsing key: the endorsement it was recorded with is resubmitted.
    let rotated_again = ok(
        &book,
        "rotation retry",
        &[
            "principal",
            "key",
            "add",
            "--sign-key",
            &second,
            "--as",
            "controller",
        ],
    );
    assert_eq!(int(&rotated_again, "generation"), Some(1));
    assert_eq!(
        rotated_again.get("already_recorded"),
        Some(&Json::Bool(true))
    );
    refused(
        &book,
        "the rotated-out key",
        &[
            "approve",
            "--proposal",
            &digest(4),
            "--as",
            "controller",
            "--sign-key",
            &first,
        ],
        7,
        "FA-REF-205",
    );

    // A signed approval admits the transition it approves: the plan is the
    // operator's, the approval the keyed controller's.
    ok(
        &book,
        "close",
        &[
            "period",
            "close",
            "FY2026-P01",
            "--reason",
            "Scheduled",
            "--as",
            "controller",
            "--yes",
        ],
    );
    let plan = dir.join("lock.plan").display().to_string();
    let planned = ok(
        &book,
        "lock plan",
        &[
            "period",
            "lock",
            "FY2026-P01",
            "--reason",
            "Scheduled",
            "--plan-out",
            &plan,
        ],
    );
    let lock_digest = text(&planned, "proposal_digest").to_string();
    refused(
        &book,
        "unsigned lock approval",
        &["approve", "--proposal", &lock_digest, "--as", "controller"],
        7,
        "FA-REF-205",
    );
    let approved = ok(
        &book,
        "signed lock approval",
        &[
            "approve",
            "--proposal",
            &lock_digest,
            "--as",
            "controller",
            "--sign-key",
            &second,
        ],
    );
    let approval = text(&approved, "approval_vid").to_string();
    ok(
        &book,
        "lock",
        &[
            "period",
            "lock",
            "FY2026-P01",
            "--plan",
            &plan,
            "--approval",
            &approval,
        ],
    );
    // The key controls and the signed approvals leave every verification
    // green.
    ok(&book, "verify book", &["verify", "book"]);
    Ok(())
}
