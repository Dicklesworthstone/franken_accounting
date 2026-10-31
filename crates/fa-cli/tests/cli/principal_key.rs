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
    // Each key file, with its public key and key id.
    let key = |name: &str| -> (String, String, String) {
        let path = dir.join(name).display().to_string();
        let created = ok(&book, name, &["principal", "key", "new", "--out", &path]);
        assert_eq!(text(&created, "out"), path);
        (
            path,
            text(&created, "public_key").to_string(),
            text(&created, "key_id").to_string(),
        )
    };
    let ((first, first_public_key, _), (second, _, second_key_id), (stranger, _, _)) =
        (key("c1.key"), key("c2.key"), key("x.key"));

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

    // Offline (fa-verify bundle format 1.1): a bundle of the prefix carries
    // the lock's signed approval and the controller's two key generations,
    // and fa-verify checks the signature against them without the book.
    ok(
        &book,
        "checkpoint",
        &["checkpoint", "create", "--grant", "witness"],
    );
    let (fab, receipt) = (dir.join("signed.fab"), dir.join("signed.receipt"));
    let produced = ok(
        &book,
        "bundle",
        &[
            "bundle",
            "produce",
            "--out",
            &fab.display().to_string(),
            "--receipt-out",
            &receipt.display().to_string(),
        ],
    );
    let checkpoint_key: [u8; 32] = unhex(text(&produced, "checkpoint_public_key"))
        .try_into()
        .expect("a 32-byte checkpoint key");
    let bundle = std::fs::read(&fab)?;
    let receipt = std::fs::read(&receipt)?;
    let report = fa_verify::verify_bundle(&bundle, &[checkpoint_key], Some(&receipt))
        .expect("a well-formed bundle");
    assert!(report.verified(), "{:#?}", report.checks);
    assert!(report.receipt.is_some(), "the receipt verified");
    assert_eq!(report.summary.format, (1, 1));
    let graded =
        |report: &fa_verify::BundleReport, name: &str| -> Vec<(String, fa_verify::Grade)> {
            report
                .checks
                .iter()
                .filter(|c| c.check == name)
                .map(|c| (c.subject.clone(), c.grade.clone()))
                .collect()
        };
    let approvals = graded(&report, "approval");
    assert_eq!(approvals.len(), 1, "{approvals:?}");
    assert!(
        approvals[0].0.ends_with("signed by key generation 1"),
        "{approvals:?}"
    );
    assert_eq!(graded(&report, "key_record").len(), 2);
    assert_eq!(graded(&report, "key_chain").len(), 1);

    // Tampering is named by the check it breaks. The signed record ends
    // `u16 scheme (1) ‖ u32 generation (1) ‖ [32] key_id ‖ [64] signature`,
    // and its body's approved proposal digest sits 49 bytes before the key
    // id. (The key id alone also occurs elsewhere in a prefix bundle.)
    let mut trailer = vec![1, 0, 1, 0, 0, 0];
    trailer.extend_from_slice(&unhex(&second_key_id));
    let found: Vec<usize> = bundle
        .windows(trailer.len())
        .enumerate()
        .filter(|(_, w)| *w == trailer.as_slice())
        .map(|(i, _)| i)
        .collect();
    assert_eq!(found.len(), 1, "one signed record names generation 1's key");
    let at = found[0] + 6;
    assert_eq!(bundle[at - 49..at - 17], unhex(&lock_digest)[..]);
    let failed = |bytes: &[u8], name: &str| -> Vec<String> {
        let report = fa_verify::verify_bundle(bytes, &[checkpoint_key], None)
            .expect("still a well-formed bundle");
        assert!(!report.verified());
        graded(&report, name)
            .into_iter()
            .filter_map(|(subject, grade)| match grade {
                fa_verify::Grade::Fail(why) => Some(format!("{subject}: {why}")),
                _ => None,
            })
            .collect()
    };
    // A changed signature does not verify under generation 1.
    let mut forged = bundle.clone();
    forged[at + 32] ^= 1;
    let why = failed(&forged, "approval");
    assert!(why[0].contains("not generation 1's signature"), "{why:?}");
    // A signature over another proposal digest: the record no longer
    // derives the identity the lock cites, nor binds the lock's proposal.
    let mut other = bundle.clone();
    other[at - 49] ^= 1;
    let why = failed(&other, "approvals");
    assert!(why[0].contains("an omitted approval"), "{why:?}");
    let why = failed(&other, "approval");
    assert!(why[0].contains("not generation 1's signature"), "{why:?}");
    // A key record is authenticated by the checkpoint: a changed public key
    // fails its inclusion, and nothing that rests on it passes. A prefix
    // bundle also lists the key's entry among its in-scope entries; the
    // last occurrence is the key leaf, which follows them.
    let first_public = unhex(&first_public_key);
    let key_at = bundle
        .windows(32)
        .rposition(|w| w == first_public.as_slice())
        .expect("generation 0's record carries its public key");
    let mut swapped = bundle.clone();
    swapped[key_at] ^= 1;
    let why = failed(&swapped, "key_record");
    assert_eq!(why.len(), 1, "{why:?}");
    let report = fa_verify::verify_bundle(&swapped, &[checkpoint_key], None).expect("readable");
    assert!(
        graded(&report, "approval")
            .iter()
            .all(|(_, g)| matches!(g, fa_verify::Grade::Unrun(_))),
        "{:#?}",
        report.checks
    );
    Ok(())
}

fn unhex(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2), "odd hex length: {hex}");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect()
}
