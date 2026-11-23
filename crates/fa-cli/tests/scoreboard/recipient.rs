//! Genesis bundle and witnessed-history questions asked of the standalone verifier.

use super::{Json, ProbeOutcome, json, setup_fixture_book, tmp_dir};
use fa::book::{Book, BookKeys, Entropy};
use fa_model::{Id128, account_vid};
use fa_time::DateDay;
use fa_verify::blake3::hex;
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

const PRODUCER: &str = env!("CARGO_BIN_EXE_fa");
const RECIPIENT: &str = env!("CARGO_BIN_FILE_FA_VERIFY");

type Result<T> = std::result::Result<T, String>;

fn field<'a>(object: &'a Json, name: &str) -> Result<&'a Json> {
    object
        .get(name)
        .ok_or_else(|| format!("missing {name}: {object:?}"))
}

fn string<'a>(object: &'a Json, name: &str) -> Result<&'a str> {
    field(object, name)?
        .as_str()
        .ok_or_else(|| format!("expected string {name}: {object:?}"))
}

fn number(object: &Json, name: &str) -> Result<i128> {
    match field(object, name)? {
        Json::Int(n) => Ok(*n),
        _ => Err(format!("expected integer {name}: {object:?}")),
    }
}

fn binary_digests() -> Result<&'static str> {
    static HASHES: OnceLock<Result<String>> = OnceLock::new();
    HASHES
        .get_or_init(|| {
            let files = [PRODUCER, RECIPIENT];
            let output = match Command::new("sha256sum").args(files).output() {
                Err(error) if error.kind() == io::ErrorKind::NotFound => Command::new("shasum")
                    .args(["-a", "256"])
                    .args(files)
                    .output(),
                result => result,
            }
            .map_err(|e| format!("UNRUN could not hash candidate executables: {e}"))?;
            if !output.status.success() {
                return Err(format!(
                    "UNRUN checksum {}: {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            String::from_utf8(output.stdout).map_err(|e| e.to_string())
        })
        .as_deref()
        .map_err(Clone::clone)
}

struct Fixture {
    vars: BTreeMap<String, String>,
    dir: PathBuf,
    trace: fs::File,
    book_key: String,
    book_id: Id128,
}

impl Fixture {
    fn new(tag: &str) -> Result<Self> {
        let root = tmp_dir(tag);
        let vars = setup_fixture_book(&root);
        let path = Path::new(&vars["{book}"]);
        // The recipient's identities come from the owner's book, before any export.
        let keys = BookKeys::load(&path.join("book.keys")).map_err(|e| e.to_string())?;
        let book =
            Book::open_dir(path, keys, Entropy::deterministic(97)).map_err(|e| e.to_string())?;
        let dir = root.join("recipient");
        fs::create_dir(&dir).map_err(|e| e.to_string())?;
        let path = dir.join("transcript.txt");
        let mut trace = fs::File::create_new(&path).map_err(|e| e.to_string())?;
        eprintln!("{tag} transcript: {}", path.display());
        writeln!(trace, "{tag} candidate SHA-256\n{}", binary_digests()?)
            .map_err(|e| e.to_string())?;
        Ok(Self {
            vars,
            dir,
            trace,
            book_key: hex(&book.checkpoint_public_key()),
            book_id: book.context().book_id,
        })
    }

    fn run(&mut self, exe: &str, args: &[&str], expected: i32) -> Result<Json> {
        let output = Command::new(exe)
            .args(args)
            .arg("--json")
            .current_dir(&self.dir)
            .env_remove("FA_BOOK")
            .env_remove("FA_TOKEN")
            .output()
            .map_err(|e| format!("UNRUN {exe} {args:?}: {e}"))?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let record = format!(
            "{exe} {args:?} --json expected exit {expected}, observed {}\nstdout={stdout}\nstderr={stderr}",
            output.status
        );
        writeln!(self.trace, "{record}").map_err(|e| e.to_string())?;
        let code = output
            .status
            .code()
            .ok_or_else(|| format!("UNRUN interrupted: {record}"))?;
        if code != expected {
            return Err(record);
        }
        json::parse(stdout.trim()).map_err(|e| format!("{e}: {record}"))
    }

    fn produce(&mut self, args: &[&str], event: &str) -> Result<Json> {
        let book = self.vars["{book}"].clone();
        let mut argv = args.to_vec();
        argv.extend(["--book", &book]);
        let result = self.run(PRODUCER, &argv, 0)?;
        if string(&result, "event")? != event {
            return Err(format!("expected {event}: {result:?}"));
        }
        field(&result, "data").cloned()
    }

    fn verify(&mut self, args: &[&str], expected: i32) -> Result<Json> {
        let report = self.run(RECIPIENT, args, expected)?;
        let verdict = if expected == 0 { "verified" } else { "failed" };
        if string(&report, "tool")? != "fa-verify"
            || string(&report, "command")? != args[0]
            || string(&report, "verdict")? != verdict
        {
            return Err(format!(
                "expected fa-verify {} {verdict}: {report:?}",
                args[0]
            ));
        }
        Ok(report)
    }

    fn checkpoint(&mut self) -> Result<Json> {
        let state = self.produce(
            &["checkpoint", "create", "--grant", "witness"],
            "checkpoint_created",
        )?;
        if string(&state, "book")? != hex(&self.book_id.0)
            || string(&state, "branch")? != hex(&Id128::TRUNK.0)
            || string(&state, "public_key")? != self.book_key
        {
            return Err(format!(
                "checkpoint differs from expected signer or book/branch: {state:?}"
            ));
        }
        Ok(state)
    }

    fn witness_key(&mut self) -> Result<(String, String, String)> {
        let file = self
            .dir
            .parent()
            .expect("fixture root")
            .join("witness.key")
            .display()
            .to_string();
        let key = self.produce(
            &["checkpoint", "witness-key", "--out", &file],
            "witness_key_created",
        )?;
        let witness = string(&key, "public_key")?.to_owned();
        if witness == self.book_key {
            return Err("witness and book signer coincide".into());
        }
        Ok((file, witness, string(&key, "signer_key_id")?.to_owned()))
    }
}

fn check<'a>(report: &'a Json, name: &str, result: &str) -> Result<&'a Json> {
    field(report, "checks")?
        .as_arr()
        .and_then(|checks| {
            checks.iter().find(|c| {
                c.get("check").and_then(Json::as_str) == Some(name)
                    && c.get("result").and_then(Json::as_str) == Some(result)
            })
        })
        .ok_or_else(|| format!("expected {result} for {name}: {report:?}"))
}

fn coordinate(detail: &Json, state: &Json) -> Result<()> {
    for (observed, expected) in [
        ("book_id", "book"),
        ("branch_id", "branch"),
        ("through_seq", "through_seq"),
        ("leaf_count", "leaf_count"),
    ] {
        if field(detail, observed)? != field(state, expected)? {
            return Err(format!("wrong {observed}: {detail:?}, expected {state:?}"));
        }
    }
    Ok(())
}

fn require_bundle(report: &Json, state: &Json, account: &str) -> Result<()> {
    let bundle = field(check(report, "bundle", "pass")?, "detail")?;
    coordinate(bundle, state)?;
    let scope = field(bundle, "scope")?;
    let march = |day| i128::from(DateDay::from_ymd(2026, 3, day).expect("March 2026").0);
    if field(bundle, "checkpoint_oid")? != field(state, "checkpoint_oid")?
        || string(scope, "account")? != account
        || number(scope, "from")? != march(1)
        || number(scope, "to")? != march(31)
        || number(bundle, "entries")? != 2
        || string(bundle, "completeness")? != "scope_index_complete"
    {
        return Err(format!(
            "wrong March invoice scope or checkpoint for {account}: {bundle:?}"
        ));
    }
    for name in [
        "checkpoint",
        "manifest",
        "completeness",
        "entries",
        "closure",
        "production_receipt",
    ] {
        check(report, name, "pass")?;
    }
    Ok(())
}

fn exercise_bundle() -> Result<()> {
    let mut f = Fixture::new("g1-07")?;
    let state = f.checkpoint()?;
    let account = format!("0x{:032x}", account_vid(f.book_id, "1200").0);
    let book_key = f.book_key.clone();
    let (_, other_key, _) = f.witness_key()?;
    f.produce(
        &[
            "bundle",
            "produce",
            "--account",
            "1200",
            "--from",
            "2026-03-01",
            "--to",
            "2026-03-31",
            "--state",
            string(&state, "oid")?,
            "--grant",
            "produce",
            "--out",
            "invoice.fab",
            "--receipt-out",
            "invoice.receipt",
        ],
        "bundle_produced",
    )?;
    let mut verify = |bundle: &str, key: &str, expected| {
        f.verify(
            &[
                "bundle",
                bundle,
                "--key",
                key,
                "--receipt",
                "invoice.receipt",
            ],
            expected,
        )
    };
    let positive = verify("invoice.fab", &book_key, 0)?;
    require_bundle(&positive, &state, &account)?;
    let wrong = verify("invoice.fab", &other_key, 8)?;
    check(&wrong, "checkpoint", "fail")?;
    let wrong_scope = format!("0x{:032x}", account_vid(f.book_id, "4000").0);
    if require_bundle(&positive, &state, &wrong_scope).is_ok() {
        return Err("accepted the bundle for another account".into());
    }
    writeln!(f.trace, "March account 1200 ({account}) accepted; account 4000 ({wrong_scope}) rejected for the same verified bytes.")
        .map_err(|e| e.to_string())?;
    // Change the human manifest alone, keeping the authentic book signature intact.
    let mut bytes = fs::read(f.dir.join("invoice.fab")).map_err(|e| e.to_string())?;
    let heading = b"# FrankenAccounting evidence bundle";
    let at = bytes
        .windows(heading.len())
        .position(|w| w == heading)
        .ok_or_else(|| "missing human manifest heading".to_owned())?;
    bytes[at] ^= 1;
    fs::write(f.dir.join("changed.fab"), bytes).map_err(|e| e.to_string())?;
    let changed = f.verify(
        &[
            "bundle",
            "changed.fab",
            "--key",
            &book_key,
            "--receipt",
            "invoice.receipt",
        ],
        8,
    )?;
    check(&changed, "checkpoint", "pass")?;
    check(&changed, "manifest", "fail")?;
    check(&changed, "production_receipt", "fail")?;
    Ok(())
}

fn exercise_witness() -> Result<()> {
    let mut f = Fixture::new("g2-06")?;
    let book_key = f.book_key.clone();
    let (key_file, witness, signer_id) = f.witness_key()?;
    let old = f.checkpoint()?;
    let old_oid = string(&old, "oid")?;
    let first = f.produce(
        &[
            "checkpoint",
            "witness",
            "--state",
            old_oid,
            "--key",
            &key_file,
            "--out",
            "before.cp",
            "--grant",
            "witness",
        ],
        "checkpoint_witnessed",
    )?;
    if field(&first, "extends")? != &Json::Null {
        return Err(format!("unexpected previous statement: {first:?}"));
    }
    let intent = f.vars["{sale_intent_2}"].clone();
    let evidence = f.vars["{doc_oid}"].clone();
    let posted = f.produce(
        &["post", "--intent", &intent, "--evidence", &evidence],
        "posted",
    )?;
    let new = f.checkpoint()?;
    let new_oid = string(&new, "oid")?;
    let seq = number(&posted, "recorded_at")?;
    if seq <= number(&old, "through_seq")?
        || number(&new, "through_seq")? < seq
        || number(&new, "leaf_count")? <= number(&old, "leaf_count")?
    {
        return Err(format!(
            "new checkpoint must extend the old one over post {seq}: {old:?}, {new:?}"
        ));
    }
    let second = f.produce(
        &[
            "checkpoint",
            "witness",
            "--key",
            &key_file,
            "--state",
            new_oid,
            "--previous",
            "before.cp",
            "--out",
            "after.cp",
            "--grant",
            "witness",
        ],
        "checkpoint_witnessed",
    )?;
    let previous = field(&second, "extends")?;
    for name in ["root", "leaf_count", "through_seq"] {
        if field(previous, name)? != field(&old, name)? {
            return Err(format!(
                "witness remembered a different {name}: {previous:?}, {old:?}"
            ));
        }
    }
    for (file, state) in [("before.cp", &old), ("after.cp", &new)] {
        let verdict = f.verify(
            &[
                "checkpoint",
                file,
                "--key",
                &book_key,
                "--witness",
                &witness,
                "--quorum",
                "1",
            ],
            0,
        )?;
        let detail = field(check(&verdict, "checkpoint", "pass")?, "detail")?;
        coordinate(detail, state)?;
        if field(detail, "state_oid")? != field(state, "oid")?
            || field(detail, "root")? != field(state, "root")?
        {
            return Err(format!("witnessed the wrong state: {detail:?}, {state:?}"));
        }
        let quorum = field(check(&verdict, "witnesses", "pass")?, "detail")?;
        let signers = field(quorum, "signed_by")?.as_arr();
        if number(quorum, "signed")? != 1
            || number(quorum, "quorum")? != 1
            || !matches!(signers, Some([signer]) if signer.as_str() == Some(signer_id.as_str()))
        {
            return Err(format!("missing required witness: {quorum:?}"));
        }
    }
    f.produce(
        &[
            "proof",
            "consistency",
            "--state",
            old_oid,
            "--next-state",
            new_oid,
            "--out",
            "extension.proof",
        ],
        "proof_exported",
    )?;
    let mut consistency = |before: &str, after: &str, expected| {
        f.verify(
            &[
                "consistency",
                "extension.proof",
                "--trusted",
                before,
                "--claimed",
                after,
                "--key",
                &book_key,
            ],
            expected,
        )
    };
    let proved = consistency("before.cp", "after.cp", 0)?;
    let detail = field(check(&proved, "consistency", "pass")?, "detail")?;
    for (name, state, key) in [
        ("trusted_leaf_count", &old, "leaf_count"),
        ("extended_leaf_count", &new, "leaf_count"),
        ("extended_through_seq", &new, "through_seq"),
    ] {
        if field(detail, name)? != field(state, key)? {
            return Err(format!(
                "continuity proof covers the wrong {name}: {detail:?}, {state:?}"
            ));
        }
    }
    check(
        &consistency("after.cp", "before.cp", 8)?,
        "consistency",
        "fail",
    )?;
    f.produce(
        &[
            "proof",
            "signed-checkpoint",
            "--state",
            new_oid,
            "--out",
            "book-only.cp",
        ],
        "proof_exported",
    )?;
    let missing = f.verify(
        &[
            "checkpoint",
            "book-only.cp",
            "--key",
            &book_key,
            "--witness",
            &witness,
            "--quorum",
            "1",
        ],
        8,
    )?;
    let valid_book = field(check(&missing, "checkpoint", "pass")?, "detail")?;
    coordinate(valid_book, &new)?;
    let absent = field(check(&missing, "witnesses", "fail")?, "detail")?;
    if number(absent, "signed")? != 0 {
        return Err(format!(
            "book-only checkpoint reported a witness: {absent:?}"
        ));
    }
    Ok(())
}

pub(super) fn genesis_bundle() -> ProbeOutcome {
    ProbeOutcome::from_check(exercise_bundle(), "genesis_bundle_verified")
}

pub(super) fn witnessed_extension() -> ProbeOutcome {
    ProbeOutcome::from_check(exercise_witness(), "witnessed_extension_verified")
}

#[test]
fn g1_scoreboard_requires_standalone_bundle_verdict() {
    let result = genesis_bundle();
    assert_eq!(result.exit, 0, "{result:?}");
}

#[test]
fn g2_scoreboard_requires_witnessed_checkpoint_extension() {
    let result = witnessed_extension();
    assert_eq!(result.exit, 0, "{result:?}");
}
