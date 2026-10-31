//! Actual executable tests for exact stock-cell requests inside witnessed bundles.
//! Fixed signed empty-journal vectors are reused, never regenerated or re-signed.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use fa_verify::BalanceScope;
use fa_verify::blake3::hex;
use fa_verify::bundle::{
    BUNDLE_FORMAT, BundleScope, Completeness, FOLD_DOMAIN, FOLD_VERSION, Manifest, Summary,
    manifest_md,
};
use fa_verify::checkpoint::verify_checkpoint;

fn fixture(name: &str) -> Vec<u8> {
    let keys = include_str!("fixtures/checkpoint_witness_v1.txt");
    let advance = include_str!("fixtures/checkpoint_witness_advance_v1.txt");
    let text = keys
        .lines()
        .chain(advance.lines())
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(' '))
        .unwrap();
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn key(name: &str) -> [u8; 32] {
    fixture(name).try_into().unwrap()
}

fn bytes(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&u32::try_from(value.len()).unwrap().to_le_bytes());
    out.extend_from_slice(value);
}

fn cell(account: u128, unit: u32, through: Option<i32>) -> BalanceScope {
    BalanceScope {
        account,
        unit,
        effective_through: through,
    }
}

fn request(cell: BalanceScope) -> String {
    format!(
        "{:032x}:{}:{}",
        cell.account,
        cell.unit,
        cell.effective_through
            .map_or_else(|| "none".into(), |day| day.to_string())
    )
}

fn bundle(cells: &[BalanceScope]) -> Vec<u8> {
    let checkpoint = fixture("empty");
    let signed = verify_checkpoint(&checkpoint, &[key("publisher")]).unwrap();
    let cp = signed.checkpoint;
    assert_eq!(cp.leaf_count, 0);
    let m = Manifest {
        book_id: cp.book_id,
        branch_id: cp.branch_id,
        through_seq: cp.through_seq,
        leaf_count: 0,
        checkpoint_oid: signed.oid,
        scope: BundleScope::Prefix,
        completeness: Completeness::SeqRangeComplete { from: 0, to: 0 },
    };
    let summary = Summary {
        format: (1, 0),
        entries: 0,
        documents: 0,
        inline: 0,
        balances: vec![(FOLD_DOMAIN.to_vec(), FOLD_VERSION); cells.len()],
        approvals: None,
    };
    let mut prefix = Vec::new();
    bytes(&mut prefix, fa_verify::proof::PREFIX_FORMAT);
    prefix.extend_from_slice(&cp.encode());
    prefix.extend_from_slice(&0u32.to_le_bytes());
    let mut out = Vec::new();
    bytes(&mut out, BUNDLE_FORMAT);
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&cp.book_id);
    out.extend_from_slice(&cp.branch_id);
    out.extend_from_slice(&cp.through_seq.to_le_bytes());
    out.extend_from_slice(&cp.leaf_count.to_le_bytes());
    out.extend_from_slice(&signed.oid);
    out.extend_from_slice(&[1, 1]); // Prefix scope, complete sequence range
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    bytes(&mut out, &checkpoint);
    bytes(&mut out, &prefix);
    out.extend_from_slice(&0u32.to_le_bytes()); // no entry payloads in an empty journal
    out.extend_from_slice(&u32::try_from(cells.len()).unwrap().to_le_bytes());
    for cell in cells {
        let mut proof = Vec::new();
        bytes(&mut proof, fa_verify::migration_balance::BALANCE_FORMAT_V3);
        proof.extend_from_slice(&cp.encode());
        proof.extend_from_slice(&cell.account.to_le_bytes());
        proof.extend_from_slice(&cell.unit.to_le_bytes());
        if let Some(day) = cell.effective_through {
            proof.push(1);
            proof.extend_from_slice(&day.to_le_bytes());
        } else {
            proof.push(0);
        }
        proof.extend_from_slice(&0i128.to_le_bytes());
        proof.extend_from_slice(&0i128.to_le_bytes());
        for _ in 0..3 {
            proof.extend_from_slice(&0u32.to_le_bytes());
        }
        bytes(&mut out, FOLD_DOMAIN);
        out.extend_from_slice(&FOLD_VERSION.to_le_bytes());
        bytes(&mut out, &proof);
    }
    bytes(&mut out, manifest_md(&m, &summary).as_bytes());
    out
}

fn directory() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let dir = std::env::temp_dir().join(format!(
            "fa-witness-balance-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        match std::fs::create_dir(&dir) {
            Ok(()) => return dir,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("create retained diagnostic fixture: {error}"),
        }
    }
}

fn args(cells: &[BalanceScope]) -> (Vec<OsString>, PathBuf) {
    let dir = directory();
    std::fs::write(dir.join("checkpoint"), fixture("empty")).unwrap();
    std::fs::write(dir.join("bundle"), bundle(cells)).unwrap();
    let mut result: Vec<OsString> = ["witness", "bundle"].map(OsString::from).into();
    for (flag, value) in [
        ("--expect-book", "11".repeat(16)),
        ("--expect-branch", "00".repeat(16)),
        ("--expect-policy", "55".repeat(32)),
        ("--publisher-key", hex(&key("publisher"))),
        ("--witness-key", hex(&key("witness_a"))),
        ("--witness-key", hex(&key("witness_b"))),
        ("--quorum", "2".into()),
        ("--expect-scope", "prefix".into()),
        ("--expect-documents", "inline".into()),
        ("--expect-receipt", "optional".into()),
    ] {
        result.extend([flag.into(), value.into()]);
    }
    result.extend([
        "--checkpoint".into(),
        dir.join("checkpoint").into_os_string(),
        "--bundle".into(),
        dir.join("bundle").into_os_string(),
        "--json".into(),
    ]);
    (result, dir)
}

fn set(args: &mut [OsString], flag: &str, value: impl Into<OsString>) {
    let index = args.iter().position(|arg| arg == flag).unwrap();
    args[index + 1] = value.into();
}

fn run(args: &[OsString]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fa-verify"))
        .args(args)
        .output()
        .unwrap()
}

fn result(out: Output, exit: i32) -> String {
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert_eq!(out.status.code(), Some(exit), "{stdout}\n{stderr}");
    assert_eq!(stdout.lines().count(), 1, "one buffered JSON report");
    if exit == 0 {
        assert!(stderr.is_empty());
        assert!(stdout.contains("\"verified\":true"));
        assert!(stdout.contains("\"event\":\"proof_verified\""));
    } else {
        assert!(stdout.contains("\"verified\":false"));
        assert!(!stdout.contains("\"event\":\"proof_verified\""));
    }
    stdout
}

fn exact(mut args: Vec<OsString>, wanted: &[BalanceScope]) -> Vec<OsString> {
    for cell in wanted {
        args.extend(["--expect-balance".into(), request(*cell).into()]);
    }
    args
}

#[test]
fn executable_accepts_exact_reordered_cells_and_does_not_write_inputs() {
    let cells = [cell(10, 1, None), cell(u128::MAX, u32::MAX, Some(i32::MIN))];
    let (input, dir) = args(&cells);
    let input = exact(input, &[cells[1], cells[0]]);
    let before = std::fs::read(dir.join("bundle")).unwrap();
    let json = result(run(&input), 0);
    for field in [
        "\"mode\":\"exact\"",
        "requested_balance_set",
        "requested_balance_amounts",
        "\"effective_through_day\":\"-2147483648\"",
        "\"unit\":\"4294967295\"",
    ] {
        assert!(json.contains(field), "{json}");
    }
    assert!(!json.contains("recipient_balance_claim_set"));
    assert_eq!(std::fs::read(dir.join("bundle")).unwrap(), before);
    assert_eq!(
        std::fs::read(dir.join("checkpoint")).unwrap(),
        fixture("empty")
    );
    assert_eq!(result(run(&input), 0), json);
}

#[test]
fn valid_missing_extra_duplicate_and_wrong_cell_productions_refuse_exact_requests() {
    let wanted = [cell(10, 1, None), cell(20, 1, Some(10))];
    for supplied in [
        vec![],
        vec![wanted[0]],
        vec![wanted[0], wanted[0]],
        vec![wanted[0], cell(21, 1, Some(10))],
        vec![wanted[0], cell(20, 2, Some(10))],
        vec![wanted[0], cell(20, 1, None)],
        vec![wanted[0], wanted[1], cell(30, 1, None)],
    ] {
        let (input, _) = args(&supplied);
        result(run(&input), 0); // genuine proof, but not the recipient's question
        let json = result(run(&exact(input, &wanted)), 8);
        assert!(json.contains("\"name\":\"requested_balance_set\""));
        assert!(json.contains("\"status\":\"fail\""));
    }
}

#[test]
fn requested_gross_columns_are_exact_and_large_mantissas_remain_strings() {
    let c = cell(10, 1, None);
    let (base, _) = args(&[c]);
    let mut good = base.clone();
    good.extend([
        "--expect-balance".into(),
        format!("{}:0:0", request(c)).into(),
    ]);
    result(run(&good), 0);
    for value in [1, i128::MAX] {
        let mut wrong = base.clone();
        wrong.extend([
            "--expect-balance".into(),
            format!("{}:{value}:{value}", request(c)).into(),
        ]);
        let json = result(run(&wrong), 8); // zero net is not zero gross
        assert!(json.contains(&format!("\"debits_mantissa\":\"{value}\"")));
        assert!(json.contains("requested_balance_amounts"));
    }
}

#[test]
fn no_balance_request_and_exactly_no_balances_have_different_results() {
    for cells in [vec![], vec![cell(10, 1, None)]] {
        let (mut input, _) = args(&cells);
        let old = result(run(&input), 0);
        assert!(old.contains("\"balance_request\":{\"mode\":\"not_requested\"}"));
        assert!(old.contains("recipient_balance_claim_set"));
        input.push("--expect-no-balances".into());
        let json = result(run(&input), if cells.is_empty() { 0 } else { 8 });
        assert!(json.contains("\"balance_request\":{\"mode\":\"exact\",\"cells\":[]}"));
        assert!(!json.contains("recipient_balance_claim_set"));
    }
}

#[test]
fn invalid_or_conflicting_requests_refuse_before_missing_checkpoint_io() {
    let (mut base, dir) = args(&[]);
    set(&mut base, "--checkpoint", dir.join("absent"));
    let valid = request(cell(10, 1, None));
    let cases: Vec<Vec<OsString>> = vec![
        vec!["--expect-balance".into()],
        vec!["--expect-balance".into(), "bad".into()],
        vec!["--expect-balance".into(), format!("{valid}:0").into()],
        vec!["--expect-balance".into(), format!("{valid}:1.0:0").into()],
        vec!["--expect-balance".into(), format!("{valid}:-1:0").into()],
        vec![
            "--expect-balance".into(),
            valid.clone().into(),
            "--expect-balance".into(),
            format!("{valid}:0:0").into(),
        ],
        vec!["--expect-no-balances".into(), "--expect-no-balances".into()],
        vec![
            "--expect-no-balances".into(),
            "--expect-balance".into(),
            valid.into(),
        ],
    ];
    for extra in cases {
        let mut input = base.clone();
        input.extend(extra);
        result(run(&input), 2);
    }
    result(run(&base), 5);
}

#[test]
fn help_and_human_reports_expose_exact_cell_requests_without_claiming_freshness() {
    let help = run(&["witness".into(), "bundle".into(), "--help".into()]);
    assert_eq!(help.status.code(), Some(0));
    let text = String::from_utf8(help.stdout).unwrap();
    assert!(text.contains("--expect-no-balances"));
    assert!(text.contains("--expect-balance"));
    let c = cell(10, 1, None);
    let (input, _) = args(&[c]);
    let mut input = exact(input, &[c]);
    input.retain(|arg| arg != "--json");
    let out = run(&input);
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("exactly 1 stock cells"));
    assert!(text.contains("Global freshness"));
    assert!(text.contains("No pin or payload bytes were written"));
}

#[cfg(unix)]
#[test]
#[cfg_attr(
    target_os = "macos",
    ignore = "macOS filesystems refuse non-UTF-8 file names (EILSEQ); exercised on Linux hosts"
)]
fn non_utf8_paths_work_but_non_utf8_balance_scalars_are_not_lossy() {
    use std::os::unix::ffi::OsStringExt;
    let c = cell(10, 1, None);
    let (input, dir) = args(&[c]);
    let mut input = exact(input, &[c]);
    for name in ["bundle", "checkpoint"] {
        let path = dir.join(OsString::from_vec(
            format!("{name}-").bytes().chain([255]).collect(),
        ));
        std::fs::copy(dir.join(name), &path).unwrap();
        set(&mut input, &format!("--{name}"), path.into_os_string());
    }
    result(run(&input), 0);
    set(
        &mut input,
        "--expect-balance",
        OsString::from_vec(vec![255]),
    );
    result(run(&input), 2);
}
