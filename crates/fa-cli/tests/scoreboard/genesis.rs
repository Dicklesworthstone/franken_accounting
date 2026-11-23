//! End-to-end witnesses for the two Genesis read criteria. Each probe posts
//! to its own Genesis book so another scoreboard row cannot supply its result.

use super::{Json, ProbeOutcome, json, setup_fixture_book, tmp_dir};
use std::collections::BTreeMap;
use std::process::Command;

const PERIOD: &str = "FY2026-P03";

fn cli(book: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(env!("CARGO_BIN_EXE_fa"))
        .args(args)
        .args(["--book", book, "--json"])
        .env_remove("FA_BOOK")
        .env_remove("FA_TOKEN")
        .output()
        .map_err(|error| format!("UNRUN could not launch fa {args:?}: {error}"))?;
    if output.status.code().is_none() {
        return Err(format!("UNRUN fa {args:?} interrupted: {}", output.status));
    }
    if !output.status.success() {
        return Err(format!(
            "fa {args:?} returned {}\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    String::from_utf8(output.stdout).map_err(|error| error.to_string())
}

fn event(line: &str, expected: &str) -> Result<Json, String> {
    let envelope = json::parse(line).map_err(|error| format!("{expected}: {error}"))?;
    if envelope.get("event").and_then(Json::as_str) != Some(expected) {
        return Err(format!("expected {expected}: {line}"));
    }
    Ok(envelope)
}

fn data(envelope: &Json) -> Result<&Json, String> {
    envelope
        .get("data")
        .ok_or_else(|| format!("missing event data: {envelope:?}"))
}

fn number(object: &Json, key: &str) -> Result<i128, String> {
    match object.get(key) {
        Some(Json::Int(value)) => Ok(*value),
        _ => Err(format!("missing integer {key}: {object:?}")),
    }
}

fn post_later(vars: &BTreeMap<String, String>) -> Result<i128, String> {
    let output = cli(
        &vars["{book}"],
        &[
            "post",
            "--intent",
            &vars["{sale_intent_2}"],
            "--evidence",
            &vars["{doc_oid}"],
        ],
    )?;
    number(data(&event(&output, "posted")?)?, "recorded_at")
}

fn advance(book: &str) -> Result<Json, String> {
    event(
        &cli(book, &["registers", "advance", "--period", PERIOD])?,
        "registers_advanced",
    )
}

fn current_cells(book: &str, selected: &str, minimum: i128) -> Result<Json, String> {
    // Even an uninitialized or stale cache can emit registers_verified.
    // Read its actual cell comparison and frontier from the journal refold.
    let verified = event(
        &cli(book, &["verify", "registers", "--period", selected])?,
        "registers_verified",
    )?;
    let Some([period]) = data(&verified)?.get("periods").and_then(Json::as_arr) else {
        return Err(format!("missing selected period: {verified:?}"));
    };
    if period.get("period").and_then(Json::as_str) != Some(selected)
        || period.get("cache_status").and_then(Json::as_str) != Some("verified")
        || period.get("green") != Some(&Json::Bool(true))
        || period.get("stale") != Some(&Json::Bool(false))
        || number(period, "lag_entries")? != 0
        || number(period, "verified_through")? < minimum
        || number(period, "cells_checked")? == 0
        || period.get("stored_digest").and_then(Json::as_str).is_none()
        || period.get("stored_digest") != period.get("refold_digest")
    {
        return Err(format!(
            "cache does not match the current journal through {minimum}: {period:?}"
        ));
    }
    Ok(period.clone())
}

fn advancing_registers(vars: &BTreeMap<String, String>) -> Result<(), String> {
    let book = &vars["{book}"];
    let baseline = advance(book)?;
    let before = number(data(&baseline)?, "through")?;
    let posted = post_later(vars)?;
    let advanced = advance(book)?;
    let result = data(&advanced)?;
    let through = number(result, "through")?;
    if !(before < posted && posted <= through)
        || number(result, "from")? != before
        || result.get("wrote") != Some(&Json::Bool(true))
        || number(result, "entries_decoded")? == 0
    {
        return Err(format!(
            "register cursor did not consume post {posted} after {before}: {result:?}"
        ));
    }
    let verified = current_cells(book, PERIOD, through)?;
    // This fixture has posted debit and credit cells and no pending entries.
    // Require every published cell to agree with the literal fold.
    if number(&verified, "verified_through")? != through
        || number(&verified, "cells_checked")? != number(result, "cells")?
        || result.get("fold_digest") != verified.get("refold_digest")
    {
        return Err(format!(
            "advanced cells differ from the refold: {result:?} / {verified:?}"
        ));
    }
    Ok(())
}

pub(super) fn registers() -> ProbeOutcome {
    let vars = setup_fixture_book(&tmp_dir("genesis-registers"));
    ProbeOutcome::from_check(advancing_registers(&vars), "registers_refolded")
}

fn issued_report(output: &str) -> Result<(&str, Json, String), String> {
    let (original, retained) = output
        .split_once('\n')
        .ok_or("missing trial-balance line")?;
    if retained.is_empty() {
        return Err("trial balance emitted no retained certificate".into());
    }
    let report = event(original, "trial_balance")?;
    let certificate = event(retained, "report_certificate")?;
    let oid = data(&certificate)?
        .get("oid")
        .and_then(Json::as_str)
        .ok_or("missing retained certificate oid")?;
    if report.get("certificate").and_then(Json::as_str) != Some(oid)
        || certificate.get("certificate").and_then(Json::as_str) != Some(oid)
        || data(&certificate)?
            .get("output_format")
            .and_then(Json::as_str)
            != Some("fa:trial-balance:v1")
        || number(data(&report)?, "known_at")? != number(data(&certificate)?, "known_at")?
    {
        return Err(format!(
            "report and retained certificate disagree: {output}"
        ));
    }
    Ok((original, report, format!("C:{oid}")))
}

fn replay_after_post(vars: &BTreeMap<String, String>) -> Result<(), String> {
    let book = &vars["{book}"];
    let output = cli(book, &["tb", "--period", PERIOD, "--certify"])?;
    let (original, report, certificate) = issued_report(&output)?;
    let posted = post_later(vars)?;
    let current = event(&cli(book, &["tb", "--period", PERIOD])?, "trial_balance")?;
    let before = data(&report)?;
    let after = data(&current)?;
    let original_rows = before
        .get("rows")
        .and_then(Json::as_arr)
        .ok_or("missing original rows")?;
    let current_rows = after
        .get("rows")
        .and_then(Json::as_arr)
        .ok_or("missing current rows")?;
    if posted <= number(before, "known_at")?
        || number(after, "known_at")? < posted
        || original_rows.is_empty()
        || original_rows == current_rows
    {
        return Err(format!(
            "post {posted} failed to change this selected trial balance"
        ));
    }
    let replay = cli(book, &["replay", &certificate])?;
    if replay != format!("{original}\n") {
        return Err(format!(
            "replay of {certificate} changed the issued bytes\nissued: {original}\nreplay: {replay}"
        ));
    }
    Ok(())
}

pub(super) fn certified_trial_balance() -> ProbeOutcome {
    let vars = setup_fixture_book(&tmp_dir("genesis-certificate"));
    ProbeOutcome::from_check(replay_after_post(&vars), "trial_balance_replayed")
}

#[test]
fn genesis_scoreboard_requires_advanced_matching_registers() {
    let vars = setup_fixture_book(&tmp_dir("genesis-stale-registers"));
    let book = &vars["{book}"];
    // The fixture opens April but only materializes March.
    let missing = current_cells(book, "FY2026-P04", 0).unwrap_err();
    assert!(missing.contains("uninitialized"), "{missing}");
    advance(book).unwrap();
    let posted = post_later(&vars).unwrap();
    let error = current_cells(book, PERIOD, posted).unwrap_err();
    assert!(error.contains("cache does not match"), "{error}");
    let advanced = advance(book).unwrap();
    let through = number(data(&advanced).unwrap(), "through").unwrap();
    assert!(through >= posted);
    current_cells(book, PERIOD, through).unwrap();
}

#[test]
fn genesis_scoreboard_requires_replay_of_issued_trial_balance() {
    let vars = setup_fixture_book(&tmp_dir("genesis-uncertified"));
    let plain = cli(&vars["{book}"], &["tb", "--period", PERIOD]).unwrap();
    assert!(event(&plain, "trial_balance").is_ok());
    assert_eq!(
        issued_report(&plain).unwrap_err(),
        "trial balance emitted no retained certificate"
    );
    replay_after_post(&vars).unwrap();
}
