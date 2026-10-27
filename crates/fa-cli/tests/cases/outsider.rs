//! The outsider stage of a book run (docs/FORENSIC_CASE_STUDIES_PLAN.md
//! §3.3 steps 8 and 9, §12.1, §12.7; bead fa-yugf.19, A8a; A12 extends it).
//!
//! A `checkpoint` step creates the book's signed checkpoint (`fa checkpoint
//! create --grant witness`). After the history, a book that has one also
//! proves four things, each a check of its own:
//! - `bundle`: the balance sheet of its first period, certified, then a
//!   checkpoint over the certificate's known-at (a report bundle's
//!   checkpoint must authenticate the prefix through it, FA-REF-126), then
//!   the report bundle (`fa bundle produce --certificate`), verified in
//!   process by `fa_verify::verify_report` with the checkpoint key and the
//!   production receipt the event names, whose independently recomputed
//!   output digest must equal the certificate's;
//! - `replay`: `fa replay` of that certificate writes output whose bytes
//!   hash, under the report-output domain, to the digest the certificate
//!   recorded when it was retained (byte equality within the run, FA-INV-11);
//! - `verify_book`: each created period's register cache advanced (`fa
//!   registers advance`), then `fa verify book --json` exits 0 and reports
//!   green (exit 8 fails the case, whatever its rows say, §12.7). A cache
//!   never advanced in a period with postings reads as corrupt today
//!   (fa-0hs4.5), so the check is that the maintained cache equals the
//!   refold, as crates/fa-cli/tests/cli.rs's verify-book test does.
//!
//! A failed check fails the case even when every row reads PASS (§12.1: "a
//! case whose bundle fails verification fails"). The run prints one
//! `OUTSIDER <variant> <check>=<verdict>...` line.

use std::cell::Cell;

use fa_oracles::cases::book::{StepDef, StepKind};
use fa_oracles::json::Json;

use super::lifecycle::as_principal;
use super::run::{BookRun, Call, reproduce, s};

thread_local! {
    /// Test-only: flip one byte of the produced bundle before it is
    /// verified (the byte-flip negative).
    pub static FLIP_BUNDLE_BYTE: Cell<bool> = const { Cell::new(false) };
    /// Test-only: the exit `fa verify book` is taken to have returned (the
    /// binary offers no way to corrupt a book from the CLI).
    pub static FORCE_VERIFY_BOOK_EXIT: Cell<Option<i32>> = const { Cell::new(None) };
}

/// What the outsider stage observed: each check and its verdict, in order.
#[derive(Clone, Debug, Default)]
pub struct Outsider {
    pub checks: Vec<(String, Result<String, String>)>,
}

impl Outsider {
    /// Every check passed.
    #[must_use]
    pub fn ok(&self) -> bool {
        self.checks.iter().all(|(_, r)| r.is_ok())
    }

    /// `OUTSIDER <variant> <check>=<verdict>...`, a failure as
    /// `<check>=fail(<why>)`.
    #[must_use]
    pub fn line(&self, variant: &str) -> String {
        let mut line = format!("OUTSIDER {variant}");
        for (check, verdict) in &self.checks {
            match verdict {
                Ok(v) => line.push_str(&format!(" {check}={v}")),
                Err(why) => line.push_str(&format!(" {check}=fail({why})")),
            }
        }
        line
    }
}

/// Each target `fa verify book` did not pass, `<target>:<verdict>:<detail>`,
/// and for the registers target each red period (its cache status, lag,
/// and drift and projection-error counts).
fn failed_targets(call: &Call) -> Vec<String> {
    let text = |j: &Json, k: &str| j.get(k).and_then(Json::as_str).unwrap_or("-").to_string();
    let mut out: Vec<String> = call
        .array_field("book_verification", "targets")
        .iter()
        .filter(|t| {
            !matches!(
                t.get("verdict").and_then(Json::as_str),
                Some("pass" | "skipped")
            )
        })
        .map(|t| {
            format!(
                "{}:{}:{}",
                text(t, "target"),
                text(t, "verdict"),
                text(t, "detail")
            )
        })
        .collect();
    let checks: Vec<Json> = call
        .observations
        .iter()
        .filter(|o| o.event == "registers_verified")
        .filter_map(|o| {
            o.field("periods")
                .and_then(Json::as_array)
                .map(<[Json]>::to_vec)
        })
        .flatten()
        .collect();
    for p in checks {
        if p.get("green").and_then(Json::as_bool) == Some(true) {
            continue;
        }
        let count = |k: &str| p.get(k).and_then(Json::as_array).map_or(0, <[Json]>::len);
        out.push(format!(
            "registers {} cache={} stale={} verified_through={} lag={} drift={} pending_drift={} first_drift={} projection_errors={:?}",
            text(&p, "period"),
            text(&p, "cache_status"),
            p.get("stale").and_then(Json::as_bool).unwrap_or(false),
            p.get("verified_through").and_then(Json::as_int).map_or_else(|| "none".to_string(), |v| v.to_string()),
            p.get("lag_entries").and_then(Json::as_int).unwrap_or(0),
            count("drift"),
            count("pending_drift"),
            p.get("drift")
                .and_then(Json::as_array)
                .and_then(<[Json]>::first)
                .map_or_else(|| "-".to_string(), ToString::to_string),
            p.get("projection_errors")
                .and_then(Json::as_array)
                .unwrap_or_default()
                .iter()
                .filter_map(Json::as_str)
                .collect::<Vec<_>>()
        ));
    }
    out
}

/// `bytes` decoded from hex, if they are hex.
fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

impl BookRun<'_> {
    fn outsider_check(&mut self, check: &str, verdict: Result<String, String>) {
        self.outsider
            .get_or_insert_with(Outsider::default)
            .checks
            .push((check.to_string(), verdict));
    }

    /// A `checkpoint` step: the book's signed checkpoint.
    pub(crate) fn checkpoint(&mut self, step: &StepDef) {
        let args = vec![s("checkpoint"), s("create"), s("--grant"), s("witness")];
        let call = self.call(
            step.seq,
            &step.reference,
            "checkpoint",
            as_principal(step, args),
        );
        let verdict = match call.str_field("checkpoint_created", "checkpoint_oid") {
            Some(_) => Ok("created".to_string()),
            None => {
                self.lines.push(reproduce(&call));
                Err(format!(
                    "expected a checkpoint (step {}) observed exit={} {}",
                    step.seq,
                    call.exit,
                    call.refusal_id().unwrap_or_default()
                ))
            }
        };
        self.outsider_check("checkpoint", verdict);
    }

    /// The outsider stage, after the history of a book with a checkpoint.
    pub(crate) fn outsider(&mut self) {
        let checkpointed = self
            .book
            .steps
            .iter()
            .any(|x| x.step_kind() == Some(StepKind::Checkpoint));
        if !checkpointed {
            return;
        }
        let bundle = self.bundle_and_replay();
        if let Err(why) = bundle {
            self.outsider_check("bundle", Err(why));
        }
        let verdict = self.verify_book();
        self.outsider_check("verify_book", verdict);
        if let Some(o) = &self.outsider {
            self.lines.push(o.line(&self.book.stem));
        }
    }

    /// The certified balance sheet of the book's first period, bundled and
    /// verified in process, then replayed.
    fn bundle_and_replay(&mut self) -> Result<(), String> {
        let first = self
            .book
            .periods
            .first()
            .and_then(|p| self.periods.get(&p.code).cloned())
            .ok_or("expected a created period observed none")?;
        let head = self.head;
        let certified = self.call(
            head,
            "outsider",
            "statement",
            vec![
                s("statement"),
                s("balance-sheet"),
                s("--for"),
                first,
                s("--certify"),
                s("--json"),
            ],
        );
        self.certificate_kind("BalanceSheet");
        let (Some(oid), Some(digest)) = (
            certified.str_field("report_certificate", "oid"),
            certified.str_field("report_certificate", "output_digest"),
        ) else {
            self.lines.push(reproduce(&certified));
            return Err(format!(
                "expected a certified balance sheet observed exit={}",
                certified.exit
            ));
        };
        self.bind(
            &oid,
            "$C_BS_outsider".into(),
            "report_certificate.oid",
            head,
            "outsider",
        );
        let anchor = self.call(
            head,
            "outsider",
            "checkpoint",
            vec![
                s("checkpoint"),
                s("create"),
                s("--grant"),
                s("witness"),
                s("--json"),
            ],
        );
        if anchor
            .str_field("checkpoint_created", "checkpoint_oid")
            .is_none()
        {
            self.lines.push(reproduce(&anchor));
            return Err(format!(
                "expected a checkpoint over the certificate observed exit={} {}",
                anchor.exit,
                anchor.refusal_id().unwrap_or_default()
            ));
        }
        let fab = self.work.join("outsider.fab");
        let receipt = self.work.join("outsider.receipt");
        let produced = self.call(
            head,
            "outsider",
            "bundle",
            vec![
                s("bundle"),
                s("produce"),
                s("--certificate"),
                format!("C:{oid}"),
                s("--out"),
                fab.display().to_string(),
                s("--receipt-out"),
                receipt.display().to_string(),
                s("--json"),
            ],
        );
        self.certificate_kind("Bundle");
        let Some(key) = produced
            .str_field("bundle_produced", "checkpoint_public_key")
            .as_deref()
            .and_then(unhex)
            .and_then(|k| <[u8; 32]>::try_from(k).ok())
        else {
            self.lines.push(reproduce(&produced));
            return Err(format!(
                "expected a bundle with its checkpoint key observed exit={} {}",
                produced.exit,
                produced.refusal_id().unwrap_or_default()
            ));
        };
        let (mut bytes, receipt_bytes) = match (std::fs::read(&fab), std::fs::read(&receipt)) {
            (Ok(b), Ok(r)) => (b, r),
            (Err(e), _) | (_, Err(e)) => return Err(format!("read the bundle: {e}")),
        };
        if FLIP_BUNDLE_BYTE.with(Cell::get)
            && let Some(last) = bytes.last_mut()
        {
            *last ^= 1;
        }
        let verdict =
            match fa_verify::report::verify_report(&bytes, &[key], None, Some(&receipt_bytes)) {
                Ok(report) => {
                    let recomputed = fa_verify::blake3::hex(&report.output_digest);
                    if recomputed == digest {
                        Ok("verified".to_string())
                    } else {
                        Err(format!(
                            "expected the recomputed output digest {digest} observed {recomputed}"
                        ))
                    }
                }
                Err(e) => Err(format!("the report bundle did not verify: {e}")),
            };
        self.outsider_check("bundle", verdict);
        let out = self.work.join("outsider.replay");
        let replayed = self.call(
            head,
            "outsider",
            "replay",
            vec![
                s("replay"),
                format!("C:{oid}"),
                s("--output"),
                out.display().to_string(),
                s("--json"),
            ],
        );
        let verdict = match std::fs::read(&out) {
            Ok(output) if replayed.exit == 0 => {
                let again = fa_verify::blake3::hex(&fa_verify::blake3::hash_parts(
                    b"fa:report-output:v1",
                    &[&output],
                ));
                if again == digest {
                    Ok("identical".to_string())
                } else {
                    Err(format!(
                        "expected the replayed output to hash to {digest} observed {again}"
                    ))
                }
            }
            _ => {
                self.lines.push(reproduce(&replayed));
                Err(format!(
                    "expected a replayed output observed exit={} {}",
                    replayed.exit,
                    replayed.refusal_id().unwrap_or_default()
                ))
            }
        };
        self.outsider_check("replay", verdict);
        Ok(())
    }

    /// Each created period's registers advanced, then `fa verify book
    /// --json`: exit 0 and green.
    fn verify_book(&mut self) -> Result<String, String> {
        let head = self.head;
        let codes: Vec<String> = self.periods.values().cloned().collect();
        for code in codes {
            let args = vec![
                s("registers"),
                s("advance"),
                s("--period"),
                code.clone(),
                s("--json"),
            ];
            let advanced = self.call(head, "outsider", "registers", args);
            if advanced.exit != 0 {
                self.lines.push(reproduce(&advanced));
                return Err(format!(
                    "expected {code}'s registers advanced observed exit={} {}",
                    advanced.exit,
                    advanced.refusal_id().unwrap_or_default()
                ));
            }
        }
        let call = self.call(
            head,
            "outsider",
            "verify",
            vec![s("verify"), s("book"), s("--json")],
        );
        let exit = FORCE_VERIFY_BOOK_EXIT.with(Cell::get).unwrap_or(call.exit);
        let green = call
            .event("book_verification")
            .and_then(|o| o.field("green"))
            .and_then(Json::as_bool);
        match (exit, green) {
            (0, Some(true)) => Ok("green".to_string()),
            _ => {
                self.lines.push(reproduce(&call));
                let mut why = format!(
                    "expected fa verify book exit=0 green observed exit={exit} green={}",
                    green.map_or_else(|| "none".to_string(), |g| g.to_string())
                );
                for failed in failed_targets(&call) {
                    why.push_str(&format!("; {failed}"));
                }
                Err(why)
            }
        }
    }
}
