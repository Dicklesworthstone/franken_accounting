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
use std::time::Instant;

use fa_oracles::cases::amount::format_amount;
use fa_oracles::cases::book::{StepDef, StepKind};
use fa_oracles::cases::expect::{Expectation, ExpectationType, Target};
use fa_oracles::cases::log::StepRecord;
use fa_oracles::cases::outsider_kind::{Recomputed, outsider_kind};
use fa_oracles::cases::verify_report::recomputed;
use fa_oracles::json::{self, Json};

use super::lifecycle::as_principal;
use super::reads::{field, key, scale_of};
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
/// A registered unit's id.
fn unit_id_of(unit: &str) -> Option<u32> {
    fa_registry::units_embedded()
        .ok()?
        .into_iter()
        .find(|r| r.code == unit)
        .map(|r| r.id)
}

/// The first check fa-verify did not pass, `<check>: <reason>`.
fn failed_check(stdout: &str) -> String {
    json::parse(stdout.trim())
        .ok()
        .and_then(|report| {
            report
                .get("checks")
                .and_then(Json::as_array)
                .unwrap_or_default()
                .iter()
                .find(|c| c.get("result").and_then(Json::as_str) != Some("pass"))
                .map(|c| {
                    format!(
                        "{}: {}",
                        c.get("check").and_then(Json::as_str).unwrap_or("-"),
                        c.get("reason").and_then(Json::as_str).unwrap_or("-")
                    )
                })
        })
        .unwrap_or_else(|| "no failing check reported".to_string())
}

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

    /// Each T read's outsider check (A12, §12.1), by its read verb's route
    /// ([`outsider_kind`]). On the report route a checkpoint over the head
    /// is created and exported once, then every certificate the read
    /// retained is bundled (`fa bundle produce --certificate`), verified
    /// with the literal `fa-verify report` argv, and replayed (`fa
    /// replay`), whose output must hash to the digest fa-verify recomputed. The recomputations, summed, must equal B. A read
    /// with no value or no certificate, or a verb outside the table, has no
    /// check: its T stays UNRUN.
    pub(crate) fn outsider_reads(&mut self) {
        let case = self.case;
        let Some(set) = case.expectations.as_ref() else {
            return;
        };
        let variant = self.book.stem.as_str();
        let mut wanted: Vec<(&Expectation, Option<&Target>)> = Vec::new();
        for e in set.expectations.iter().filter(|e| {
            e.kind == ExpectationType::T && e.fields.str("book_variant") == Some(variant)
        }) {
            let targets: Vec<&Target> = set.targets_of(&e.id).collect();
            if targets.is_empty() {
                wanted.push((e, None));
            } else {
                wanted.extend(targets.into_iter().map(|t| (e, Some(t))));
            }
        }
        let mut anchor: Option<Result<String, String>> = None;
        for (e, t) in wanted {
            let reference = key(e, t);
            let Some((kind, what)) = outsider_kind(field(e, t, "read_verb").unwrap_or("-")) else {
                continue;
            };
            let certificates = match self.reads.get(&reference) {
                Some(read) if read.value.is_ok() && !read.certificates.is_empty() => {
                    read.certificates.clone()
                }
                _ => continue,
            };
            let checkpoint = anchor.get_or_insert_with(|| self.anchor()).clone();
            let verdict = checkpoint
                .and_then(|c| self.report_route(&reference, e, t, what, &certificates, &c));
            self.read_checks.insert(reference, (kind, verdict));
        }
    }

    /// A checkpoint over the head for the T reads' bundles, exported with
    /// `fa proof signed-checkpoint` for fa-verify's report to check them
    /// against: the exported file's path.
    fn anchor(&mut self) -> Result<String, String> {
        let head = self.head;
        let created = self.call(
            head,
            "outsider-reads",
            "checkpoint",
            vec![
                s("checkpoint"),
                s("create"),
                s("--grant"),
                s("witness"),
                s("--json"),
            ],
        );
        if created
            .str_field("checkpoint_created", "checkpoint_oid")
            .is_none()
        {
            self.lines.push(reproduce(&created));
            return Err(format!(
                "expected a checkpoint over the reads observed exit={} {}",
                created.exit,
                created.refusal_id().unwrap_or_default()
            )
            .trim_end()
            .to_string());
        }
        let file = self.work.join("outsider-reads.checkpoint");
        let exported = self.call(
            head,
            "outsider-reads",
            "proof",
            vec![
                s("proof"),
                s("signed-checkpoint"),
                s("--out"),
                file.display().to_string(),
                s("--json"),
            ],
        );
        if exported.exit != 0 {
            self.lines.push(reproduce(&exported));
            return Err(format!(
                "expected the signed checkpoint exported observed exit={} {}",
                exported.exit,
                exported.refusal_id().unwrap_or_default()
            )
            .trim_end()
            .to_string());
        }
        Ok(file.display().to_string())
    }

    /// One T read's report route ([`Self::outsider_reads`]).
    fn report_route(
        &mut self,
        reference: &str,
        e: &Expectation,
        t: Option<&Target>,
        what: Recomputed,
        certificates: &[String],
        checkpoint: &str,
    ) -> Result<(), String> {
        let (b, unit) = field(e, t, "published")
            .and_then(|f| self.value_of(f))
            .ok_or("expected a published value observed none")?;
        let unit_id =
            unit_id_of(&unit).ok_or_else(|| format!("unit `{unit}` is not registered"))?;
        let target = field(e, t, "read_target").unwrap_or("-");
        let head = self.head;
        let mut sum = 0_i128;
        for oid in certificates {
            let stem = self.work.join(format!("read-{}", self.steps.len()));
            let (fab, receipt, replayed) = (
                stem.with_extension("fab").display().to_string(),
                stem.with_extension("receipt").display().to_string(),
                stem.with_extension("replay"),
            );
            let produced = self.call(
                head,
                reference,
                "bundle",
                vec![
                    s("bundle"),
                    s("produce"),
                    s("--certificate"),
                    format!("C:{oid}"),
                    s("--out"),
                    fab.clone(),
                    s("--receipt-out"),
                    receipt.clone(),
                    s("--json"),
                ],
            );
            self.certificate_kind("Bundle");
            let Some(public_key) = produced.str_field("bundle_produced", "checkpoint_public_key")
            else {
                self.lines.push(reproduce(&produced));
                return Err(format!(
                    "expected a bundle of C:{oid} with its checkpoint key observed exit={} {}",
                    produced.exit,
                    produced.refusal_id().unwrap_or_default()
                )
                .trim_end()
                .to_string());
            };
            // A report bundle is `fa:report-bundle:v1`, which `fa-verify
            // report` authenticates (checkpoint, receipt, records) before it
            // recomputes; `fa-verify bundle` reads `fa:bundle:v1` evidence
            // bundles only and refuses this one (exit 8), so §12.1's `fa-verify
            // bundle` step does not apply to a certificate's bundle.
            let report = self.fa_verify(
                reference,
                "FaVerifyReport",
                vec![
                    s("report"),
                    fab,
                    s("--key"),
                    public_key,
                    s("--checkpoint"),
                    checkpoint.to_string(),
                    s("--receipt"),
                    receipt,
                    s("--json"),
                ],
            );
            if report.exit != 0 {
                return Err(format!(
                    "expected fa-verify report of C:{oid} exit=0 observed exit={} {}",
                    report.exit,
                    failed_check(&report.stdout)
                ));
            }
            let recomputation = recomputed(&report.stdout, what, target, unit_id)?;
            let replay = self.call(
                head,
                reference,
                "replay",
                vec![
                    s("replay"),
                    format!("C:{oid}"),
                    s("--output"),
                    replayed.display().to_string(),
                    s("--json"),
                ],
            );
            let output = match std::fs::read(&replayed) {
                Ok(output) if replay.exit == 0 => output,
                _ => {
                    self.lines.push(reproduce(&replay));
                    return Err(format!(
                        "expected a replayed output of C:{oid} observed exit={} {}",
                        replay.exit,
                        replay.refusal_id().unwrap_or_default()
                    )
                    .trim_end()
                    .to_string());
                }
            };
            let again = fa_verify::blake3::hex(&fa_verify::blake3::hash_parts(
                b"fa:report-output:v1",
                &[&output],
            ));
            if again != recomputation.output_digest {
                return Err(format!(
                    "expected the replay of C:{oid} to hash to the recomputed {} observed {again}",
                    recomputation.output_digest
                ));
            }
            sum = sum
                .checked_add(recomputation.value)
                .ok_or("the recomputations overflow")?;
        }
        if sum == b {
            Ok(())
        } else {
            let scale = scale_of(&unit).unwrap_or(0);
            Err(format!(
                "expected the recomputed {} observed {}",
                format_amount(b, scale),
                format_amount(sum, scale)
            ))
        }
    }

    /// A literal `fa-verify` argv, run in process (`fa_verify::cli::run`)
    /// over the runner's files and logged as a step, like an `fa` call.
    fn fa_verify(
        &mut self,
        reference: &str,
        kind: &str,
        args: Vec<String>,
    ) -> fa_verify::cli::Output {
        let started = Instant::now();
        let out = fa_verify::cli::run(&args, &|path: &str| std::fs::read(path));
        let (argv_redacted, binds) = self.redact(&args);
        self.steps.push(StepRecord {
            case: self.case.header.id.clone(),
            book_variant: self.book.stem.clone(),
            branch_class: None,
            filler_variant: None,
            book_id: self.book_id.clone(),
            step: self.head,
            reference: reference.to_string(),
            verb: "fa-verify".to_string(),
            argv_redacted,
            exit: i128::from(out.exit),
            refusal_id: None,
            finding_procedure: None,
            certificate_kind: Some(kind.to_string()),
            elapsed_ms: i128::try_from(started.elapsed().as_millis()).unwrap_or(i128::MAX),
            binds,
        });
        out
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
