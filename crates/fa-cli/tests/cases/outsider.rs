//! The outsider stage of a book run (docs/FORENSIC_CASE_STUDIES_PLAN.md
//! §3.3 steps 8 and 9, §12.1, §12.7; bead fa-yugf.19, A8a; A12 extends it).
//!
//! A `checkpoint` step creates the book's signed checkpoint (`fa checkpoint
//! create --grant witness`). After the history, every book proves its
//! integrity (`verify_book`, below), and a book with a checkpoint also
//! proves the others, each a check of its own:
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
//!   refold, as crates/fa-cli/tests/cli.rs's verify-book test does;
//! - `witness` and `append_only` (A12): a `checkpoint_witness` step's
//!   cosignature before the case, and the restated book proved to extend
//!   it ([`BookRun::checkpoint_witness`]).
//!
//! Each T read's outsider route (A12) is checked apart, per row
//! ([`BookRun::outsider_reads`]).
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

/// The examiner witness's key and its cosignature of a checkpoint before the
/// case (A12, §12.7).
#[derive(Clone, Debug)]
pub struct Witness {
    /// The witness key file.
    pub key: String,
    pub public_key: String,
    /// The cosigned checkpoint, the statement a later cosignature extends.
    pub statement: String,
    /// The cosigned state's oid.
    pub state: String,
    /// The book's checkpoint public key.
    pub book_key: String,
}

/// The role that cosigns checkpoints when a step names none.
const WITNESS: &str = "examiner-witness";

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
        if let Some(state) = call.str_field("checkpoint_created", "oid") {
            self.checkpoints.insert(step.reference.clone(), state);
        }
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

    /// A `checkpoint_witness` step (§12.7): the examiner witness makes a key
    /// (`fa checkpoint witness-key`) and cosigns the earlier checkpoint its
    /// `ref` names (`fa checkpoint witness --state`), the statement a later
    /// cosignature must extend.
    pub(crate) fn checkpoint_witness(&mut self, step: &StepDef) {
        let verdict = self.cosign(step);
        self.outsider_check("witness", verdict.map(|()| "cosigned".to_string()));
    }

    fn cosign(&mut self, step: &StepDef) -> Result<(), String> {
        let state = self
            .checkpoints
            .get(&step.reference)
            .cloned()
            .ok_or_else(|| format!("expected a checkpoint {} observed none", step.reference))?;
        let principal = step.principal.as_deref().unwrap_or(WITNESS).to_string();
        let key = self.work.join("witness.key").display().to_string();
        let made = self.call(
            step.seq,
            &step.reference,
            "checkpoint",
            vec![
                s("checkpoint"),
                s("witness-key"),
                s("--out"),
                key.clone(),
                s("--json"),
            ],
        );
        let Some(public_key) = made.str_field("witness_key_created", "public_key") else {
            self.lines.push(reproduce(&made));
            return Err(format!(
                "expected a witness key (step {}) observed exit={} {}",
                step.seq,
                made.exit,
                made.refusal_id().unwrap_or_default()
            ));
        };
        let statement = self
            .work
            .join(format!("{}.witness", step.reference))
            .display()
            .to_string();
        let cosigned = self.call(
            step.seq,
            &step.reference,
            "checkpoint",
            vec![
                s("checkpoint"),
                s("witness"),
                s("--key"),
                key.clone(),
                s("--state"),
                state.clone(),
                s("--out"),
                statement.clone(),
                s("--grant"),
                s("witness"),
                s("--as"),
                principal,
                s("--json"),
            ],
        );
        let Some(book_key) = cosigned.str_field("checkpoint_witnessed", "book_public_key") else {
            self.lines.push(reproduce(&cosigned));
            return Err(format!(
                "expected the witness's cosignature (step {}) observed exit={} {}",
                step.seq,
                cosigned.exit,
                cosigned.refusal_id().unwrap_or_default()
            ));
        };
        self.witness = Some(Witness {
            key,
            public_key,
            statement,
            state,
            book_key,
        });
        Ok(())
    }

    /// The append-only witness (A12, §12.7), after the history of a book
    /// whose examiner witness cosigned an earlier checkpoint:
    /// - the witness cosigns a fresh checkpoint of the restated book with
    ///   `--previous`, which the book must prove extends the statement it
    ///   cosigned, and `fa-verify checkpoint --quorum 1` accepts it;
    /// - `fa proof consistency` from the cosigned state to the fresh one, and
    ///   `fa proof inclusion` of every entry a delta restates, verify with
    ///   `fa-verify` against the exported signed checkpoints: the as-filed
    ///   entries are still in the restated book;
    /// - the harness-only twins are refused: a rollback (the restated
    ///   statement as `--previous` for the as-filed state, FA-REF-124, exit
    ///   8), and a statement this witness cosigned on another book, which the
    ///   book refuses as no history it signed (FA-REF-100, exit 2; the other
    ///   book's own calls are setup, not case steps).
    fn append_only(&mut self) -> Result<String, String> {
        let witness = self.witness.clone().ok_or("no witness")?;
        let head = self.head;
        let reference = "append-only";
        let fail = |what: &str, call: &Call| {
            format!(
                "expected {what} observed exit={} {}",
                call.exit,
                call.refusal_id().unwrap_or_default()
            )
            .trim_end()
            .to_string()
        };
        let created = self.call(
            head,
            reference,
            "checkpoint",
            vec![
                s("checkpoint"),
                s("create"),
                s("--grant"),
                s("witness"),
                s("--json"),
            ],
        );
        let Some(after) = created.str_field("checkpoint_created", "oid") else {
            self.lines.push(reproduce(&created));
            return Err(fail("a checkpoint of the restated book", &created));
        };
        let extended_statement = self.work.join("restated.witness").display().to_string();
        let extended = extended_statement.clone();
        let cosigned = self.call(
            head,
            reference,
            "checkpoint",
            vec![
                s("checkpoint"),
                s("witness"),
                s("--key"),
                witness.key.clone(),
                s("--previous"),
                witness.statement.clone(),
                s("--state"),
                after.clone(),
                s("--out"),
                extended.clone(),
                s("--grant"),
                s("witness"),
                s("--as"),
                s(WITNESS),
                s("--json"),
            ],
        );
        if cosigned.exit != 0 {
            self.lines.push(reproduce(&cosigned));
            return Err(fail(
                "the restated book cosigned with --previous",
                &cosigned,
            ));
        }
        let quorum = self.fa_verify(
            reference,
            "FaVerifyCheckpoint",
            vec![
                s("checkpoint"),
                extended,
                s("--key"),
                witness.book_key.clone(),
                s("--witness"),
                witness.public_key.clone(),
                s("--quorum"),
                s(1),
                s("--json"),
            ],
        );
        if quorum.exit != 0 {
            return Err(format!(
                "expected fa-verify checkpoint at quorum 1 exit=0 observed exit={} {}",
                quorum.exit,
                failed_check(&quorum.stdout)
            ));
        }
        let mut signed = Vec::new();
        for (name, state) in [("as-filed", &witness.state), ("restated", &after)] {
            let file = self
                .work
                .join(format!("{name}.checkpoint"))
                .display()
                .to_string();
            let exported = self.call(
                head,
                reference,
                "proof",
                vec![
                    s("proof"),
                    s("signed-checkpoint"),
                    s("--state"),
                    state.clone(),
                    s("--out"),
                    file.clone(),
                    s("--json"),
                ],
            );
            if exported.exit != 0 {
                self.lines.push(reproduce(&exported));
                return Err(fail(&format!("the {name} signed checkpoint"), &exported));
            }
            signed.push(file);
        }
        let consistency = self
            .work
            .join("append-only.consistency")
            .display()
            .to_string();
        let proved = self.call(
            head,
            reference,
            "proof",
            vec![
                s("proof"),
                s("consistency"),
                s("--state"),
                witness.state.clone(),
                s("--next-state"),
                after.clone(),
                s("--out"),
                consistency.clone(),
                s("--json"),
            ],
        );
        if proved.exit != 0 {
            self.lines.push(reproduce(&proved));
            return Err(fail("a consistency proof", &proved));
        }
        let verified = self.fa_verify(
            reference,
            "FaVerifyConsistency",
            vec![
                s("consistency"),
                consistency,
                s("--trusted"),
                signed[0].clone(),
                s("--claimed"),
                signed[1].clone(),
                s("--key"),
                witness.book_key.clone(),
                s("--json"),
            ],
        );
        if verified.exit != 0 {
            return Err(format!(
                "expected fa-verify consistency exit=0 observed exit={} {}",
                verified.exit,
                failed_check(&verified.stdout)
            ));
        }
        // Every entry a delta restates (the as-filed entries) is still
        // included in the restated book.
        let restated: Vec<String> = self
            .book
            .intents
            .iter()
            .filter(|i| i.is_delta())
            .filter_map(|i| i.target.as_ref().and_then(|t| self.vids.get(t)).cloned())
            .collect();
        if restated.is_empty() {
            return Err("expected an entry a delta restates observed none".into());
        }
        for (n, entry) in restated.iter().enumerate() {
            let proof = self
                .work
                .join(format!("append-only-{n}.inclusion"))
                .display()
                .to_string();
            let included = self.call(
                head,
                reference,
                "proof",
                vec![
                    s("proof"),
                    s("inclusion"),
                    s("--entry"),
                    entry.clone(),
                    s("--state"),
                    after.clone(),
                    s("--out"),
                    proof.clone(),
                    s("--json"),
                ],
            );
            if included.exit != 0 {
                self.lines.push(reproduce(&included));
                return Err(fail(&format!("an inclusion proof of {entry}"), &included));
            }
            let verified = self.fa_verify(
                reference,
                "FaVerifyInclusion",
                vec![
                    s("inclusion"),
                    proof,
                    s("--checkpoint"),
                    signed[1].clone(),
                    s("--key"),
                    witness.book_key.clone(),
                    s("--json"),
                ],
            );
            if verified.exit != 0 {
                return Err(format!(
                    "expected fa-verify inclusion of {entry} exit=0 observed exit={} {}",
                    verified.exit,
                    failed_check(&verified.stdout)
                ));
            }
        }
        // The twins. A rollback: the restated statement as `--previous` for
        // the as-filed state, which does not extend it (FA-REF-124). And the
        // witness's statement on another book, which this book refuses as
        // no history it signed (FA-REF-100, exit 2) before any extension
        // proof.
        let rollback = self.twin(
            reference,
            &witness,
            &extended_statement,
            Some(&witness.state),
            "rollback",
        );
        if rollback != (Some("FA-REF-124".to_string()), 8) {
            return Err(format!(
                "expected the as-filed state cosigned with the restated --previous refused FA-REF-124 exit=8 observed {} exit={}",
                rollback.0.as_deref().unwrap_or("admitted"),
                rollback.1
            ));
        }
        let other = self.other_book_statement(&witness)?;
        let foreign = self.twin(reference, &witness, &other, None, "foreign");
        if foreign != (Some("FA-REF-100".to_string()), 2) {
            return Err(format!(
                "expected another book's statement as --previous refused FA-REF-100 exit=2 observed {} exit={}",
                foreign.0.as_deref().unwrap_or("admitted"),
                foreign.1
            ));
        }
        Ok(format!(
            "ok:inclusion={}:rollback=FA-REF-124:foreign=FA-REF-100",
            restated.len()
        ))
    }

    /// A twin cosignature that must be refused: `--previous` set to
    /// `previous`, at `state` when given. Its (refusal, exit); an unexpected
    /// outcome also prints the argv to reproduce.
    fn twin(
        &mut self,
        reference: &str,
        witness: &Witness,
        previous: &str,
        state: Option<&str>,
        name: &str,
    ) -> (Option<String>, i32) {
        let mut args = vec![
            s("checkpoint"),
            s("witness"),
            s("--key"),
            witness.key.clone(),
            s("--previous"),
            previous.to_string(),
        ];
        if let Some(state) = state {
            args.extend([s("--state"), state.to_string()]);
        }
        args.extend([
            s("--out"),
            self.work
                .join(format!("{name}.witness"))
                .display()
                .to_string(),
            s("--grant"),
            s("witness"),
            s("--as"),
            s(WITNESS),
            s("--json"),
        ]);
        let call = self.call(self.head, reference, "checkpoint", args);
        if call.exit == 0 {
            self.lines.push(reproduce(&call));
        }
        (call.refusal_id(), call.exit)
    }

    /// The witness's cosignature of a checkpoint of another, fresh book with
    /// the same calendar (harness setup for the FA-REF-124 twin).
    fn other_book_statement(&mut self, witness: &Witness) -> Result<String, String> {
        let dir = self.work.join("other-book");
        let header = &self.book.book;
        let run = |args: &[&str]| {
            super::run::fa(
                &dir,
                &args.iter().map(|a| (*a).to_string()).collect::<Vec<_>>(),
            )
        };
        let periods = self.work.join("periods.json").display().to_string();
        let created = run(&[
            "book",
            "create",
            "--name",
            "other-book",
            "--base-unit",
            &header.base_unit,
            "--calendar",
            "custom",
            "--periods",
            &periods,
            "--opening-date",
            &header.opening_date,
            "--json",
        ]);
        let checkpointed = run(&["checkpoint", "create", "--grant", "witness", "--json"]);
        let statement = self.work.join("other-book.witness").display().to_string();
        let cosigned = run(&[
            "checkpoint",
            "witness",
            "--key",
            &witness.key,
            "--out",
            &statement,
            "--grant",
            "witness",
            "--json",
        ]);
        for call in [&created, &checkpointed, &cosigned] {
            if call.exit != 0 {
                self.lines.push(reproduce(call));
                return Err(format!(
                    "expected the other book's witnessed checkpoint observed exit={} {}",
                    call.exit,
                    call.refusal_id().unwrap_or_default()
                ));
            }
        }
        Ok(statement)
    }

    /// The outsider stage, after the history of a book with a checkpoint.
    pub(crate) fn outsider(&mut self) {
        let checkpointed = self
            .book
            .steps
            .iter()
            .any(|x| x.step_kind() == Some(StepKind::Checkpoint));
        if checkpointed && let Err(why) = self.bundle_and_replay() {
            self.outsider_check("bundle", Err(why));
        }
        // Book integrity runs on every book variant (§12.7, A12 step 5);
        // the bundle, replay and witness checks need the book's checkpoint.
        let verdict = self.verify_book();
        self.outsider_check("verify_book", verdict);
        if self.witness.is_some() {
            let verdict = self.append_only();
            self.outsider_check("append_only", verdict);
        }
        if let Some(o) = &self.outsider {
            self.lines.push(o.line(&self.book.stem));
        }
    }

    /// Each T read's outsider check (A12, §12.1), by its read verb's route
    /// ([`outsider_kind`]). On the report route a checkpoint over the head
    /// is created and exported once, then every certificate the read
    /// retained is bundled (`fa bundle produce --certificate`), verified
    /// with the literal `fa-verify report` argv, and replayed (`fa
    /// replay`), whose output must hash to the digest fa-verify recomputed.
    /// The recomputations, summed, must equal B. A read
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

    /// Each recorded finding run's outsider replay (A12, §12.1, D reads),
    /// recipient-bound: `fa finding export --certificate C:<run>
    /// --export-format canonical --include-reviews --known-at <head>` writes
    /// its workpaper with a review appendix fixed at the head, and `fa
    /// finding replay <workpaper> --certificate C:<run> --known-at <head>`
    /// must re-execute it against retained native evidence to the same
    /// certified run and review cutoff. (A plain canonical workpaper replayed
    /// with `--known-at` is refused FA-REF-150: that flag names a review
    /// cutoff, not the run's sequence.)
    pub(crate) fn finding_replays(&mut self) {
        let runs: Vec<(String, String)> = self
            .runs
            .iter()
            .map(|(procedure, r)| (procedure.clone(), r.certificate.clone()))
            .collect();
        let cutoff = self.head;
        for (procedure, certificate) in runs {
            let workpaper = self
                .work
                .join(format!("{procedure}.workpaper"))
                .display()
                .to_string();
            let exported = self.call(
                self.head,
                &procedure,
                "finding",
                vec![
                    s("finding"),
                    s("export"),
                    s("--certificate"),
                    format!("C:{certificate}"),
                    s("--export-format"),
                    s("canonical"),
                    s("--include-reviews"),
                    s("--known-at"),
                    s(cutoff),
                    s("--out"),
                    workpaper.clone(),
                    s("--json"),
                ],
            );
            let verdict = if exported.exit == 0 {
                let replayed = self.call(
                    self.head,
                    &procedure,
                    "finding",
                    vec![
                        s("finding"),
                        s("replay"),
                        workpaper,
                        s("--certificate"),
                        format!("C:{certificate}"),
                        s("--known-at"),
                        s(cutoff),
                        s("--json"),
                    ],
                );
                self.certificate_kind("FindingRun");
                if replayed.exit == 0 {
                    Ok(())
                } else {
                    self.lines.push(reproduce(&replayed));
                    Err(format!(
                        "expected the workpaper replayed exit=0 observed exit={} {}",
                        replayed.exit,
                        replayed.refusal_id().unwrap_or_default()
                    )
                    .trim_end()
                    .to_string())
                }
            } else {
                self.lines.push(reproduce(&exported));
                Err(format!(
                    "expected a canonical workpaper exported observed exit={} {}",
                    exported.exit,
                    exported.refusal_id().unwrap_or_default()
                )
                .trim_end()
                .to_string())
            };
            self.run_replays.insert(procedure, verdict);
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
