//! History steps of the restatement life cycle
//! (docs/FORENSIC_CASE_STUDIES_PLAN.md §3.3 steps 4 and 5; bead fa-yugf.16,
//! A7b). So far, the `issue` step.
//!
//! An `issue` step certifies its period's balance sheet, plans that
//! certificate's StatementIssuance to the SEC citing the step's filing stub
//! in the step principal's hand, has each of the step's approvers approve
//! the plan's digest, and commits exactly that plan. A period's n-th
//! issuance binds its certificate to `$C_ISSUE_<period>` (n = 1) or
//! `$C_ISSUE_<period>_<n>`, and a `reported_in:<period>#<n>` read reads the
//! period as reported in it. An issuance the book refuses is a setup
//! failure: the reads after it would answer a different question.

use fa_oracles::cases::book::StepDef;

use super::run::{BookRun, reproduce, s};

impl BookRun<'_> {
    /// An `issue` step (§3.3 step 4).
    pub(crate) fn issue(&mut self, step: &StepDef) {
        let label = step.reference.as_str();
        let Some(code) = self.periods.get(label).cloned() else {
            self.fail(format!(
                "expected a created period for label {label} (step {}) observed none",
                step.seq
            ));
            return;
        };
        let n = self.issuances.get(label).map_or(0, Vec::len) + 1;
        let placeholder = if n == 1 {
            format!("$C_ISSUE_{label}")
        } else {
            format!("$C_ISSUE_{label}_{n}")
        };
        let principal = step.principal.clone();
        let with_principal = |mut args: Vec<String>| {
            if let Some(p) = principal.as_deref() {
                args.extend([s("--as"), p.to_string()]);
            }
            args.push(s("--json"));
            args
        };
        // Retaining the certificate needs produce, which the owner holds and
        // the planner need not.
        let certified = self.call(
            step.seq,
            label,
            "statement",
            vec![
                s("statement"),
                s("balance-sheet"),
                s("--for"),
                code.clone(),
                s("--certify"),
                s("--json"),
            ],
        );
        self.certificate_kind("BalanceSheet");
        let Some(oid) = certified.str_field("report_certificate", "oid") else {
            self.lines.push(reproduce(&certified));
            self.fail(format!(
                "expected a certified balance sheet of {label} to issue (step {}) observed exit={}",
                step.seq, certified.exit
            ));
            return;
        };
        self.bind(&oid, placeholder, "report_certificate.oid", step.seq, label);
        let mut args = vec![
            s("statement"),
            s("issue"),
            s("--certificate"),
            format!("C:{oid}"),
            s("--for"),
            code,
            s("--issued-to"),
            s("sec"),
        ];
        if let Some(doc) = step.document.as_deref().and_then(|d| self.documents.get(d)) {
            args.extend([s("--document"), doc.clone()]);
        }
        args.push(s("--dry-run"));
        let planned = self.call(step.seq, label, "statement", with_principal(args));
        let (Some(digest), Some(bytes)) = (
            planned.str_field("statement_issuance_plan", "proposal_digest"),
            planned.str_field("statement_issuance_plan", "bytes"),
        ) else {
            self.lines.push(reproduce(&planned));
            self.fail(format!(
                "expected an issuance plan for {label} (step {}) observed exit={} {}",
                step.seq,
                planned.exit,
                planned.refusal_id().unwrap_or_default()
            ));
            return;
        };
        let plan = self.work.join(format!("issue-{}.plan", step.seq));
        if let Err(err) = std::fs::write(&plan, bytes) {
            self.fail(format!("write {}: {err}", plan.display()));
            return;
        }
        let mut args = vec![
            s("statement"),
            s("issue"),
            s("--plan"),
            plan.display().to_string(),
        ];
        for approver in step.approvers.clone().unwrap_or_default() {
            match self.approve_as(step.seq, &approver, &digest) {
                Some(vid) => args.extend([s("--approval"), vid]),
                None => {
                    self.fail(format!(
                        "expected {approver} to approve the issuance of {label} (step {}) observed no approval",
                        step.seq
                    ));
                    return;
                }
            }
        }
        let issued = self.call(step.seq, label, "statement", with_principal(args));
        self.certificate_kind("StatementIssuance");
        if issued.event("statement_issued").is_none() {
            self.lines.push(reproduce(&issued));
            self.fail(format!(
                "expected {label}'s issuance #{n} recorded (step {}) observed exit={} {}",
                step.seq,
                issued.exit,
                issued.refusal_id().unwrap_or_default()
            ));
            return;
        }
        self.issuances
            .entry(label.to_string())
            .or_default()
            .push(oid);
    }

    /// Marks the last step record's call as retaining a certificate of
    /// `kind` (§3.5).
    pub(crate) fn certificate_kind(&mut self, kind: &str) {
        if let Some(last) = self.steps.last_mut() {
            last.certificate_kind = Some(kind.to_string());
        }
    }
}
