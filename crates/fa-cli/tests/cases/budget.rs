//! The per-case runtime budget (docs/FORENSIC_CASE_STUDIES_PLAN.md §16;
//! bead fa-yugf.17, A7c): per book, its invocation count and wall time; per
//! case, the total wall time from its first book and the warm cost of one
//! invocation. A case over its budget fails; nothing is skipped or capped to
//! fit. The budget is 60 s, or `FA_CASES_BUDGET_MS` when set (the planted
//! negative and diagnosis on a slow worker; `scripts/check.sh` never sets it).

use std::path::Path;
use std::time::Instant;

use super::run::fa;

/// The default budget, in milliseconds.
pub const DEFAULT_BUDGET_MS: u64 = 60_000;

/// One case's budget account.
pub struct Budget {
    pub budget_ms: u64,
    started: Instant,
    invocations: usize,
    warm_ms: Option<u64>,
}

impl Budget {
    /// `override_ms`, else `FA_CASES_BUDGET_MS`, else 60 s; the clock starts
    /// now.
    #[must_use]
    pub fn new(override_ms: Option<u64>) -> Self {
        let budget_ms = override_ms
            .or_else(|| {
                std::env::var("FA_CASES_BUDGET_MS")
                    .ok()
                    .and_then(|v| v.parse().ok())
            })
            .unwrap_or(DEFAULT_BUDGET_MS);
        Self {
            budget_ms,
            started: Instant::now(),
            invocations: 0,
            warm_ms: None,
        }
    }

    /// Measures the warm cost of one invocation once per case: the median
    /// `elapsed_ms` of five `fa tb --period <code> --json` on a built book.
    /// These probes are not case steps and are not logged as steps.
    pub fn measure_warm(&mut self, dir: &Path, period: &str) {
        if self.warm_ms.is_some() {
            return;
        }
        let mut times: Vec<u64> = (0..5)
            .map(|_| {
                let c = fa(
                    dir,
                    &[
                        "tb".to_string(),
                        "--period".to_string(),
                        period.to_string(),
                        "--json".to_string(),
                    ],
                );
                u64::try_from(c.elapsed_ms).unwrap_or(u64::MAX)
            })
            .collect();
        times.sort_unstable();
        self.warm_ms = times.get(2).copied();
    }

    /// A book's line: `BUDGET <case> <variant> book=<n> invocations=<n>
    /// wall_ms=<n>`.
    pub fn book(
        &mut self,
        case: &str,
        variant: &str,
        index: usize,
        invocations: usize,
        wall_ms: u128,
    ) -> String {
        self.invocations += invocations;
        format!("BUDGET {case} {variant} book={index} invocations={invocations} wall_ms={wall_ms}")
    }

    /// The case's line, and its `FAIL budget` line when it is over budget.
    #[must_use]
    pub fn finish(&self, case: &str) -> (Vec<String>, bool) {
        let total = self.started.elapsed().as_millis();
        let over = total > u128::from(self.budget_ms);
        let warm = self
            .warm_ms
            .map_or_else(|| "-".to_string(), |w| w.to_string());
        let mut lines = vec![format!(
            "BUDGET {case} total_ms={total} warm_invocation_ms={warm} budget_ms={} {}",
            self.budget_ms,
            if over { "FAIL" } else { "PASS" }
        )];
        if over {
            lines.push(format!(
                "FAIL budget {case} wall={total} budget={} invocations={}",
                self.budget_ms, self.invocations
            ));
        }
        (lines, !over)
    }
}
