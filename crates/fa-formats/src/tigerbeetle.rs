//! TigerBeetle semantic corpus runner and two-phase sub-vector differential
//! evaluator (plan §5.4, §16.3, bead `fa-npi`).

use std::collections::BTreeMap;

use fa_registry::toml::{self, Table, Value};

use crate::FormatError;

pub const TIGERBEETLE_CORPUS_TOML: &str = include_str!("../corpora/tigerbeetle_semantics.toml");

/// Account balance sub-vector matching TigerBeetle's 4-field account state and
/// FrankenAccounting's `fa-registers` / `fa-escrow` pending + posted sub-vectors.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TbAccountState {
    pub code: String,
    pub unit: String,
    /// Optional ceiling on `debits_posted + debits_pending - credits_posted` (`0` = unlimited).
    pub max_debit_net: i128,
    pub debits_pending: i128,
    pub debits_posted: i128,
    pub credits_pending: i128,
    pub credits_posted: i128,
}

impl TbAccountState {
    pub fn format_summary(&self) -> String {
        format!(
            "{}:dp={}:dpost={}:cp={}:cpost={}",
            self.code,
            self.debits_pending,
            self.debits_posted,
            self.credits_pending,
            self.credits_posted
        )
    }
}

/// One step in a TigerBeetle semantic scenario.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TbStep {
    Post {
        id: String,
        debit_account: String,
        credit_account: String,
        amount: i128,
        day: i32,
    },
    Pending {
        id: String,
        debit_account: String,
        credit_account: String,
        amount: i128,
        day: i32,
        expiry_day: i32,
    },
    Capture {
        id: String,
        pending_id: String,
        amount: i128,
        day: i32,
    },
    Void {
        id: String,
        pending_id: String,
        day: i32,
    },
    Expire {
        id: String,
        pending_id: String,
        day: i32,
    },
}

/// One scenario from `corpora/tigerbeetle_semantics.toml`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TbScenario {
    pub id: String,
    pub description: String,
    pub divergence: String,
    pub divergence_reason: String,
    pub accounts: Vec<TbAccountState>,
    pub steps: Vec<TbStep>,
    pub expected_outcomes: Vec<String>,
    pub expected_balances: Vec<String>,
}

/// Result of executing a `TbScenario`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TbScenarioResult {
    pub scenario_id: String,
    pub outcomes: Vec<String>,
    pub final_balances: Vec<String>,
    pub divergence: String,
    pub divergence_reason: String,
}

/// Parsed TigerBeetle semantic corpus.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TbCorpus {
    pub schema_version: u32,
    pub scenarios: Vec<TbScenario>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingHold {
    debit_account: String,
    credit_account: String,
    reserved_amount: i128,
    expiry_day: i32,
    resolved: bool,
}

impl TbCorpus {
    pub fn embedded() -> Result<Self, FormatError> {
        Self::parse(TIGERBEETLE_CORPUS_TOML)
    }

    pub fn parse(src: &str) -> Result<Self, FormatError> {
        const FMT: &str = "tigerbeetle_corpus_v1";
        let doc = toml::parse(src).map_err(|e| FormatError::Parse {
            format: FMT,
            detail: e.to_string(),
        })?;
        let schema_version = doc
            .root
            .get("schema_version")
            .and_then(Value::as_int)
            .ok_or_else(|| FormatError::Parse {
                format: FMT,
                detail: "missing schema_version".to_owned(),
            })? as u32;
        if schema_version != 1 {
            return Err(FormatError::Parse {
                format: FMT,
                detail: format!("unsupported schema_version {schema_version}"),
            });
        }
        let tables = doc
            .arrays
            .get("scenario")
            .ok_or_else(|| FormatError::Parse {
                format: FMT,
                detail: "missing [[scenario]]".to_owned(),
            })?;
        let mut scenarios = Vec::with_capacity(tables.len());
        for t in tables {
            let id = req_str(t, "id")?;
            let description = req_str(t, "description")?;
            let divergence = req_str(t, "divergence")?;
            let divergence_reason = req_str(t, "divergence_reason")?;
            let acct_specs = req_str_array(t, "accounts")?;
            let step_specs = req_str_array(t, "steps")?;
            let expected_outcomes = req_str_array(t, "expected_outcomes")?;
            let expected_balances = req_str_array(t, "expected_balances")?;

            let mut accounts = Vec::with_capacity(acct_specs.len());
            for a_spec in acct_specs {
                let parts: Vec<&str> = a_spec.split(':').collect();
                if parts.len() != 3 {
                    return Err(FormatError::Parse {
                        format: FMT,
                        detail: format!("invalid account spec {a_spec:?}"),
                    });
                }
                let max_debit_net: i128 = parts[2].parse().map_err(|_| FormatError::Parse {
                    format: FMT,
                    detail: format!("invalid max_debit_net in {a_spec:?}"),
                })?;
                accounts.push(TbAccountState {
                    code: parts[0].to_owned(),
                    unit: parts[1].to_owned(),
                    max_debit_net,
                    ..Default::default()
                });
            }

            let mut steps = Vec::with_capacity(step_specs.len());
            for s_spec in step_specs {
                steps.push(parse_step(&s_spec)?);
            }

            scenarios.push(TbScenario {
                id,
                description,
                divergence,
                divergence_reason,
                accounts,
                steps,
                expected_outcomes,
                expected_balances,
            });
        }

        Ok(Self {
            schema_version,
            scenarios,
        })
    }

    /// Execute and verify every scenario in the corpus, returning the verified results.
    pub fn evaluate_all(&self) -> Result<Vec<TbScenarioResult>, FormatError> {
        let mut out = Vec::with_capacity(self.scenarios.len());
        for sc in &self.scenarios {
            let res = evaluate_scenario(sc)?;
            if res.outcomes != sc.expected_outcomes {
                return Err(FormatError::TigerBeetleViolation {
                    scenario: sc.id.clone(),
                    detail: format!(
                        "outcomes mismatch: expected {:?}, observed {:?}",
                        sc.expected_outcomes, res.outcomes
                    ),
                });
            }
            if res.final_balances != sc.expected_balances {
                return Err(FormatError::TigerBeetleViolation {
                    scenario: sc.id.clone(),
                    detail: format!(
                        "balances mismatch: expected {:?}, observed {:?}",
                        sc.expected_balances, res.final_balances
                    ),
                });
            }
            out.push(res);
        }
        Ok(out)
    }
}

/// Evaluate a single [`TbScenario`] under FrankenAccounting's two-phase hold and
/// worst-case reservation limit semantics.
pub fn evaluate_scenario(scenario: &TbScenario) -> Result<TbScenarioResult, FormatError> {
    let mut accounts: BTreeMap<String, TbAccountState> = scenario
        .accounts
        .iter()
        .map(|a| (a.code.clone(), a.clone()))
        .collect();
    let mut holds: BTreeMap<String, PendingHold> = BTreeMap::new();
    let mut outcomes = Vec::with_capacity(scenario.steps.len());

    for step in &scenario.steps {
        match step {
            TbStep::Post {
                id,
                debit_account,
                credit_account,
                amount,
                ..
            } => {
                let dr_acct = accounts.get(debit_account).ok_or_else(|| {
                    FormatError::TigerBeetleViolation {
                        scenario: scenario.id.clone(),
                        detail: format!("unknown debit account {debit_account}"),
                    }
                })?;
                let worst_case_debit = dr_acct.debits_posted + dr_acct.debits_pending + *amount
                    - dr_acct.credits_posted;
                if dr_acct.max_debit_net > 0 && worst_case_debit > dr_acct.max_debit_net {
                    outcomes.push(format!("{id}:refused_exceeds_limit"));
                    continue;
                }
                accounts
                    .get_mut(debit_account)
                    .expect("checked")
                    .debits_posted += *amount;
                accounts
                    .get_mut(credit_account)
                    .expect("checked")
                    .credits_posted += *amount;
                outcomes.push(format!("{id}:committed"));
            }
            TbStep::Pending {
                id,
                debit_account,
                credit_account,
                amount,
                expiry_day,
                ..
            } => {
                let dr_acct = accounts.get(debit_account).ok_or_else(|| {
                    FormatError::TigerBeetleViolation {
                        scenario: scenario.id.clone(),
                        detail: format!("unknown debit account {debit_account}"),
                    }
                })?;
                let worst_case_debit = dr_acct.debits_posted + dr_acct.debits_pending + *amount
                    - dr_acct.credits_posted;
                if dr_acct.max_debit_net > 0 && worst_case_debit > dr_acct.max_debit_net {
                    outcomes.push(format!("{id}:refused_exceeds_limit"));
                    continue;
                }
                accounts
                    .get_mut(debit_account)
                    .expect("checked")
                    .debits_pending += *amount;
                accounts
                    .get_mut(credit_account)
                    .expect("checked")
                    .credits_pending += *amount;
                holds.insert(
                    id.clone(),
                    PendingHold {
                        debit_account: debit_account.clone(),
                        credit_account: credit_account.clone(),
                        reserved_amount: *amount,
                        expiry_day: *expiry_day,
                        resolved: false,
                    },
                );
                outcomes.push(format!("{id}:committed"));
            }
            TbStep::Capture {
                id,
                pending_id,
                amount,
                day,
            } => {
                let hold =
                    holds
                        .get_mut(pending_id)
                        .ok_or_else(|| FormatError::TigerBeetleViolation {
                            scenario: scenario.id.clone(),
                            detail: format!("unknown pending hold {pending_id}"),
                        })?;
                if hold.resolved {
                    outcomes.push(format!("{id}:refused_already_resolved"));
                    continue;
                }
                if *day >= hold.expiry_day {
                    outcomes.push(format!("{id}:refused_expired"));
                    continue;
                }
                if *amount > hold.reserved_amount || *amount <= 0 {
                    outcomes.push(format!("{id}:refused_exceeds_pending"));
                    continue;
                }
                hold.resolved = true;
                let dr = hold.debit_account.clone();
                let cr = hold.credit_account.clone();
                let reserved = hold.reserved_amount;
                let dr_state = accounts.get_mut(&dr).expect("debit account");
                dr_state.debits_pending -= reserved;
                dr_state.debits_posted += *amount;
                let cr_state = accounts.get_mut(&cr).expect("credit account");
                cr_state.credits_pending -= reserved;
                cr_state.credits_posted += *amount;
                outcomes.push(format!("{id}:committed"));
            }
            TbStep::Void { id, pending_id, .. } => {
                let hold =
                    holds
                        .get_mut(pending_id)
                        .ok_or_else(|| FormatError::TigerBeetleViolation {
                            scenario: scenario.id.clone(),
                            detail: format!("unknown pending hold {pending_id}"),
                        })?;
                if hold.resolved {
                    outcomes.push(format!("{id}:refused_already_resolved"));
                    continue;
                }
                hold.resolved = true;
                let dr = hold.debit_account.clone();
                let cr = hold.credit_account.clone();
                let reserved = hold.reserved_amount;
                accounts.get_mut(&dr).expect("debit").debits_pending -= reserved;
                accounts.get_mut(&cr).expect("credit").credits_pending -= reserved;
                outcomes.push(format!("{id}:committed"));
            }
            TbStep::Expire {
                id,
                pending_id,
                day,
            } => {
                let hold =
                    holds
                        .get_mut(pending_id)
                        .ok_or_else(|| FormatError::TigerBeetleViolation {
                            scenario: scenario.id.clone(),
                            detail: format!("unknown pending hold {pending_id}"),
                        })?;
                if hold.resolved {
                    outcomes.push(format!("{id}:refused_already_resolved"));
                    continue;
                }
                if *day < hold.expiry_day {
                    outcomes.push(format!("{id}:refused_not_yet_expired"));
                    continue;
                }
                hold.resolved = true;
                let dr = hold.debit_account.clone();
                let cr = hold.credit_account.clone();
                let reserved = hold.reserved_amount;
                accounts.get_mut(&dr).expect("debit").debits_pending -= reserved;
                accounts.get_mut(&cr).expect("credit").credits_pending -= reserved;
                outcomes.push(format!("{id}:committed"));
            }
        }
    }

    let final_balances: Vec<String> = accounts
        .values()
        .map(TbAccountState::format_summary)
        .collect();

    Ok(TbScenarioResult {
        scenario_id: scenario.id.clone(),
        outcomes,
        final_balances,
        divergence: scenario.divergence.clone(),
        divergence_reason: scenario.divergence_reason.clone(),
    })
}

fn req_str(t: &Table, key: &str) -> Result<String, FormatError> {
    t.get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| FormatError::Parse {
            format: "tigerbeetle_corpus_v1",
            detail: format!("missing string `{key}`"),
        })
}

fn req_str_array(t: &Table, key: &str) -> Result<Vec<String>, FormatError> {
    let arr = t
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| FormatError::Parse {
            format: "tigerbeetle_corpus_v1",
            detail: format!("missing array `{key}`"),
        })?;
    arr.iter()
        .map(|v| {
            v.as_str()
                .map(str::to_owned)
                .ok_or_else(|| FormatError::Parse {
                    format: "tigerbeetle_corpus_v1",
                    detail: format!("non-string in `{key}`"),
                })
        })
        .collect()
}

fn parse_step(spec: &str) -> Result<TbStep, FormatError> {
    const FMT: &str = "tigerbeetle_corpus_v1";
    let parts: Vec<&str> = spec.split(':').collect();
    match parts.first().copied() {
        Some("post") if parts.len() == 6 => {
            let amount: i128 = parts[4].parse().map_err(|_| FormatError::Parse {
                format: FMT,
                detail: format!("invalid amount in {spec:?}"),
            })?;
            let day = parse_kv_i32(parts[5], "day=")?;
            Ok(TbStep::Post {
                id: parts[1].to_owned(),
                debit_account: parts[2].to_owned(),
                credit_account: parts[3].to_owned(),
                amount,
                day,
            })
        }
        Some("pending") if parts.len() == 7 => {
            let amount: i128 = parts[4].parse().map_err(|_| FormatError::Parse {
                format: FMT,
                detail: format!("invalid amount in {spec:?}"),
            })?;
            let day = parse_kv_i32(parts[5], "day=")?;
            let expiry_day = parse_kv_i32(parts[6], "expiry=")?;
            Ok(TbStep::Pending {
                id: parts[1].to_owned(),
                debit_account: parts[2].to_owned(),
                credit_account: parts[3].to_owned(),
                amount,
                day,
                expiry_day,
            })
        }
        Some("capture") if parts.len() == 5 => {
            let amount: i128 = parts[3].parse().map_err(|_| FormatError::Parse {
                format: FMT,
                detail: format!("invalid capture amount in {spec:?}"),
            })?;
            let day = parse_kv_i32(parts[4], "day=")?;
            Ok(TbStep::Capture {
                id: parts[1].to_owned(),
                pending_id: parts[2].to_owned(),
                amount,
                day,
            })
        }
        Some("void") if parts.len() == 4 => {
            let day = parse_kv_i32(parts[3], "day=")?;
            Ok(TbStep::Void {
                id: parts[1].to_owned(),
                pending_id: parts[2].to_owned(),
                day,
            })
        }
        Some("expire") if parts.len() == 4 => {
            let day = parse_kv_i32(parts[3], "day=")?;
            Ok(TbStep::Expire {
                id: parts[1].to_owned(),
                pending_id: parts[2].to_owned(),
                day,
            })
        }
        _ => Err(FormatError::Parse {
            format: FMT,
            detail: format!("invalid TigerBeetle step spec {spec:?}"),
        }),
    }
}

fn parse_kv_i32(part: &str, prefix: &str) -> Result<i32, FormatError> {
    let val = part
        .strip_prefix(prefix)
        .ok_or_else(|| FormatError::Parse {
            format: "tigerbeetle_corpus_v1",
            detail: format!("expected prefix {prefix:?} in {part:?}"),
        })?;
    val.parse().map_err(|_| FormatError::Parse {
        format: "tigerbeetle_corpus_v1",
        detail: format!("invalid integer in {part:?}"),
    })
}
