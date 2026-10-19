# FrankenAccounting Vision & Convergence Gate Scoreboard

> Generated deterministically from [`registries/scoreboard.toml`](../registries/scoreboard.toml) and verified against the live `fa` binary by `crates/fa-cli/tests/scoreboard.rs` (beads `fa-e9z`, `fa-7s6d`).

## 1. Vision Workflow Summary (README Quick Example + Plan §15.6)

- **Total workflow steps:** 33 (`works`: **29** [87%], `refused`: **0**, `absent`: **4**)

| Workflow | Plan Ref | Reader | Works | Refused | Absent | Total | Delivery % |
|---|---|---|---:|---:|---:|---:|---:|
| `readme-quick` (README Quick Example) | README.md §Quick example | Agent / Operator | 11 | 0 | 1 | 12 | 91% |
| `agent-closes-month` (The agent closes a month) | §15.6.1 | AI Agent + Controller | 4 | 0 | 0 | 4 | 100% |
| `cpa-audits-fy2025` (The CPA audits FY2025) | §15.6.2 | External CPA / Auditor | 4 | 0 | 0 | 4 | 100% |
| `fdic-examiner-positions` (The FDIC examiner needs close-of-business positions) | §15.6.3 | FDIC Examiner / Receiver | 2 | 0 | 1 | 3 | 66% |
| `trustee-receiver-takeover` (The trustee or receiver takes over) | §15.6.4 | Bankruptcy Trustee / Receiver | 1 | 0 | 1 | 2 | 50% |
| `litigation-consultant-damages` (The litigation consultant computes but-for damages) | §15.6.5 | Litigation Consultant / Expert Witness | 4 | 0 | 1 | 5 | 80% |
| `investigator-traces-funds` (The investigator traces funds) | §15.6.6 | Forensic Investigator | 3 | 0 | 0 | 3 | 100% |

### Workflow Steps Detail

| Step | Vision Row | Workflow | Status | Exit | Event / Refusal | Bead | Description |
|---|---|---|---|---:|---|---|---|
| `WF-RQ-01` | `VC-01` | `readme-quick` | `works` | `0` | `book_triage` | `—` | Triage the book in robot mode (`fa triage --json`) |
| `WF-RQ-02` | `VC-02` | `readme-quick` | `works` | `0` | `plan` | `—` | Dry-run a typed invoice intent (`fa invoice ... --dry-run`; explicit accounts, no Canon rule or tax yet) |
| `WF-RQ-03` | `VC-03` | `readme-quick` | `works` | `0` | `plan` | `—` | Dry-run a balanced posting proposal and seal its plan (`fa post --dry-run --plan-out`) |
| `WF-RQ-04` | `VC-04` | `readme-quick` | `works` | `0` | `plan_committed` | `—` | Commit the sealed posting plan (`fa commit --plan`) |
| `WF-RQ-05` | `VC-05` | `readme-quick` | `works` | `0` | `balance_explained` | `—` | Explain a leaf account balance with fold proof (`fa explain balance`) |
| `WF-RQ-06` | `VC-06` | `readme-quick` | `works` | `0` | `trial_balance` | `—` | Trial balance at a historical known-at sequence (`fa tb --period --as-known-at`) |
| `WF-RQ-07` | `VC-07` | `readme-quick` | `works` | `0` | `trial_balance` | `—` | Trial balance as originally reported (`fa tb --as-originally-reported`) |
| `WF-RQ-08` | `VC-08` | `readme-quick` | `works` | `0` | `reversed` | `—` | Reverse a committed entry with SupersessionKind::Reverses lineage (`fa reverse`) |
| `WF-RQ-09` | `VC-09` | `readme-quick` | `absent` | `2` | `error` | `fa-75j4` | Open a restatement case from the CLI (`fa case open`) |
| `WF-RQ-10` | `VC-10` | `readme-quick` | `works` | `0` | `procedure_run` | `—` | Run Lantern journal-entry test (`fa procedure run jet.round_amounts`) |
| `WF-RQ-11` | `VC-11` | `readme-quick` | `works` | `0` | `procedure_run` | `—` | Run LIBR fund tracing (`fa procedure run trace.libr`) |
| `WF-RQ-12` | `VC-12` | `readme-quick` | `works` | `0` | `bundle_produced` | `—` | Produce a signed offline evidence bundle (`fa bundle produce`) |
| `WF-ACM-01` | `VC-13` | `agent-closes-month` | `works` | `0` | `next_step` | `—` | Inspect book triage and next recommended step (`fa next --json`) |
| `WF-ACM-02` | `VC-14` | `agent-closes-month` | `works` | `0` | `draft_opened` | `—` | Create a close draft branch (`fa draft new close-03`) |
| `WF-ACM-03` | `VC-15` | `agent-closes-month` | `works` | `0` | `bank_imported` | `—` | Import a CAMT.053 bank statement (`fa bank import`; matching its lines is `fa bank match`) |
| `WF-ACM-04` | `VC-16` | `agent-closes-month` | `works` | `0` | `period_transitioned` | `—` | Soft-close an open period (`fa period soft-close FY2026-P04`) |
| `WF-CPA-01` | `VC-17` | `cpa-audits-fy2025` | `works` | `0` | `journal_exported` | `—` | Export AICPA Audit Data Standard GL package (`fa export ads`) |
| `WF-CPA-02` | `VC-18` | `cpa-audits-fy2025` | `works` | `0` | `procedure_run` | `—` | Run Benford first-digit procedure (`fa procedure run benford.first_digit`) |
| `WF-CPA-03` | `VC-19` | `cpa-audits-fy2025` | `works` | `0` | `evidence_explained` | `—` | Walk full provenance closure of an entry (`fa explain evidence`) |
| `WF-CPA-04` | `VC-20` | `cpa-audits-fy2025` | `works` | `0` | `proof_exported` | `—` | Export signed transparency checkpoint (`fa proof signed-checkpoint`) |
| `WF-FDIC-01` | `VC-21` | `fdic-examiner-positions` | `works` | `0` | `trial_balance` | `—` | Trial balance as of an effective date and known-at sequence (`fa tb --as-of --as-known-at`) |
| `WF-FDIC-02` | `VC-22` | `fdic-examiner-positions` | `works` | `0` | `trial_balance` | `—` | Replay a certified trial balance byte-for-byte (`fa replay`) |
| `WF-FDIC-03` | `VC-23` | `fdic-examiner-positions` | `absent` | `2` | `error` | `fa-pbm` | Export FDIC Part 370 deposit insurance determination files (`fa export part370`) |
| `WF-TRT-01` | `VC-24` | `trustee-receiver-takeover` | `works` | `0` | `legal_hold_placed` | `—` | Place a legal hold on a document (`fa document hold place`) |
| `WF-TRT-02` | `VC-25` | `trustee-receiver-takeover` | `absent` | `2` | `error` | `fa-k07b` | Fork a receivership branch (`fa book fork receivership`) |
| `WF-LCD-01` | `VC-26` | `litigation-consultant-damages` | `works` | `0` | `scenario_forked` | `—` | Fork a counterfactual scenario (`fa scenario fork`; materialized as a scratch replay until substrate branches ship) |
| `WF-LCD-02` | `VC-27` | `litigation-consultant-damages` | `works` | `0` | `statement` | `—` | Certified income statement for a period (`fa statement income-statement --certify`) |
| `WF-LCD-03` | `VC-28` | `litigation-consultant-damages` | `works` | `0` | `scenario_run` | `—` | Run a counterfactual intent in the scenario (`fa scenario run`; rehearsed on the scenario's replay, never posted to trunk) |
| `WF-LCD-04` | `VC-29` | `litigation-consultant-damages` | `works` | `0` | `scenario_diff` | `—` | Diff the scenario against trunk as known at its fork (`fa scenario diff`: the damages schedule per account and unit) |
| `WF-LCD-05` | `VC-30` | `litigation-consultant-damages` | `absent` | `2` | `error` | `fa-k07b` | Retain the diff as a replayable certificate (`fa scenario diff --certify`; a DiffCertificate is not built yet) |
| `WF-ITF-01` | `VC-31` | `investigator-traces-funds` | `works` | `0` | `procedure_run` | `—` | Run structuring detection procedure (`fa procedure run graph.structuring`) |
| `WF-ITF-02` | `VC-32` | `investigator-traces-funds` | `works` | `0` | `procedure_run` | `—` | Run FIFO fund tracing (`fa procedure run trace.fifo`) |
| `WF-ITF-03` | `VC-33` | `investigator-traces-funds` | `works` | `0` | `procedure_run` | `—` | Run related-party exposure graph procedure (`fa procedure run graph.related_party_exposure`) |

## 2. Convergence Gate Scoreboard (Plan §19: G0, Genesis, G1–G4)

- **Total gate criteria:** 18 (`works`: **15**, `refused` [lawful refusal]: **2**, `absent`: **1**; verified active: **17/18** [94%])

| Gate | Works | Lawful Refusal | Absent | Total | Verified Active % |
|---|---:|---:|---:|---:|---:|
| `G0` | 4 | 0 | 0 | 4 | 100% |
| `Genesis` | 4 | 2 | 0 | 6 | 100% |
| `G1` | 3 | 0 | 0 | 3 | 100% |
| `G2` | 2 | 0 | 0 | 2 | 100% |
| `G3` | 2 | 0 | 0 | 2 | 100% |
| `G4` | 0 | 0 | 1 | 1 | 0% |

### Gate Criteria Detail

| ID | Gate | Probe | Status | Exit | Event / Refusal | Bead | Criterion |
|---|---|---|---|---:|---|---|---|
| `G0-01` | `G0` | `registry` | `works` | `0` | `registry_ok` | `—` | FA-INV spine with 16 invariants, checker strengths, disjoint negative checkers, and waiver=forbidden |
| `G0-02` | `G0` | `registry` | `works` | `0` | `registry_ok` | `—` | Threat and trust model (`registries/threat_model.toml`) with 8 threats, 5 boundaries, and 10 tamper vectors |
| `G0-03` | `G0` | `registry` | `works` | `0` | `registry_ok` | `—` | Admissibility matrix (`registries/admissibility.toml`) four-way equality with Appendix C, oracle, and kernel |
| `G0-04` | `G0` | `cli` | `works` | `0` | `robot_schema` | `—` | Robot-mode envelope and pinned schema (`fa robot-docs schema --json`) |
| `GEN-01` | `Genesis` | `cli` | `works` | `0` | `entry` | `—` | Post balanced entry through admit/resolve/laws/plan/commit and explain committed entry (`fa entry show`) |
| `GEN-02` | `Genesis` | `cli` | `works` | `0` | `trial_balance` | `—` | Certified trial balance (`fa tb --period FY2026-P03 --json`) |
| `GEN-03` | `Genesis` | `cli` | `works` | `0` | `registers_verified` | `—` | Registers verified by journal refold (`fa verify registers`) |
| `GEN-04` | `Genesis` | `cli` | `refused` | `3` | `error` (`FA-REF-001`) | `fa-lm7` | Unbalanced proposal refused with exit 3 and per-unit imbalance (`FA-REF-001`) |
| `GEN-05` | `Genesis` | `cli` | `refused` | `7` | `error` (`FA-REF-010`) | `fa-lm7` | Posting into a Closed period refused with exit 7 and admissibility cell (`FA-REF-010`) |
| `GEN-06` | `Genesis` | `cli` | `works` | `0` | `trial_balance` | `—` | Replay reproduces certified trial balance bytes (`fa replay`) |
| `G1-01` | `G1` | `registry` | `works` | `0` | `registry_ok` | `—` | All 13 Genesis invariant clauses live with positive and disjoint negative checkers |
| `G1-02` | `G1` | `cli` | `works` | `0` | `doctor` | `—` | Polish Bar diagnostics and orientation (`fa doctor --json`) |
| `G1-03` | `G1` | `cli` | `works` | `0` | `accumulator_verified` | `—` | Projection and accumulator verification (`fa verify projections` & `fa verify accumulator`) |
| `G2-01` | `G2` | `cli` | `works` | `0` | `period_explained` | `—` | Period explanation with admissibility row and lineage (`fa explain period`) |
| `G2-02` | `G2` | `cli` | `works` | `0` | `trial_balance` | `—` | Selector `AS ORIGINALLY REPORTED` on CLI trial balance (`fa tb --as-originally-reported`) |
| `G3-01` | `G3` | `cli` | `works` | `0` | `statement` | `—` | Certified balance sheet and income statement (`fa statement balance-sheet --certify`) |
| `G3-02` | `G3` | `cli` | `works` | `0` | `demo_initialized` | `—` | Interactive sandbox generator (`fa demo init --scenario retail`) |
| `G4-01` | `G4` | `registry` | `absent` | `2` | `error` | `fa-kby` | Every FA-INV clause in `registries/invariants.toml` is live (zero dormant clauses remaining for 1.0) |
