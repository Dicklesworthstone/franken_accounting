# FrankenAccounting Vision & Convergence Gate Scoreboard

> Generated deterministically from [`registries/scoreboard.toml`](../registries/scoreboard.toml) and verified against the live `fa` binary and registries by `crates/fa-cli/tests/scoreboard.rs` (beads `fa-e9z`, `fa-7s6d`, `fa-ubl0`).

## 1. Vision Workflow Summary (README Quick Example + Plan §15.6)

- **Total workflow steps:** 33 (`works`: **33** [100%], `refused`: **0**, `absent`: **0**)

| Workflow | Plan Ref | Reader | Works | Refused | Absent | Total | Delivery % |
|---|---|---|---:|---:|---:|---:|---:|
| `readme-quick` (README Quick Example) | README.md §Quick example | Agent / Operator | 12 | 0 | 0 | 12 | 100% |
| `agent-closes-month` (The agent closes a month) | §15.6.1 | AI Agent + Controller | 4 | 0 | 0 | 4 | 100% |
| `cpa-audits-fy2025` (The CPA audits FY2025) | §15.6.2 | External CPA / Auditor | 4 | 0 | 0 | 4 | 100% |
| `fdic-examiner-positions` (The FDIC examiner needs close-of-business positions) | §15.6.3 | FDIC Examiner / Receiver | 3 | 0 | 0 | 3 | 100% |
| `trustee-receiver-takeover` (The trustee or receiver takes over) | §15.6.4 | Bankruptcy Trustee / Receiver | 2 | 0 | 0 | 2 | 100% |
| `litigation-consultant-damages` (The litigation consultant computes but-for damages) | §15.6.5 | Litigation Consultant / Expert Witness | 5 | 0 | 0 | 5 | 100% |
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
| `WF-RQ-09` | `VC-09` | `readme-quick` | `works` | `0` | `case_opened` | `—` | Open a restatement case from the CLI (`fa case open`: journaled Proposed; `fa case` determine, rehearse, approve, post, disclose and close carry it on, and all four case kinds post) |
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
| `WF-FDIC-03` | `VC-23` | `fdic-examiner-positions` | `works` | `0` | `part370_exported` | `—` | Export FDIC Part 370 deposit insurance determination files (`fa export part370`) |
| `WF-TRT-01` | `VC-24` | `trustee-receiver-takeover` | `works` | `0` | `legal_hold_placed` | `—` | Place a legal hold on a document (`fa document hold place`) |
| `WF-TRT-02` | `VC-25` | `trustee-receiver-takeover` | `works` | `0` | `receivership_forked` | `—` | Fork a receivership branch on the appointing order: a book-scope legal hold over the pre-appointment trunk and the `receivership` scenario at the appointment (`fa book fork receivership`) |
| `WF-LCD-01` | `VC-26` | `litigation-consultant-damages` | `works` | `0` | `scenario_forked` | `—` | Fork a counterfactual scenario (`fa scenario fork`; materialized as a scratch replay until substrate branches ship) |
| `WF-LCD-02` | `VC-27` | `litigation-consultant-damages` | `works` | `0` | `statement` | `—` | Certified income statement for a period (`fa statement income-statement --certify`) |
| `WF-LCD-03` | `VC-28` | `litigation-consultant-damages` | `works` | `0` | `scenario_run` | `—` | Run a counterfactual intent in the scenario (`fa scenario run`; rehearsed on the scenario's replay, never posted to trunk) |
| `WF-LCD-04` | `VC-29` | `litigation-consultant-damages` | `works` | `0` | `scenario_diff` | `—` | Diff the scenario against trunk as known at its fork (`fa scenario diff`: the damages schedule per account and unit) |
| `WF-LCD-05` | `VC-30` | `litigation-consultant-damages` | `works` | `0` | `scenario_diff` | `—` | Retain the diff as a replayable certificate (`fa scenario diff --certify`; `fa replay` re-materializes exactly the intents it covered) |
| `WF-ITF-01` | `VC-31` | `investigator-traces-funds` | `works` | `0` | `procedure_run` | `—` | Run structuring detection procedure (`fa procedure run graph.structuring`) |
| `WF-ITF-02` | `VC-32` | `investigator-traces-funds` | `works` | `0` | `procedure_run` | `—` | Run FIFO fund tracing (`fa procedure run trace.fifo`) |
| `WF-ITF-03` | `VC-33` | `investigator-traces-funds` | `works` | `0` | `procedure_run` | `—` | Run related-party exposure graph procedure (`fa procedure run graph.related_party_exposure`) |

## 2. Convergence Gate Scoreboard (Plan §19: G0, Genesis, G1–G4)

> **Gate rule:** Gate met only when every row is `works`.

- **Plan §19 transcription BLAKE3:** `1b846fd2e9fead56d46bc81eec807e23aec956c64c17ac57097916189078568a` (55 verbatim clauses: `works`: **36**, `refused`: **2**, `absent`: **17**)

| Gate | Works | Lawful Refusal | Absent | Total | Gate Status |
|---|---:|---:|---:|---:|---|
| `G0` | 13 | 0 | 0 | 13 | **MET** |
| `Genesis` | 9 | 2 | 0 | 11 | **UNMET** |
| `G1` | 5 | 0 | 2 | 7 | **UNMET** |
| `G2` | 6 | 0 | 4 | 10 | **UNMET** |
| `G3` | 3 | 0 | 5 | 8 | **UNMET** |
| `G4` | 0 | 0 | 6 | 6 | **UNMET** |

### Gate Criteria Detail

| ID | Gate | Evidence Class | Probe | Artifact | Status | Exit | Event / Refusal | Bead | Criterion |
|---|---|---|---|---|---|---:|---|---|---|
| `G0-01` | `G0` | `registry` | `registry` | `—` | `works` | `0` | `registry_ok` | `—` | every registry in §18.2 materialized with its schema and first rows |
| `G0-02` | `G0` | `registry` | `registry` | `—` | `works` | `0` | `registry_ok` | `—` | the FA-INV spine of Appendix F with clause activation predicates, checker entrypoints, and `waiver = "forbidden"` |
| `G0-03` | `G0` | `registry` | `registry` | `—` | `works` | `0` | `registry_ok` | `—` | the threat model |
| `G0-04` | `G0` | `registry` | `registry` | `—` | `works` | `0` | `registry_ok` | `—` | the admissibility matrix with its exhaustive generated test |
| `G0-05` | `G0` | `registry` | `registry` | `—` | `works` | `0` | `registry_ok` | `—` | the unit, law, class, intent, procedure, caveat, verb, exit-code, and refusal catalogs frozen at major 1 |
| `G0-06` | `G0` | `registry` | `registry` | `—` | `works` | `0` | `registry_ok` | `—` | the canonical object schemas of Appendix A with `BodyDigest` recipes and golden vectors |
| `G0-07` | `G0` | `registry` | `registry` | `—` | `works` | `0` | `registry_ok` | `—` | the bundle and certificate schemas marked `externally_verifiable` |
| `G0-08` | `G0` | `cli` | `cli` | `—` | `works` | `0` | `robot_schema` | `—` | the robot-mode envelope and schema fixtures |
| `G0-09` | `G0` | `registry` | `registry` | `—` | `works` | `0` | `registry_ok` | `—` | the operation-cost registry (Appendix G) with the derivability law |
| `G0-10` | `G0` | `registry` | `registry` | `—` | `works` | `0` | `registry_ok` | `—` | `foundation_dependencies.toml` with every row's status checked against the substrate on the G0 date |
| `G0-11` | `G0` | `registry` | `registry` | `—` | `works` | `0` | `registry_ok` | `—` | `tools/registry-check` green |
| `G0-12` | `G0` | `registry` | `registry` | `—` | `works` | `0` | `registry_ok` | `—` | `scripts/check.sh` with the verdict contract |
| `G0-13` | `G0` | `registry` | `registry` | `—` | `works` | `0` | `registry_ok` | `—` | README/AGENTS synchronization checks |
| `GEN-01` | `Genesis` | `cli` | `cli` | `—` | `works` | `0` | `book_triage` | `—` | create a book |
| `GEN-02` | `Genesis` | `cli` | `cli` | `—` | `works` | `0` | `period_explained` | `—` | install the chart and calendar as journaled schema effects |
| `GEN-03` | `Genesis` | `cli` | `cli` | `—` | `works` | `0` | `entry` | `—` | post a balanced two-leg entry via `PostEntry` through admit/resolve/laws/plan/commit |
| `GEN-04` | `Genesis` | `cli` | `cli` | `—` | `works` | `0` | `projections_verified` | `—` | the derived legs exist and equal the payload |
| `GEN-05` | `Genesis` | `cli` | `cli` | `—` | `works` | `0` | `balance_explained` | `—` | the register maintainer advances and `balance = fold` |
| `GEN-06` | `Genesis` | `lab-campaign` | `lab-campaign` | `FA-ART-LAB-02` | `works` | `0` | `lab_campaign_ok` | `—` | crash at every barrier (between plan and commit, commit and ack, delta consumption and watermark) and recover |
| `GEN-07` | `Genesis` | `cli` | `cli` | `—` | `works` | `0` | `trial_balance` | `—` | `fa tb --json` returns the certified trial balance |
| `GEN-08` | `Genesis` | `cli` | `cli` | `—` | `works` | `0` | `registers_verified` | `—` | `fa verify registers` is green |
| `GEN-09` | `Genesis` | `cli` | `cli` | `—` | `refused` | `3` | `error` (`FA-REF-001`) | `fa-lm7` | an unbalanced proposal is refused with exit `3` and the per-unit imbalance |
| `GEN-10` | `Genesis` | `cli` | `cli` | `—` | `refused` | `7` | `error` (`FA-REF-010`) | `fa-lm7` | a post into a `Closed` period is refused with exit `7` and the matrix cell |
| `GEN-11` | `Genesis` | `cli` | `cli` | `—` | `works` | `0` | `trial_balance` | `—` | `fa replay` reproduces the trial balance bytes |
| `G1-01` | `G1` | `lab-campaign` | `lab-campaign` | `FA-ART-LAB-04` | `works` | `0` | `lab_campaign_ok` | `—` | Genesis slice green under lab and live |
| `G1-02` | `G1` | `registry` | `registry` | `—` | `works` | `0` | `registry_ok` | `—` | the Genesis clause set (FA-INV-01, 02, 03.core, 04, 05.minimum, 06, 07.core, 09, 10.core, 11.core, 14.leaf-and-consistency, 15.core, 16) live with checkers and the remaining clauses registered dormant with their activating workstream named |
| `G1-03` | `G1` | `differential` | `differential` | `—` | `works` | `0` | `differential_ok` | `—` | registers verified by fold on every fixture |
| `G1-04` | `G1` | `lab-campaign` | `lab-campaign` | `—` | `absent` | `2` | `error` | `fa-nl7` | idempotency and batches under crash |
| `G1-05` | `G1` | `differential` | `differential` | `—` | `absent` | `2` | `error` | `fa-2ihd` | the reference differential over model-generated histories |
| `G1-06` | `G1` | `cli` | `cli` | `—` | `works` | `0` | `polish_bar_ok` | `—` | the robot-mode envelope and `fa triage`, `fa post`, `fa tb`, `fa explain balance`, `fa doctor` at the Polish Bar |
| `G1-07` | `G1` | `cli` | `cli` | `—` | `works` | `0` | `bundle_produced` | `—` | `fa-verify` verifies a produced bundle of the Genesis book |
| `G2-01` | `G2` | `lab-campaign` | `lab-campaign` | `FA-ART-LAB-01` | `works` | `0` | `lab_campaign_ok` | `—` | period state machine, admissibility matrix, and witness-resolved post-vs-close races proven in both orders |
| `G2-02` | `G2` | `cli` | `cli` | `—` | `works` | `0` | `trial_balance` | `—` | selectors including `AS ORIGINALLY REPORTED` and `AS REPORTED IN` |
| `G2-03` | `G2` | `cli` | `cli` | `—` | `works` | `0` | `restatement_cases_ok` | `—` | supersession netting and restatement cases with diff certificates |
| `G2-04` | `G2` | `lab-campaign` | `lab-campaign` | `FA-ART-LAB-03` | `works` | `0` | `lab_campaign_ok` | `—` | two-phase entries with expiry sweeps under lab |
| `G2-05` | `G2` | `cli` | `cli` | `—` | `works` | `0` | `evidence_explained` | `—` | documents, custody, attestations, balance assertions |
| `G2-06` | `G2` | `cli` | `cli` | `—` | `works` | `0` | `accumulator_verified` | `—` | accumulator continuity and witnessed checkpoints |
| `G2-07` | `G2` | `registry` | `registry` | `—` | `absent` | `2` | `error` | `fa-0x0` | FA-INV-03/07/08/10/14 live |
| `G2-08` | `G2` | `external-oracle` | `external-oracle` | `—` | `absent` | `2` | `error` | `fa-3ock` | the Beancount/hledger differential green on all fixtures |
| `G2-09` | `G2` | `differential` | `differential` | `—` | `absent` | `2` | `error` | `fa-c34` | Canon rules with golden corpora and backtests |
| `G2-10` | `G2` | `cli` | `cli` | `—` | `absent` | `2` | `error` | `fa-we7` | dry-run plans with `confirm_plan` |
| `G3-01` | `G3` | `registry` | `registry` | `—` | `absent` | `2` | `error` | `fa-z5u` | the full verb registry across CLI/daemon/MCP with the parity gate green |
| `G3-02` | `G3` | `agent-campaign` | `agent-campaign` | `—` | `absent` | `2` | `error` | `fa-y6eu` | fresh-context simulated agents complete every §15.6 workflow with zero `useless_error` outcomes in the intent corpus |
| `G3-03` | `G3` | `registry` | `registry` | `—` | `absent` | `2` | `error` | `fa-651f` | SoD and caveats enforced at commit (FA-INV-10 full) |
| `G3-04` | `G3` | `cli` | `cli` | `—` | `absent` | `2` | `error` | `fa-bwri` | statements and consolidation certified |
| `G3-05` | `G3` | `measurement` | `measurement` | `FA-ART-CAL-01` | `works` | `0` | `measurement_ok` | `—` | Lantern's procedures with evidence rows and measured precision/recall |
| `G3-06` | `G3` | `cli` | `cli` | `—` | `works` | `0` | `exports_with_proofs_ok` | `—` | ADS/SAF-T exports with proofs |
| `G3-07` | `G3` | `cli` | `cli` | `—` | `works` | `0` | `demo_initialized` | `—` | `fa demo init` scenarios |
| `G3-08` | `G3` | `agent-campaign` | `agent-campaign` | `—` | `absent` | `2` | `error` | `fa-nmk4` | the gauntlet's surface-parity and ergonomics scorecards published |
| `G4-01` | `G4` | `measurement` | `measurement` | `—` | `absent` | `2` | `error` | `fa-ykbp` | all activated §17 manifests green and public |
| `G4-02` | `G4` | `external-oracle` | `external-oracle` | `—` | `absent` | `2` | `error` | `fa-3ock` | conformance matrices (ADS, SAF-T, XBRL, Beancount/hledger, TigerBeetle corpus) published with documented divergences |
| `G4-03` | `G4` | `registry` | `registry` | `—` | `absent` | `2` | `error` | `fa-09q8` | every FA-INV clause live or its capability absent from the manifest |
| `G4-04` | `G4` | `registry` | `registry` | `—` | `absent` | `2` | `error` | `fa-rdid` | the papers match the proven scope |
| `G4-05` | `G4` | `cli` | `cli` | `—` | `absent` | `2` | `error` | `fa-q5kx` | `fa-verify` released as a static binary with golden proofs |
| `G4-06` | `G4` | `registry` | `registry` | `—` | `absent` | `2` | `error` | `fa-nfq2` | 1.0 |

## 3. Governance & Verdict Integrity Rows (`fa-8jcr`, `fa-j1fc`, `fa-1qk0`)

| ID | Metric | Evidence Class | Probe | Status | Exit | Bead | Description |
|---|---|---|---|---|---:|---|---|
| `GOV-01` | `closure_debt` | `registry` | `registry` | `absent` | `2` | `fa-8jcr` | Zero unbacked closed beads without a machine-verified acceptance-tests block and verdict note (pre-fa-8jcr closures remain in debt until backfilled) |
| `GOV-02` | `verdict_freshness` | `registry` | `registry` | `absent` | `2` | `fa-ygj2` | Published PASS verdict note in refs/notes/fa-verdict is present and within the 7-day freshness window |
| `GOV-03` | `tier0_coverage` | `registry` | `registry` | `absent` | `2` | `fa-0hs4.3` | Unskippable Tier-0 gate hooks (.githooks/pre-commit, .githooks/pre-push) and scripts/tier0.sh are installed and active |
