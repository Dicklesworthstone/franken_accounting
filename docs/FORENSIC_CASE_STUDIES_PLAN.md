# Public-Record Forensic Case Studies as End-to-End Tests — Plan

> Status: revision 3 (2026-10-25), after review rounds 1–4 (Appendix Z). Round 4 judged the plan at
> steady state; its local fixes and a mechanical id/reference/edge lint are applied. Author:
> StormyLion (Claude Opus 5.5) for the franken_accounting owner. The work items of §15 are tracked as
> beads labelled `case-studies`.
>
> Review round 1 consisted of three independent inputs:
> - six independent modes-of-reasoning passes over draft v0 (run `20261024T205000Z`: baseline,
>   boundary attack, adversarial source check, capability/dependency map, reader-credibility against
>   published evidence standards, legal/normative);
> - the Phase 5 adjudications of the Brenner research session `RS-20261024-fa-forensic-cases`
>   (DEBATE-001 on the form of tie-out claims; DEBATE-002 on admissible detection claims; the H-013
>   falsifier check);
> - a read-only survey of franken_accounting at `8196f5e40`.
>
> The changes from v0 are listed in Appendix Z.
>
> This document is self-contained: an implementer does not need the research workspace. Where a fact
> came from the research, it carries its source id and anchor so it can be re-verified. Every such
> fact MUST be re-verified against the fetched source at authoring time (§4.5) before it enters a
> facts file. The research record itself contained anchor errors (Appendix Z.3), which is exactly why
> that rule exists.

---

## 0. Why this exists, and what it may honestly claim

### 0.1 The request

The owner asked (2026-10-24):

> "take super detailed publicly available forensic account examples (say, from the enron or worldcom
> bankruptcy cases, stuff that we can readily find in digital formats already on the web) and use them
> to make elaborate case studies and basically end to end integration tests showing off ALL the deep
> functionality of franken_accounting and how it could have automatically found the problems and
> prevented the fraud/malfeasance (since that stuff would set of alarms or violate invariants, whatever
> the case may be). We can also look for complex mergers and restatements from public companies and
> show that our system was able to match the final work of the Big4 auditors in terms of reconciling
> everything, or get close enough. It would also be a good test that everything works end to end."

The request contains three goals. They need different evidence, so the plan keeps them separate:

1. **A demonstration** to forensic accountants, examiners and expert witnesses (the product's users,
   AGENTS.md "Project Mission"). It shows what franken_accounting detects, what it refuses, and what
   it does *not* catch on documented real events.
2. **A public-record tie-out target**: published restated and as-reported numbers that franken_accounting's
   certified folds must reproduce exactly. Every target carries its own assurance status. Several of
   the best targets were never audited: Enron's November-2001 figures are marked "UNAUDITED", and its
   Q3-2001 10-Q was "not been reviewed". So the honest phrase is "reproduces the published bridge",
   with the assurance status stated, not "matches the auditors" (§0.3, owner decision 4, §14).
3. **An end-to-end regression gate.** It drives the real `fa` binary through a book shaped by real
   events rather than by our own generator:
   - setup: book creation, chart roles, principals and capabilities, documents and attestations;
   - posting: posting law, period transitions, evidence and SoD;
   - analysis: Lantern procedures, restatement cases and bitemporal reads;
   - output: statements, scenarios and diffs, exports, checkpoints, bundles and `fa-verify`.

### 0.2 The paradox the research had to resolve

The best-documented frauds in history (WorldCom, Enron, Lehman, Madoff) produced investigation reports
thousands of pages long, but **none of them published a general ledger**. franken_accounting's claims
(detection, prevention at commit, exact certified folds) are claims about ledgers. So every case book
is a *reconstruction*, and a reconstruction can silently become a test of what we planted.

The project has been burned by exactly that:
- fa-4psc measured 100% precision for the Lantern calibration "by construction"
  (`registries/lantern_calibration.toml:22-32`, `FA-ART-CAL-01`, because fa-gen labels what it plants);
- fa-kkxl and fa-e75k retracted oracle claims that overstated what a green test proved.

The research answer is that the public record supports **narrow, exact, checkable predicates** per
case. The honest product is therefore a harness that *enforces* the narrowness. Three rules make it
so:
- every expectation is tied to sourced facts;
- every unsourced input is either disciplined filler that provably cannot move the verdict, or an
  explicit, labelled branch;
- every claim names the encoding and premises under which it holds.

### 0.3 Claim types (normative for every case test and every sentence of case documentation)

| Code | Name | Predicate form (template) | What it proves | Evidence class |
|---|---|---|---|---|
| **D** | detection | "Given the documented entries {F…} (source, anchor) encoded as ⟨encoding⟩, procedure `P` v`N` reports a finding citing each of them; component statuses ⟨S/Sd/Si/B/Rel/X⟩." | that a registered procedure's predicate holds on the encoded entries | the procedure's registered class (never upgraded to `invariant`), plus its calibration status rendered verbatim (§5.6) |
| **P** | prevention at commit | "Given the documented entry F posted as ⟨encoding⟩ with premises ⟨premise closure⟩, the kernel's first refusal is `FA-REF-NNN` (exit `E`, law row L)." | that the kernel refuses that encoding | an observation conditional on its encoding; it cites the invariant the refusal exercises but never inherits `invariant` class |
| **T** | exact tie-out (bridge) | "franken_accounting's certified ⟨read⟩ at ⟨coordinate⟩ equals the published B (source, vintage, accession, assurance status) exactly at B's declared precision, computed from separately sourced A and Δ that were posted." | that FA's posting, case and fold machinery reproduces a published bridge: A + ΣΔ = B, or posted lines fold to printed totals / balances | exact observation on the constructed book, replayable (`fa replay`) and refolded by `fa-verify`; never `proof`, which is reserved for registered Lean 4 theorems (`registries/constitution.toml:17-22`) |
| **C** | consistency check | "… agrees with the published value within ⟨band⟩ derived from ⟨display unit or rounding note⟩; every row satisfies \|Δ − d\| ≤ one display unit; detection limit ⟨…⟩." | agreement up to a stated, sourced display precision | observation; never rendered as T |
| **R** | read-back | "⟨read⟩ at ⟨coordinate⟩ returns the posted ⟨value⟩" (e.g. `AS ORIGINALLY REPORTED` after a restatement) | that a selector, attestation or report path returns what was posted | regression observation; never rendered as T |
| **N** | negative result | "Given the documented entry F encoded as ⟨encoding⟩, no registered law refuses it / procedure `P` does not report it, because ⟨mechanism, file:line⟩." | a limit of the system, published with equal prominence | observation |

Each of D, P, N and T may also carry **counterfactual (CF) rows**. A T's CF changes one input or one rule
version, never the published value. A CF row is the documented entry with
exactly one attribute changed, for example the self-approved transfer posted without its approval. It
shows what an expectation depends on, and is rendered as "if ⟨attribute⟩ were ⟨value⟩ …". A CF row is
never a claim about what happened.

Wording rules. The owner's decision on public wording (owner decision 4, §14) is pending; these are the recommended
defaults:
- Never "franken_accounting would have caught/stopped/prevented ⟨company⟩". Always the predicate.
- Never "matches the Big-4 auditors". Write "reproduces the published bridge ⟨source⟩", and render the
  source's assurance status (§2.2).
- Never "proves", "proven" or "proof" for any T, C, R, D, P or N row. The renderer has no such word in its
  templates.
- Every sourced phrase carries its source's assertion status:
  - the SEC "alleges";
  - an indictment "charges";
  - a special committee or examiner "found" or "reported";
  - a trustee "computed";
  - a filer "reported (audited | reviewed | unaudited | not from audited statements)".
- A D finding is "a finding", never "fraud detected" or an accusation (AGENTS.md: "Do not call a
  statistic an invariant, a detector's flag an accusation").
- A P refusal names the documented attribute it rests on, and its avoidability CF row is rendered next
  to it.
- An N result is published with the same prominence as D/P/T. A case study that shows only what fires
  is marketing. One that shows what does not fire, and why, is evidence an expert witness can use.

### 0.4 What the research established (summary; the case chapters §6–§11 are normative, and this table is generated from their expectation rows once the harness exists, §12.3)

**WorldCom, line-cost capitalization 2001–1Q02.** Facts are journal_entry granularity: 13 entry facts, Beresford pp.105–116.
- D:
  - `expense.capitalization` cites 6 of 13 documented entries;
  - `jet.round_amounts` cites F4 and F6 (F6a and F6b);
  - `jet.self_approved` cites F6 only on a branch (approvals_recorded) of a migration-encoded book;
  - `cutoff.period_boundary` cites F10, whose draft journal entry is dated in the quarter after the one
    it adjusted (W-D-06);
  - after the native restatement, `expense.capitalization` still cites the corrected entries and
    `jet.round_amounts` cites the correction's own entries: FA's own false positives, shown (W-D-07,
    W-D-08);
  - the rest are branch tables.
- P:
  - `FA-REF-008` on the 2001-08-22 transfers. It is conditional on the interpretation (Si) that the
    director both entered and approved them, and holds on a native book. It is reachable now as draft
    self-promotion of the CIP → clearing transfer on admitted Original or Adjusting cells (W-P-01(a)).
    The entry-approval encoding may be reachable now for the allocation step (`fa allocate --approval`)
    and needs the CLI approval surface A0 for `fa post`;
  - `FA-REF-185` when the $544M transfer is encoded as one Reclassification (W-P-04);
  - `FA-REF-080` and `FA-REF-010` as branch tables over evidence attached, entry class and period state.
- T:
  - a bridge (FY2000 total assets, restater's vintage, not from audited statements);
  - the $818M 2002Q1 income-statement diff of the native restatement (W-T-03);
  - F6's allocation through a registered law (W-T-04).

**Enron (reserve releases, Raptors, notes-for-stock, Nov-2001 restatement).** Facts are entry-level (Powers, indictment) and statement-level.
- D: conditional; `cutoff.period_boundary` depends on which dated document the entries cite.
- P: a branch table over class × period state.
- N: no contra-equity law.
- T:
  - the FY1999 bridge (EX-27 A + 10-Q Note 3 Δ = 10-Q B, unaudited); the 8-K vintage is held separately;
  - **E-T-03**, the program's one T whose Δ is *derived from documented entries*. The published "Raptor
    equity adjustment" (−172 FY2000; −1,000 1Q01/2Q01) equals the reversal of the two
    Powers-documented notes-for-stock entries ($172M + $828M).

**Lehman Repo 105 (2007–2008).** Facts are dated_aggregate granularity, on irregular dates.
- D: none admissible as a single verdict.
- P: none (N: no derecognition law).
- T: statement footing at the quarter ends whose full statement of financial condition the 10-Q prints
  (2008-05-31, 2007-11-30). Per-account values shared with Valukas are R rows. Ratios and (b)/(d) are
  computed by the harness. The scenario recharacterization is checked via a certified scenario diff.

**Madoff / BLMIS (trustee Exhibit B).** Facts are ledger_row granularity.
- D: `ponzi.net_investment` equals the trustee's closing principal on 1ZR176 only.
- N: transfers are not followed.
- P: none.
- T and C: exhibit footing on 7 accounts (rows → printed balances), with the trustee-credited transfer legs named as inputs; C on 6 accounts.

**XBRL restatements.** Facts are xbrl_fact granularity.
- D and P: n/a.
- T: SunPower 10-K/A FY2022 (122/122 tagged A+Δ=B triples); Microsoft FY2018 recast (16/16).

**Mergers.** Facts are statement / xbrl_fact granularity.
- D and P: n/a.
- T: LinkedIn PPA footing (total = Σ tagged components).
- C: consideration at its declared ±$50M precision.
- Research item: an exact consolidation T on an Article 11 pro forma.

What the research refuted, which the plan must therefore never claim:
- "Honesty is just the sourced:synthetic ratio", or "filler never matters" (H-001 refuted: registry-level
  classification of procedure dependence agreed with code on only 54/68 = 79.4%).
- "Procedure dependence tiers can be read reliably from code by one reader" (H-040 refuted: an
  independent second reader disagreed on 4 of 12 sampled procedures; and `expense.capitalization`'s
  statistic depends on account VId order, which hashes the synthetic book id).
- "Enron needs the Batson reports" (H-020 refuted: the Powers report and the DOJ indictment give ≥ 15
  anchored facts; Batson's First Interim Report is an image PDF).
- "Enron's 8-K is the tie-out oracle" (H-021 refuted). The Q3-2001 10-Q restates the same periods
  differently in 20 of 30 cells (5 restated lines × 6 periods), and restated values have vintages.
- "BLMIS Exhibit B is an exact T oracle on every account" (H-022 refuted: 6 of 13 tested accounts drift
  by $1–$42 between the displayed rows and the printed balance column).
- "WorldCom P collapses to forced attribution" (H-011 refuted: under the natural reading of Beresford
  p.111, "Abide rarely entered and approved entries himself so his involvement in these transfers was
  unusual", the 2001-08-22 transfers have a `FA-REF-008` branch; the reading is an interpretation).

### 0.5 Non-goals

- Legal conclusions, culpability, or "would have prevented" claims.
- Non-public data: nothing paywalled, behind a login, leaked, or from sealed discovery.
- Benchmarks. Case books are small; their value is semantic.
- A second accounting engine, a PDF or XBRL parsing dependency in shipped crates, or network access in
  tests. Tests are offline and deterministic, and the closed dependency universe holds.
- Replacing fa-gen or the fa-4psc calibration (§12.4).
- Precision or recall figures from case books. Case populations are tiny and hand-selected.

---

## 1. The data reality

### 1.1 What exists, digitally and publicly

1. **Investigation and examiner reports with entry-level facts**, several filed as EDGAR exhibits:
   - WorldCom Special Investigative Committee report (Beresford, 2003-03-31): EDGAR accession
     `0000931763-03-001862`, exhibit `dex991.htm` (SRC-WC-001).
   - Enron Special Investigative Committee report (Powers, 2002-02-01), filed on EDGAR as Exhibit 99.2 to
     Enron's 8-K accession `0000909518-02-000089` (filed 2002-02-07; 217 pages). A university mirror
     also exists (`https://picker.uchicago.edu/Enron/PowersReport(2-2-02).pdf`, SHA-256
     `c2236c873bd08a81d90e6fccd3224de9e7b0e4f96369d4998f38c33d3d0ddf04`, SRC-ENR-005). The EDGAR exhibit is
     the primary source row; the mirror is a retrieval route (§4.1).
   - Lehman examiner report (Valukas, 2010), volumes and appendices (SRC-LEH-001, SRC-LEH-003).
2. **Court and government filings**:
   - SEC complaints (SEC v. Vinson & Normand, SRC-WC-002; the companion Yates and Myers complaints);
   - the DOJ superseding indictment in United States v. Skilling and Causey (SRC-ENR-001,
     `https://www.justice.gov/archive/dag/cftf/chargingdocs/skillingindictment.pdf`, SHA-256
     `7d626cd687f18cd99d152322461255bb78465f08a08ccf4e6864dff12c0fcf2a`);
   - the BLMIS trustee's avoidance complaints with per-account Exhibit B ledgers, hosted outside PACER at
     `madofftrustee.com`: Picard v. Glantz (SRC-BLM-001, SHA-256
     `751a8a55bf02b022076af39c8637086630090b41164f70e2a04184c0d003dec1`), Square One (SRC-BLM-005) and
     Magnify (SRC-BLM-006).
3. **Reported statements on EDGAR**:
   - 10-K / 10-Q / 8-K text. Pre-2001 filings may carry an `EX-27` Financial Data Schedule, which is
     machine readable. Enron's FY1999 10-K carries one; WorldCom's FY2000 10-K405 does not. WorldCom's
     FY2001 10-K was not retrieved, so its EX-27 status is unknown.
   - XBRL instances (2009+). Their `srt:RestatementAxis` members separate *as previously reported*
     (`srt:ScenarioPreviouslyReportedMember`), *adjustment* (`srt:RestatementAdjustmentMember`) and
     *as restated* (undimensioned) values.
   - Restatement reconciliation tables in HTML (as previously reported / adjustment / as restated).
4. **What is NOT available**: any complete general ledger, subledger, trial balance, or bank statement
   of these companies. Every case book is a reconstruction (§2).

### 1.2 Access constraints discovered

- **SEC User-Agent.** `sec.gov` and `data.sec.gov` return HTTP 403 to a request whose User-Agent lacks
  a contact address. The SEC's "Accessing EDGAR Data" page asks for a User-Agent of the form
  `Sample Company Name AdminContact@<sample company domain>.com` and a rate of at most 10 requests per
  second. The research used Internet Archive captures, and recorded the original URL, the archive URL
  and the SHA-256 of the captured bytes.
  - The project's own rule applies to every request:
    `franken_accounting-agent (+https://github.com/Dicklesworthstone/franken_accounting)`.
  - A contact address is an owner decision (§14, item 1). The owner's personal address is never put in a
    header without explicit permission.
  - Archive-only is not neutral. The Internet Archive's terms grant access "for scholarship and research
    purposes only". Archive captures also cannot settle whether archive bytes equal the EDGAR originals.
- **companyfacts drops dimensional facts.** The XBRL JSON API carries no `srt:RestatementAxis`
  adjustment members and no dimensional PPA facts. Instance-wide, 57 dimension-only (concept, value)
  pairs are absent, 40 of them LinkedIn-member facts. The T oracle is therefore the XBRL **instance**
  (or the HTML table), never the companyfacts API.
- **Some captures do not exist**: Kraft Heinz and Hertz companyfacts; some Lehman 10-Qs; RH's 10-Q/A
  HTML restatement table, which was never retrieved. Those rows are recorded `BLOCKED` in the sources
  ledger, never silently substituted.
- **Batson's Enron First Interim Report** is an image PDF without a text layer. Using it would need OCR,
  which is outside the closed dependency universe for shipped code. It is not needed (H-020).

### 1.3 Redistribution (owner decision 2, §14; facts the decision rests on)

- The SEC's FAQ: "All Government-created content on sec.gov and EDGAR public filing content are free to
  access and reuse."
- 17 U.S.C. §105 removes copyright only from works "prepared by an officer or employee" of the U.S.
  Government in that capacity. That covers the SEC complaints and the DOJ indictment, not company
  filings.
- 11 U.S.C. §107(a) makes bankruptcy-court filings public records. That is a statement about access,
  not copyright.
- Neither special-committee report carries a copyright notice. Notice has been optional since 1989
  (Copyright Office Circular 3), so its absence proves nothing.
- madofftrustee.com publishes no terms of use that the research could find.

Recommended policy (pending the owner):
- **Hash-first vendoring.** The repository vendors, for every sourced fact, the anchor, the literal
  values, and the SHA-256 of the sentence-aligned quote. Verbatim quote text (≤ 60 words per fact)
  follows only after the owner rules. The harness never needs quote text at test time (§4.6). This keeps
  the program moving without making an irreversible vendoring decision.
- Never whole documents. Numeric exhibits (all 1,429 Glantz Exhibit B rows; the Valukas balance series)
  are a separate sub-question of decision 2, because vendoring them is vendoring a whole table.

---

## 2. The provenance model (normative)

### 2.1 Every fact has exactly one provenance

Provenance kinds (flattened into `[[fact]]` rows with scalar fields, because the fa-registry TOML
parser accepts no inline tables, dotted keys, multi-line strings, floats or dates;
`crates/fa-registry/src/toml.rs:1-9`):

| kind | fields | meaning |
|---|---|---|
| `sourced` | `source`, `anchor_kind`, `anchor`, `quote_sha256`, `quote` (optional until owner decision 2), `about_scope`, `values` | a sentence-aligned verbatim excerpt that states this fact |
| `interpretation` | `from` (sourced fact ids), `reader`, `second_reader`, `rationale` | a fact the record implies but does not state; for example, that the property-accounting director both entered and approved the 2001-08-22 transfers, inferred from "Abide rarely entered and approved entries himself so his involvement in these transfers was unusual" |
| `derived` | `from` (fact ids), `rule` (registered id), `params` | computed from other facts by a registered rule |
| `synthetic` | `reason`, `discipline` | filler; never supports a claim |

Binding rules (checks K-BIND and K-SCOPE, §3.6):
- **Value binding.** Every numeric or date value of a sourced fact appears as a literal in its quote,
  after a registered `scale` derivation (for example "$742,725,000" → 742725000.00 USD; "$560 million"
  → the literal 560 with scale 10^6 and precision "stated to $1M"). A value that is not literally in the
  quote cannot be `sourced`. It is `interpretation` or `derived`.
- **Scope binding.** `about_scope` names what the quote is about:
  - `entry:F12`, `period:2001Q1`, `scheme:capitalization-2001Q1-2002Q1`, or `account:1ZR010`.
  - A quote whose own words name a period, an entry or an account that conflicts with the fact's scope
    is refused (K-SCOPE).
  - A scheme-level quote supports an entry-level fact only through an `interpretation` row.
  - The research's own error is the test case. The SEC's ¶29 phrase "without any supporting
    documentation or proper business rationale" is about entries "for the first quarter of 2001"
    (SEC v. Vinson & Normand). It was applied to the 1Q02 entries; K-SCOPE must refuse that binding.
- **Sentence alignment.** A quote is one or more whole sentences of the extraction. A fragment such as
  "entered and approved" fails alignment, because its sentence ("Abide rarely entered and approved
  entries himself …") says something different from the fragment.
- **Oracle outputs.** A sourced fact may carry `role = "oracle_output"`: a value that is itself the
  result of the method the case would tie out to. Examples are the trustee's credited transfer amounts
  in Exhibit B and the filer's goodwill residual. Such a fact may feed a T only if the T's predicate
  names it as an input (§5.3, K-ORACLE).

### 2.2 Source assertion status and assurance

Every sources row carries `assertion_status`, which is rendered into every claim sentence that rests on
it (K-ASSERT):

| status | sources | phrase |
|---|---|---|
| `allegation` | SEC complaints | "the SEC alleges" |
| `charge` | indictments | "the indictment charges" |
| `investigative_finding` | special committee, examiner | "the committee found" / "the examiner reported" |
| `trustee_computation` | trustee exhibits | "the trustee computed" |
| `filer_audited` | annual statements with an audit opinion | "reported (audited)" |
| `filer_reviewed` | interim statements reviewed under AS 4105 | "reported (reviewed; a review is not an audit)" |
| `filer_unaudited` | 8-K tables, unreviewed 10-Qs | "reported (unaudited)" |
| `filer_not_from_audited_statements` | selected data the filer disclaims | "reported (selected data; not derived from audited statements)" |
| `court_ruling` | appellate opinions | "the court held" |

The assurance status of a T target is determined from the filing itself at authoring time, from its
audit report, review report or legend. It is never assumed.

### 2.3 Granularity tags

Every sourced fact carries `granularity`, one of:
- `journal_entry`;
- `dated_aggregate` (for example Valukas fn 3365's 36 end-of-day balances on irregular dates);
- `period_total`;
- `statement_line`;
- `xbrl_fact`;
- `ledger_row` (BLMIS Exhibit B).

A claim inherits the coarsest granularity of its basis and must state it. Write "on 36 dated end-of-day
aggregate balances on irregular dates", never "on the Repo 105 entries" or "daily".

### 2.4 The derivation-rule table

The derivation rules live in `crates/fa-oracles/data/case_derivations.toml`, a harness table with one
consumer. It sits beside `case_procedure_tiers.toml` and `case_branch_rules.toml`, and all three are
embedded with `include_str!` from inside the `fa-oracles` crate. They are **not** product registries,
for two reasons:
- `scripts/crate_verdicts.py` puts every `registries/*.toml` into a global invalidation digest. Every
  edit to a registry invalidates every crate's cached verdict and forces a cold re-proof of the
  workspace (`scripts/crate_verdicts.py:1-22`).
- Registries are durable formats that must stay versioned additive-minor / breaking-major.

The tables still follow the conventions of `registries/verbs.toml:1-13`: `schema_version = 1` and a
Consumer/Gate/Retire header.

Each rule lists:
- id;
- arity;
- parameter schema;
- exact semantics: integer arithmetic at the unit's scale, with no floats, and no rounding unless the
  rule names a law in `registries/rounding_laws.toml`;
- whether it is **interpretive** (`interpretive = true`);
- an example.

The harness recomputes every derived fact at load and fails on any mismatch (K-DERIVE).

An interpretive rule is a judgment. Every claim that uses one names it in its rendered sentence. For
example, the account-role mapping is a judgment, so a D on WorldCom tests the procedure's predicate
*under our mapping*. Initial rules:

| rule | interpretive | semantics |
|---|---|---|
| `scale{multiplier}` | no | literal × 10^k (EX-27 MULTIPLIER, XBRL decimals, "$X million") |
| `date_literal` | no | "July 17, 2001" → `"2001-07-17"` |
| `number_word` | no | "three" → 3 |
| `period_literal` | no | "the second quarter of 2001" → `2001Q2` |
| `sum`, `difference` | no | exact integer arithmetic |
| `negate` | no | the exact additive inverse of a sourced entry's legs, same accounts and units (a correction Δ) |
| `round_residue{power}`, `weekday_of`, `same_leg_multiset_same_day`, `same_leg_multiset_within{days}`, `rsf_ratio`, `first_digit_counts` | no | predicate models of the §9.4 procedures; integer only; each named with its registry parameter names |
| `date_offset{days}` | no | "three days later" → date + 3. The weekday is recomputed and rendered. |
| `remainder{line, of_total}` | no | one remainder account per account type, so that a statement partitions (§3.8) |
| `last_balance_on_or_before{date}` | no | selects a printed running balance; used for declared trial balances (M-T-03) |
| `legacy_tb_from_chunks` | no (tautological; supports no claim) | the legacy trial balance a migration book must declare, derived from its own staged chunks (§6.6) |
| `role_map{chart_rule}` | **yes** | sourced account name → account **type** (`registries/account_types.toml`) and optional **role** (closed set of 15, `registries/account_roles.toml`) |
| `one_leg_per_named_account` | **yes** | the default leg encoding when the record names accounts but not legs |
| `subledger_to_gl_legs` | **yes** | maps F6's ten sub-ledger assets of $54.4M each (p.111: "creating 10 assets"; pp.260–261: "making 10 different entries") to GL entries. It is a branch: one allocation entry (W-T-04) or ten two-leg entries |
| `round_dollar_lower_bound` (R-QUAL) | **yes** | DEBATE-002: "round-dollar" maps to "a whole multiple of 10^3 units", only within the characterization's stated scope (§2.6) |
| `trustee_transfer_credit` | **yes** | Exhibit B footnotes [1]/[2] read as credit = min(statement amount, max(0, originating principal)); tested on 2 in-file pairs only |
| `same_day_display_reorder` | **yes** | Glantz 1ZB010's same-day CHECK / STOP PAYMENT pair displayed out of computation order |

### 2.5 Procedure tiers (dependence of a verdict on non-target data)

The tier vocabulary is adopted from DEBATE-002. H-040 itself was refuted, but its adjudicated rules
stand.

| Tier | Reads | Admissible for D | Filler discipline that keeps the verdict invariant |
|---|---|---|---|
| L (entry-local) | only the target entry's own legs, approvals, memo | yes | filler never supersedes, reverses or edits the target |
| C (entry + book context) | also calendar, account roles and types, account codes, rule ids, period state | yes, **only** if every context fact it reads is sourced, declared-derived, an observed covariate (§2.6 rule 9), or a listed branch attribute | as L, and context facts are fixed by the case, never by filler |
| S-rel | related entries by key (reversal pairs, duplicates) | yes | key-disjoint filler |
| S-acct / S-party | one account, party or cell population | yes | account-, party- or cell-disjoint filler |
| G (graph search over a bounded component) | SCC/BFS over party or flow graphs | yes, with extremal variants (§3.7) | component-disjoint filler |
| O (commit-ordinal) | commit order | yes | commit-order-disjoint filler |
| P (population-relative) | rarity, share, digit tests, ratios, community detection | **no**, unless the comparison population is itself sourced and complete | — |
| A (aggregate) | period-wide or book-wide aggregates, truncation by count | **no** | — |

Two procedures need particular care:
- `graph.party_communities` (Louvain) is tier **P**. Its partition moves with unrelated same-scope volume
  and, on small graphs, with node order.
- `ponzi.net_investment` is classed S-party by the research's code reading, and the two-reader row
  must confirm it.
  - Each investor's flag, severity and value come from that investor's own attributed cash.
  - The earliest first inflow across all parties shapes only the cohort number in the finding's
    narrative text, which is not in the projection (`crates/fa-lantern/src/cutoff.rs:2712-2725`).
  - The procedure has no findings cap; its only parameter is `cohort_window_days`.
  - A Phase 6 synthesis claimed a cap of 100. That claim does not hold at 8196f5e40 and was withdrawn.
  - Its population rule still retains every party with attributed cash in as an investor (AN-401,
    `cutoff.rs:2626`). That is a membership question, not a dependence of the target's own figures.

`crates/fa-oracles/data/case_procedure_tiers.toml` holds one row per claimed procedure:
- the tier;
- the code location that justifies it, as file:line at the pinned commit;
- **two readers** (agent or human ids). Each classified the procedure independently from code, with the
  class definitions in this section in hand. If they disagree, the row takes the more conservative
  (higher-dependence) tier and records the disagreement;
- the procedure's id, version, and the SHA-256 of its `registries/procedures.toml` row, including its
  `[[parameter]]` rows;
- `reads_evidence` (bool, two readers): whether the procedure reads an entry's evidence, documents or
  attestations. It is required for any expectation on a `ledger` or `statement` variant.

A version or row change invalidates the tier row and requires a fresh two-reader classification
(K-TIER). Undeclared behaviour drift is caught at runtime by the filler-invariance witness with
extremal variants (§3.7), which fails and names the procedure.

A per-crate code-closure hash is deliberately not used. `scripts/crate_verdicts.py` closures include
every transitive workspace crate and every registry, so such a hash would invalidate the row on almost
every landing. That would leave a gate that is permanently red, or pressure to weaken it.

### 2.6 Unanchored target attributes are branches; constraints cannot decide the predicate

Some inputs that a procedure or the kernel reads belong to the documented entry, but the record does
not state them. They are enumerated as **branches**. The attribute list is a closed enum (DEBATE-002
rule 3, extended):

| attribute | meaning |
|---|---|
| `encoding_origin` | `native`, `migration` |
| `approval_encoding` | `entry_approval` (needs A0), `draft_self_promotion` (a draft promoted by its owner; reachable now), `migration_legacy_pair`, `none` |
| `entry_class` | Original, Adjusting, Reclassification, … |
| `reclassification_target` | which posting a Reclassification reclassifies; the move is capped by the target's remaining leg (`FA-REF-185`, RECLASSIFICATION_SHAPE) |
| `period_state_at_commit` | Future, Open, SoftClosed, Closed, Locked, including the order of close transitions relative to the entry |
| `effective_date` | |
| `document_date` | |
| `amount_precision` | per leg |
| `leg_split` | legs per side and per-leg amounts |
| `entry_decomposition` | how a documented compound transfer maps to GL entries, from a registered interpretive rule (`subledger_to_gl_legs`): `one_allocation_entry` / `ten_two_leg_entries` for F6b; `one_entry` / `twelve_entries` for F8 (p.261: "this time they made 12 entries") |
| `evidence_attached` | `none`; `placeholder_unreviewed` (an `AgentUpload` placeholder, → `FA-REF-086`); `placeholder_reviewed` (Reviewed by `case-second-reader`); `manual_assertion(code)`. A placeholder is never a citation stub: its bytes are `fa:case-placeholder:v1`, the fact id, and "the record describes this document; its bytes are not public". It is never filed in the provenance engagement, and renders as "a placeholder the reconstruction attached". Every admission it enables is a scenario result (W-P-02) |
| `approvals_recorded` | which approvals exist, and by whom |
| `capability_grants` | the ops the acting principal holds (`--grant`), read by kernel step 1a and by period-law cells that require an op (`registries/admissibility.toml:63`, `:237`) |
| `acting_principal` | which role label prepares, approves or posts; read by SoD and by ManualAssertion signing (`crates/fa-journal/src/attestation.rs:873-877`) |
| `account_lifecycle` | account opened/closed dates; read by kernel step 6 |
| `party_and_dimension_values` | |
| `chart_role_mapping` | |
| `case_determination_date` | the day of the non-reliance (or immateriality) determination a case records (`fa case open --determined-on` / `fa case determine --on`). It is sourced from the Item 4.02 8-K where one exists (Item 4.02(a)(1) requires the date), and is otherwise a declared default (the restating filing's date: it is the one date every restatement case has, it is public and fixed, and it never precedes the restated figures' basis; an earlier "first disclosure" date would need a sourced reading of which press release or call counts) |

**Book context.** Attributes a book variant fixes once, such as the opening date, calendar, unit scale
and idempotency keys, are declared in `books/<variant>.toml`. They are never varied, and every premise
list that reads them names them.

Rules:

1. **Component statuses** (DEBATE-002 rules 1–2, extended).
   - A D verdict is a projection with components: procedure@version, cited entry (and cited accounts and
     legs, projected to account codes and (fact, leg ordinal)), severity, and statistic.value.
   - A P verdict's components are the refusal id and the law row.
   - Each component has one status:
     - **S**: single on sourced inputs;
     - **Sd**: single under a declared derived rule;
     - **Si**: single under a named `interpretation` read by two readers. It renders as "under the
       reading ⟨rationale⟩", with the counterfactual row of the weaker reading beside it. W-P-01 is the
       model case.
     - **B(attrs)**: a branch table over exactly the attributes that component reads;
     - **Rel(covariate)**: a relational expectation over an observed covariate (rule 9);
     - **X**: inadmissible.
   - A component is single (S, Sd or Si) iff every input the code reads for it is sourced, declared,
     interpreted, or an observed covariate, at the precision the code tests.
2. **Default encodings are declared rules**, not silent choices. Examples: one leg per named (account,
   side); one approval encoding per entry; the role mapping; the effective date defaulting to the
   reporting period's last day. A component that depends on an undeclared default is a branch.
   A declared default makes a component single (Sd) only if the component's value is the same in every
   feasible cell of the defaulted attribute's branch classes; K-PRED applies to defaults as to
   constraints. Otherwise the component is B(attribute), and the default's cell is marked `default` in
   the branch table.
3. **R-QUAL** (DEBATE-002 rule (c)). A sourced qualitative fact may constrain branches only:
   - if its stated scope covers the target entry with no documented exception;
   - through a declared interpretive rule anchored on the source's own usage;
   - and only for the attribute it describes (entry amounts, never leg splits, leg counts or severity).

   The component's basis is then `derived{rule: R-QUAL}`.
4. **A constraint may not decide the claimed predicate** (K-PRED). A numeric branch domain must contain
   at least one *feasible* representative in each cell of the claimed predicate's partition that the
   literal sourced values allow.
   - For `jet.round_amounts`, that partition is residue 0 versus ≠ 0 modulo 10^round_power units.
   - "Feasible" means the encoded entry still balances per unit. For example, F4 cannot have exactly one
     non-round credit leg.
   - If a qualitative constraint alone collapses the domain onto the hit cell, the expectation renders as
     "restates the source's characterization", not as D.
   - A capped or sampled enumeration never yields a single verdict.
5. **Equivalence classes instead of exhaustive enumeration.** Branch cells are registered,
   predicate-derived equivalence classes: residue classes mod 10^round_power, "inside / outside the last
   `window_days`", and so on.
   - Each class rule lives in `crates/fa-oracles/data/case_branch_rules.toml` with its code
     justification.
   - Each rule is property-tested: random members of a class must give the same projection through the
     real binary on a micro-book.
6. **P verdicts are first-refusal verdicts.** The kernel aborts at the first failing step of
   `prepare_post_in`. There are about thirty numbered steps, from `:1594` (structure) to `:3814` (seal).
   Among them, in order:
   - authorization (1a, `:1599`);
   - balance law (2, `:2044`);
   - period resolution (3, `:2132`);
   - identity (4, `:2246`);
   - reclassification target (`:2491`);
   - period law (5, `:2591`: `FA-REF-010/011`);
   - SoD (`:2866`: `FA-REF-008/012`);
   - event citation (5a, `:2939`, which also emits `FA-REF-080`);
   - evidence minimum (5b, `:3009`: `FA-REF-080/086`);
   - account laws (6, `:3074`), after evidence.

   Two step labels repeat (`3''` at `:2156` and `:2491`; `5''` at `:2666` and `:2866`), so the case
   names steps by their comment text, not their label. A P cell records the first refusal only.
   `FA-REF-080` is claimed only in cells that pass period law and SoD, and the cell names its law row.
   - **Premises.** A P claim's premises are **every attribute the intent's encoding sets**: each declared
     default (rule 2), each enumerated branch value, and the book context. This deliberately over-lists
     and never under-lists. It needs no hand-maintained table of kernel steps, which would go stale with
     every edit to `post.rs`.
   - **Reference differential.** Where `fa-reference`'s `Oracle` models the deciding law, the same intent
     is also posted to the oracle, and its verdict must equal the kernel's first refusal. The oracle
     mirrors the kernel's law order with independent constants (`crates/fa-reference/src/lib.rs:1-20`)
     and covers balance, period resolution, identity, period law and admissibility, case membership and
     folds. Its top-level `Intent.approvals` is a count, but dedicated modules model the rest:
     - SoD with approver identity (`fa_reference::sod::verdict`, `crates/fa-reference/src/sod.rs`;
       `FA-REF-008`, `FA-REF-012`);
     - the evidence minimum with self-sourced review and reason codes (`fa_reference::evidence::verdict`,
       `crates/fa-reference/src/evidence.rs`; `FA-REF-080`, `-086`, `-111`, `-112`);
     - naive Lantern procedures (`fa_reference::lantern`: `round_amounts`, `post_closing`,
       `self_approved`, `cutoff`);
     - statement rendering in its own limb arithmetic (`fa_reference::statements::render`).

     A4r uses all of them.
7. **D and P on one entry have disjoint scopes** (K-JOINT). A refused branch removes the entry from every
   D population on that branch, because procedures read `snapshot.live_postings()`. Every D target
   therefore names the *admitted* cell it runs on, its evidence cell at least.
8. **Counterfactual (CF) rows** are a separate type. They are exempt from the rule that branch values may
   not contradict sourced constraints, and they never support a claim about what happened.
9. **Observed covariates.** An input the code reads but the harness cannot set is not a branch.
   - Today the only one is account-VId order. `fa book create` draws the book id from production entropy
     (`crates/fa-cli/src/cli.rs:3879-3883`), and `account_vid = H("fa:vid:account:v1" ‖ book_id ‖ code)`
     (`crates/fa-model/src/ids.rs:294-298`).
   - Its component is expected **relationally**. The expectation states the code's rule, for example
     "statistic.value = the magnitude of the debit leg on the minimum-VId fixed-asset account of the
     entry". The runner checks it on every run, computing the order from the logged book id with the
     public `fa_model::account_vid`, or reading `account_vid` from `fa explain balance --json`.
   - The rendering lists the values the documented legs allow, and says the selection depends on a random
     identifier.

### 2.7 The source report is provenance, never the evidence for an entry under test

A reconstructed *documented historical entry* must not cite the investigation report or filing as its
supporting document. The evidence minimum requires at least one document of any kind for Original,
Reclassification and Adjusting (`registries/evidence_policy.toml:166-212`). Citing the report would
therefore make every evidence-based P claim vacuous.

Rules:

- **K-EVID (scoped).** On every *entry-level* book variant (`native`, `migration`), the oids of evidence
  cited by every intent that encodes a *documented entry* (its `fact` is a sourced or interpretation fact),
  and by every filler intent, must be disjoint from the engagement's provenance documents. A case Δ
  intent (`fact = derived:<rule>`) cites the restating filing's stub, as on a `statement` variant: the
  Restatement, Revision and PPA minimums admit no ManualAssertion, and that filing is the Δ's basis.
- **Filler evidence.** Each filler variant cites one `fa:case-filler:v1` document (kind `Other`, reviewed
  by `case-second-reader`). It never cites a provenance stub, or a placeholder of a documented entry.
- **Statement-level books cite the publishing filing.** On a `statement` variant (§3.2), each posted
  figure cites the citation stub of the filing that publishes it:
  - an A posting cites the as-filed filing;
  - a Restatement/Revision/PPA Δ cites the restating filing;
  - a migration chunk cites the exhibit it reproduces.

  The Restatement, Revision, PriorPeriodAdjustment and Migration minimums require a document and admit
  no ManualAssertion (`evidence_policy.toml:239-261`). The filing is the true basis of the figure. No P,
  N, CF or evidence-reading D expectation may sit on a `statement` variant.
- **Ledger books cite the exhibit.** On a `ledger` variant (§3.2), each row cites the citation stub of
  the exhibit it reproduces, as a migration chunk does. No expectation whose procedure reads evidence may
  be declared there (the tier row's `reads_evidence`, §2.5).
- **Self-disclosure.** Every book variant runs `jet.self_sourced_evidence` (`registries/procedures.toml:97-105`;
  `crates/fa-lantern/src/jet.rs:418-516`).
  - An expectation with `about = "reconstruction"` asserts that it cites every posting that cites a
    reviewed citation stub, at severity Medium. Such a row is a D about our encoding, not about history,
    so it is exempt from K-EVID's bar on `statement` and `ledger` variants.
  - It renders first in "How this book was built": "franken_accounting's own
    `jet.self_sourced_evidence` reports that every posting here rests on documents this reconstruction
    uploaded itself".
  - `fa explain evidence` for each documented entry renders its stub or its reconstruction-placeholder
    assertion (an R row).
- **What a document's bytes are.** Originals are never committed (§4.2), and tests never read the cache
  (§4.3). So every document the harness adds is a **citation stub**: the canonical bytes of its
  `sources.toml` row.
  - The format is `fa:case-source-stub:v1`, then one `key=value` line each for `id`, `title`,
    `accession`, `original_url`, `sha256`, `assertion_status` and `retrieval_route`. A fact-level stub
    adds `anchor` and `quote_sha256`. `fa-oracles` renders it.
  - Its kind is `Other`, except one `Disclosure`-kind stub per restatement case, of the restating
    filing, used only by `fa case disclose`.
  - It is added with the CLI's default grade `AgentUpload` (`crates/fa-cli/src/document.rs:363-371`),
    never `HumanUpload`, because no human uploaded it. An `AgentUpload` is self-sourced. It counts toward
    the evidence minimum only after a principal other than its uploader records a Reviewed attestation;
    otherwise the refusal is `FA-REF-086` (`crates/fa-journal/src/evidence.rs:1104-1173`).
  - The Reviewed attestation is recorded by the role `case-second-reader`: the principal whose
    independent `case_fetch.py verify` receipt (§4.5) exists for that source.
  - Renderings say "a citation of ⟨source⟩ (bytes: the reference, not the document)".
- **The provenance engagement.** The case runs `fa engagement open <id> --kind investigation --period
  <code>… --overall "0.00 <BASE>" --performance "0.00 <BASE>" --clearly-trivial "0.00 <BASE>"`. All
  three materiality figures are required, and they are stated, never judged (`registries/verbs.toml:736`).
  This rendering is "no materiality stated". Then `fa engagement file <id> --document <oid>` files each
  stub. The materiality figures are never invented.
- **Documents whose bytes are not public.** Where the record says a document existed (a schedule, a
  Post-it, a draft journal entry, an e-mail), the honest representation is the doctrine's own: an
  explicit `ManualAssertion`, never a plausible stand-in file. Three facts constrain it:
  - (a) **Reason codes are a closed set.** `attest manual` accepts only the five registered codes in
    scope `manual_assertion` (`registries/reason_codes.toml:29-53`): NoDocumentIssued, DocumentLost,
    OralAgreement, ManagementEstimate, InternalTransfer. Each asserts a historical fact that the record
    may not state.
    - The plan proposes an additive code, `NotInPublicRecord` ("a document is described in the public
      record; its bytes are not public"). This is owner decision 5 (H14).
    - Until it exists, the case uses `InternalTransfer` for the capitalization entries, which are
      literally transfers between the book's own accounts. The assertion's `--statement` carries
      "reconstruction placeholder: ⟨the record describes …⟩".
  - (b) **The preparer signs.** A ManualAssertion must be signed by the entry's own preparer
    (`crates/fa-journal/src/attestation.rs:873-877`). In a reconstruction that is the role-labelled
    preparer principal, so a historical person would appear to sign an act they never performed. Every
    such assertion is therefore marked `encoding{reconstruction_placeholder}` and rendered as "the
    reconstruction attaches a manual assertion in place of the described document".
    `evidence_attached` is a branch attribute, and a P or N result that depends on it is a branch row,
    never a single verdict.
  - (c) **Presence, not content.** The evidence minimum checks presence and kind, not content, and every
    evidence-related claim sentence says so.
- **Traversal.**
  - `fa explain evidence <entry-vid>` walks from an entry.
  - `fa engagement show` lists filed documents and findings side by side.
  - **Finding → source.** After each D run, `case-second-reader` records
    `fa finding review F:<vid> --action acknowledge --note <template> --evidence D:<fact stub>` for every
    finding that cites a documented entry with an S, Sd or Si cite. The reviewer is a Human with read and
    approve, independent of the run producer (`registries/verbs.toml:881`), and the stub is that entry's
    fact-level citation.
    - Then `fa engagement file <id> --finding <vid>` files the finding (`registries/verbs.toml:736`), and
      `fa finding export --include-reviews --export-format canonical` replays it.
    - R row: each such finding carries exactly one review, whose evidence is its entry's stub. No finding
      that cites only filler carries one.
    - It renders as "acknowledged, citing ⟨source, anchor⟩", never "confirmed". `dismiss` is never used.
    - K-EVID does not apply to review evidence, which is not an intent's evidence.

### 2.8 Real people

Books and tests use role labels (`gen-acct-director-1`, `property-accounting-director-1`), and a case's
`roles.toml` maps each label to the report's role description. The SEC's 2002 complaint against Vinson
and Normand refers to the property-accounting director as "the DPA", which is precedent for the
practice. That person was later sued by the SEC: SEC v. Mark P. Abide, 06 Civ. 5660 (S.D.N.Y.),
Litigation Release 19776, 2006-07-27, a civil action settled without admitting or denying. So the case
for role labels rests on the branch-table ground and on minimizing names, not on anyone being uncharged.

- **BLMIS.** The role-label rule covers BLMIS account holders, whose names appear in Exhibit B headers.
  Account numbers such as `1ZR010` are trustee identifiers and are kept.
- **No names in clear.** The K-NAMES deny list is stored as SHA-256 hashes of normalized name tokens,
  never in clear.
- **Gating.** Owner decision 3 gates every facts file whose quotes contain a name. That includes the
  F6 pilot quote, Beresford p.111.

---

## 3. Architecture of the harness

### 3.1 Placement (grounded in the code at 8196f5e40)

- **There is no shared e2e crate.** Every e2e test file defines its own helpers. The established pattern
  is `crates/fa-cli/tests/cli.rs:78-96`: `fa(dir, args)` spawns `env!("CARGO_BIN_EXE_fa")`, removes
  `FA_BOOK`, and checks every `--json` line with `check_robot_output` against
  `fa_cli::verbs::registry().check_line`.
- **The runner.** `CARGO_BIN_EXE_fa` exists only for integration tests of the `fa-cli` package
  (`[[bin]] name = "fa"`). So the case **runner** is the integration test target
  `crates/fa-cli/tests/cases.rs`, with one `#[test]` per case and one per cross-cutting check (§12). It
  is the only engine-touching code in the program. It:
  - spawns `fa`;
  - checks each line with `check_line`;
  - computes account VIds with `fa_model::account_vid` where a component is relational (§2.6 rule 9);
  - hands the raw robot lines to `fa_oracles::cases::Observation::from_robot_line`;
  - calls `fa_verify::verify_bundle` in-process for bundles. The precedents are
    `crates/fa-cli/tests/proofs.rs:335` and `crates/fa-cli/tests/production.rs:1014`; `fa-verify` is
    already a dev-dependency of fa-cli.
- **The case model.** It covers the schema, loader, validators, derivation engine, filler generator,
  branch enumeration, expectation evaluation, citation-stub renderer and README renderer. It goes in
  **`crates/fa-oracles`** (module `cases`).
  - **Why this crate.**
    - `fa-oracles` is already a planned row in the verification layer
      (`registries/workspace_topology.toml:201-205`, `planned = true`), and COMPREHENSIVE_PLAN §18.1
      names it.
    - Public-record tie-outs are exactly the external oracles of COMPREHENSIVE_PLAN §16.
    - The topology pin test (`crates/fa-registry/src/topology.rs:160-235`) pins names and layers to
      COMPREHENSIVE_PLAN §18.1, so a new crate name would need a plan edit; `planned` itself is not pinned.
    - The two existing verification crates are wrong homes. `fa-conformance` is the substrate behaviour
      suite (one test per FrankenGraphDB behaviour against the pinned `fgdb` API). `fa-reference` is the
      independent oracle, allowlisted to `fa-time` and `fa-registry`, and must stay independent.
  - **Creating the crate**:
    - flips `planned = false`;
    - adds the crate to the root `Cargo.toml` members;
    - sets `publish = false`;
    - adds `allowlist = ["fa-registry", "fa-reference"]` to its topology row, which the existing
      `topology` step enforces.
  - **Engine independence.** fa-oracles does its own exact integer arithmetic (checked i128 at each
    unit's declared scale) and has its own minimal JSON reader, SHA-256 and canonical renderers. It
    never links `fa-money`, `fa-model`, `fa-cli` or the substrate. This follows the reasoning behind
    `fa-reference` (`crates/fa-reference/src/lib.rs:3-14`): a bug shared with the engine must not be
    able to make a tie-out agree. fa-oracles needs its own SHA-256 because the only workspace
    implementation is private (`crates/fa-docket/src/intake.rs:566`). It is std-only and tested against
    the FIPS 180-4 vectors.
  - **Edges.** `fa-cli` takes fa-oracles as a dev-dependency. Dev edges into the verification layer are
    lawful (topology header); the precedent is `fa-lantern` dev-depending on `fa-gen`
    (`crates/fa-lantern/Cargo.toml:31`).
- **Case data and harness tables** live under `crates/fa-oracles/cases/<case-id>/` and
  `crates/fa-oracles/data/`. They are embedded with `include_str!` from inside the crate, so
  `scripts/crate_verdicts.py` hashes them into fa-oracles' tree, and through the dev edge into fa-cli's
  closure. Editing a facts file therefore invalidates exactly the verdicts it can affect.
- **Data format: TOML subset, not JSON.** Case data uses the public std-only subset parser
  `fa_registry::toml::parse` (`crates/fa-registry/src/lib.rs:29`, `toml.rs:155`).
  - **Why TOML.**
    - Every other hand-authored data file in the repository is a registry in this subset.
    - Its parser is public, std-only and gives canonical bytes (`toml.rs:56-95`).
    - It allows comments, which JSON does not. Without comments, every rationale in a facts file would
      be pushed into string fields.
  - **Accepted costs**:
    - every array is on one line;
    - strings are basic strings with the escapes `\n \t \" \\` only (`toml.rs:267-287`);
    - an array of tables is not nested under the previous row, so legs, values, targets and branch cells
      are foreign-key rows;
    - arrays of different names lose their relative order, because the parser keeps them in a
      `BTreeMap` by name (`toml.rs:56-60`). The documented history of a book is therefore a single
      ordered `[[step]]` array.
  - **The CLI's JSON.** The runner renders each intent to the JSON the CLI accepts (`crates/fa-cli/src/cli.rs:7339-7363`).
    That JSON is a derived artifact and is never committed.

### 3.2 Files of one case

```text
crates/fa-oracles/cases/<case-id>/
  case.toml          # id, title, version, kind (`case` | `harness_selftest`), scope, claim list, declared capabilities, pinned commit, book variants
  sources.toml       # sources ledger rows (§4.1)
  receipts.toml      # GENERATED by case_fetch.py verify; never hand-edited (§4.4)
  facts.toml         # [[fact]] (sourced / interpretation / derived / synthetic) + [[value]] rows (§2.1)
  roles.toml         # role labels ↔ report role descriptions; hashed name deny list (§2.8)
  books/<variant>.toml  # one per book variant (schema §3.2a)
  expectations.toml  # [[expectation]] + [[target]] + [[branch_cell]] rows (§5)
  README.md          # GENERATED from the last green run (§12.3); never hand-edited
```

**Book variants are first-class.** One documented entry can need several books, and each expectation
names the variant it runs on:
- `native`: entry-level. It carries D, P, N and CF expectations, plus T and R rows whose inputs are
  documented entries and whose read isolates them from filler (a case statement diff, an allocation's
  legs).
- `migration`: entry-level, legacy-origin replay. It carries D rows of legacy-attribute procedures and
  migration tie-out T rows.
- `statement`: one or more per case (one per vintage that must not share a chart), with T, C or R rows.
  It is a statement-level reconstruction with its own calendar and chart, citation-stub evidence from the
  publishing filings (§2.7), and no filler. It carries no D/P/N/CF expectations except
  `about = "reconstruction"` rows.
- `ledger`: one per case whose facts are `ledger_row` (BLMIS Exhibit B) or entries derived from a
  `dated_aggregate` series (Lehman L-D-01).
  - Each row cites the citation stub of its exhibit (§2.7).
  - There is no filler: the rows are the population.
  - It carries T, C and R rows, plus D and N rows of procedures whose tier row records
    `reads_evidence = false`. It carries no P, no CF and no evidence-reading D.
  - Rows post through `fa batch` (`registries/verbs.toml:350`), at most 8,190 entries per batch
    (`registries/limits.toml:99-101`), each batch with a derived idempotency key.

Entry-level facts and statement-level aggregates never share a book. If they did, a
98,727,000,000.00 total-assets posting would enter `jet.round_amounts`' population and add findings no
source supports.

#### 3.2a Book-variant schema (`books/<variant>.toml`)

| table | fields (all scalars or one-line arrays) |
|---|---|
| `[book]` | `variant`, `opening_date`, `calendar` (`custom`), `base_unit`, `posture` |
| `[[period]]` | `code`, `start`, `end`, `fiscal_year`, `kind`. Every period the history uses is created (`fa period create --fiscal-year N`) and then opened (`fa period open`). Periods are born `Future`, which admits nothing (`registries/admissibility.toml:55`). |
| `[[principal]]` | `label` (from roles.toml), `profile`, `grants` (one-line array of ops) |
| `[[account]]` | `code`, `name_fact` (the sourced name), `type`, `role` (may be empty), `opened`, `closed`, `role_map_rule` |
| `[[document]]` | `id`, `stub_of` (source id, or fact id for a fact stub), `grade` (`AgentUpload`), `reviewed_by` (principal label or empty) |
| `[[intent]]` | `id`, `fact` (the documented entry it encodes, `derived:<rule>` for a Δ, or `synthetic`), `class`, `principal`, `effective_date`, `document_date`, `memo`, `evidence` (document id, `manual_assertion:<code>`, or empty), `idempotency_key`, `target` (the intent id it reverses, restates, revises or reclassifies; required for those classes), `target_kind` (`reverses` / `restates` / `revises` / `reclassifies`), `reason` (a `registries/reason_codes.toml` name in scope `supersession`; a declared default with its rationale), `scenario` (the case scenario it is planned into, or empty), `allocation` (law, total, targets; §5.3) |
| `[[case]]` | `id`, `kind`, `periods`, `determined_on` (fact id or declared default, §2.6), `authority` (document id), `disclosure` (document id), `approvers` (two role labels with no shared session lineage, `crates/fa-cli/src/cli.rs:3450`), `poster` |
| `[[leg]]` | `intent`, `ordinal`, `account`, `side` (`Dr` or `Cr`), `amount_literal`, `amount_rule`, `unit` |
| `[[step]]` | `seq`, `kind` (`intent` / `batch` / `allocate` / `period_open` / `period_soft_close` / `period_close` / `period_lock` / `issue` / `assert_balance` / `scenario_fork` / `scenario_run` / `scenario_diff` / `case_open` / `case_determine` / `case_rehearse` / `case_approve` / `case_post` / `case_disclose` / `case_close` / `checkpoint` / `checkpoint_witness` / `finding_record` / `finding_review` / `engagement_file` / `filler_batch`), `ref` (an intent, period, case or procedure id, etc.), `known_at` (`head` / `pre_case`, for `finding_record`), `branch_class` (empty = all) |
| `[[branch_class]]` | `id`, `attribute` (§2.6 enum), `rule` (from `case_branch_rules.toml`), `values` |
| `[[default]]` | `attribute`, `rule`, `rationale`: the declared default encodings (§2.6 rule 2) |

A complete worked example for the A8 pilot (WorldCom F2, F4, F9, F12) follows. Items A1a–A1c share it
as their acceptance fixture.
It writes all four files (sources, facts, books/native, expectations) in this subset, and every foreign
key resolves.

### 3.3 The run pipeline

**Cell evaluation.** Each P branch cell is evaluated by `fa post --dry-run`, which runs the same
admission pipeline. Planning skips only the Agent-on-trunk check, which never applies to a Human
principal (`crates/fa-policy/src/admit.rs:153`; `crates/fa-journal/src/post.rs:873-889`). So for the
case's Human principals, the dry run and the commit admit identically.
- All cells of one entry are swept on one book. The book's period is advanced Open → SoftClosed →
  Closed → Locked between sweeps.
- For each distinct outcome (a refusal id, or admit), one representative is committed, and the commit
  must agree with its dry run (otherwise FAIL).
- D branch cells for tier L and C procedures are co-resident target entries in one book. Each is the
  other's filler, so the filler-invariance witness also checks that co-residents do not interact. Each D
  cell of tier S-rel, S-acct, G or O gets its own book.
- A filler variant is posted as one `PostBatch` (`registries/verbs.toml:263`).
- **Combination rule.** Filler variants (K seeded, empty and extremal) run on the default branch cell
  only. Branch cells run on the empty-filler variant only. This is sound because a tier's filler
  discipline does not depend on target attributes; class equivalence is property-tested separately
  (§3.7).

Steps, with verb names as registered at 8196f5e40. The harness's verb table is checked against
`registries/verbs.toml`, so a renamed verb fails before any book is created.

1. **Load and validate**, purely, with no binary: all of §3.6, derived facts, branch cells, and filler
   for the seed.
2. **Create the book**:
   - `fa book create --calendar custom --periods <json> --opening-date <d>`;
   - `fa period create --fiscal-year N` and `fa period open <code>` for every period used. The
     custom-calendar flow is in `crates/fa-cli/tests/cli.rs:15494-15530`;
   - principals via `--as <label>` and `--grant <op>` per invocation. There is no principal registry,
     and issued tokens cannot approve on the CLI (`FA-REF-011`);
   - chart, types and roles;
   - parties and `party relate --kind owns --pct --basis --valid-from` (`crates/fa-cli/src/rea.rs:23`);
   - the provenance engagement (§2.7);
   - citation stubs via `fa document add` (default grade `AgentUpload`), each followed by
     `fa document attest review` by `case-second-reader`.
3. **Replay the documented history** in `[[step]]` order, through `fa post` or `fa commit --plan`.
   - **Approvals.** At 8196f5e40, `fa post` and `fa commit` cannot attach an approval, although
     `fa allocate` and `fa settle` can (`registries/verbs.toml:459`). `fa post` and `fa commit` have no
     `--approval` (`registries/verbs.toml:259`, `:395`), and the request builder
     hard-codes `approvals: Vec::new()` (`crates/fa-cli/src/cli.rs:8230`). There are two consequences:
     - An approval encoded as **draft self-promotion** is reachable now. The owner promoting their own
       draft is refused with `Denial::SelfApproval{rule: "draft-promote"}` → `FA-REF-008`
       (`crates/fa-journal/src/draft.rs:980-1001`; `crates/fa-policy/src/denial.rs:167-181`;
       `registries/sod_policy.toml:564-573`).
     - An approval encoded as an **entry approval** needs prerequisite A0. Until then those rows are
       UNRUN, never faked through the library.
   - **Migration books** use `fa migrate open|stage|finalize` with legacy `source_entered_by` and
     `source_approved_by` (`crates/fa-cli/src/cli.rs:21340-21420`). They require `migrate` plus 2
     approvals in Locked Opening/Historical periods (`registries/admissibility.toml:335-355`) and a
     declared legacy trial balance (§6.6).
   - **Period transitions:**
     - `fa period soft-close`;
     - `fa period close --reason … --yes`;
     - `fa period lock --plan … --approval <vid>`, where the vid is printed by `fa approve --proposal
       <digest> --as <another principal>`.
   - **Refusals are observations.** Each is captured with its exit code and refusal id. The expected exit
     comes from `registries/refusal_catalog.toml`: `FA-REF-008/010/011/012` are `exit = "safety"` (7),
     and `FA-REF-080/086` are `exit = "refusal"` (3).
4. **Issue before bitemporal reads.** `AS ORIGINALLY REPORTED` reads the known-at of the period's first
   StatementIssuance, else its first Lock, else it refuses with `FA-REF-161`. So a period to be restated
   is issued first:
   - `fa statement balance-sheet --for <p> --certify`;
   - `fa statement issue --certificate C:<oid> --for <p> --issued-to sec --document <filing stub>
     --dry-run`;
   - `fa approve --proposal <digest> --as <non-planner>`, which prints an approval vid;
   - `fa statement issue --plan <file> --approval <vid>`.

   The period is then closed or locked.
5. **Restatement cases** follow the full lifecycle, as the CLI test does (`crates/fa-cli/tests/cli.rs:4524-4733`):
   - open the case with a verified authority document (the Item 4.02 8-K's stub where one exists, else
     the restating filing's), with `--determined-on` the sourced or declared `case_determination_date`;
   - plan the deltas in a scenario (`fa scenario run`) and diff it (`fa scenario diff --certificate-out`);
   - `fa case rehearse`;
   - `fa case approve --dry-run`;
   - two Human approvals by non-planners;
   - `fa case approve`;
   - `fa case post` by a non-approver.

   Each Restatement delta names the posting it `restates` (`post.rs:2503-2512`). Restatement is admitted
   only in Closed or Locked periods, as `with:restate,2` (`admissibility.toml:381-397`).
   PolicyChangeRetrospective cases post through the same RESTATEMENT class (`crates/fa-journal/src/case.rs:1661-1675`),
   but no test posts one yet (H13).

   After the post:
   - `fa case diff <case> --statements --certify` retains one statement-diff certificate per affected
     period and definition. Its lines carry `before`, `after` and `delta`.
   - `fa explain lineage <A>` must name the Restates edge.
   - `fa case disclose <case> --document <D>`, where D is a `Disclosure`-kind stub of the restating
     filing, reviewed by `case-second-reader`. Its harness-only twin (unreviewed) is refused
     `FA-REF-179`.
   - Then `fa case close <case>`. R row: `fa case show` reports the state Closed and the sourced
     determination day.
6. **Run the audit program**: `fa procedure run <id>`, `fa jet …`, and `fa finding record <id>` for each
   claimed procedure. D components are read with `fa finding list --certificate C:<run>`.
7. **Read certified results.**
   - `fa tb`, `fa explain balance --certify` and `fa gl detail --certify`.
   - `fa statement balance-sheet|income-statement --certify`. These are the only two certified report
     definitions (§3.8).
   - `--as-originally-reported`, `--as-reported-in C:<issuance cert>` and `--as-currently-stated`.
   - `fa query --certify` with the FA GQL profile, as the second read path for every T and R (§12.7).
   - `fa scenario diff --certify` for scenarios. `fa diff` compares two trunk frontiers, and
     scenario-branch statement reads are uncertified.
8. **Verify outsiders' way** (§12.1):
   - `fa checkpoint create --grant witness`;
   - `fa bundle produce`, verified in-process;
   - `fa replay <certificate>`;
   - for D reads: `fa finding export --certificate C:<run> --export-format canonical --out <f>`, then
     `fa finding replay <f> --certificate C:<run> --known-at <seq>`.
9. **Integrity**: `fa verify book --json` must exit 0 (§12.7).
10. **Evaluate expectations** (§5) per component status.
11. **Log** every step (§3.5).

### 3.4 Determinism and identifiers

- **Book ids are random.** `fa book create` draws the book id and the book's signing keys from
  production entropy (`crates/fa-cli/src/cli.rs:3879-3883`), and there is no seed flag.
  `SOURCE_DATE_EPOCH` changes no byte of output (`crates/fa-cli/tests/cli.rs:12603`). So book ids,
  VIds, certificate ids, finding ids and bundle digests differ between runs. Within a run, `fa replay`
  byte identity (FA-INV-11) is unaffected.
- **We do not add a seed flag.** A shipped flag that makes key generation deterministic would be a
  backdoor, and the doctrine forbids test-only product paths. Instead the harness logs the book id and
  treats VId order as an observed covariate (§2.6 rule 9). Repeated runs sample different orders without
  making a test nondeterministic.
- **Generated READMEs render only run-invariant fields**: fact ids, expectation ids, refusal ids,
  procedure ids and versions, component statuses and values. They never render VIds, certificate ids,
  finding ids or digests.

### 3.5 The run log

One JSONL line per step:

```text
{case, book_variant, branch_class, filler_variant, book_id, step, verb, argv_redacted, exit, refusal_id?,
 finding_procedure?, certificate_kind?, elapsed_ms}
```

stdout is data and stderr is diagnostics. The log goes to the test's temp dir and, when
`FA_CASES_LOG_DIR` is set, is copied there for the renderer.

### 3.6 Load-time checks (each a named, unit-tested refusal of the harness with a planted-violation fixture)

| Check | Rule | Item |
|---|---|---|
| K-PROV | every fact has exactly one provenance kind with its required fields | A3a |
| K-BIND | sourced values occur literally in the quote (after a registered literal rule); quotes are sentence-aligned and unique at the anchor; `quote_sha256` matches when the quote is present, otherwise the receipt records the binding check | A3a |
| K-SCOPE | a quote's own period, entry or account words must not conflict with `about_scope`; scheme-level quotes support entry facts only via `interpretation` | A3a |
| K-ANCHOR | the anchor kind matches the source format, and the page or line is in range for the recorded original (from the receipt) | A3a |
| K-DERIVE | every derived fact recomputes exactly under its rule | A3a |
| K-BASIS | every expectation's basis, taken transitively over `derived.from` and `interpretation.from`, contains ≥ 1 sourced fact and no synthetic fact; non-sourced premises are listed | A3b |
| K-TAUT | for every expectation asserting equality with a published value, whatever its declared type, the published value is not posted, directly or through any derivation, to the line or account it checks; violations re-type it R | A3b |
| K-ORACLE | an `oracle_output` fact feeds a T only if the T's predicate names it as an input; otherwise C | A3b |
| K-VINTAGE | per T kind, the accessions are named: `bridge` names A, Δ and B; `footing` the exhibit; `per_account` its source. A later restating vintage in `sources.toml` that differs on an asserted cell forces the latest vintage, or an explicit `AS REPORTED IN ⟨earlier⟩` | A3b |
| K-ASSERT | every sentence renders the assertion status of each source in its basis (§2.2) | A3c |
| K-ERRRATE | every D sentence renders the procedure's claim class and calibration clause (§5.6) | A3c |
| K-NAMES | no principal, party, memo or assertion text matches the hashed name deny list (§2.8) | A3c |
| K-EVID | on entry-level variants, evidence cited by replayed intents is disjoint from provenance documents; no P, N, CF or evidence-reading D on a `statement` variant; no P, CF, `no_refusal` N or evidence-reading D/N on a `ledger` variant; `about = "reconstruction"` rows are exempt (§2.7) | A3c |
| K-REASON | no intent carries a reason that is a legal conclusion (`Fraud`, `registries/reason_codes.toml:99-102`); every correction reason is a declared default with a rationale, rendered with the expectation | A3c |
| K-TIER | every claimed procedure has a two-reader tier row whose (id, version, `procedures.toml` row digest) matches the tree; tiers P and A cannot carry D | A4 |
| K-BRANCH | every unanchored attribute that a claimed component or the kernel reads is sourced, declared, interpreted, an observed covariate, or a branch class (closed enum, §2.6); branch values may not contradict sourced constraints (CF rows exempt) | A5b |
| K-PRED | no branch constraint collapses the claimed predicate's feasible partition (§2.6 rule 4) | A5b |
| K-JOINT | P(refused) and D(reported) expectations on one entry have disjoint branch scopes; every D target names its admitted cell | A5b |

A check that examined zero rows reports UNRUN, not PASS.

### 3.7 Runtime witnesses (executed, not just declared)

Every expectation type declares the witnesses it requires. The runner prints UNRUN for any expectation
whose witness is not implemented yet, and never PASS.

1. **Filler and identifier invariance (D/P/N).** The case runs:
   - K = 5 seeded discipline-obeying filler variants;
   - the empty variant;
   - one extremal variant per tier, which maximizes what its discipline leaves free. For tier G and
     S-party that means same-scope volume of at least 10^3 × the target; this is where truncation by
     `max_findings` shows.
   - at least 2 runs, so at least 2 book ids.

   Every S, Sd, Si and Rel component must agree across all of them. A disagreement fails and names the
   procedure. Wording: "shown on N variants", never "proved".
2. **Contributing-entry witness (T).** For each T on a leaf account, the harness reads `fa explain
   balance <account> --period <p> --certify --json` at the T's coordinate. The T passes only if all
   three hold:
   - the `balance_explained` contributions (`registries/verbs.toml:2443-2446`) are exactly the postings
     the predicate names as inputs;
   - no contributing posting carries the published comparison value B, directly or through a
     derivation (the dynamic half of K-TAUT);
   - the contributions re-add to the certified value, which the command itself enforces.

   For a type-level line, the check runs over each account the line selects. When a line selects more
   than 8 accounts, the harness reads `fa statement trace --certify` instead
   (`registries/verbs.toml:543`, event `:2053-2056`). That is `--from-diff C:<case statement-diff>`
   for bridges, and `--definition … --before <seq0> --after <seqT>` for footing.
   - Every publication that changes the line must be a posting the predicate names as an input, and
     none may carry B.
   - In addition, `fa explain balance --certify` runs over every leaf account the line selects (case
     books have tens of accounts, not thousands). `fa_reference::statements::render` then recomputes the
     line from those explained balances in its own arithmetic.
   - A scenario-fork probe is not used. `fa scenario diff` reports per-account rows, not statement lines
     (`crates/fa-cli/src/scenario.rs:6-9`, `:515-530`), and posting probe intents into Closed or Locked
     periods is itself refused.
   - A8a and W6 run the trace and the explained-balance witnesses, which must agree.
   - Any failure or disagreement re-types the T as R. An `AS ORIGINALLY REPORTED` read on a line where Δ = 0 is
   flagged "selector not exercised".
3. **Mutation twin (N).** An N `no_finding` must come from a run with no refusal and no error. Its
   harness-only twin flips the one attribute that the N's mechanism names, and the procedure must then
   report the target. The twin is never rendered.
   - N is barred on tier-P procedures; for example, Benford below its 500-leg minimum returns a finding
     that cites nothing.
   - The exception is a population that is sourced and complete (§2.5, §9.4). There a tier-P N is
     admissible, with a planted digit-skew or residue twin.
4. **Kernel twin (kernel-attested T: `per_account` kinds and single-cell bridges, §5.3).** The T value is also asserted with `fa assert-balance`
   (§5.3). Its twin, B ± 1 minor unit, must be refused with `FA-REF-140`.
5. **Equivalence-class property test.** Each registered branch-class rule (§2.6 rule 5) is property-tested
   through the real binary on micro-books.

### 3.8 Statements: what can be tied out today

- **Two definitions only.** The report surface accepts two embedded definitions,
  `registries/statements/balance-sheet.toml` and `income-statement.toml`
  (`crates/fa-statements/src/definition.rs:116-127`). The four-name list at
  `crates/fa/src/statements.rs:118-125` is the `fa statement lint` list.
- **Lines and identity.**
  - Lines select whole account types: assets, liabilities, equity, unclosed revenue/expense/earnings,
    total equity, liabilities-and-equity and the balance check.
  - Formula lines are add/subtract only (`crates/fa-statements/src/custom.rs:214-223`); there is no
    division or ratio operator.
  - A balance sheet must partition all covered types and satisfy the identity (`custom.rs:729-735`,
    `:856`; `lib.rs:98-102`, `:505`).
- **No user-loaded definitions.** `StatementDefinition::from_toml` is public at library level but wired
  to no verb.

Consequences for T:
- Lines below type level (Lehman's net assets (b), tangible equity (d), segregated cash) are read as
  **per-account balances** (`fa tb`, `fa explain balance`) on role- or code-tagged accounts. Where they
  read back a posted value, they are R rows. The harness derives (b), (d) and the ratios and labels them
  harness-derived. The T is the type-level footing (L-T-01).
- Where the source publishes only some lines (Enron Note 3's total assets, debt and equity), the book
  carries one `remainder` account per account type. K-TAUT forbids a T on any line whose published
  value fed a remainder.
- Ratio lines and user-loaded definitions are product questions (§13), not case dependencies.

---

## 4. Sources ledger and the fetch tool

### 4.1 `sources.toml` rows

| field | contents |
|---|---|
| `id` | SRC-… |
| `title`, `publisher` | |
| `original_url`, `archive_url?` | |
| `retrieval_route` | `original`, `archive_capture`, `third_party_copy`, or `re_render` |
| `original_hash_compared` | true/false: whether the retrieved bytes were compared with the publisher's original |
| `retrieved_utc` | |
| `sha256` | of the bytes as retrieved |
| `format` | pdf / htm / txt / xml / json |
| `extraction` | tool + version + SHA-256 of the extracted text, when the anchor scheme needs text |
| `redistribution_basis` | public-record/sec-filing, public-record/court, government-work (§105), company-commissioned/edgar-exhibit, or third-party-hosted |
| `assertion_status` | §2.2 |
| `assurance` | for filer statements: audited / reviewed / unaudited / not-from-audited, with the sentence that establishes it |
| `anchor_scheme` | |
| `status` | `OK` or `BLOCKED{reason}` |
| `notes` | |

Each case's facts may cite only `OK` rows.

### 4.2 What is vendored

- **Before owner decision 2** (hash-first): anchors, literal values, `quote_sha256`, `about_scope`.
- **After it**: quote text of at most 60 words per fact.
- **Never**: original bytes, whole documents, or (pending decision 2b) whole numeric exhibits.

The validator reports the excerpt volume per case.

### 4.3 The fetch cache

Originals are cached outside the repository, under `$FA_CASES_CACHE` (default
`$XDG_CACHE_HOME/franken_accounting/cases/<sha256>`). Tests never read the cache.

### 4.4 `tools/case-fetch/case_fetch.py`

The fetch tool is Python and lives outside the Rust workspace, for three reasons:
- it needs an HTTP client, which would be a new third-party dependency in a closed universe;
- it runs only at authoring time;
- its outputs, the receipts, are reviewable data that the offline Rust validator checks. Nothing in a
  test depends on the network or on the tool's code.

The tool uses the Python 3 standard library only and runs with `python3 -B`, following
`scripts/foundation_check.py:1-20`.

- **`fetch <case>`**
  - Downloads each `OK` source by its `retrieval_route`.
  - Sends the project's User-Agent and keeps to at most 1 request per second.
  - Verifies each SHA-256 and stores the bytes in the cache.
  - Direct sec.gov requests are made only when `FA_SEC_CONTACT` is set. The variable is read from the
    environment only and is never written to any committed file, receipt, log or fixture; a test greps
    for leaks.
- **`extract <case>`**
  - PDF: `pdftotext -layout`, when installed. This is a system tool used only by this authoring tool,
    never by shipped code.
  - HTML/XML: a stdlib tag-stripper whose algorithm version is recorded.
- **`xbrl-facts <case>`**: from an XBRL instance, extracts (concept, context id, period, unit, decimals,
  dimension members, value) rows for the facts a case cites. Each row is anchored by instance line.
- **`exhibit-b <case>`**: extracts BLMIS Exhibit B rows per complaint column layout into the generated
  `exhibit_b_rows.toml` (never hand-edited). Its layouts, structural checks and diagnostics are item
  M2t's (§15).
- **`verify <case>`** checks, for every sourced fact:
  - the quote occurs **sentence-aligned** and **exactly once** in the extraction at the anchor, after
    normalization;
  - its literal values occur in it after the literal rule;
  - `about_scope` passes the K-SCOPE word check.

  It then writes `receipts.toml`, one `[[receipt]]` row per sourced fact: `source`, `fact`,
  `verified_utc`, `tool_version`, `extraction_sha256`, `quote_sha256`, and the five binding booleans. The
  file is regenerated whole and never edited by hand. Python's stdlib has no TOML writer, and a rewrite
  of `sources.toml` would lose its comments, which is why receipts get their own file.
- **Normalization.** It is identical in Python and Rust, and fixture-tested in both:
  - decode UTF-8;
  - replace every run of U+0009, U+000A, U+000B, U+000C, U+000D, U+0020 and U+00A0 with one U+0020;
  - trim;
  - no case folding, no Unicode normalization, and typographic quotes are kept.

  `quote_sha256` is the SHA-256 of the normalized bytes. Python's `str.split()` and Rust's
  `char::is_whitespace` disagree on other characters (U+001C–U+001F), so neither is used.
- **Sentence alignment.**
  - A quote starts at the extraction's start, or after `[.?!]` plus an optional closing `"` or `)` plus
    whitespace.
  - It ends with `[.?!]` plus an optional closing `"` or `)`, followed by whitespace or the end.
  - A boundary preceded by a registered abbreviation (`p`, `pp`, `Inc`, `Co`, `No`, `U.S`, `Mr`, `Ms`,
    `Dr`) is not a boundary.
- **Exit codes** follow the gate vocabulary:
  - 0 when everything is verified;
  - non-zero with `FAIL ` lines on failure;
  - `UNRUN` when a required system tool or the network is unavailable, never reported as success.
- **Tests**: stdlib `unittest` over a small fixture document written for the test, with planted failures:
  - a quote not found;
  - a quote found twice;
  - a value not in the quote;
  - a scope conflict;
  - a sentence fragment.

### 4.5 Authoring discipline

Every fact quoted in this plan came from a research pane. The research record itself contained:
- quotes that occur in no stored source (EV-040: 0 hits in 22 stored texts);
- account ids that are not in the texts;
- a procedure name that does not exist (`cutoff.late_posting`);
- a misattributed scope (SEC ¶29).

So **the research workspace is not a source**. A facts file is accepted only with a receipt from
`case_fetch.py verify` run by its author. Its review re-runs `verify` independently: a second agent,
with a second cache.

### 4.6 The offline gate

There is no new `scripts/check.sh` step. The validator is a `#[test]` of `fa-oracles`
(`ledgers_validate_offline`), which check.sh's existing `test` step already runs and counts in its gate
evidence. The test covers:
- ledger well-formedness;
- receipts present and consistent with the facts;
- K-PROV … K-JOINT.

It never touches the network. Source fidelity is established by the receipt, which is reviewable
evidence bound to a SHA-256.

`registries/claims_lint.toml` `scanned_docs` gains `docs/FORENSIC_CASE_STUDIES.md`, so every `FA-REF-*`
and `FA-INV-*` marker the renderer emits must resolve against the registries
(`tools/registry-check/src/main.rs:797-843`).

---

## 5. Expectations: schema and semantics

### 5.1 Common fields

`[[expectation]]` rows:

| field | meaning |
|---|---|
| `id` | `<case>-D-NN`, `-P-NN`, `-T-NN`, `-C-NN`, `-R-NN`, `-N-NN`; CF rows are `<parent>-CF-NN`, numbered per parent from 01 |
| `type` | |
| `book_variant` | |
| `statement_template` | the §0.3 template id; the sentence is generated, never hand-written |
| `basis` | fact ids |
| `premises` | non-sourced premises; generated from the encoding (§2.6 rule 6), and authored only where an interpretation is named |
| `granularity` | |
| `capabilities` | verbs, procedures, laws, selectors; feeds §12.2 |
| `owner_review` | true when the owner must approve the wording before it renders |
| `about` | `history` (default) or `reconstruction` (a D about our own encoding; exempt from K-EVID's variant bars, §2.7) |
| `record_label` | `characterized` (default) or `silent` (a §9.4 record-silent row; renders only as counts) |
| `known_at` | `pre_case` (default for D on `native`) or `head` (W-D-07/W-D-08 only, §6.3) |

Per-entry detail lives in `[[target]]` rows: `expectation`, `fact`, `basis`, `branch_scope`, the
admitted cell for D, the component statuses, and the expected values.

Branch tables live in `[[branch_cell]]` rows: `expectation`, `target`, `cell` (one value per branched
attribute), the expected verdict, `record_consistent` (true when a sourced or derived fact supports
the cell; §12.3), and `default` (true on the one cell a declared default selects, §2.6 rule 2).

**Notes.** A published observation that franken_accounting does not compute (a two-point comparison of
printed values, for example) is a `[[note]]` row: `id` (`<case>-NOTE-NN`), `case`, `basis` (fact ids),
`template`. A note has no verdict, is never PASS or FAIL, renders only in Limits, and is never counted as
an expectation (W-NOTE-01).

### 5.2 D, P, N and CF

- **D**
  - Fields: `procedure` and `version`. Each target carries `cite`, `severity` and `statistic`
    components, each with a status and an expected value. Cited accounts project to account codes, and
    cited legs to (fact, leg ordinal); `jet.round_amounts` cites legs (`crates/fa-lantern/src/jet.rs:130-133`).
  - Passes when, on every branch cell in scope and every required variant:
    - every S, Sd, Si and Rel component equals its expectation;
    - every B component matches its `[[branch_cell]]` rows;
    - no X component is asserted.
- **P**
  - Fields: `intent` (fact id), `refusal`, `law_row`, `attribute` (the documented attribute the refusal
    rests on), and `reference_verdict` (the fa-reference oracle's verdict, or `not_modelled`).
  - The expected exit is not a field: the harness reads it from `registries/refusal_catalog.toml`.
  - Passes when the documented intent's first refusal is that id, the exit matches the catalog, the
    refusal envelope names that row, and the reference verdict (where modelled) agrees.
  - It also requires the structured remedy (`registries/verbs.toml:1582-1584`):
    - `refusal.why.matrix` equals the cell's {state, class}, compared structurally, never as text;
    - `refusal.fix.argv` parses against verbs.toml;
    - the `alternatives` include every admissible class or op that fa-oracles derives independently
      from `registries/admissibility.toml` for that state.
  - `fa explain refusal <refusal.id>` echoes the instance. The rendering prints "the system's stated
    remedy" beside each P cell, from the catalog's `fix` template filled with the cell's values. For
    `FA-REF-010` that template reads "keep the entry's true effective date (never re-date it to escape the
    period law): use a class the period's state admits, with the op and approvals its cell names"
    (`registries/refusal_catalog.toml:103-108`).
  - The observed premises are logged. Nothing observed in a run is written back into an authored file.
- **N**
  - Fields: `kind` (`no_refusal` | `no_finding`), the target, `mechanism` (file:line at the pinned
    commit), and its mutation twin (§3.7).
  - Passes when the documented intent is admitted, or the procedure reports no finding on it, **and**
    the twin reports.
  - An N is a regression lock in both directions.
- **CF**: the parent expectation, the one changed attribute, and the expected verdict.

### 5.3 T, C and R

- **T kinds**:
  - `bridge{A, Δ, B}`: posted A, posted Δ through a restatement case, and a certified B;
  - `footing{lines → totals}`: posted lines whose certified type-level totals, or certified running
    balances, equal printed totals or balances that were never posted;
  - `per_account{balance}`: a certified per-account balance equal to a separately sourced published
    value that was not itself posted;
  - `allocation{law, total → parts}`: legs that a registered allocation law
    (`registries/allocation_laws.toml`) computed from a sourced, posted total, equal to separately
    sourced parts that were never posted. The residual is exactly the sourced remainder;
  - `delta{entries → published Δ line}`: a certified statement-diff Δ on a type-level line
    (`fa case diff --statements --certify`), computed from posted correction entries that are derived
    from sourced entries (`negate`), equal to a separately published Δ line that was never posted.
    K-VINTAGE names the Δ's accession(s); there is no A or B (E-T-03).
- **T fields**: `read` (verb, line or account, coordinate, selector), `published` (fact id), `kind`,
  `vintages`, `assurance`, and `inputs_named` (for `oracle_output` inputs).
- **T passes** on exact integer equality at the published value's declared precision, after the
  literal rule. It also needs its contributing-entry witness (§3.7), and the **outsider check of its
  read kind** (§12.1):
  - for TB/BS/IS certificates, `fa-verify report` (argv through `fa_verify::cli::run`) must recompute
    the line or row equal to B;
  - for other read kinds, the replay that §12.1 names.
- **Kernel-attested T** (`per_account` kinds, and `bridge` kinds whose A and Δ sit on one leaf account in
  one period, on a `statement` variant). `fa assert-balance` and `recon.assertion_drift` work on a single
  (account, unit, period, entity) cell (`crates/fa-cli/src/document.rs:1942-1958`;
  `crates/fa-lantern/src/assertion_drift.rs:83-95`). A multi-account footing total cannot be asserted. B is also recorded with
  `fa assert-balance --account <a> --period <p> --balance "<B> <UNIT>" --evidence <filing stub>`
  (`registries/verbs.toml:487-497`). The kernel records a RegisterEquals attestation only if B equals the
  fold, and refuses any other amount with `FA-REF-140` (exit 3). The T requires the attestation to be
  recorded, and its twin (B ± 1 minor unit) to be refused.
- **Two read-backs on the same book** are typed R:
  - **As filed.** Before the case, A is asserted, citing the as-filed stub.
  - **Drift.** After the case, `recon.assertion_drift` must report exactly the A assertion, citing the
    case's Restatement entries, with drift = ΣΔ. That procedure is registered `claim = "invariant"`
    (`registries/procedures.toml:1402-1411`).
- **Restatement artifacts.** For line-level bridges, `fa case diff --statements --certify` gives the
  certified `after` column (the T) and `before` column (an R) in one replayable artifact.
- **C** (DEBATE-001 ruling). A comparison that holds only within a band derived from a display unit or
  rounding note. A C row:
  - cites that display unit or note;
  - passes the exact per-row test |ΔP − d| ≤ one display unit;
  - states its cumulative band and its detection limit;
  - is never reported as T.
- **R**: a read-back of a posted value. R is a regression of the selector or attestation path, never a
  T.
- **Evidence class.** A T is an **exact observation** on the constructed book. It is replayable byte for
  byte (`fa replay`) and refolded by the independent std-only verifier (`fa-verify`). It is never
  `proof`: that class is reserved for registered Lean 4 theorems (`registries/constitution.toml:17-22`),
  and no T is one.

### 5.4 The verdict projection

Projection = (procedure|law id, version, cited fact ids, severity|refusal id + exit, statistic name,
statistic value, statistic scale), each component with its status (§2.6).

Always excluded:
- `statistic.population`;
- `findings_digest`;
- finding and certificate ids;
- any value that depends on storage identifiers.

### 5.5 Phase-5 rulings incorporated (normative)

- **DEBATE-001 (H-009 confirmed as narrowed; H-022 refuted).** A T row asserts exact integer equality,
  at each side's declared precision, between independently sourced, accession-named values
  (A + ΣΔ = B). A ledger whose opening balance plus its displayed rows equals every printed day-end
  balance is one such bridge. A comparison that holds only within a band derived from a display unit or
  rounding note is a C row (§5.3).
- **DEBATE-002 (H-040 refuted; H-010 maintained as narrowed).** Component statuses S/Sd/B/X, the closed
  branch-attribute enum, declared default encodings, the tier-C context rule, and R-QUAL (§2.6). The
  WorldCom single-verdict table is §6.4.
- **H-013 falsifier (d) check (not fired; narrowed).** The record does not say that the 1Q02 preparer
  had no document. It describes the absence of *support* (substantiation), and puts a Post-it bearing
  the combined $818M in her hands (Beresford p.116). For the 1Q02 entries, crediting an instruction
  document is a derived reading, so `evidence_attached` is a branch.

### 5.6 Claim class and calibration status in every D sentence (K-ERRRATE)

A D sentence renders the procedure's registered claim class (`claim = "statistical" | "invariant"`) and
its calibration status (`crates/fa-registry/src/procedures.rs:61-79`). Each status has one fixed clause:

| `procedures.toml` calibration | rendered clause |
|---|---|
| `planted` (e.g. `expense.capitalization`, `procedures.toml:1482`) | "exercised only on planted anomalies in tests; its false-positive rate on real books has not been estimated" |
| `corpus` (a `lantern_calibration.toml` row exists, e.g. the `jet.*` rows) | "measured on fa-gen's labelled synthetic corpora (`FA-ART-CAL-01`), where precision is 100% by the generator's construction (`lantern_calibration.toml:22-33`); its false-positive rate on real books has not been estimated" |
| `uncalibrated` (e.g. `trace.network_fifo`) | "its thresholds are pinned, not measured; its false-positive rate on real books has not been estimated" |

The clause follows the 2023 Federal Rule of Evidence 702 committee note, which asks forensic experts to
state error rates where known. The renderer has no free-text path, so the clause comes from the
registries.

---

## 6. Case W — WorldCom line-cost capitalization (2001 – 1Q02)

### 6.1 Sources

| Id | Source | Assertion status | Notes |
|---|---|---|---|
| SRC-WC-001 | Report of Investigation by the Special Investigative Committee of the Board of Directors of WorldCom, Inc. (Beresford, 2003-03-31), EDGAR `0000931763-03-001862`, `dex991.htm` | investigative_finding | anchor = printed page + extraction line |
| SRC-WC-002 | SEC v. Betty L. Vinson and Troy M. Normand, complaint (`comp17783`) | allegation | anchor = paragraph |
| SRC-WC-003/004 | SEC complaints against Yates and Myers (`comp17771`, `comp17753`) | allegation | same scheme-level sentence as ¶7 |
| SRC-WC-401 | WorldCom 10-K405 FY2000 (originally filed) | filer_audited | total assets 98,903 ($M) |
| SRC-WC-406 | WorldCom (MCI) 10-K FY2002 (restating, EDGAR `0001193125-04-039709`) | filer_audited for the balance sheets at 2002-12-31 and 2001-12-31 only; Item 6 excludes the 2000-12-31 summarized balance-sheet data from the audited figures (`filer_not_from_audited_statements`) | restatement tables |
| SRC-WC-EX27-1999 | WorldCom 10-K FY1999, EX-27 | filer_audited (FDS of audited statements) | TOTAL-ASSETS 91,072 at MULTIPLIER 1,000,000 |

### 6.2 The documented entries (re-verify at authoring; SRC-WC-001 §IV.C.3–4)

Conventions:
- "A → B" means credit A, debit B.
- **"Date" is the booking date.** It fixes commit order relative to period transitions, releases and
  filings, and nothing else, because recorded time is the CommitSeq (doctrine 6).
- **The effective date** is the reporting period's last day by declared default, or the
  `effective_date` branch.
- **Reporting period.** Each row's reporting period (the quarter whose results it adjusted) is a sourced
  fact: F1–F3 are 1Q01, F4–F5 2Q01, F6–F9 3Q01, F10–F11 4Q01, and F12–F13 1Q02.
- **One fact per sentence.** Each row is one or more sourced facts, one per sentence. Facts from
  different sentences are joined by an `interpretation`; for example, F4 joins p.108's description with
  p.26's exact amount.

| Fact | Date | Entry as documented | Amount as stated | Page | Provenance notes |
|---|---|---|---|---|---|
| F1 | 2001-04-20 | Dr Other Long Term Assets 629M, Dr Construction in Progress 142M / Cr line costs 771M | $771M | 106 | 1Q01 "not effected through a single, round-dollar entry" (p.105); preparer received a one-page "March 2001 Adjustments" document (p.106) |
| F2 | 2001-04-23/24 | OLTA → CIP 402M | $402M | 106 | asset→asset; the line costs were "parking" in OLTA (p.106) |
| F3 | 1Q01 (no day) | OLTA 227M offset by an Ocean Cable Liability accrual release | $227M | 106 | accrual offset; day unsourced |
| F4 | 2001-07-17 | line costs → CIP 560M (gen-acct-manager-1) | $560M; p.26 lists "$560,000,000 on … July 17, 2001" among unsupported journal entries | 108, 26 | exact dollars at p.26; credits over "three separate line cost accounts" (split unsourced) |
| F5 | 2001-07-17 | line costs → SG&A 50M | $50M | 108 | expense→expense |
| F6 | 2001-08-22 | CIP 544M → asset clearing → "10 assets in the amount of exactly $54.4 million each in Property Accounting's sub-ledger under the Fiber Optic Cable account" | $544M; 10 × $54.4M | 111 | self-approval is `interpretation` of "Abide rarely entered and approved entries himself so his involvement in these transfers was unusual"; the ten items are ten declared leaf accounts under Fiber Optic Cable. Encoded as two intents: **F6a** (CIP → clearing, 544M; class branch Original / Adjusting / Reclassification split per target) and **F6b** (clearing → ten items; class `Allocation`, posted by `fa allocate` under `EqualSplitResidualFirst`, evidence = its driver Workpaper, W-T-04). Under `entry_decomposition = ten_two_leg_entries`, F6b is instead ten Original or Adjusting entries |
| F7 | 2001-08-25 (`derived{date_offset: 3}`) | "the $0.2 million that remained", likewise | $0.2M | 111 | the derived booking date is a Saturday. `jet.weekend` reads effective or document date (`registries/procedures.toml:78-86`), so it sees F7 only on a branch whose effective or document date is that day; this renders as a branch row, not a finding |
| F8 | 2001-09-20 | CIP 560M → Ocean Cable 250M / Computer Equipment 150M / Fiber Optic Cable 160M | $560M | 111, 261 | asset→asset; booked as "12 entries in similar, round-dollar amounts" (p.261), so `entry_decomposition` is `one_entry` / `twelve_entries` |
| F9 | 2001-10-19 | line costs → PP&E, "in the amount of $742,725,000"; proposed split Transmission Equipment $300M + Communications Equipment $442M (= $742M, not the booked amount); credit accounts changed, amounts not stated | $742,725,000 | 113 | Abide e-mailed Vinson and Normand the account numbers and amounts; "Vinson sent it to Renfroe to have the entry booked" (p.113). The e-mail is undated |
| F10 | 2002-01-23 | line cost expense → PP&E 941M, into "furniture and fixture accounts" (plural; split unsourced) | $941M | 114 | "On January 23, 2002, Howard in Abide's group prepared a draft journal entry" (p.114): the only instruction document the record dates |
| F11 | 2002-01-25 (`derived{date_offset: 2}`) | 100M out of an asset account, offset by a release from a corporate accrual account | $100M | 114–115 | accrual offset |
| F12 | 2002-04-12 | line cost expense → capital 718M | $718M | 116 | Vinson booked the entry and then "handed him [Capital Reporting] a Post-it Note that had the $818 million adjustment on it" (p.116): the preparer *handed on* an undated note bearing the combined amount, a `derived` reading; the record gives F12 no instruction document |
| F13 | 2002-04-17 | line cost expense → capital 100M | $100M | 116 | as F12 |

Context facts:
- **General ledger adjustments.** The entries were corporate-level general-ledger adjustments without
  an Authorization for Expenditure (p.103).
- **Round-dollar wording.** "The capitalization entries were made in large, round-dollar amounts after
  the close of the quarter and only a few days before the Company announced its earnings." (p.90). The
  Committee's usage is "in the tens, and often hundreds, of millions" (p.21).
- **Earnings releases**: 2001-04-26 (p.107), 2001-07-26 (p.110), 2001-10-25 (p.114).
- **Filing dates.** SRC-WC-002 ¶¶48–50 give, "on or about", 2001-05-15, 2001-08-14, 2002-03-31 and
  2002-05-15. The 3Q01 10-Q was "filed on November 14, 2001" (SRC-WC-001 p.301).
- **Oral instructions.** The PP&E roll-forward instructions were oral ("NORMAND telephoned", ¶30). For
  1Q02, "Yates, with Normand and Vinson on the phone, called and asked Abide to book the entry" (p.116).
- **Support.** "these accounting entries were made without supporting documentation" (SRC-WC-002 ¶7;
  scope ¶6, 1Q01–1Q02). This is a characterization of **support** at scheme level, not a statement that
  no document existed. ¶29's "without any supporting documentation or proper business rationale" is
  about the first quarter of 2001 only.
- **Source conflict, quarantined (AN-100).** For 4Q01, ¶34 gives both a $941M line-cost reduction
  (agreeing with Beresford) and $560M of journal entries "in or around February 2002". Beresford p.114
  gives 2002-01-23. Both are recorded as separate sourced facts, and no expectation rests on the disputed
  JE amount or date.

### 6.3 Book variants and branch attributes

- **`native`**:
  - Opening date before 2001-01-01, calendar quarters 2001Q1 … 2002Q2.
  - The chart uses `role_map` (interpretive). It assigns each named account an account **type**
    (`registries/account_types.toml`) and an optional **role** (`registries/account_roles.toml`):
    - CIP / PP&E / Transmission Equipment / Communications Equipment / Fiber Optic Cable / Ocean Cable /
      Computer Equipment / furniture and fixtures → `fixed_asset`;
    - line costs → Expense;
    - OLTA → an `Asset`-type account with no role (none of the 15 roles fits);
    - SG&A → Expense;
    - accruals → `accrued_expense`.
  - Principals are the role labels.
  - Prior activity per quarter is filler under the claimed tiers' disciplines.
  - **Issuance and correction** (default branch cell only).
    - Each quarter's statements are issued at its sourced filing date (SRC-WC-002 ¶¶48–50; SRC-WC-001
      p.301), and the quarter is then locked.
    - Then one Restatement case negates the documented capitalization entries (F1, F4, F9, F10, F12,
      F13). Each Δ `restates` its entry with `reason = WrongAccount` (`registries/reason_codes.toml:63-66`),
      a declared default and never `Fraud` (K-REASON).
    - Two `case-approver-*` roles with no shared session lineage approve (`crates/fa-cli/src/cli.rs:3450`).
    - The determination date is a declared default (no WorldCom non-reliance 8-K row exists yet). W1
      looks for one.
  - **D pinning.** Every D row on `native` except W-D-07/W-D-08 (which declare `known_at = head`) is
    evaluated at `known_at = pre_case`, the frontier before the
    case's Post (`fa finding record <id> --known-at <seq>`). Otherwise the case's own entries enter the D
    populations.
- **`migration`**:
  - The same history is replayed as Migration-origin entries in Historical periods, with legacy
    `source_entered_by` and `source_approved_by`.
  - It exists only for `jet.self_approved` on F6, the one documented approval.
  - Its prerequisites are `migrate` plus 2 approvals in Locked Opening/Historical periods, and a declared
    legacy trial balance derived from its own chunks (§6.6). Building the variant is item A7m.
- **`statement`**: FY2000 with a 2000Q4 period, for W-T-02. The `native` calendar starts at 2001Q1, and a
  Historical period admits only Migration. Citation-stub evidence; no filler.
- **Branch classes**, from the §2.6 enum:
  - `effective_date`: inside / outside the last `window_days` of the quarter;
  - `amount_precision`: per leg, residue classes mod 10^3;
  - `leg_split`: for F4's three credit accounts, F9 and F10;
  - `entry_class`: Original or Adjusting for the capitalization entries. For F2, F6a, F7 and F8: Original,
    Adjusting, or Reclassification with `reclassification_target`. F6b is an `Allocation`
    (`crates/fa-journal/src/allocation.rs:263`), whose period-law cells are `admissibility.toml:283-289`
    (Closed → `post_closed` + 1 approver; Locked → refuse) and whose evidence is the driver Workpaper
    `fa allocate` imports (`crates/fa-cli/src/cli.rs:9730-9751`; `evidence_policy.toml:221-224`), not the
    `evidence_attached` branch.
    - A Reclassification names exactly one target entry and moves at most what that target posted
      (`crates/fa-journal/src/post.rs:1991-1999`; `crates/fa-palimpsest/src/lib.rs:537-548`).
    - F6a's $544M left CIP from two entries: F1's $142M CIP leg and F2's $402M (pp.106, 111). So F6a as
      a Reclassification is encoded **split per target**: one Reclassification of F1's leg and one of
      F2's.
    - **W-P-04 (branch cell).** The documented single $544M transfer, encoded as one Reclassification,
      is refused with `FA-REF-185` (RECLASSIFICATION_SHAPE, `post.rs:2491`, after identity and before
      period law and SoD), so on this encoding the self-approval is never reached. `record_consistent =
      false`; it renders beside W-P-01;
  - `period_state_at_commit`: Open / SoftClosed / Closed. Locked is excluded by the sourced filing
    dates;
  - `evidence_attached`: none / placeholder_unreviewed / placeholder_reviewed / manual_assertion(code);
  - `entry_decomposition`: F6b (`one_allocation_entry` / `ten_two_leg_entries`) and F8 (`one_entry` /
    `twelve_entries`);
  - `document_date` (F1, F9, F10, F12): the instruction document's sourced date, where W2 anchors one;
    otherwise absent / inside the reporting period / after it;
  - `approval_encoding` (F6a, F6b): draft_self_promotion (F6a only; drafts refuse Allocation) /
    entry_approval / migration_legacy_pair / none;
  - `approvals_recorded`.
- **Observed covariate**: account-VId order (§2.6 rule 9).

### 6.4 Claims (DEBATE-002 table as re-verified by the H-010 final-state review; H-013 deferred with the narrowed scope below)

**Confirmed scope (H-010).** `expense.capitalization`@2 cites each of F1, F4, F9, F10, F12, F13 at
severity High. The cite rests on two independent sources: Beresford pp.106–116, and SEC v. Vinson &
Normand ¶¶30–35 ("approximately" amounts, with the PP&E capital expenditure accounts named). Every
other single verdict below rests on Beresford alone.

**D on `native` (procedures read `live_postings`, so only admitted branches)**

| id | procedure | entries | cite | severity | statistic.value |
|---|---|---|---|---|---|
| W-D-01 | `expense.capitalization` (C) | F4 | Sd (sourced account names + `role_map`) | S (constant High) | Sd: 560,000,000.00 under `one_leg_per_named_account` (one CIP account named; single-source, Beresford pp.26, 108) |
| W-D-01 | " | F1 | Sd | S | B(amount_precision): "$142 million" is presentation-rounded |
| W-D-01 | " | F12, F13 | Sd | S | B(amount_precision, leg_split) |
| W-D-01 | " | F9, F10 | Sd for the entry; Rel(account VId order) for the cited fixed-asset account (`cutoff.rs:1103-1104`) | S | B(leg_split), and Rel(account VId order): the value is the debit leg on the minimum-VId fixed-asset account of the entry (`cutoff.rs:1100-1122`), checked on every run from the logged book id; rendered as the set of documented leg amounts it can take |
| W-N-01 | " | F2, F3, F5–F8, F11 | not cited | — | — (N: asset→asset or accrual moves are outside the predicate; mechanism `cutoff.rs:1066-1124`) |
| W-D-03 | `jet.round_amounts` (L, round_power 3) | F4 | Sd: the 560,000,000.00 CIP debit leg is a multiple of 10^3 units under `one_leg_per_named_account` | B(leg_split) | B(leg_split) |
| W-D-03 | " | F6a and F6b (the ten sub-ledger assets) | Sd on the fact; B(entry_decomposition) on the cited (fact, leg ordinal) set, under `subledger_to_gl_legs` ("exactly $54.4 million each", p.111; "10 different entries", pp.260–261) | Sd: Medium, because every leg is a multiple of 10^3 units under either decomposition (`jet.rs:134-138`) | B(entry_decomposition): `round_legs` = 11 on one compound entry (10 × 54.4M Dr + 544M Cr) versus 2 on each of ten two-leg entries |
| W-D-03 | " | F1, F9, F10, F12, F13 | B(amount_precision, leg_split); F1 has a documented exception to R-QUAL | B | B |
| W-D-04 | `jet.period_end_timing` (C) | all capitalization entries | B(effective_date): no effective day is sourced | S (constant Low) | B |
| W-D-05 | `jet.post_closing` | all | X | X | X |
| W-D-06 | `cutoff.period_boundary` (C) | F10 (draft JE dated 2002-01-23, p.114); F1, F9 and F12 only as B(document_date) | Sd for F10: the document's period (1Q02) ≠ the sourced reporting period (4Q01). The effective day is not read for the cite (`cutoff.rs:52-67`). F9's e-mail is undated; F12's Post-it was *handed on* by the preparer (p.116), a derived reading; F1's document is undated: all three are B(document_date) | S (constant Medium, `cutoff.rs:83`) | B(effective_date), default cell marked: `days_between_dates` reads the effective day (`cutoff.rs:68`) |
| — | population tiers (`jet.unusual_*`, `numbers.round_amount_density`, `benford.*`) | — | X | X | X |

**W-D-05 is inadmissible.** The corrected code-tier table classes `jet.post_closing` as tier P, because
its commit gap depends on the population of commits. Its verdict would also only mirror where the
harness places the period close. Its X components render in Limits (§12.3) as a limit of what a
reconstruction can show. It has no N row: N is barred on tier P (§3.7).

**W-D-06's caveat.** A legitimately documented post-closing adjustment satisfies the same predicate. The
claim class is statistical and the calibration is `corpus`, so the sentence says so.

**D on `migration`**
- **W-D-02** `jet.self_approved` (L) on F6's entries attributed to the property-accounting director
  (not the specialist's $0.2M entry). Statuses:
  - cite: **B(approvals_recorded)**. The record states the approval only as a habit ("Abide rarely
    entered and approved entries himself so his involvement in these transfers was unusual", p.111), and
    pp.260–261 credit the ten entries to "Abide and his staff". The procedure fires only on the branch
    "legacy entered-by = approved-by", which is a declared encoding resting on an `interpretation`, not a
    sourced fact;
  - severity: S (constant High) on that branch;
  - statistic: Sd on that branch.

**P on `native` (first refusal, exit from the catalog)**
- **W-P-01** Posting F6 with the documented approval, encoded in one of two declared ways:
  - **(a) `draft_self_promotion`, reachable at 8196f5e40, F6a only** (drafts refuse Allocation,
    `draft.rs:759-767`). The director plans F6a into a draft and
    promotes it himself. The first refusal is `FA-REF-008` (exit 7) under `sod_policy.toml#draft-promote`
    (`crates/fa-journal/src/draft.rs:996-1000`, `crates/fa-policy/src/denial.rs:167-181`). Promotion
    attaches no Approval to the promoted entries, so W-D-02 still needs the migration book.
  - **(b) `entry_approval`.** A native Approval by the preparing principal, cited at commit. On F6a it
    needs A0 (`fa post`/`fa commit` take no `--approval`). On F6b it may be reachable now: `fa allocate`
    takes `--approval <vid>` (`registries/verbs.toml:459`), so item W5 probes `fa allocate --approval
    <self vid>`; if it reaches `FA-REF-008`, that cell needs no A0.
  - **Reading.** The claim is conditional on the `interpretation` that the director approved these
    transfers (p.111's "so" clause, the natural reading). On the weaker reading, "entered only",
    `approvals_recorded` is a branch, and the no-approval cell is CF-01.
  - **Result, by encoding.**
    - **(a) `draft_self_promotion`** is a two-step sequence: `fa post --draft <d>`, then
      `fa draft promote <d>`.
      - Step 1 (`plan_into_draft`) accepts only batchable classes: Original, Adjusting, Reversal, Pending
        and Resolution (`crates/fa-journal/src/draft.rs:759-767`; `crates/fa-journal/src/batch.rs:389-399`).
        On the Reclassification branch, step 1 refuses with a usage error (exit 2).
      - Step 1 then rehearses the intent, with no approvals, through the whole posting pipeline
        (`draft.rs:863-870`). So period law and the evidence minimum decide it first:
        - in Closed or Locked, an Original is refused with `FA-REF-010`;
        - with no admitting evidence, the refusal is `FA-REF-080` or `FA-REF-086`, and the empty draft's
          promotion is then a usage refusal (`draft.rs:1022-1024`).
      - Only on an admitted cell (Original or Adjusting in an admitting state, with `placeholder_reviewed` or
        `manual_assertion` evidence) does step 2 reach the owner check. There the refusal is `FA-REF-008`
        (exit 7, `draft.rs:996-1001`).
    - **(b) `entry_approval`** (A0) is one `fa post`/`fa commit` carrying the self-approval. SoD (step 5'')
      runs before the evidence minimum (step 5b), so `FA-REF-008` is the first refusal in every cell that
      period law admits, whatever evidence is attached. In a cell period law refuses, `FA-REF-010` comes
      first.
  - **CF row W-P-01-CF-01.** The same transfer with no approval attached passes SoD. Step 5b then
    decides on `evidence_attached`: `FA-REF-080` with none; admitted with a document or a
    ManualAssertion (a reconstruction placeholder, §2.7).
  - **Scope.** The director's transfers only (F6a, F6b).
- **W-P-02** (evidence minimum) is a branch table over `evidence_attached` for each capitalization
  entry. It is evaluated only in cells that pass period law and SoD.
  - With no document and no ManualAssertion, the result is `FA-REF-080` (exit 3).
  - With an unreviewed placeholder (`placeholder_unreviewed`), the result is `FA-REF-086` (exit 3).
  - The record-consistent branch differs by entry. The record describes a document for F1, F9 and F10
    (sourced existence) and F12/F13 (derived: the Post-it the preparer handed on), but none is public. For those entries the
    record-consistent cell is `manual_assertion(InternalTransfer, reconstruction placeholder)`; it is
    never a stand-in file. For F4 the record-consistent cell is "none named".
  - No admitting branch is sourced. Every admission is a scenario result. Its rendering states that the
    evidence minimum checks presence and kind, not content.
- **W-P-03** (period law) is the branch table over (entry_class × period_state_at_commit) under no
  recorded approvals:

| class \ state | Open | SoftClosed | Closed | Locked |
|---|---|---|---|---|
| Adjusting | admit | admit | needs `post_closed` (else `FA-REF-011`, exit 7) and 1 approver other than the preparer (none recorded → `FA-REF-012`) | `FA-REF-010` (exit 7) |
| Original | admit | needs `post_softclosed` (else `FA-REF-011`) | `FA-REF-010` | `FA-REF-010` |

  Locked is excluded by the sourced booking-before-filing facts, which only constrains the branch set.
  No row is fixed by the record. So there is no unconditional period-law P.
- **W-P-03-CF-01.** Suppose F4 is refused as Original in a Closed 2Q01 and then re-posted effective on
  its 2001-07-17 booking date. The kernel would admit it, because 3Q01 is Open. Over fa-mcp, in the same
  session, `redated_intent` refuses it before dispatch (§12.5). This renders in Limits: the period law
  protects closed periods, but it cannot know an entry's true effective date.

**T**
- **W-T-02** `bridge`, Dec-31-2000 total assets, on the `statement` variant. Kernel-attested with
  `fa assert-balance` (§5.3). A = the restater's "previously reported" 98,727 ($M); Δ
  = −745 and −53,794; B = 44,188. All three come from SRC-WC-406. Their assurance is `filer_not_from_audited_statements`: the audit
  opinion covers the 2002 and 2001 balance sheets only, and Item 6 excludes the 2000-12-31 summarized
  data. The rendering never calls W-T-02 audited. The book posts A, posts Δ through a Restatement case, and certifies B.
  - The originally filed value was 98,903 (SRC-WC-401). The $176M gap is a reclassification footnoted by
    the restater. The T names both vintages and states that the bridge uses the restater's A.
  - **R-row W-R-01**: `AS ORIGINALLY REPORTED` returns the posted 98,727 after the restatement.
- **W-T-03** `footing`, on `native`. The certified 2002Q1 income-statement diff of the native
  Restatement case (`fa case diff --statements --certify`) moves expenses by exactly 818,000,000.00.
  - That is "the $818 million adjustment" the committee reports (p.116).
  - The inputs are F12 (718M) and F13 (100M), stated in the same sentence as the $818M (p.116), each
    negated by the non-interpretive `negate` rule. 818 is never posted (K-TAUT).
  - The rendering says "reproduces the committee's own total of the two entries it names", never
    "independently".
  - The diff isolates the correction's own effect, so filler cancels.
  - Assertion status: "the committee found". Assurance: none (an investigative finding, not a filer
    statement).
- **W-R-02**: the other quarters' income-statement diffs equal their posted Δ (read-backs), unless W2
  sources a separate quarterly total.
- **W-R-03**: `--as-originally-reported` on the 2002Q1 income statement returns the pre-case frontier.
  The selector is exercised, because Δ ≠ 0.
- **W-R-04**: `recon.assertion_drift` reports drift = ΣΔ on each line-cost account asserted at
  issuance, and `damages.attested_baseline` (`registries/procedures.toml:1702-1713`) reports the same
  per-account, per-period delta. That is the "but-for" view an expert witness uses. Only the drift is
  asserted, because it does not depend on filler.
- **W-D-07 / W-D-08 (post-correction, at `known_at = head`).** These are FA's own false positives on a
  real-shaped book, which an examiner should see.
  - `expense.capitalization` still cites every entry W-D-01 cites, because Restates lineage does not
    remove a target from `live_postings` (`crates/fa-lantern/src/snapshot.rs:505-512`). The rendering
    names the Restates edge from `fa explain lineage`, and says "the finding persists because the
    corrected entry stays in the journal (append-only, doctrine 5)" (W-D-07).
  - `jet.round_amounts` also cites the case's Restatement entries, because `live_postings` keeps every
    class except Reversal (`snapshot.rs:505-512`) and the procedure does not filter by class
    (`crates/fa-lantern/src/jet.rs:102`) (W-D-08, `about = "reconstruction"`: a finding on our own Δ
    entries). `jet.post_closing` does the same (`jet.rs:249`), but it is tier P, so it renders only as an
    X row in Limits: "a correction looks like the entry it corrects to these predicates" (H17).
- **W-T-04** `allocation`. `fa allocate` under `EqualSplitResidualFirst`
  (`registries/allocation_laws.toml:36-38`), applied to the posted 544,000,000.00 and ten declared
  targets, yields ten legs of exactly 54,400,000.00 and residual 0. That equals "exactly $54.4 million
  each" (p.111). The legs are computed by the law and posted (F6b); the sourced "$54.4 million" is
  never posted.
- **W-NOTE-01** (replaces v0's W-T-01; a Limits note, not an expectation, never PASS/FAIL): FY1999 total assets, 91,072 in the EX-27 against 85,280 "(Restated)"
  in the restating 10-K's selected data. The filer marks those selected data as not derived from audited
  statements, and no published Δ exists for 1999. This is a published two-point comparison with no
  franken_accounting computation. It is rendered as an observation, never as T.

### 6.5 Capabilities exercised

All of these appear only through expectations whose verdict depends on them (§12.2):
- book setup: `fa book create` (custom calendar); chart and roles; principals via `--as`/`--grant`;
- provenance and evidence: `fa engagement open|file`; `fa document attest manual`; the evidence
  minimum;
- posting: `fa post`/`fa commit` (Original, Adjusting, Reclassification); `fa allocate` (Allocation, with
  `--approval`); approvals on `fa post` (A0);
- period law: period soft-close/close/lock; SoD; the admissibility matrix;
- Lantern: `expense.capitalization`, `jet.round_amounts`, `jet.period_end_timing`, `jet.post_closing`,
  and `jet.self_approved` on the migration book;
- migration: `fa migrate open|stage|finalize`;
- restatement: statement issue; the `fa case` Restatement lifecycle on both the `statement` and the
  `native` book (determine, rehearse, approve, post, disclose, close); `--as-originally-reported`;
  `recon.assertion_drift`; `damages.attested_baseline`; findings before and after a correction;
- allocation: `fa allocate` under a registered law;
- outsider: checkpoint witness, proofs, certificate status, `fa-verify` argv, ADS extract;
- agents: the MCP walkthrough, its detectors and macros, and guidance reachability;
- outputs: `fa tb`; `fa statement balance-sheet`; checkpoint + bundle + `fa_verify`; `fa replay`;
  `fa finding replay`.

### 6.6 Settled research item, and one open runtime question

**Migration finalize (settled from code).**
- `fa migrate open` requires a `trial_balance` document with non-zero balanced `lines`
  (`crates/fa-cli/src/cli.rs:21024-21052`; `crates/fa-journal/src/migration.rs:362-412`).
- Finalize refuses with `FA-REF-131` unless the staged chunks fold to it (`migration.rs:1000-1065`).
- So A7m derives the legacy trial balance from its own chunks (`legacy_tb_from_chunks`). That tie-out is
  tautological and supports no claim.
- The trial balance is filed as a reconstruction-placeholder citation stub, which also meets the
  Migration evidence minimum.
- `source_recorded_at_ns` stays null. Chunks are staged with two approvals in Locked Historical periods
  (`admissibility.toml:350`).

**Staged-chunk visibility (settled from code).**
- `jet.self_approved` reads `snapshot.live_postings()` (`crates/fa-lantern/src/jet.rs:360`), which reads
  `fa_registers::entries_at`. That filters every entry through `fa_journal::migration::visible_at`
  (`crates/fa-registers/src/lib.rs:355-357`).
- `visible_at` requires the run to be Finalized, and, for a non-sole FullDetail run, an effective date on
  or after the opening date (`crates/fa-journal/src/migration.rs:594-613`).
- So staged-but-unfinalized chunks are invisible to every Lantern procedure. The migration book must be
  finalized, and its pre-opening chunks need `sole_opening_source`.

AN-100 stays quarantined.

**New candidate source.** The SEC's 2006 complaint in SEC v. Mark P. Abide (LR-19776) may carry
control-layer facts that the 2002 complaints and Beresford lack, such as who approved the 2001-08-22
transfers. Fetching and reading it is a W1 sub-task. Until then it is unread, and nothing rests on it.

---

## 7. Case E — Enron

### 7.1 Sources

| Id | Source | Assertion status |
|---|---|---|
| SRC-ENR-001 | United States v. Skilling and Causey, Cr. No. H-04-25 (S.D. Tex.), superseding indictment, SHA-256 `7d626cd6…` | charge |
| SRC-ENR-002 | Enron 8-K 2001-11-08, restatement Table 1 (headed "UNAUDITED"); EDGAR original accession `0000950129-01-503835`, captured by the Internet Archive (2017-05-11, 58,002 bytes) — the primary row, with the university print as a retrieval route only | filer_unaudited |
| SRC-ENR-003 | Enron 10-Q Q3-2001, EDGAR `0000950129-01-504218` (filed 2001-11-19): restated 2000-12-31 balance sheet (pp.5–6) and Note 3 ("not been reviewed") | filer_unaudited |
| SRC-ENR-005 | Powers report, EDGAR Exhibit 99.2 to 8-K `0000909518-02-000089` (primary); university mirror SHA-256 `c2236c87…` (retrieval route) | investigative_finding |
| SRC-ENR-008 | Enron 10-K FY2000, EDGAR `0001024401-01-500010` | filer_audited |
| SRC-ENR-402 | Enron 10-K FY1999, EDGAR `0001024401-00-000002` (filed 2000-03-30), with EX-27 | filer_audited |

The 2001–2003 EDGAR full-index captures show no 10-K/A. No audited restated statements exist.

### 7.2 Claims (H-023 deferred with this narrowed scope: "no documented Enron entry yields a single P or D verdict on sourced facts; every P and D component found is a branch; T holds as named-vintage bridge closure")

**Override strand: the reserve releases.** "On or about and between July 17 and 19, 2000, after the
second quarter ended, … caused entries to be made in Enron's books and records … which entries
improperly released funds from a reserve account solely to ensure that Enron reported a better earnings
per share number" (SRC-ENR-001 PDF p.37). The amount is stated only as "millions of dollars" (p.13). The
entry class, the period state and the documents are not stated.
- **E-P-01** is a first-refusal branch table over entry_class × period_state_at_commit, plus
  `evidence_attached` and `approvals_recorded`. Its cells are those of W-P-03's table. `FA-REF-080` is
  claimed only in cells that pass period law and SoD. The indictment is silent on documents: it neither
  names one nor says none existed, so `evidence_attached` is a branch. The amount is synthetic, so no
  amount-reading procedure carries a claim on these entries.

**Raptor restructuring (Q1 2001).** "Each of the transaction documents is dated April 13, 2001--after
the close of the first quarter--but say they are "effective as of March 26, 2001." A letter agreement
was executed on March 30, 2001, which stated an intention to enter into an agreement, and set forth the
agreement's material terms and conditions." (SRC-ENR-005 PDF pp.128–129, fn 58)
- **E-D-01** `cutoff.period_boundary` is B(document_date) with three cells:
  - document_date absent: not evaluated (`cutoff.rs:54-56`; the field is optional, and no commit law
    requires it);
  - 2001-03-30 (the letter agreement): no finding;
  - 2001-04-13 (the transaction documents): finding.

  `document_date` is in the §2.6 enum.

**Notes-for-stock ($1.0B equity overstatement).** The Talon note of $172M, April 2000, was booked "as an
increase to "notes receivable" and to "shareholders' equity"". "similar entries … in March 2001 … for
notes totaling $828 million" followed. "a reduction of $1 billion ($172 million plus $828 million)" was
recorded in Q3 2001 (Powers pp.125–126).
- **E-N-01**: no registered law or procedure refuses or reports an asset debit paired with an equity
  credit for own-stock issuance against a note. franken_accounting registers no contra-equity pairing
  rule. This is a capability gap visible on the entries' own legs, not concealment. The mutation twin is
  a planted rule in a test-only Canon policy (§13). The case cites no accounting standard number,
  because none is in the corpus. It quotes Powers's own "proper accounting" sentence instead.

**SPE strand.** The defects there are concealed side deals and backdated documents attached to booked,
documented transactions, for example Cuiaba, $11.3M, 1999-09-30. No refusal or named D procedure
applies.
- **E-N-02** is the N result.
- The graph procedures need posted party flows, not bare ownership edges:
  - `graph.related_party_exposure` reads OWNS/CONTROLS/RELATED_TO reach intersected with live postings
    carrying a party dimension;
  - `graph.circular_flows` reads money-flow cycles;
  - `graph.party_communities` is tier P.

  A graph D on Enron exists only if the case sources deal-level postings with party legs. That is
  research item E5. Its candidate facts and expectations, each conditional on anchoring:
  - a `CONTROLS` or `RELATED_TO` edge from the role-labelled CFO party to LJM1, with its valid-from date
    (Powers), posted with `party relate --kind controls|related --basis --valid-from`
    (`registries/verbs.toml:832`);
  - the Cuiaba sale (1999-09-30, $11.3M) with an LJM1 party leg, plus the repurchase if Powers states
    its date and amount;
  - **E-D-02**: `graph.related_party_exposure` (G) cites the Cuiaba posting(s);
  - **E-N-03**: `graph.party_circular_flows` does not report the sale/repurchase pair, because the legs
    are further apart than its `window_days`. The twin moves the repurchase inside the window. This
    renders in Limits as "a related-party round trip spread over two years escapes a windowed cycle
    detector";
  - optionally, `lookback.preferences`' 365-day insider window (`procedures.toml:1564-1604`), only if the
    payment and the petition date are sourced, and then as a branch over the obligation date.

**Restatement (T)**

| id | kind | lines | A (as previously reported) | Δ and B | status |
|---|---|---|---|---|---|
| E-T-01 | bridge | net income 1998, 1999, 2000; total assets, debt, equity 1997–2000 | FY2000 10-K (SRC-ENR-008); for FY1999, also the EX-27 (SRC-ENR-402: NET-INCOME 893, TOTAL-ASSETS 33,381, equity derived 1,130 + 6,637 + 1,803 = 9,570) | Q3-2001 10-Q Note 3 (24/24 bridges close: 4 lines × 6 periods), e.g. FY1999 restated net income 635, total assets 33,272, equity 8,724 | T, filer_unaudited |
| E-T-04 | bridge (earlier vintage; statements issued to `sec` citing the 8-K stub, read with `--as-reported-in`) | the same FY1999 lines | as above | 8-K Table 1: Δ (−153, −95, 0, −2 for net income; +187, −222, 0, −147 for total assets; −540, −166, 0, −128 for equity); B 643 / 33,199 / 8,736 | T on its own vintage, rendered as "AS REPORTED IN the 8-K of 2001-11-08", explicitly superseded 11 days later |
| E-T-02 | footing (both vintages) | 2000-12-31: every printed line of the FY2000 10-K balance sheet, and separately of the restated 10-Q pp.5–6 balance sheet, each posted on its own `statement` book; the type-level totals are certified folds compared with the printed totals | FY2000 10-K | Q3-2001 10-Q pp.5–6 | T on the totals only, filer_unaudited. A per-line A→B bridge is T only where the 10-Q prints Δ separately; a Δ derived as B − A is a derivation tautology and renders R. Verify at E1 that both captures print every line |
| **E-T-03** | **`delta`** (Δ derived from sourced entries; `native` variant, §7.2a; the program's one entry-derived T) | the "Raptor equity adjustment" line on total assets and equity: −172 at FY2000 and −1,000 at 1Q01 and 2Q01, in both 8-K Table 1 and 10-Q Note 3 | the Enron `native` book posts the Powers-documented notes-for-stock entries as Enron booked them: Dr notes receivable / Cr shareholders' equity, $172M (Talon, April 2000) and $828M (Raptors II/IV, March 2001), Powers pp.125–126 | the Restatement case's Δ entries are **derived** from those sourced entries (Dr equity / Cr notes receivable, same amounts; Powers p.126: "a reduction of $1 billion ($172 million plus $828 million)"). The published Δ line is compared, never posted | T, filer_unaudited; the only T in the program whose Δ is computed from documented entries rather than replayed from a published bridge. The equity/contra-equity role mapping is an interpretive `role_map` rule, named in the claim. Verify at E2d that both vintages carry the line with these values |
| — | not T | 1997 net income; all 1Q01 and 2Q01 cells | the FY2000 10-K gives only "income before cumulative effect" for 1997; 1Q/2Q-2001 A needs the Q1/Q2-2001 10-Qs | — | research; until then internal footing of Note 3 only |

The 8-K and the 10-Q differ in 20 of 30 cells (5 restated lines × 6 periods). EX-27 BONDS 7,151 is a
different concept from the 8-K's "Debt as reported" and is excluded: tag semantics decide coverage.
Debt, total assets and equity on the Note 3 periods need remainder accounts (§3.8). The remainder is a
**derived** residual (restated TA − debt − equity = 10,650 / 14,924 / 15,711 / 43,780 / 42,751 / 39,230
$M), not synthetic, and no T is asserted on it. **E-R-01** (10-Q vintage) and **E-R-02** (8-K vintage):
`AS ORIGINALLY REPORTED` returns the posted A after each case.

### 7.2a Book variants

- `native`: quarters 2000Q1–2001Q3; the reserve-release entries (synthetic amount), the notes-for-stock
  entries, the Raptor documents, and (if E5 succeeds) the Cuiaba postings with party legs. It carries
  E-P-01, E-D-01, E-N-01, E-N-02, E-T-03 and, if E5 succeeds, E-D-02 and E-N-03.
- `statement`: one per vintage, so the vintages never share a chart: the FY2000 10-K, the Q3-2001 10-Q
  pp.5–6 and Note 3, and the 8-K Table 1 issuance. It carries E-T-01, E-T-04, E-T-02, E-R-01 and E-R-02.

### 7.3 Capabilities exercised

- Parties and entities with OWNS edges (only if E5 succeeds), the graph procedures, and N results.
- `cutoff.period_boundary` with `document_date`.
- The admissibility-matrix and evidence-minimum branch tables.
- Two successive restatement vintages: two cases, or a case and a revision (E4 decides).
- `--as-originally-reported` and the `AS REPORTED IN` profile, the EX-27 scale derivation, and the
  remainder derivation.

---

## 8. Case L — Lehman Repo 105

### 8.1 Sources

| Id | Source | Assertion status |
|---|---|---|
| SRC-LEH-001 | Valukas examiner report Vol. 3: p.889 "Gross and Net Balance Sheet Ratios", p.734 fn 2854 (definitions), fn 3365 (printed p.874; the dated balances), pp.891, 897 | investigative_finding |
| SRC-LEH-002 | LBHI 10-Q Q2 2008 (EDGAR `0001104659-08-045115`; Internet Archive capture), printed pp.86, 89 | filer_reviewed: the review legend reads "We have reviewed the consolidated statement of financial condition … as of May 31, 2008" (re-verify at authoring) |
| SRC-LEH-003 | Valukas Appendix 17: Repo 105 accounting policy excerpts (p.8, p.3); §E table pp.36–37 (56 dated observations) | investigative_finding |

The FY2007 10-Q captures returned 404, so those rows are `BLOCKED`.

### 8.2 Facts

- **Valukas p.889.** Seven quarter ends from 2006-11-30 to 2008-05-31 give:
  - (a) total assets;
  - three deductions: segregated cash, collateralized lending agreements, identifiable intangibles;
  - (b) net assets;
  - (c) stockholders' equity;
  - (d) tangible equity capital;
  - (e) Repo 105/108 usage;
  - the reported and adjusted ratios.

  For example, (b) = 327,774 / 396,673 / 372,959 / 357,102 / 337,667 / 300,797 / 268,936, and
  (e) = 50,383 / 49,102 / 38,634 / … ($M). All 49 cells were recomputed. The additive lines close
  exactly; the 4 ratio rows match at 0.1x and the 2 percentage rows at 1%. Those are display-precision
  agreements (C), not exact equalities.
- **The 10-Q double-sources three quarter ends.** It prints, for 2008-05-31, 2008-02-29 and 2007-11-30,
  the same total assets, deductions and net assets (p.86), plus equity, junior subordinated notes
  (5,004 / 4,976 / 4,740), intangibles and tangible equity (p.89). It prints net leverage 12.06x /
  15.44x / 16.14x. The adjustment (e) is single-sourced (Valukas); the 10-Q never mentions Repo 105.
- **The dated series.** fn 3365 gives 36 dated end-of-day balances on **irregular** dates (none between
  2007-11-30 and 2008-01-29, nor between 2008-05-30 and 2008-07-14), each labelled "Repo 105 usage".
  Appendix 17 §E gives 56 dated observations headed "Total Repo 105", whose quarter-end values equal
  p.891's combined 105/108 totals. So both series are **combined** 105/108, with no split.
- **Inconsistencies, carried rather than resolved.**
  - Repo-105-only usage differs between p.891 and p.897 in 3 of 7 quarters (Q3 2007 29,054 vs 29,075;
    Q4 2007 29,727 vs 29,916; Q1 2008 42,200 vs 41,844).
  - For 2008-08-27, Appendix 17 gives $17.847B (supported), $22.067B (with "a manual addition of $4.220
    billion … There is no underlying support"), and $24.601B (the combined series).
- **Accounting form** (Appendix 17 p.8). "The re‐characterization entry is: Dr. Repo $100 / Dr. Long
  inventory‐derivative $5 / Cr. Inventory $105." That is a 3-leg entry. Repo 108 differs in collateral
  (equities) and haircut (8).

### 8.3 Claims (H-014 deferred with this narrowed scope)

- **L-T-01** `footing`, for the two quarter ends whose full statement the Q2-2008 10-Q prints
  (2008-05-31 and 2007-11-30; the research corpus's text extraction of SRC-LEH-002, lines 284–290). 2008-02-29 is footed only if the
  Q1-2008 10-Q is retrieved (item L1); until then its p.86/p.89 values are R rows (L-R-01).
  - Every printed line of the 10-Q's condensed consolidated statement of financial condition is posted
    to its own account. The certified type-level totals (total assets, total liabilities, total
    liabilities and stockholders' equity) must equal the printed totals, which are never posted.
  - No remainder account is needed when every line is sourced. If one is needed, K-TAUT applies.
  - Verify at L1 that the capture prints every line.
  - The harness derives (b) = (a) − deductions and (d) = (c) + junior notes − intangibles from certified
    balances, then net leverage (b)/(d). The rendering is "computed by the harness from certified
    balances; franken_accounting has no ratio operator".
- **L-R-01.** The per-account values that Valukas p.889 shares with the 10-Q (segregated cash,
  collateralized lending, intangibles, equity, junior notes) are posted from the 10-Q and read back. They
  are R rows. Valukas's agreement with them is a published two-source observation with no FA
  computation.
- **L-T-02** (scenario). On a scenario branch, `fa scenario run` recharacterizes (e) as secured
  borrowing (+e assets, +e liabilities). The certified artifact is the `fa scenario diff` certificate,
  because scenario statement reads are uncertified. The harness reproduces Valukas's adjusted 13.9x from
  the scenario's balances plus the diff.
- **L-N-01**: no registered law refuses a repo recharacterized as a sale. There is no derecognition or
  repurchase law. This is an N result with a product question (§13). It runs on the `native` variant
  (§8.3a), because a `no_refusal` N is barred on `ledger` (K-EVID).
- **L-T-02-CF-01** (optional, low priority; a Canon rule-version CF).
  - Two rule versions over `sale` events derived from the combined series: one books the documented
    recharacterization (Appendix 17 p.8, without the haircut leg the series lacks), the other a secured
    borrowing.
  - `fa rule backtest --compare` (`registries/verbs.toml:664`) must report exactly those events as
    differing, by ±(e).
  - It is a CF row with L-T-02's content and adds no claim. It is the only honest Canon exercise the
    record allows. Feasibility is checked at L3.
- **L-N-02**: `events.subsequent` reports nothing on the natural encoding. Repurchases are new Original
  entries, path (b)'s class gate admits only Reversal / Replacement / Restatement / PriorPeriodAdjustment
  / Adjusting, and path (a) needs a supersession (`cutoff.rs:681-713`, window 30). On an unsourced
  Adjusting branch, 2 of 4 quarter ends fall inside the window. So the N is B(entry_class), not
  unconditional.
- **L-D-01** (dated_aggregate, derived entries; lowest rank). `jet.period_end_timing` on net-change
  entries derived from the 56-observation combined series. The haircut legs and the 105/108 split are
  omitted, because the series lacks them. The claim holds only for quarter ends with observations inside
  the window. The entries are `derived`, and the claim is rendered "on derived net-change entries from a
  dated aggregate series".
- **No T on any Repo-105-only split** (not single-valued in the record).

### 8.3a Book variants

- `statement`: the quarter-end statements of financial condition (L-T-01, L-R-01) and the scenario
  branch of L-T-02.
- `ledger`: the net-change entries derived from the 56-observation combined series (L-D-01, L-N-02,
  L-T-02-CF-01). No filler: the derived rows are the population.
- `native`: one entry of Appendix 17 p.8's documented form at its illustrative per-$100 amounts
  (Dr Repo 100 / Dr Long inventory-derivative 5 / Cr Inventory 105), evidence
  `manual_assertion(InternalTransfer, reconstruction placeholder)`, in an Open period. It carries only
  L-N-01 and its mutation twin (a planted test-only Canon rule, H6). No D runs on it, so it needs no
  filler.

---

## 9. Case M — Madoff / BLMIS trustee ledgers

### 9.1 Sources

| Id | Source | Assertion status |
|---|---|---|
| SRC-BLM-001 | Picard v. Glantz et al., complaint, Exhibits B-1 … B-6 (madofftrustee.com `008796-glantzcomplaint10-05394docket93.pdf`, SHA-256 `751a8a55…`); 9 columns ending "Balance of Principal \| 2-Year Fraudulent Transfers - Fictitious Profits" (no 6-year column) | trustee_computation (allegation in a complaint) |
| SRC-BLM-005 | Picard v. Square One Fund (`009665-squareonecomplaint10-04330docket0167.pdf`); 12 columns incl. 6-year; 709 cells marked `*` under footnote [1] | trustee_computation |
| SRC-BLM-006 | Picard v. Magnify (Adv. 10-05279); 11-column layout incl. "Six Year Transfers"; note "Numbers might not add to totals shown due to rounding." | trustee_computation |
| In re BLMIS, 654 F.3d 229 | the net-equity method (cited at `cutoff.rs:2653`); the case adds a sources row when it quotes the opinion | court_ruling |

SRC-BLM-004 (the "United Congregations" file) is a SIPC reply memorandum with no Exhibit B, so it is not
a case source.

### 9.2 Facts and replay results (DEBATE-001 re-verification across 3 complaints, 13 accounts, 3,793 rows)

| Account | Source | TRANS rows | Pure running sum of displayed rows vs printed balance | Class |
|---|---|---|---|---|
| 1T0026 | Glantz | 10 | exact at every row (117) | T footing; 10 transfer credits are trustee outputs |
| 1ZA192 | Glantz | 3 | exact (75) | T footing; transfers include one recomputable pair |
| 1ZB143 | Glantz | 3 | exact (51) | T footing; as above |
| 1ZB010 | Glantz | 1 | exact under `same_day_display_reorder` (interpretive; one CHECK/STOP PAYMENT pair) | T footing under a named rule |
| 1FN025, 1FN097, 1FR051 | Magnify | (per account, at authoring) | exact | T footing |
| 1ZR010 | Glantz | 0 | 50/57 rows off cumulatively, closing gap $9; the Deposits footer 5,979,184 agrees with the balance column, the displayed rows sum to 5,979,193 | C (display unit whole dollars; cause inferred) |
| 1ZR176 | Glantz | 0 | intermediate gaps ≤ $1, closes at 0 | C |
| 1FR048 | Square One | — | $3 closing drift (cumulative metric: 1,010/1,050 rows off, max $3) | C |
| 1FN024, 1FN037, 1FN073 | Magnify | — | −$42, +$16, +$1 | C, citing Magnify's rounding note |

Inter-account transfers (Glantz):
- There are 17 TRANS rows across 4 accounts.
- Only 2 transfers have both ledgers in the same complaint, and both reproduce under
  `trustee_transfer_credit` (interpretive):
  - 1993-10-20, 1ZA192 → 1ZB143, $4,000,000: full credit (originating principal 4,855,000);
  - 2005-12-23, 1ZB143 → 1ZA192, $200,000: credit 0 (originating principal (4,854,688)).
- The other 13 credits can only be copied from the trustee's columns (`role = "oracle_output"`).

### 9.3 Claims

- **M-T-01** `footing{rows → printed balances}` on the 7 T accounts, on the `ledger` variant (§3.2). The predicate names its inputs:
  "given the trustee-credited transfer amounts (Columns 4–7) as inputs, franken_accounting's certified
  running principal equals every printed balance". This is the exhibit's own arithmetic reproduced
  exactly. It is not an independent reproduction of the trustee's net-equity determination on transfer
  accounts (K-ORACLE).
  - **Certified read.** One `fa gl detail --account <a> --from <first row> --to <last row> --certify` per
    account. Each `gl_line.running_balance` must equal the printed balance of its row, with rows matched
    by entry key, and `fa replay` must reproduce the certificate.
  - **Independent refold.** At each printed balance that ends a period, `fa bundle produce --account <a>
    --from … --to … --balance <a>:USD:<date>` is verified in-process by `fa_verify::verify_bundle`, and
    the refolded balance must equal the printed value.
- **M-T-03** (optional; `migration` variant). The same rows imported with `fa migrate import`
  (FullDetail), driven as `--action prepare --intent <import.json>` → `--action stage --package D:<oid>
  --chunk <n> --approval <vid> --approval <vid>` → `fa migrate finalize`
  (`crates/fa-cli/src/migration_import.rs:41`, `:94-103`), against declared period-end trial balances, selected from the printed balances by
  `last_balance_on_or_before`. The kernel's tie-out admits the run. Its twin, one row moved by $1, is
  refused `FA-REF-131`.
- **M-T-02** (independent part). The 2 intra-complaint transfer pairs recomputed by
  `trustee_transfer_credit` from the originating ledgers. This is a T over the interpretive rule, and is
  rendered with the rule's name.
- **M-C-01** consistency on the 6 C accounts (§5.3), each citing its display unit or rounding note, with
  the per-row test and the detection limit.
- **M-D-01** `ponzi.net_investment` (v3) equals the trustee's closing principal on 1ZR176, built from
  its rows. It is conditional on the two-reader tier row confirming S-party (§2.5).
  - 1ZR010 is C: the equality holds on footer totals only, which would be a read-back.
  - The extremal variant (thousands of same-scope investor parties) must still give 1ZR176 the same
    flag, severity and value.
  - If the tier row instead classes the procedure P or A, M-D-01 becomes an N with the mechanism named,
    and the per-account equality survives only as the account-level T/C footing (M-T-01 / M-C-01).
- **M-N-01**: on every account with a TRANS row, `ponzi.net_investment` v3 diverges by exactly the net
  principal transferred (1T0026 +2,384,266; 1ZA192 −3,462,634; 1ZB010 −200,000; 1ZB143 +3,955,000). v3
  attributes cash-role legs only (`cutoff.rs:2475`, `:2662`). This is an N result plus product bead H1.
  - AN-401: v3 retains every party with attributed cash in as an investor, so the case book contains only
    customer cash movements, one party per account.
- **Lookback columns**: `lookback.fraudulent_transfer` scans badges of fraud with 730-day and UVTA
  1,460-day windows (`registries/procedures.toml:1617-1626`). It does not compute the trustee's lookback
  amounts, so there is no claim, and product research H5 follows.
- **Account holders** are role-labelled (§2.8).

### 9.4 The program over real rows (record-silent observations, `ledger` variant)

Exhibit B is the only real, row-level transaction data in the program: 3,793 rows across 13 accounts in
3 complaints. The applicable procedures run over it, and the case publishes what they report.

- **Population.** The rows of the accounts the three complaints present, as presented
  (trustee_computation). This is a population the litigation selected, not a sample of BLMIS accounts.
  Row descriptions are encoded only as transaction-type tokens and trustee account ids (K-NAMES).
- **Procedures**, admissible under §2.5:
  - `jet.round_amounts` and `jet.weekend` (L);
  - `duplicates.same_same_same` and `duplicates.same_same_different` (S-rel);
  - `numbers.relative_size_factor` (S-party, one party per account);
  - `numbers.round_amount_density` and `benford.first_digit` (P over a sourced, complete population;
    Glantz alone exceeds Benford's 500-leg minimum);
  - `jet.thin_descriptions`, only if OD 2b vendors the row descriptions.
- **Expected values** come from registered predicate-model derivations in `case_derivations.toml`, never
  from a run: `round_residue{power}`, `weekday_of`, `same_leg_multiset_same_day`,
  `same_leg_multiset_within{days}`, `rsf_ratio`, `first_digit_counts`.
  - Benford's digit counts are S. Its MAD statistic and band are Sd, under fa-oracles' own copy of the
    published 10^9-scaled first-digit table. FA computes them with `BENFORD_1E9` in integer arithmetic
    (`crates/fa-lantern/src/digits.rs:60-115`), so a disagreement is a FAIL naming the digit.
- **Typing.** These are D (or N) rows with `record_label = "silent"`, one per procedure (**M-D-10…**).
  - They render as counts under "What the analytics report on real customer cash flows that the record
    does not characterize".
  - Many findings will be ordinary customer behaviour, such as fixed recurring withdrawals. That is the
    point: this is the program's only view of FA's false-positive exposure on real data.
  - They never appear in summaries, and are never a rate (§0.5).

---

## 10. Case X — XBRL-era restatements

### 10.1 SunPower 10-K/A FY2022 (error correction): the flagship T case

- **Source.** EDGAR `0000867773-23-000117` (10-K/A, `AmendmentFlag true`), the XBRL instance. It was
  selected from the EDGAR full-text-search index of 8-K Item 4.02 filings: accession
  `0000867773-23-000089`, items 4.02 / 5.02 / 9.01, filed 2023-10-24.
- **Assurance is per line.** The 10-K/A names Ernst & Young as auditor of the annual statements. The
  quarterly figures, including the worked example below, come from the filing's "SELECTED UNAUDITED
  QUARTERLY FINANCIAL DATA". So every X-T-01 row carries `assurance`: `filer_audited` for annual lines
  inside the audit opinion, and `filer_unaudited` for the quarterly lines. "Reproduces audited figures"
  may be said only of the former.
- **What the instance tags.** A (`srt:ScenarioPreviouslyReportedMember`), Δ
  (`srt:RestatementAdjustmentMember`) and B (undimensioned), for the same concept, period and unit. 122
  complete (concept, period) triples close: A + Δ = B.
  - Example: Q4 FY2022 (2022-10-03 … 2023-01-01) `us-gaap:NetIncomeLoss`: A 7,613,000 (c-441) + Δ
    −4,188,000 (c-442) = B 3,425,000 (c-443), `decimals="-3"`, USD.
  - The fact census depends on a counting rule: 506 / 524 in the research, 508 / 526 raw in the review.
    The case states its rule: distinct (concept, context, value), dimensional members included.
  - The coverage count depends on a rule too. Strict one-fact-per-role triples give 122/122. Including
    groups with several restated facts, 486 (concept, period) groups close exactly (MOR audit AUD02). The
    case reports both counts with their rules.
- **X-T-01** `bridge`, on every modelled concept that maps to a certifiable read: a type-level
  statement line, or a per-account balance through `role_map` (interpretive).
  - Each tagged Δ is posted through a Restatement case. Each Δ must name the A posting it `restates`, so
    A is posted at (concept, period) granularity.
  - Concepts with no certifiable read are listed as not modelled. Coverage is reported per line, never as
    "the statements".
  - **Duration rule.** A and Δ are posted only for the finest non-overlapping durations the instance tags
    for a concept, normally quarters. A coarser duration's B (fiscal year, year to date) is a certified
    fold (`fa tb --fiscal-year N --activity` over the concept's accounts), compared with its own tagged
    B. These fold rows are reported separately from the per-quarter bridges. Where a finer value is only
    implied (FY − 9M YTD), it is a `difference` derivation, and K-TAUT bars a T on the line it came from.
  - **X-R-01**: `AS ORIGINALLY REPORTED` returns A on every X-T-01 line.
- **X-T-02** (narrow round trip). `fa export xbrl` writes only type-level concepts in instant contexts,
  with no dimensions (`crates/fa-formats/src/xbrl.rs:66-135`, `:785`). So the round trip covers only the
  as-restated instant totals (Assets, Liabilities, StockholdersEquity, LiabilitiesAndStockholdersEquity),
  compared by concept QName and value. Two caveats:
  - Some bindings, such as `us-gaap:CurrentPeriodNetIncome`, are not US-GAAP elements, so those
    concepts are excluded.
  - This is not taxonomy validation.

  A fuller writer is an optional product bead (§13).

### 10.2 Microsoft FY2018 10-K (ASC 606 / ASC 842 full retrospective recast)

- **Source.** EDGAR `0001564590-18-019062`. Its 16 complete triples close. For FY2017:
  - NetIncomeLoss: 21,204M + 4,285M = 25,489M;
  - revenue: 89,950M + 6,621M = 96,571M;
  - StockholdersEquity at 2017-06-30: 72,394M + 15,317M + 0 (the ASU 2016-02 member) = 87,711M.

  Three pairs are incomplete, so coverage is per line.
- **X-T-03**: as X-T-01 (with its read-back **X-R-02**), with case kind PolicyChangeRetrospective. Two
  qualifications:
  - This is a change in accounting principle, not an error correction, and the case says so.
  - PolicyChangeRetrospective posting has never been tested anywhere, so this would be its first
    exercise. Item X5 lands a library-level test first.

### 10.3 RH 10-Q/A

The instance tags A but no adjustment member. Δ exists only in the HTML table, which was **not
retrieved**. **X-T-04** is research item X6 (`BLOCKED` until the HTML is fetched with a SHA-256 and its Δ
rows are anchored). Until then RH supports only "A and B as filed".

### 10.4 Vintage rule

"As previously reported" has vintages too. The restater's A can differ from the originally filed value
by a reclassification (WorldCom 98,727 vs 98,903). K-VINTAGE requires naming both. When the restater's A
differs from the filed A, the case carries both and states which one the bridge uses.

---

## 11. Case C — Mergers: purchase-price allocation and consolidation

### 11.1 Microsoft–LinkedIn PPA

The PPA is tagged at 2016-12-08 under `BusinessAcquisitionAxis = msft:LinkedInCorporationMember` ($):

| line | amount |
|---|---|
| cash | 1,328,000,000 |
| short-term investments | 2,110,000,000 |
| other current assets | 697,000,000 |
| PP&E | 1,529,000,000 |
| intangibles (3,607 + 2,148 + 2,109 + 23 $M) | 7,887,000,000 |
| goodwill | 16,803,000,000 |
| short-term debt | 1,323,000,000 |
| other current liabilities | 1,117,000,000 |
| deferred tax | 774,000,000 |
| other | 131,000,000 |
| net, "Total purchase price" | 27,009,000,000 |

Consideration transferred is tagged 27,000,000,000 at `decimals="-8"`.
- **C-T-01** `footing`: the certified fold of the posted acquisition-date components equals the tagged
  total 27,009,000,000, with goodwill (16,803,000,000, `oracle_output`, the filer's residual:
  consideration − net identifiable assets) named in `inputs_named` (K-ORACLE). This is the filer's own
  footing, reproduced; it is not an independent goodwill computation.
- **C-R-01**: reading goodwill back returns the posted 16,803,000,000. It is R, not T.
- **C-C-01**: consideration 27,000,000,000 agrees with the total only at its declared precision
  (±50,000,000). That makes it C, never T.

### 11.2 Consolidation on a published pro forma combination (research item C2)

The strongest merger T for `fa consolidate` would be a Regulation S-X Article 11 pro forma condensed
combined balance sheet, from an 8-K/A Exhibit 99 or an S-4. Its columns are acquirer historical + target
historical + footnoted pro forma adjustments = pro forma combined. Two entities, an OWNS edge,
eliminations and PPA adjustments would have to reproduce the combined column exactly.

**No such filing was examined.** A bounded research bead must find and anchor one before any
consolidation T is claimed. If none supports exact closure, consolidation is demonstrated only as a
labelled scenario.

---

## 12. Cross-cutting checks every case runs

### 12.1 Outsider verification (run the way an outsider runs it)

For every T read from a TB, balance-sheet or income-statement certificate (on any book variant), the
case runs:
- `fa checkpoint create --grant witness`, covering the read's known-at;
- `fa bundle produce --certificate <tb|bs|is cert>` (`crates/fa-cli/src/proof.rs:804`;
  `registries/verbs.toml:784`);
- `fa-verify bundle <bundle> --key K --receipt R --json` and `fa-verify report <bundle> --key K
  --checkpoint C --receipt R --json`. Both run as the literal argv through `fa_verify::cli::run`
  (`crates/fa-verify/src/cli.rs:100-145`), and must exit 0. The `report` recomputation of the T's line
  or row must equal B; fa-oracles makes that comparison on fa-verify's report;
- `fa replay <certificate>`, which must reproduce byte for byte within the run (FA-INV-11).

Other read kinds replay their own way:
- D reads: `fa finding export --certificate C:<run> --export-format canonical --out <f>`, then
  `fa finding replay <f> --certificate C:<run> --known-at <seq>`;
- scenario expectations: their `fa scenario diff` certificate;
- BLMIS footing: `gl detail` certificates and account bundles (§9.3).

For every `statement` and `ledger` variant, `fa export ads --period <p> --out <dir> --with-proofs`
runs, then `fa-verify ads <dir> --key K` (`registries/verbs.toml:917`). The rendering says "an
ADS-shaped GL extract (column set not yet the published standard, fa-ipom), verified complete by
`fa-verify ads`".

**Outsider kit.** With `FA_CASES_OUT=<dir>`, the runner writes per case:
- the book directory and the book's public key;
- signed and witnessed checkpoints;
- bundles with receipts and proofs;
- the ADS extract;
- canonical finding workpapers;
- `VERIFY.txt`, generated from the run log: exactly the `fa-verify` and `fa replay` argv the runner
  executed, with their exit codes.

The kit is never committed, because its ids vary per run (§3.4). Its consumer is an examiner or opposing
expert re-checking the case. Its gate is that every listed command was executed in the run that wrote
it.

A case whose bundle fails verification fails, whatever its expectations say. That is plan bet A3.

### 12.2 Capability coverage: exercised or accounted for

Each `case.toml` declares the capabilities it exercises: verbs, procedures with versions, refusal ids,
laws, bitemporal selectors, case kinds, statement kinds and export formats. A capability counts as
**exercised** only if some passing expectation's verdict depends on its output. The dependency is
supplied by the contributing-entry, mutation-twin and kernel-twin witnesses (§3.7 items 2–4) and by
the outsider checks (§12.1). So a verb that merely ran does not count. This answers the project's own
precedent: "the registry check proves names, not behavior" (`crates/fa-cli/tests/readme.rs:19`).

The test asserts *declared ⊆ exercised* per case. The program also asserts **registry closure** over
`crates/fa-oracles/data/case_coverage.toml`, a harness table embedded like those of §2.4. It has one
row for every `[[procedure]]` in `registries/procedures.toml` (68) and every `[[verb]]` in
`registries/verbs.toml` (81, with subcommands listed). Each row is exactly one of:
- `exercised`: the expectation ids whose verdicts depend on it. The row passes only if each passed in
  the last run; an UNRUN expectation makes the row UNRUN.
- `not_exercisable`: a `reason` from a closed set, plus `covered_by`, naming the fa-gen scenario or
  motif (`crates/fa-gen/src/lib.rs:130-136`, `:412-425`), the fa-demo scenario, or the existing test that
  does exercise it. The reasons:
  - `no_public_data`: the public record holds no population of the kind the predicate reads;
  - `population_relative`: tier P or A over a population the record does not give completely;
  - `needs_judgment`: an input the auditor states and the record does not, such as tolerable
    misstatement (`registries/verbs.toml:724`);
  - `law_absent`: no law or procedure exists; the row names its §13 bead;
  - `adds_no_claim`: it runs in setup, but no expectation could depend on it;
  - `research`: the row names its bead.

The closure test fails on:
- a registry row without a coverage row;
- a coverage row naming no registry row;
- an `exercised` row whose expectations did not pass.

The coverage table of `docs/FORENSIC_CASE_STUDIES.md` renders both kinds of row with equal prominence:
what the cases exercise, and what they cannot and where it is exercised instead. Its consumer is the
owner's "ALL the deep functionality" requirement. Its gates are the per-case assertion and the closure
test. It retires with the program.

The seed content, by procedure family, is in Appendix Z.5.1. A13 seeds it,
and every `covered_by` must name an existing test that actually runs the procedure.

### 12.3 Generated write-ups

`fa-oracles::cases` renders, from the last green run's JSONL log and the data files, each case's
`README.md`, its `AGENT_WALKTHROUGH.md` (§12.5), and the program overview
`docs/FORENSIC_CASE_STUDIES.md`.

**Section order of a case README (normative):**
1. Reader and workflow: the COMPREHENSIVE_PLAN §15.6 reader, with a step table (each step either executed, citing
   its expectation id, or not executable here, with the reason):

   | Case | Reader workflow |
   |---|---|
   | W, X | CPA audit and examiner |
   | E | investigator |
   | L | litigation consultant's but-for |
   | M | receiver or trustee |
   | C | CPA audit (business combination) |

2. What the record says: the sourced facts table (value, anchor, assertion status, granularity; quote
   text only after OD 2a).
3. How this book was built: book variants, declared defaults, interpretive rules, branch attributes,
   and the self-disclosure rows (§2.7).
4. Findings, refusals with the system's stated remedy (§5.2), and tie-outs with their assurance status.
5. **What franken_accounting does not catch here, and why** (below).
6. Verify it yourself: the §12.1 kit commands and the §12.7 witness.
7. Reproduce.
8. What green does not show: the work items' no-claim lines.

**The Limits section** (item 5) is generated from:
- the case's N rows, each with its mechanism (file:line) and twin status;
- its X components, each with the rule that makes it inadmissible;
- the CF rows that show what a D or P depends on;
- the `not_exercisable` coverage rows for procedures a reader would expect for this scheme, such as
  the population JET tests for WorldCom and `graph.ponzi_motif` for BLMIS;
- the §13 beads the case raised.

It is never shortened in summaries.

**Rendering rules:**
- Every sentence comes from an expectation template (§0.3). There is no free-text path.
- Each claim sentence carries:
  - the assertion status of every source in its basis (§2.2);
  - the claim class and calibration clause for D (§5.6);
  - the encoding and premises;
  - the named interpretive rules.
- Branch tables render as tables. Each row is marked *record-consistent* (supported by a sourced or
  derived fact) or *unconstrained*. Only record-consistent rows appear in summaries, which is the FRE 702
  "sufficient facts or data" point.
- Rows with `record_label = "silent"` (§9.4) render only as counts per procedure, under "What the
  analytics report on data the record does not characterize". They are never in summaries and never a
  rate.
- N results and CF rows render with the same prominence as D/P/T.
- **Reproduce** is rendered from the run log's `argv_redacted`, with symbolic placeholders (`$BOOK`,
  `$C_IS_2002Q1`, `$F4`) bound to the event fields that produced them. With `FA_CASES_TRANSCRIPT=1`, a
  separate test re-executes the rendered text and must reproduce every projection; otherwise the README
  is not rendered.
- Statement tables are FA's own presentation in the filing's unit (`fa statement … --present-in
  thousands|millions`, `registries/verbs.toml:543`), never renderer arithmetic.
- Only run-invariant fields are rendered (§3.4). A test re-renders and compares bytes, so the docs
  cannot drift from the evidence.
- An `owner_review = true` expectation renders only after its wording is approved in the data file.

### 12.4 Relation to fa-gen and the fa-4psc calibration

fa-gen plants its own motifs, so its precision is 100% by construction
(`registries/lantern_calibration.toml:22-32`). Case books contribute three things it cannot:
1. **Predicate-level negatives from documented scheme entries.** F2, F6, F7 and F8 are documented parts
   of the WorldCom scheme: "parking", and transfers designed to keep Andersen from detecting the
   capitalized amounts (pp.106, 111). They fall outside `expense.capitalization`'s predicate (W-N-01).
   They are **not** legitimate look-alikes and must never enter a "legitimate / near-miss" denominator.
   BLMIS accounts that move principal by transfer rather than by cash (M-N-01) are the second example.
2. **Externally labelled positives**: entries the investigators documented, rather than entries we
   planted.
3. **Real-data exposure.** The §9.4 sweep shows what the analytics report on real customer cash flows
   the record does not characterize. These are counts on a litigation-selected population, never a
   rate.

The program does not change `lantern_calibration.toml`. H9 adds `crates/fa-oracles/data/case_calibration.toml`, a harness table (§2.4) that becomes a registry
only if a product consumer appears:
case-derived rows with their own denominators and labels taken from the sources. No case result is ever
reported as a precision or recall figure.

**WorldCom-labelled synthetic artifacts.** Two exist:
- fa-gen's `WorldComCapitalization` scenario ("WorldCom-Style Operating Line-Cost Capitalization",
  `crates/fa-gen/src/lib.rs:202`);
- fa-demo's `worldcom` scenario ("WorldTel Line Systems Demo Corp.", `crates/fa-demo/src/lib.rs:115,129`;
  a Sunday 50,000.00 entry).

Both plant attributes the sourced record contradicts (weekend booking and self-approved
capitalization). Whether their hedged labels are enough is owner decision 6.

### 12.5 Agents: a deterministic MCP walkthrough, guidance reachability, and the campaign

**The deterministic MCP walkthrough runs on every case, now.**
- **Where it runs.** `crates/fa-mcp/tests/cases_mcp.rs`, with fa-oracles as a dev-dependency. fa-mcp's
  topology row carries an allowlist (`registries/workspace_topology.toml:183-187`), and `edge_allowed`
  rejects any edge outside it, dev edges included (`crates/fa-registry/src/topology.rs:141-149`), so item
  A15 adds `fa-oracles` to that allowlist: one registry edit, so one global crate-verdict invalidation. `CARGO_BIN_EXE_fa-mcp` is available only to
  fa-mcp's own tests.
- **How it builds the book.** In-process, through `fa_cli::entry::fa`, as
  `crates/fa-mcp/tests/e2e_stdio.rs:48-60` does. It then spawns fa-mcp with an Agent template
  (`--cluster fa.forensics --cluster fa.findings --cluster fa.case --cluster fa.query --cluster fa.notary
  --grant read --grant produce`).
- **Parity.** It replays the case's audit program as tool calls. Every D/T/R projection (§5.4) must
  equal the CLI runner's.
- **Case-shaped mistakes:**
  - an Agent trunk post is refused `FA-REF-013` (AGENT_TRUNK), then planned into a draft;
  - F4 as Original into the Closed 2Q01 is refused `FA-REF-010`. The same legs re-dated to the
    2001-07-17 booking date are then refused *before dispatch* by fa-mcp's `redated_intent` detector
    (`crates/fa-mcp/src/detect.rs:677-712`). The CLI and the kernel admit that re-dated intent, because
    3Q01 is Open. This is CF row W-P-03-CF-02, rendered in Limits: the period law protects closed
    periods, but it cannot know an entry's true effective date;
  - `self_approval` on the session's own lock or issuance proposal (`detect.rs:715-739`);
  - the `investigate_account` and `certify_period_reports` macros (`crates/fa-mcp/src/registry.rs:154-184`).
- **Output.** `cases/<id>/AGENT_WALKTHROUGH.md`, generated from the green run (tools, arguments with
  placeholders, projections) and drift-tested like the README. Its consumers are agents learning the
  forensic workflow, and fa-y6eu card authors.

**Guidance reachability runs on every case.**
- From each built book, the runner follows only read-only `next_actions` of `fa triage` / `fa next`,
  and of MCP `fa_orient_next`, to depth 6.
- It records whether a Lantern procedure or `fa jet` is ever offered, and whether an offered command
  contains a placeholder (`crates/fa-mcp/src/detect.rs:251`).
- At 8196f5e40, no procedure is offered before a finding run exists (`crates/fa-cli/src/triage.rs:798-890`).
  On an all-Closed book, the first step offered is `fa period open <code> --json` (`:809-815`): a write
  step with a placeholder, which fa-mcp's own detector refuses.
- That is an ergonomics N row per case, rendered in Limits and locked in both directions. It is the
  reason for H16. When H16 lands, the N flips and is retired with a trailer.

**The fresh-agent campaign (fa-y6eu).** Once two cases are green, a fresh-context agent is given only
a case book (no facts file, no expectations), under an Agent-profile token, and works through fa-mcp.
- Case books are the sandboxes for four fa-y6eu cards: examiner (W, X), investigator (E), litigation
  consultant (L) and receiver (M). Case C has no campaign card: its one book holds a filer's own
  footing, which offers an agent nothing to find; its README walkthrough is the CPA reader's.
- The measures are fa-y6eu's: useless_error outcomes and steps.
- "Documented entries reached: k of n" is recorded per run as a count, never aggregated into a rate
  (§0.5).

### 12.6 Litigation production (optional per case)

For WorldCom and BLMIS, `fa production` (`crates/fa-cli/src/production.rs`) produces a Bates-numbered
set with a privilege log over the case's engagement documents, and verifies it. It adds no claim, so it
is optional.

### 12.7 Book integrity, append-only witness, read-path cross-checks and interop identity (every run)

- **Book integrity.** After step 8 of §3.3, `fa verify book --json` must exit 0 on every book variant
  (`registries/verbs.toml:929`). Exit 8 fails the case, whatever its expectations say.
- **Append-only witness**, for every restatement case (W-T-02, W-T-03, E-T-01/03/04, X-T-01, X-T-03):
  - the role `examiner-witness` makes a key (`fa checkpoint witness-key`) and cosigns the checkpoint
    before the case (`fa checkpoint witness --out w1`);
  - after the case, `fa checkpoint witness --previous w1 --out w2` must succeed, and `fa-verify
    checkpoint w2 --key <book key> --witness <key> --quorum 1` must exit 0 (`registries/verbs.toml:760`:
    "a rollback or rewritten history is refused (FA-REF-124, exit 8)");
  - `fa proof consistency` (before → after) and `fa proof inclusion --entry <A>` (at the after state)
    must verify with `fa-verify` (`registries/verbs.toml:772`);
  - `fa certificate status C:<as-filed statement certificate>` must report SupersededBy, with
    `later_entries` equal as a set to the case's posted Δ entries (`registries/verbs.toml:567`). This is
    an independent second half of the contributing-entry witness;
  - harness-only twin: `--previous` set to another book's witness statement must be refused
    `FA-REF-124`.

  It renders as "an examiner who witnessed the as-filed root can verify offline that the restated book
  extends it; the as-filed entry is still included".
- **Second read path.** Every T and R value is also read with `fa query --certify` under the FA GQL
  profile (`registries/verbs.toml:652`), as a `MATCH` aggregate of legs grouped by unit and side and
  netted by the harness:
  - stock with `EFFECTIVE BETWEEN '<opening>' AND '<end>' AS KNOWN AT <seq>`;
  - activity with `FOR PERIOD`;
  - R rows with `AS ORIGINALLY REPORTED`;
  - Lehman's scenario with `AT BRANCH 'scenario:<name>'`.

  It must equal the fold-path value. This is an R-class cross-check of two FA read paths, never
  independent evidence. A book with pending holds refuses the check, because GQL rows include them.
- **Interop identity.**
  - Every `statement` and `ledger` book's ADS extract must re-import byte-identically
    (`registries/formats.toml:65-71`, `round_trip_identity = true`).
  - `fa export beancount` and `fa export ads` are each checked with the native `fa verify export
    beancount|ads <file|dir>` (`registries/verbs.toml:929`; `crates/fa-cli/src/export.rs:401-412`). That
    command re-reads the file with the format's own reader and requires the balances to refold (beancount)
    or the journal to be re-read identically (ads), byte for byte; exit 8 names the first difference.
    There is no `--format` flag on `fa migrate import`; the format is a field of its `--intent` JSON.
  - Once fa-sa4w's harness exists, the same books join its bean-check/hledger differential, reported
    UNRUN when the binaries are absent.

---

## 13. Product findings and prerequisites (separate beads)

| id | Finding | Evidence | Bead |
|---|---|---|---|
| A0 | **`fa post` and `fa commit` cannot attach an approval** (only `fa allocate` and `fa settle` take `--approval <vid>`, `registries/verbs.toml:459`). `fa post` and `fa commit` have no `--approval`; the builder hard-codes empty approvals; the repo's own closed-period test falls back to the library. | `registries/verbs.toml:259`, `:395`; `crates/fa-cli/src/cli.rs:8230`; `crates/fa-cli/tests/bank.rs:885-905` | feature, P1: `--approval <vid>` on `fa commit` and `fa post --dry-run` with verbs.toml + MCP parity, write-authority matrix rows, and refusal tests for FA-REF-008/012. Agents need it anyway for SoD workflows. |
| H1 | `ponzi.net_investment` v3 credits only cash-role legs. | `cutoff.rs:2475`, `:2662`; M-N-01 | v4 follows `investor_capital` transfers under a named rule. Version bump; the BLMIS case is the regression oracle. |
| H2 | v3 retains every party with attributed cash in as an investor, contrary to its registry summary (AN-401). | `cutoff.rs:2626` | fix the population predicate or the summary, plus a negative test with a vendor party |
| H3 | `fa demo` usage lists scenarios that `Scenario::parse` rejects (saas, manufacturing, nonprofit, holding, crypto) and omits ghost-payroll. fa-v6j's close reason claims 11 scenarios; the code has 7. | `cli.rs:3990`, `verbs.toml:1050`, `crates/fa-demo/src/lib.rs:52-120` | bug |
| H4 | The evidence minimum checks presence and kind, not content. | `evidence_policy.toml:166-212` | docs: README and refusal-catalog text state the limit |
| H5 | `lookback.fraudulent_transfer` has 730-day and UVTA 1,460-day windows only. The trustee's New York 6-year window would mislabel the law if forced through `uvta_days`. | `procedures.toml:1617-1626` | research |
| H6 | No law refuses a repo recharacterized as a sale. | L-N-01 | research: a Canon rule or a Lantern detector? |
| H7 | No contra-equity pairing law. | E-N-01 | research: Canon rule candidate. Its test twin is reused by E-N-01. |
| H8 | `fa-statements` has no ratio lines, and user-loaded definitions are unwired. | `custom.rs:214-223`; `definition.rs:129` | research, only if users need them; no case depends on it |
| H12 | verbs.toml:251 (`case post` usage) says Restatement entries are "refused with FA-REF-178", and the `fa-journal` case module doc says "This build posts PriorPeriodAdjustment and Revision cases". But the CLI test posts one. | `verbs.toml:251`; `crates/fa-journal/src/case.rs:41-45`; `crates/fa-cli/tests/cli.rs:4512-4730`; `crates/fa-cli/src/cli.rs:3450` | doc bug (robot-docs and module docs mislead agents) |
| H13 | PolicyChangeRetrospective posting has no test anywhere. | `case.rs:1661-1675` | test bead; blocks X5 |
| H14 | ManualAssertion reason codes cannot express "described in the public record, bytes not public". | `reason_codes.toml:29-53` | registry: additive code `NotInPublicRecord` (owner decision) |
| H16 | `fa triage`/`fa next` never offer the audit program when no finding run exists. On an all-closed book they offer a write step with a placeholder (`fa period open <code>`), which fa-mcp's own detector refuses. | `crates/fa-cli/src/triage.rs:798-890`, `:809-815`; `crates/fa-mcp/src/detect.rs:251` | feature: an open audit, examination or investigation engagement makes triage offer `fa jet` / `fa procedure list`; triage never emits a placeholder command. Flips the §12.5 guidance N |
| H17 | Lantern populations keep a restated target and include its Restatement entries; findings do not mention the correction lineage (W-D-07/W-D-08). | `crates/fa-lantern/src/snapshot.rs:505-512`; `jet.rs:102`, `:249` | research: should findings carry supersession lineage, as `shares_supersession_lineage` does for duplicates? |
| H15 | `fa export xbrl` emits only type-level instant facts and binds a non-US-GAAP element (`us-gaap:CurrentPeriodNetIncome`). | `xbrl.rs:66-135`, `:94`, `:785`; fa-ipom | optional: duration contexts and real element bindings (links fa-ipom) |

---

## 14. Owner decisions (each blocks only what it gates)

1. **SEC EDGAR contact address.**
   - Gates direct sec.gov fetches by `case_fetch.py`, and therefore verification of archive bytes against
     the EDGAR originals.
   - Options: a project contact address, the owner's address, or archive-only.
   - Archive-only is not neutral. The Internet Archive grants access "for scholarship and research
     purposes only", and archive captures cannot settle byte equality with the originals.
   - Whatever the owner picks, the address lives only in `FA_SEC_CONTACT` and never lands in a committed
     file.
2. **Redistribution of excerpts.**
   - (a) Quote text: ≤ 60 words per fact. This gates committing quote text, not the harness, because of
     hash-first vendoring (§1.3).
   - (b) Whole numeric exhibits, such as all Exhibit B rows and the Valukas series. This gates committing
     those tables, and therefore M2a–M2c and L1's committed form.
   - The facts the decision rests on are in §1.3.
3. **Real names.**
   - Gates committing quote *text* that contains names (a sub-item of OD 2a). Under hash-first
     vendoring no quote text is committed, so OD 3 gates neither the pilot nor W1, E1 or M1. It gates the
     post-OD-2a quote text of the F6 quote (Beresford p.111), the BLMIS account holders, and most
     WorldCom quotes.
   - Recommended: role labels, the SEC's "the DPA" precedent, and a hashed deny list.
4. **Public claim wording.**
   - The request's phrases "prevented the fraud" and "match the final work of the Big4 auditors"
     conflict with the project doctrine (no accusations; a statistic is never an invariant). The second
     phrase is also factually false for Enron, whose restated figures were never audited or reviewed.
   - Recommended: the §0.3 templates, assertion-status phrases, and N results with equal prominence. Only
     the owner can choose otherwise (RULE 0).
5. **The `NotInPublicRecord` reason code (H14).** An additive registry change.
6. **WorldCom-labelled synthetic artifacts.**

---

## 15. Work breakdown (dependency-ordered; becomes beads)

Notation: `[id]` is a work item, `← deps` its dependencies, and `(OD n)` an owner decision. Work-item ids
carry their case letter: `A` foundation, `W` WorldCom, `X` XBRL, `E` Enron, `L` Lehman, `M` BLMIS, `C`
mergers, `H` product findings. Check ids are `K-*` (§3.6). Every textual "needs X" in an item is also a
`←` edge.

Rules for every item:
- It lands real code and real tests in the same unit of work, and never closes on a refusal-only path.
- Each item states three acceptance criteria:
  - a **positive** observable;
  - a **planted negative**: a failure that must be observed;
  - a **no-claim** line, saying what green does *not* prove.
- **Walking skeleton.** The runner exists early. An expectation whose required witness is not
  implemented yet prints UNRUN, never PASS. Honesty is therefore enforced per row by the runner, not by
  withholding the runner. An item whose acceptance requires a row to FAIL depends on every item that
  row's witnesses need, because an UNRUN row cannot FAIL.

### Phase A: foundation (walking skeleton first)

- **[A0] CLI approval surface for `fa post` and `fa commit`** ← none. Product feature, P1 (§13).
  - Adds `--approval <vid>` on `fa commit` and `fa post --dry-run`, with verbs.toml and MCP parity and
    write-authority matrix rows. `fa allocate` and `fa settle` already take `--approval <vid>`
    (`registries/verbs.toml:459`), so A0 follows their flag shape.
  - **Design constraints at 8196f5e40.**
    1. `fa approve` is a publication, and any intervening publication invalidates a plan
       (`registries/verbs.toml:399`).
    2. The request builder seals the description with fresh entropy on every JSON parse
       (`crates/fa-cli/src/cli.rs:8137`). So re-parsing the intent after `fa approve --proposal <digest>`
       changes the proposal digest and invalidates the approval (`crates/fa-cli/tests/bank.rs:887-888`;
       checked at `crates/fa-journal/src/post.rs:2923-2928`).
    3. An entry that requires an approval (Adjusting in Closed) is refused with `FA-REF-012` during
       planning, before any PostPlan exists (`crates/fa-journal/src/plan.rs:105-122`). The plan
       certificate also binds the intent's digest, approvals included (`plan.rs:112`).

    A0 therefore follows the year-end close review pattern (`registries/verbs.toml:179`):
    - seal the proposal once and emit its portable sealed bytes and `proposal_digest`;
    - record `fa approve --proposal <digest> --as <approver>`;
    - pass the retained sealed proposal plus `--approval <vid>` into `fa post [--dry-run --plan-out]`,
      then `fa commit --plan`.
  - Positive: a native Adjusting post in a Closed period, with an approval by a second principal, is
    admitted.
  - Negative: a self-approval is refused `FA-REF-008`, and a missing approver is refused `FA-REF-012`.
  - No-claim: A0 proves the CLI can carry approvals, nothing about any case.
- **[A1a] `fa-oracles` crate, topology flip, allowlist, Source / Fact / Value / Receipt types and loader**
  ← none.
  - Positive: a minimal source+facts pair loads, and re-serializing with the parser's canonical bytes
    equals the parsed files.
  - Negatives: one fixture per malformed shape, each refused with a named error and line:
    - a fact with two provenance kinds;
    - a `[[value]]` whose fact does not exist;
    - a dotted key;
    - a multi-line array;
    - a float;
    - a TOML date.
  - No-claim: well-formedness only, nothing about whether a fact is true.
  - Items A1a–A1c share the four-file pilot fixture of §3.2a; each owns its own file's loader.
- **[A1b] Book-variant schema** (§3.2a) ← A1a.
  - Positive: the A8 pilot `books/native.toml` loads, every foreign key resolves, and every intent
    balances per unit under every amount class.
  - Negatives: a `[[leg]]` whose intent does not exist; an unbalanced intent; a `[[step]]` referencing an
    unknown period.
  - No-claim: as A1a.
- **[A1c] Expectation schema** (`[[expectation]]`, `[[target]]`, `[[branch_cell]]`, `[[note]]`) ← A1a.
  Acceptance as A1b, over the pilot expectations, plus: a `[[note]]` that names a verdict is refused.
- **[A2] Derivation table and engine** (`crates/fa-oracles/data/case_derivations.toml`) ← A1a.
  - Positive: every rule in §2.4, including `negate` and the §9.4 predicate-model rules, recomputes its
    example.
  - Negative: a planted wrong value per rule.
  - No-claim: arithmetic correctness, not the truth of inputs.
- **[A3a] K-PROV, K-BIND, K-SCOPE, K-ANCHOR, K-DERIVE**, plus the std-only SHA-256 and normalization ←
  A1a, A2.
  - Positive: the pilot facts pass. A check report lists the rows each check examined; a check that
    examined zero rows is UNRUN.
  - Negatives:
    - the SEC ¶29 → F12 misbinding fails K-SCOPE;
    - the "entered and approved" fragment fails K-BIND's sentence alignment;
    - a quote occurring twice fails;
    - the FIPS 180-4 vectors fail if altered.
  - No-claim: K-BIND proves the vendored values occur in the vendored quote or its receipt. Only the
    receipt binds the quote to source bytes, and only `original_hash_compared = true` binds those bytes to
    the publisher's.
- **[A3b] K-BASIS, K-TAUT, K-ORACLE, K-VINTAGE** ← A1b, A1c, A2.
  - Negatives: a planted read-back T is re-typed R; an oracle-output-fed T becomes C unless the input is in
    `inputs_named`; a T on a superseded vintage is refused; a `delta` T that names no Δ accession is
    refused.
- **[A3c] K-ASSERT, K-ERRRATE, K-NAMES, K-EVID** ← A1b, A1c.
  - Negatives: a book citing a provenance stub on a `native` variant fails K-EVID; a `no_refusal` N on a
    `ledger` variant fails K-EVID; a principal named with a deny-listed token fails K-NAMES.
- **[A4] Procedure tier table and K-TIER** ← A1a. Two-reader rows keyed by (id, version, row digest),
  seeded for every procedure any case claims:
  - `expense.capitalization`, `jet.round_amounts`, `jet.self_approved`, `jet.period_end_timing`,
    `jet.post_closing`, `jet.weekend` and `jet.self_sourced_evidence`;
  - `cutoff.period_boundary`, `events.subsequent` and `ponzi.net_investment`;
  - `recon.assertion_drift` and `damages.attested_baseline`;
  - for §9.4: `duplicates.same_same_same`, `duplicates.same_same_different`,
    `numbers.relative_size_factor`, `numbers.round_amount_density` and `benford.first_digit`;
  - for E6: `graph.related_party_exposure` and `graph.party_circular_flows`.

  Each row records `reads_evidence`.

  Negative: a version bump in a test copy invalidates the row.
- **[A4r] Reference differential adapter** ← A1b, A7a. Builds, from a book variant, the fa-reference
  oracle's inputs and compares its verdicts, findings and folds with the CLI run's.
  - **Field map** (`[[intent]]` → `fa_reference::Intent`, `crates/fa-reference/src/lib.rs:429-447`):
    `class` → `class`; `effective_date` → `date`; `[[leg]]` rows → `legs`; `idempotency_key` → `key`;
    the acting principal's grants → `ops`; the count of approvals the intent cites → `approvals`; a
    `target_kind = reverses` target → `reverses` (its journal index); `reason` → `supersession_reason`
    (the registered tag). `Intent` has no reclassification, restates or revises target, no allocation
    and no evidence field.
  - **Composition, in kernel order.** On a clone of the oracle: `Oracle::post` (`lib.rs:1713`) decides
    the steps it models (balance, period, identity, period law with its approval count). If it admits,
    `fa_reference::sod::verdict` (`crates/fa-reference/src/sod.rs:28`) runs over the intent's approvals,
    then `fa_reference::evidence::verdict` (`crates/fa-reference/src/evidence.rs:236`) over its
    citations and attestations. The first refusal is the reference verdict. The clone replaces the
    oracle only if all three admit.
  - **`not_modelled`.** A P cell is `not_modelled` when its intent is a Reclassification, a case Δ
    (`restates`/`revises`), an allocation, or a migration chunk, or when the kernel's order puts an
    unmodelled step (reclassification shape, event) before the first modelled refusal. A D target is
    `not_modelled` when its procedure has no `fa_reference::lantern` function (`expense.capitalization`,
    `ponzi.net_investment` and the graph procedures, for example). Otherwise D cite sets are compared
    with `fa_reference::lantern::{round_amounts, period_end_timing, post_closing, weekend, self_approved,
    cutoff, same_same_same, same_same_different, first_digit_counts, relative_size_factor_by_account}`
    over `lantern::Row` slices built from the run's live postings. T folds are compared with
    `fa_reference::statements::render` (`statements.rs:148`).
  - Each row logs `agree`, `disagree` or `not_modelled`. `disagree` is FAIL, and `not_modelled` is
    printed, never skipped silently.
  - Negative: a planted disagreement (a wrong period state in the adapter) fails.
  - No-claim: agreement shows two implementations agree on our encoding; it does not show either matches
    the sourced history.
- **[A5a] Branch rules, enumerator, balance-law feasibility, cap, property tests** ← A1b, A4, A7a.
  - `crates/fa-oracles/data/case_branch_rules.toml` rows: `attribute` (the §2.6 enum), `reader` (a
    procedure id@version or a kernel step), `class_rule` (`enum`, `residue_mod{power}`,
    `inside_window{window_days}`, `before_after{date}`), `parameters` (the registry parameter names the
    rule reads), and `code_justification` (file:line at the pinned commit).
  - **Feasibility of multi-leg splits.** A cell assigns each leg a residue class mod 10^p. It is feasible
    iff integer amounts exist with those residues, each at least one minor unit, summing to the sourced
    total: Σ rᵢ ≡ total (mod 10^p) and total ≥ the number of legs. For F4's three credit legs at p = 3 and
    the total 560,000,000.00, the cells "all multiples" and "two or three non-multiples" are feasible,
    and "exactly one non-multiple" is not.
  - **Cap.** At most 256 cells per (expectation, target), counted as the product of the class counts of
    the target's branched attributes after equivalence-class reduction. The value is a declared default
    in the rules file, revisited when A7c measures per-invocation cost. A capped enumeration logs its
    order and never yields a single verdict.
  - **Property tests.** 64 concrete witnesses per class, seeded by SHA-256(case id ‖ expectation id ‖
    cell), run through the real binary (A7a): every witness in a class gives the class's verdict.
  - Positive: on the pilot, F4's `leg_split` under `round_power = 3` enumerates exactly the feasible
    cells, and names the infeasible ones.
  - Negatives: an emptied branch set is refused; a capped enumeration never yields a single verdict.
  - No-claim: equivalence of a class is shown on the property-test sample, not proved.
- **[A5b] Status model (S/Sd/Si/B/Rel/X), K-BRANCH, K-PRED, K-JOINT, CF rows** ← A5a, A1c, A3b.
  - Negatives: a constraint that collapses the predicate is refused; a declared default that decides the
    predicate is refused (§2.6 rule 2); a D target with no admitted cell is refused; a D and P with
    overlapping scopes are refused.
- **[A6] Filler generator** ← A4, A1b. Seeded and discipline-obeying, emitted as book-variant intents and
  one `PostBatch` per variant.
  - **Account universe per tier** (§2.5): L and C filler posts only to filler accounts the case declares
    (`code` prefix `9`), never to an account a target names; S-rel filler uses idempotency keys and
    references disjoint from every target's; S-acct, S-party and G filler use accounts, parties and
    components no target touches; O filler commits only before the first target or after the last.
  - **Extremal variants**: L and C, 10^3 × the target's leg count of filler entries on the filler
    accounts, dated in every period the history opens; S-rel, one filler duplicate pair per target key
    shape, under disjoint keys; S-acct, 10^3 entries on a sibling account of the same type and role; G
    and S-party, same-scope volume of at least 10^3 × the target (§3.7); O, 10^3 commits interleaved
    before the first target.
  - **Seed → content.** A variant's content is a pure function of SHA-256(case id ‖ variant id ‖ seed):
    accounts, amounts (integers at the unit's scale), dates and keys are drawn from it in a fixed order.
  - **Timing.** Filler for a period posts while that period is Open, before the history's first
    soft-close step for it; filler never posts into a SoftClosed, Closed or Locked period.
  - **Evidence.** Each variant cites one `fa:case-filler:v1` document (§2.7).
  - **Co-residence.** Co-resident D cells (§3.3) are targets, not filler: the generator excludes their
    accounts and keys as it excludes any target's.
  - Property test: filler never touches the target's keys, accounts or components, per tier.
- **[A7a] Runner core** ← A1b, A1c, A3a. It builds and replays a book, runs procedures and reads `tb`,
  using the registered verb table, catalog exit codes and the JSONL log with its fact↔vid map, and prints
  PASS/FAIL/UNRUN.
  - Positive: the `_selftest` case runs every implemented stage, emits one JSONL record per step whose
    verb is in verbs.toml, and prints one line per expectation.
  - Negatives:
    - a wrong refusal id reports FAIL with a reproducible argv;
    - a renamed verb fails before any book is created;
    - an approval-dependent row without A0 reports UNRUN and the run exits non-zero;
    - a cite of the wrong fact reports FAIL.
  - No-claim: the runner proves what the binary printed for this book, nothing about the sourced history
    beyond the encodings named.
- **[A7b] Restatement lifecycle, issuance, bitemporal reads, case diff, assert-balance** ← A7a.
- **[A7c] Cell evaluation and the combination rule** (dry-run sweeps, co-residence, PostBatch, budget
  logging) ← A7a, A5a.
- **[A7m] Migration fixture** ← A7a. `migrate open|stage|finalize` with a derived legacy trial balance
  (§6.6), staged with two approvals.
  - Negative: `jet.self_approved` after `fa migrate stage` but before `fa migrate finalize` returns no
    finding (`migration.rs:594-605`).
  - Positive: after finalize, it cites F6 on the cell `approval_encoding = migration_legacy_pair`,
    `approvals_recorded = {approved_by = entered_by = property-accounting-director-1}`.
- **[A8a] Harness self-test** (`cases/_selftest/`, `kind = "harness_selftest"`: no sources, never
  rendered, exempt from K-BASIS by kind) ← A7a, A7b, A7c, A11c, A4r.
  - Contents: one bridge T plus R, P cells by dry run (`FA-REF-080`, `FA-REF-086`, `FA-REF-010`), one N
    with its twin, checkpoint, bundle, `fa_verify`, replay, and `fa verify book`.
  - Positive: every P and N row passes; the T row prints UNRUN until A11b and A12 land.
- **[A8] WorldCom pilot** (native book, F2, F4, F9, F12) ← A8a, A2, A3a, A3b, A3c, A4r, A5b, A7c, A9,
  A10a, A11a, A11c, A12, the SRC-WC-001 slice of W1 (receipts for pp.26, 105–116), and (OD 5 or the
  recorded `InternalTransfer` choice).
  - Expectations:
    - W-D-01 on F4 and F9;
    - W-D-03 on F4;
    - W-N-01 on F2;
    - W-P-02's no-evidence branch on F4 (`FA-REF-080`);
    - W-P-03's Original-in-Closed cell (`FA-REF-010`).
  - Negatives, each of which must FAIL, then be restored before landing:
    - moving F4's debit by one minor unit fails W-D-01's statistic;
    - retyping F2's credit account as Expense fails W-N-01;
    - removing the `period_close` step makes W-P-03 fail with an admitted post.
  - No-claim: the pilot shows that registered predicates hold, and named refusals occur, on our encoding
    of four documented entries over N variants. It shows nothing about WorldCom's actual ledger,
    false-positive rates on real books, or what any control would have prevented.
- **[A8b] F6 pilot** ← A7m, A8, A11a.
  - W-P-01(a) (draft self-promotion of F6a, `FA-REF-008`) with W-P-01-CF-01, on the native book;
  - W-D-02 on the migration book, on the cell `approval_encoding = migration_legacy_pair`,
    `approvals_recorded = {approved_by = entered_by = property-accounting-director-1}`.
- **[A9] `tools/case-fetch/case_fetch.py`** (fetch, extract, xbrl-facts, verify, `receipts.toml`) ← A1a
  (schema).
  - Positive: on the fixture document, `verify` writes receipts with every binding true, and re-running
    on an unchanged cache is byte-identical.
  - Negatives: the five planted failures of §4.4; an `FA_SEC_CONTACT` leak test.
  - No-claim: a receipt proves the quote occurs in bytes with that SHA-256 at that anchor. It does not
    prove the bytes are the publisher's unless `original_hash_compared = true`.
- **[A10a] Offline ledger test** (`ledgers_validate_offline`, §4.6) ← A3a, A3b, A3c, A4, A5b, A9. A
  `#[test]` in fa-oracles, plus a second fa-oracles test that every `FA-REF-*`/`FA-INV-*` marker the
  renderer can emit resolves against the registries, independent of whether any rendered file exists.
  - Negative: a planted unresolved marker fails the marker test.
- **[A10b] Claims-lint scan entries** ← A14. Adds `docs/FORENSIC_CASE_STUDIES.md` and every generated
  case `README.md` to `registries/claims_lint.toml` `scanned_docs`. registry-check skips a missing file
  (`tools/registry-check/src/main.rs:830-837`), so this lands only once A14 renders the files.
  - Negative: a planted unresolved marker in a rendered README fails `scripts/check.sh`.
- **[A11a] Filler and identifier invariance** ← A6, A7c.
  - Positive: W-D-01/F4's single components agree across 5 seeded + empty + extremal variants and 2
    runs.
  - Negative: a test-only tier row declaring `numbers.round_amount_density` tier L fails, naming the row.
- **[A11b] Contributing-entry witness** ← A7b, A8a.
  - Positive: the `_selftest` bridge's contributions are exactly A and Δ.
  - Negative: a planted read-back T (B posted directly) is re-typed R.
- **[A11c] Mutation twins** ← A7a.
  - Negative: Benford below its minimum, used as an N, fails its twin.
- **[A12] Outsider verification** (§12.1, §12.7) ← A7b, A8a.
  - Scope:
    - TB/BS/IS certificates through checkpoint, bundle, the literal `fa-verify` argv including `report`
      recomputation, and replay;
    - `finding export|replay`; scenario-diff certificates; `gl detail` certificates and account
      bundles;
    - the ADS extract and `fa-verify ads`;
    - the outsider kit;
    - the append-only witness (witness, consistency, inclusion, certificate status) on the `_selftest`
      bridge.
  - Positive: with A11b, the `_selftest` bridge T passes. This is the first green run of a T.
  - Negative: the FA-REF-124 twin is observed.
- **[A13] Coverage gate tied to expectations, with registry closure** (§12.2) ← A7a, A11a, A11b, A11c,
  A12.
  - Seeds `case_coverage.toml` with all 68 procedures and 81 verbs.
  - Negative: a test-only procedures.toml copy with a new row fails the closure test.
  - No-claim: a `not_exercisable` row records a reason; it does not prove that no public source exists.
- **[R-TRACE] Research: a public tracing computation** ← none.
  - Find a free, public court opinion or receiver report (not PACER) that states a deposit/withdrawal
    series and the traceable amount computed under LIBR, FIFO or pro rata.
  - If one exists, `trace.<law>` gets a T against it. Otherwise it closes with a decision record.
- **[A14] Renderer + drift test** (§12.3) ← A7a, A13, (OD 4) for `docs/FORENSIC_CASE_STUDIES.md`.
- **[A14b] Limits section, normative README order, transcript mode, `--present-in` tables** (§12.3) ←
  A14.
  - Negative: a rendered transcript that does not reproduce a projection blocks rendering.
- **[A15] MCP case runner and walkthrough renderer** (§12.5) ← A7a, A12, A14.
  - Adds `fa-oracles` to fa-mcp's topology allowlist (`registries/workspace_topology.toml:183-187`):
    `edge_allowed` rejects any edge outside a present allowlist, dev edges included
    (`crates/fa-registry/src/topology.rs:141-149`). That is one registry edit, so one global crate-verdict
    invalidation (`scripts/crate_verdicts.py:13-15`), which the landing states.
  - Positive: the `_selftest` projections over MCP equal the CLI's.
  - Negatives: a re-dated retry is refused by `redated_intent`; a deliberately divergent projection
    fails parity.
  - No-claim: fa-mcp's behaviour on a reconstruction; nothing about any agent's ability to find fraud.
- **[A16] Guidance-reachability probe** (§12.5) ← A7a, A11c, A15. One ergonomics N per case, locked in
  both directions. It flips when H16 lands.
  - **Read-only entry.** A `next_actions` entry whose `writes` is false (`crates/fa-cli/src/triage.rs:671-686`);
    `write_step` entries are never counted.
  - **When.** The probe runs twice per case book: before the case's first `finding_record` step, and
    after its last. The N is asserted on the first run: no read-only entry offers `fa jet`, `fa procedure
    list` or an MCP `fa.audit` tool. The second run is logged, not asserted.
  - **Per-case expected value.** Computed from the book's state at the probe: a book with a `Future`
    period and none Open expects the concrete `fa period open <code>` with that period's code
    (`triage.rs:810-816`), never a placeholder.
  - **Twin.** A test-only book with an open engagement and the H16 behaviour planted in a copy of the
    triage table must make the N fail.
  - No-claim: the probe shows what triage offers on these books, not what an agent would do.

### Phase W: WorldCom

- **[W1]** Sources ledger and receipts: SRC-WC-001, -002, -003, -004, -401, -406, -EX27-1999, and the
  SEC v. Abide (LR-19776) candidate row ← A9. Hash-first; quote text only after (OD 2a).
- **[W2]** Facts F1–F13, one per sentence, with interpretations joining sentences, reporting periods,
  derived dates, AN-100 quarantine and roles ← W1, A3a. F6 is encoded as F6a and F6b (§6.2), F8 carries
  its `entry_decomposition` (p.261), and the instruction documents are as §6.2 records them (F10's draft
  JE is the only dated one).
- **[W3]** Book variants `native`, `migration` and `statement`, branch classes and defaults ← W2, A1b,
  A5a, A7m.
- **[W4]** W-D-01, -03 and -04, and W-N-01 on native; W-D-02 on migration. W-D-05's X components render
  in Limits ← W3, A4, A5b, A8, A11a, A11c.
- **[W5]** W-P-01(a) + W-P-01-CF-01, W-P-01(b) on F6b, W-P-02, W-P-03 + W-P-03-CF-01, W-P-04 ← W3, A4r,
  A5b, A7c, A8b.
  - Probe first: `fa allocate --review … --approval <self vid>` on F6b. If it reaches `FA-REF-008`,
    W-P-01(b) on F6b needs no A0; otherwise the cell reports UNRUN with the observed refusal logged.
- **[W5b]** W-P-01(b) on F6a (`fa post` with a self-approval) ← W5, A0.
- **[W6]** W-T-02 + W-R-01 on the `statement` variant; note W-NOTE-01 ← W3, A3b, A7b, A11b, A12.
- **[W7]** Native restatement: W-T-03, W-R-02..04, W-D-07/W-D-08, D pinning on `native` ← W3, W4, A7b,
  A11b, A12.
  - Negative: dropping the `known_at` pin makes W-D-03 fail with extra cites (the Restatement entries).
  - No-claim: the native restatement is our encoding of the restatement's line-cost component,
    restricted to the documented entries. It is not WorldCom's restated ledger.
- **[W8]** W-D-06 (`cutoff.period_boundary`), with F10's draft-JE date anchored at W2 ← W2, W3, A4, A5b,
  A11a.
- **[W9]** W-T-04 (F6b through `fa allocate`) ← W3, A1b, A7a, A11b, A12.

### Phase X: XBRL restatements (the flagship T)

- **[X1]** SunPower sources, `xbrl-facts` rows and receipts; assurance from the audit report; whether
  durations overlap ← A9.
- **[X1m]** Microsoft FY2018 sources and `xbrl-facts` rows ← A9.
- **[X2]** us-gaap → FA `role_map` for the modelled concepts ← A2.
- **[X3]** SunPower `statement` book: A and Δ for the finest non-overlapping durations only, each Δ
  `restates` its A. X-T-01 per modelled concept, coarser-duration fold rows, X-R-01, case-diff
  certificates ← X1, X2, A3b, A7b, A11b, A12.
- **[X4]** X-T-02, the narrow export round trip on the as-restated instant totals ← X3.
- **[X5]** Microsoft X-T-03 (PolicyChangeRetrospective) and X-R-02 ← X1m, X2, A7b, A11b, A12, H13.
- **[X6]** Research: RH's 10-Q/A HTML restatement table, with a SHA-256 → X-T-04 ← A9. BLOCKED until
  retrieved.
- **[X7]** Case lifecycle completion for SunPower ← X1, X3.
  - `case_determination_date` from the Item 4.02 8-K.
  - `case disclose`, with the FA-REF-179 twin.
  - `case close`.

### Phase E: Enron

- **[E1]** Sources and receipts:
  - Powers via the EDGAR exhibit;
  - the 10-K FY2000 and FY1999 (with EX-27);
  - the 10-Q Q3-2001;
  - the 8-K of 2001-11-08;
  - the indictment.

  ← A9.
- **[E2a]** Facts: the override strand (indictment) ← E1.
- **[E2b]** Facts: the Raptor restructuring and notes-for-stock (Powers) ← E1.
- **[E2c]** Facts: the SPE relationships and deal amounts (Powers) ← E1.
- **[E2d]** Facts: the statement tables (EX-27, 8-K Table 1, 10-Q Note 3 and pp.5–6) ← E1.
- **[E3]** E-P-01, E-D-01, E-N-01 (twin from H7), E-N-02 on the Enron `native` variant (§7.2a) ← E2a,
  E2b, E2c, A4, A4r, A5b, A7c, A11a, A11c, H7.
- **[E3b]** E-P-01's Adjusting-in-Closed admitted cell (needs an approval by a second principal) ← E3,
  A0.
- **[E4]** E-T-01 (10-Q vintage), E-T-04 (8-K vintage via issuance and `--as-reported-in`), E-T-02
  (footing on both statement vintages), E-T-03 (`delta`, Δ derived from the documented notes-for-stock
  entries, on `native`), E-R-01 and E-R-02. Decide two cases versus a case plus a revision ← E2b, E2d,
  A3b, A7b, A11b, A12.
- **[E5]** Research: sourced deal-level party postings (Talon $172M, Cuiaba $11.3M, …), and the
  Q1/Q2-2001 10-Qs for the 1Q01/2Q01 A side ← E2c. Closes with a decision record if insufficient.
- **[E6]** E-D-02 and E-N-03 on E5's postings ← E5, A11a, A11c. Only if E5 succeeds.
  `graph.party_circular_flows` and `graph.related_party_exposure` are registered and implemented at
  8196f5e40 (`registries/procedures.toml:1155`; `crates/fa-lantern/src/graph.rs:646`). E6 depends on
  fa-b6xs only if, at conversion, fa-b6xs's open scope still includes the party-level PAID projection
  these procedures read.

### Phase L: Lehman

- **[L1]** Sources and receipts: Valukas p.889, fn 3365 and App. 17; the 10-Q Q2 2008 with its review
  legend; the Q1-2008 10-Q (for a 2008-02-29 statement footing); the FY2007 10-Qs recorded `BLOCKED`.
  Check that each capture prints a full condensed statement of financial condition ← A9, (OD 2b) for the
  dated series.
- **[L2]** L-T-01 (statement footing at the quarter ends the retrieved 10-Qs print in full), L-R-01, and
  the harness-derived (b), (d) and ratios ← L1, A3b, A7b, A11b, A12.
- **[L3]** L-T-02 (scenario + certified diff), and optionally L-T-02-CF-01 ← L2.
- **[L4]** L-N-01 on the Lehman `native` variant (§8.3a), L-N-02 (branch over class) and L-D-01
  (derived entries; lowest rank) on `ledger` ← L2, M0, A4, A11a, A11c, H6.

### Phase M: BLMIS

- **[M0]** The `ledger` variant ← A1b, A4, A7a. Its schema, the `reads_evidence` tier field, batch
  posting, and the K-EVID rule.
  - Positive: 3,793 rows post within budget, at most one batch per account.
  - Negative: an evidence-reading D declared on `ledger` fails K-EVID.
- **[M1]** Sources and receipts (Glantz, Square One, Magnify) ← A9, (OD 2b).
- **[M2t]** `case_fetch.py exhibit-b` ← A9, A1a.
  - **Output.** `crates/fa-oracles/cases/blmis/exhibit_b_rows.toml`, GENERATED and never hand-edited,
    like `receipts.toml`. One `[[row]]` per printed Exhibit B row: `complaint` (source id), `account`,
    `page`, `line`, `date`, `transaction_description`, `amount_literal`, the column it was printed in, and
    `star` (true for Square One's `*` cells). `facts.toml` declares one `[[fact]]` per complaint that
    points at this file, so the rows are `ledger_row` facts by reference, not 3,793 hand-written facts.
  - **Layouts.** Per complaint: Glantz 9 columns, Square One 12 (including its 6-year column), Magnify
    11 (§4.1 rows SRC-BLM-*). A layout table in the tool names each column, in printed order, as the
    complaint's own column header, and maps it to a row field. The tool never infers a layout.
  - **Structural checks (FAIL on mismatch).** Every extracted row has exactly its layout's column count;
    every amount parses under the literal rule; and the row count per account equals the count of dated
    lines on that account's pages of the extraction.
  - **Arithmetic diagnostics (logged, never FAIL).** The pure running sum of each account's rows is
    logged against its printed balance column, and the column sums against any printed footer (Glantz's
    Deposits footer, for example). The T/C classification is §9.2's, made by the case, not by the
    extractor: a footer or balance disagreement is evidence for C, not an extraction error.
  - **`*` cells.** Square One's 709 cells marked `*` under footnote [1] (SRC-BLM-005) are extracted
    with `star = true` and their printed amount. An expectation that reads a starred cell names the
    footnote in its premises.
  - **Gating.** The rows file is generated in the cache; committing it requires OD 2b.
  - Negatives: a planted extra column and a planted dropped row each fail; a planted balance
    disagreement is logged and does not fail.
- **[M2a]** Glantz rows as facts (`ledger_row`, `oracle_output` flags on credited transfers) ← M1, M2t,
  A3a, M0.
- **[M2b]** Square One rows as facts ← M1, M2t, A3a.
- **[M2c]** Magnify rows as facts ← M1, M2t, A3a.
- **[M3]** M-T-01 footing on the 7 T accounts (`gl detail --certify` + account bundles), and M-T-02 on
  the 2 recomputable pairs ← M2a, M2c, A7b, A11b, A12.
- **[M4]** M-C-01 on the 6 C accounts ← M2a, M2b, M2c, A7a.
- **[M5]** M-D-01 (conditional on the tier row) + M-N-01 ← M3, A4, A11a, A11c.
- **[M6]** (optional) M-T-03, the migration-import tie-out ← M3, A7m.
- **[M7]** The §9.4 sweep (the record-silent rows M-D-10…), its predicate-model derivations and the
  `record_label` rendering ← M0, M2a,
  M2b, M2c, A2, A4, A11a, A11c.
  - Negative: one planted row's amount changed by 1 cent moves exactly the predicted cites.
  - No-claim: counts on a litigation-selected population. No rate, and no characterization of any row.

### Phase C: mergers

- **[C0]** LinkedIn sources and `xbrl-facts` rows ← A9.
- **[C1]** C-T-01 (footing, goodwill in `inputs_named`), C-R-01 (goodwill read-back), C-C-01 ← C0, X2,
  A3b, A7b, A11b, A12.
- **[C2]** Research: an Article 11 pro forma combination that closes exactly ← none. Closes with a
  decision record.
- **[C3]** Consolidation T on C2's filing ← C2, A7b, A11b, A12. Only if C2 finds one.

### Phase H: product findings (§13)

- **H1** ← M5. It needs the BLMIS oracle.
- **H2, H3, H4, H5, H8, H12, H14, H15** ← none.
- **H6** ← none. L4 reuses its test twin for L-N-01.
- **H7** ← none. E3 reuses its twin for E-N-01.
- **H13** ← none. It blocks X5.
- **[H9] Case-derived calibration rows** ← W4, M5. Adds `crates/fa-oracles/data/case_calibration.toml`
  (a harness table, §2.4; it becomes a registry only if a product consumer appears) with its loader and
  test.
  - **Row schema**: `procedure`, `version`, `case`, `expectation`, `fact`, `label` (`scheme_part` or
    `unlabelled`), `cited` (bool), `source` (the fact's source id).
  - **Label rule.** A documented entry is `scheme_part` only where the source names it part of the
    scheme (WorldCom F1–F13; BLMIS rows the trustee's complaint flags). Nothing is labelled
    "legitimate": the denominators are the case's own labelled rows, never a negative class (§12.4).
  - **Consumer.** fa-4psc's calibration review reads the rows as case evidence beside its fa-gen corpus
    figures; nothing reports them as a rate.
  - **Gate.** A fa-oracles test that every row's `expectation` and `fact` resolve and that no row's
    label disagrees with its expectation's verdict.
- **[H10] Agent campaign on case books** ← fa-y6eu, W4, X3, A15.
- **H16** (triage offers the audit program) ← none. It flips §12.5's guidance N (A16).
- **H17** (findings and correction lineage) ← W7.
- **External edges**: §12.7's differential ← fa-sa4w; §12.1's ADS wording ← fa-ipom; E6 ← fa-b6xs only
  under the condition stated in E6.

---

## 16. Acceptance and logging standards (apply to every item)

- **Unit tests.** Every check, derivation and branch rule in `fa-oracles` has unit tests, each with a
  planted negative.
- **Output.** The runner prints, per expectation:

  ```text
  PASS|FAIL|UNRUN <id> <type> <variant> <cell> <projection-with-statuses>
  ```

  On failure it prints the exact `fa` argv to reproduce, and at the end it prints the JSONL log path.
- **UNRUN.** An expectation whose prerequisite or witness is missing reports UNRUN, never PASS. Any UNRUN
  makes the test's exit non-zero for a case that claims completeness.
- **No `#[ignore]`.** No case test may be ignored to land. A case that cannot pass stays on a train
  branch.
- **Trailers.**
  - Removing an expectation needs a `Retired-tests:` trailer.
  - Weakening one needs a `Weakened-tests:` trailer. Weakening means fewer cites, a branch where there
    was a single verdict, or a C or R where there was a T.
- **Runtime budget.** Each case completes in under 60 s on a warm worker.
  - A7c measures the warm per-invocation cost and records each case's invocation count and wall time per
    book.
  - The budget is met by the §3.3 cell-evaluation and combination rules, not by capping.
  - A case above budget fails; it never silently caps. If it must cap, it states the cap and the
    enumeration order, and a capped run never yields a single verdict.

## 17. Risks and how the plan answers them

| Risk | Answer |
|---|---|
| Overclaiming in docs | template-only rendering; assertion-status phrases; calibration clause; owner review; N and CF rows rendered |
| A wrong quote, anchor, value or scope | sentence-aligned value and scope binding (K-BIND, K-SCOPE); receipts plus independent re-verify. The research's own errors are planted as test fixtures. |
| Tautological T | type-independent K-TAUT; K-ORACLE; contributing-entry witness; R and C types |
| Filler- or identifier-dependent D | two-reader tier rows keyed by row digest; extremal variants and ≥ 2 runs (2 book ids); VId-ordered components checked relationally (Rel) |
| Hidden unsourced target attributes | closed branch enum; over-listed premises; first-refusal model with the fa-reference differential; K-JOINT |
| A constraint manufacturing a D | K-PRED |
| Vacuous N | mutation twin; N barred on tier P |
| Upstream change silently changes a case | tier rows keyed by (id, version, row digest); over-listed premises plus the fa-reference differential; N results as two-way locks |
| Licensing and redistribution | hash-first vendoring; OD 2 gates quote text and whole tables |
| Missing product surfaces (approvals, PCR tests) | A0 and H13 as explicit prerequisites; UNRUN until they land |
| The program becoming ceremony | every artifact has a consumer and a gate; Phase A ends with a real, reachable pilot (A8) before more machinery |
| Source conflicts (AN-100, AN-301, the Valukas inconsistencies) | separate sourced facts; no expectation on contested attributes; later vintages win (K-VINTAGE) |

---

## 18. Order of work and why

1. **A0, A1–A7, then the A8 pilot.** The harness is the product, and the pilot proves it on a slice the
   binary can reach today. A0 runs in parallel: it unblocks the F6 pilot (A8b) and every
   approval-dependent cell.
2. **WorldCom next.** It has the densest entry-level record, D and P together, and it is the case users
   will ask about.
3. **SunPower in parallel with WorldCom.** Its data is independent, and it is the cleanest exact T: the
   "reproduces the published bridge" leg.
4. **Enron, then Lehman, then BLMIS.** Each adds a different capability set:
   - Enron: conditional law tables and two restatement vintages;
   - Lehman: statement footing, scenarios and dated aggregates;
   - BLMIS: footing, C rows and the transfer gap.
5. **Mergers last.** The strongest consolidation case needs research that has not been done.
6. **Product findings any time.** H1 waits for the BLMIS oracle; H13 must precede X5.

---

## Appendix Z. Review history

### Z.1 Round 1 inputs

- MOR run `20261024T205000Z`: P00 baseline, P01 boundary attack, P02 adversarial source check, P03
  capability/dependency, P04 reader credibility against FRE 702 / Daubert / AS 2401 / AS 4105 / SSFS
  No. 1, and P05 legal/normative. These were independent fresh-context passes over draft v0.
- Brenner Phase 5:
  - DEBATE-001 (H-009 confirmed as narrowed; the C-row rule);
  - DEBATE-002 (H-040 refuted; the harness rules adopted);
  - the H-013 falsifier check (not fired) and final states for H-013, H-014 and H-023 (deferred, with
    narrowed scopes).

### Z.2 What changed from v0

> Superseded later: `account_identity_order` (Z.4: observed covariate, Rel); fold sensitivity (Z.4:
> contributing-entry witness); id-permutation variants (Z.4: ≥ 2 runs); A4k (Z.4: dropped). Item and
> check ids throughout this appendix use the round-4 namespace (Z.7).

- **New claim types.** C (consistency), R (read-back), CF rows. P is retyped as an observation
  conditional on its encoding. The "audited" framing is replaced by per-source assurance status.
- **Provenance.** `interpretation` is a fourth kind. Value and scope binding, sentence alignment, the
  `oracle_output` role, the assertion-status table and the retrieval route are new.
- **Tiers.** Two readers, content hashes, `graph.party_communities` classed as P.
- **Branches.**
  - closed enum with `encoding_origin`, `reclassification_target`, `document_date`, `leg_split` and
    `account_identity_order`;
  - component statuses S/Sd/B/X; R-QUAL; K-PRED;
  - equivalence classes; the first-refusal model with premise closures; K-JOINT.
- **Source report as provenance.** It is enforced by K-EVID and held by `fa engagement`. The
  ManualAssertion constraints (closed reason codes, preparer signature) are stated.
- **Architecture.**
  - `fa-oracles` replaces a new `fa-cases` crate;
  - book variants (native and migration);
  - the corrected pipeline: verb names, `--as`/`--grant`, the A0 prerequisite, the migration path,
    issuance or lock before `AS ORIGINALLY REPORTED`, the full case lifecycle, checkpoints, and the
    bundle scope;
  - catalog exit codes (`FA-REF-008/010/011` exit 7);
  - the determinism model (random book ids; run-invariant rendering).
- **Runtime witnesses.** Extremal and id-permutation variants, fold sensitivity, mutation twins,
  property tests.
- **Statements surface.** Corrected: 2 certified definitions, whole-type lines only, library
  `from_toml` unwired.
- **WorldCom.**
  - The facts table is corrected (F4 exact on p.26; F6 sub-ledger plus interpretation; F7 and F11
    derived dates, F7 on a Saturday; F8 on p.111; the 3Q01 10-Q filing date; ¶34 states both amounts).
  - The SEC anchor moves from ¶29 to ¶¶6–7, as "support", not document absence.
  - The claims follow DEBATE-002's table. `cutoff.late_posting` (nonexistent) becomes `jet.post_closing`.
  - The pilot is split.
  - W-T-01 is retyped as observation W-N-04 (round 4: the Limits note W-NOTE-01).
  - The §12.4 mislabel ("legitimate look-alikes") is corrected.
- **Enron.** T is rebased on the 10-Q Note 3 vintage with an independent A from the FY2000 10-K; the 8-K
  vintage is held separately. Unaudited status is stated. The P table follows first-refusal semantics.
  Graph D needs posted party flows. The EITF citation is dropped.
- **Lehman.** T is on per-account balances, with (b), (d) and the ratios harness-derived. The series is
  irregular, not daily. The `events.subsequent` mechanism is corrected to the class gate (a branch, not
  an unconditional N). The scenario certificate is the scenario diff.
- **BLMIS.**
  - T/C split per DEBATE-001: 7 T and 6 C accounts across 3 complaints.
  - Trustee-credited transfers are named as inputs (oracle_output).
  - M-D-01 holds on 1ZR176 only.
  - Glantz has no 6-year column; United Congregations is not a source; Magnify is added.
  - The transfer rule is labelled interpretive.
- **XBRL.** Each Δ restates a named A posting. The export round trip is narrowed and RH is blocked. The
  census rule is stated and PCR is untested (H13).
- **Mergers.** The goodwill read-back is R, not T; consideration is C.
- **Owner decisions.** Hash-first vendoring; the decisions now gate the right items; the wording
  conflict is surfaced; new decisions 5 and 6.
- **Work breakdown.** A0, A4k, A7m, A8b, X6, E5, H11–H15 added; the dependencies re-cut.

### Z.3 Research-record errors found during round 1 (kept for the honesty record)

- **EV-040** (agy pane). Its three record excerpts occur in none of the 22 stored WorldCom texts, and its
  source path does not exist. Corrections were requested from its author.
- **Phase-4 devil's summary.** It cites BLMIS account ids not in the texts and procedure ids not in the
  registry (`cutoff.late_posting`). EV-031 shows a `Statistic` struct with `value: f64`; the code uses
  `i128`.
- **SEC ¶29.** It was applied to 1Q02 by several research items and by draft v0.
- **draft v0 itself:**
  - wrong exit codes for safety refusals;
  - nonexistent verbs (`fa book init`, `fa finding run`);
  - "legitimate look-alikes";
  - an Enron T pinned to a superseded vintage;
  - BLMIS "United Congregations" described as a complaint.

### Z.4 Round 2 inputs and changes (2026-10-25)

Round 2 had two inputs, each a fresh-context reviewer of revision 1 with read-only access to the code at
8196f5e40:
- an **architecture** review: 20 proposals, each with a diff and verified evidence;
- an **implementability** review: self-containment of 10 items, the dependency graph, justifications,
  concrete A8 example files in the TOML subset (which exposed 32 ambiguities), and acceptance tests.

Adopted:
- **Evidence and documents.**
  - K-EVID scoped to entry-level variants. Statement-level books cite the publishing filing, because
    Restatement, Revision, PPA and Migration admit no ManualAssertion (`evidence_policy.toml:239-261`).
    As written in v1, every bridge T would have been refused.
  - Citation stubs as document bytes, graded `AgentUpload` and reviewed by `case-second-reader`.
    `FA-REF-086` cells added.
  - Engagement materiality stated as zeros ("no materiality stated").
- **Claim classes and witnesses.**
  - T is an exact observation, never `proof` (`constitution.toml:17-22`).
  - The contributing-entry witness replaces fold sensitivity, which was vacuous on all-published
    bridges.
  - Kernel-attested T via `fa assert-balance` and RegisterEquals, with a `FA-REF-140` twin.
  - `recon.assertion_drift` R rows; `case diff --statements --certify`; issuance to `sec` with
    `--as-reported-in`; `gl detail --certify` and account bundles for BLMIS; optional M-T-03 migration
    tie-out.
- **Cases.**
  - A `statement` book variant per case (W-T-02 needed a 2000 calendar).
  - L-T-01 and E-T-02 rebased on statement footing; per-account read-backs re-typed R.
  - W-P-01 reachable now through draft self-promotion (`draft.rs:980-1001`). A0 adds a second encoding,
    and its design constraint is noted.
  - The XBRL duration rule.
- **Harness design.**
  - Account-VId order is an observed covariate checked relationally (Rel), not a branch. Book ids are
    random, and no seed flag is added.
  - The kernel-step table (A4k) is dropped. Premises are every encoding attribute, plus the fa-reference
    differential (A4r). The kernel order is restated with about 30 steps.
  - Tier rows keyed by (id, version, row digest), not code-closure hashes. Harness tables moved out of
    `registries/`. No new check.sh step. Generated docs added to the claims-lint scan.
  - fa-oracles allowlisted to `fa-registry` and `fa-reference`, with its own SHA-256.
  - Cell evaluation by dry run and co-residence, PostBatch filler, and the combination rule for the
    runtime budget.
  - New status Si (single under a named interpretation). New attributes `approval_encoding`,
    `capability_grants`, `acting_principal` and `account_lifecycle`; `Future` added to the period-state
    enum.
- **Schema and tooling.**
  - The book-variant schema (§3.2a): one ordered `[[step]]` array, foreign-key rows, and the TOML subset
    limits stated with their reasons.
  - `receipts.toml` generated separately; the normalization and sentence-alignment spec; the
    `xbrl-facts` and `exhibit-b` extractors.
  - Missing CLI steps added: period create and open, statement issue flags, approve → vid, finding
    export → replay, `fa verify book`, and export→import identity.
- **Work breakdown.**
  - Re-cut as a walking skeleton: an expectation whose witness is missing is UNRUN, never PASS. A8a is
    the harness self-test and the first green run.
  - Items split: A1a/b/c, A3a/b/c, A5a/b, A7a/b/c, A11a/b/c, E2a–d, M2t/a/b/c.
  - Items added: X1m, C0, E6.
  - The 17 missing edges added.
  - Positive / negative / no-claim acceptance criteria per item.
- **WorldCom details.** The F7 Saturday is visible only on an effective- or document-date branch.
  Booking dates fix commit order only. Reporting periods added. Arrow convention "A → B = Cr A, Dr B".
  role_map assigns a type and a role; OLTA has no role.
- **Wording and decisions.** Three calibration clauses plus the claim class. OD 3 gates quote text only.
  H11 moved to §14 only. H9 made a real deliverable.

Not adopted, or adopted in modified form:
- The implementability review proposed keeping a full kernel-step table (A4k) recorded in full. The
  architecture review's alternative was adopted instead: over-listing premises plus the fa-reference
  differential. Reason: maintenance cost, and fragility under concurrent edits to `post.rs`.
- The implementability review proposed `HumanUpload` stubs. The `AgentUpload`-plus-review design was
  adopted instead, because no human uploads the stubs.

### Z.5 Round 3 inputs and changes (2026-10-25)

Round 3 had three inputs:
- the independent audit of the MOR claims, whose 199 audited claims are listed below;
- a coverage and user-value review: 23 proposals, focused on under-delivery against the owner's "ALL the
  deep functionality";
- reconciliation passes on the research meta-synthesis, which corrected the `ponzi.net_investment`
  tier.

Adopted from the claim audits:
- F6 encoded as a single Reclassification is refused `FA-REF-185`, so the F6 encodings are split per
  target, Original, or Adjusting (W-N-05; round 4: the P branch cell W-P-04).
- W-T-02 and SunPower's quarterly lines are not audited. Assurance is stated per line.
- `jet.post_closing` is tier P, so W-D-05 becomes the N row W-N-06 (round 4: no N row; its X components
  render in Limits).
- **E-T-03**: Enron's "Raptor equity adjustment" equals the Powers-documented $172M + $828M
  notes-for-stock entries. It is the first T whose Δ is derived from documented entries.
- "The DPA" was later sued (SEC v. Abide, 2006), so the role-label rationale is restated.
- The Enron 8-K's EDGAR original is archived.
- `ponzi.net_investment` has no findings cap. The cap claim came from a meta-synthesis and was withdrawn.

Adopted from the coverage review:
- Registry-closed coverage (`case_coverage.toml`: every procedure and verb exercised or accounted for).
- A generated Limits section, and a normative README order with a tested transcript and FA-presented
  tables.
- **WorldCom**:
  - the native restatement W-T-03 (the $818M IS diff) and W-R-02..04, including
    `damages.attested_baseline`;
  - the post-correction false positives W-D-07/W-N-07 (H17; round 4: W-D-07/W-D-08);
  - `cutoff.period_boundary` on dated instruction documents (W-D-06);
  - the F6 allocation through a registered law (W-T-04);
  - the re-dating CF row W-P-03-CF-02 (round 4: W-P-03-CF-01).
- **BLMIS**: the `ledger` variant and the record-silent sweep over the real Exhibit B rows (§9.4).
- **Evidence and lifecycle**:
  - self-disclosure via `jet.self_sourced_evidence`;
  - the full case lifecycle with a sourced determination date;
  - Enron E5 candidates with E-D-02/E-N-03.
- **Outsider verification**:
  - the witnessed append-only restatements and certificate supersession;
  - `fa-verify` run as literal argv with `report` recomputation;
  - the ADS extract;
  - the outsider kit.
- **Checks on reads and refusals**:
  - finding → source review links;
  - refusals asserted with their structured remedy;
  - the GQL second read path;
  - `fa statement trace` as a witness.
- **Agents**:
  - the deterministic MCP walkthrough and its detectors (A15);
  - the guidance-reachability probe (A16, H16);
  - campaign measures aligned with fa-y6eu.
- **Schema**: the correction fields (`target`, `target_kind`, `reason`, `scenario`, `allocation`,
  `[[case]]`), the step kinds, and K-REASON (never `Fraud`).
- **Lehman (optional)**: a Canon backtest CF row.
- **New and changed items**: A13 (closure), A14b, A15, A16, W7–W9, X7, M0, M7, R-TRACE, H16 and H17,
  plus the external edges to fa-b6xs, fa-sa4w and fa-ipom.

#### Z.5.1 Coverage seed by procedure family (round-3 review, for A13)

"→" names where a non-exercisable capability is exercised instead. Motif and scenario names are from
`crates/fa-gen/src/lib.rs:130-136` and `:412-425`. The pairings are candidates. When A13 seeds the
coverage table (§12.2), each `covered_by` must name an existing test that actually runs the procedure,
found in the fa-lantern and fa-gen tests. The closure test checks that the named test exists.

| Family (count) | In the plan | Proposed here | Not honestly exercisable on public records (reason → where instead) |
|---|---|---|---|
| jet (13) | round_amounts, period_end_timing, post_closing, self_approved, weekend (branch) | self_sourced_evidence (P8, every variant); round_amounts and weekend on BLMIS rows (§9.4); round_amounts and post_closing after correction (§6.4 W-T-03/W-D-07); thin_descriptions on BLMIS only if row descriptions are vendored (§9.4) | unusual_accounts, unusual_preparers, manual_vs_rule: tier P, no sourced comparison population → fa-gen corpora. large_round_reversals: no sourced reversal pairs → fa-gen `RoundAmountAnomaly`. suspense_aging, intercompany_unmatched: no sourced suspense or intercompany accounts → fa-gen |
| duplicates (3) | — | same_same_same, same_same_different on BLMIS rows (§9.4) | near: needs a tolerance judgment; optional on BLMIS, else fa-gen `DuplicateSameDay/DifferentDay` |
| numbers (4) | round_amount_density only as an A11a planted negative | relative_size_factor (per party) and round_amount_density on the complete BLMIS population (§9.4) | sequence_gaps: no sourced external ids → fa-gen `SequenceGap`. threshold_splitting: no cash/CTR facts → fa-gen `SubThresholdStructuring` |
| benford (3) | only as the A11c planted negative | first_digit (and second-digit / first-two where the minimum holds) on Glantz Exhibit B rows (§9.4) | — |
| cutoff (1) | period_boundary on Enron (B) | on WorldCom F9, F10, F12 (§6.4 W-D-06) | — |
| aging (2) | — | — | open_items, inventory: no sourced open items or inventory → fa-gen `CleanRetailer`, `ChannelStuffing` |
| graph (13) | related_party_exposure, circular_flows, party_communities (Enron, conditional on E5) | sharpened E5: related_party_exposure (D) and party_circular_flows (N) (§7.2 E5/E6) | round_trips, structuring, layering, party_layering, communities, shell_signature, concentration, identity_resolution: no sourced party money flows → fa-gen `ShellNetwork`, `KitingBank`, `RoundTripKiting`. party_communities: tier P → X. ponzi_motif: population-relative over all investors; 13 accounts of thousands → X; fa-gen `Ponzi`, `PonziCohortRedemption` |
| trace (9) | — | — | No public source gives a commingled-account series together with a court's computed traceable amount. Forcing the trustee's transfer rule through `trace.libr` would mislabel the law, which is the reasoning of H5. → research R-TRACE (§12.2), else fa-gen tests |
| recon (5) | assertion_drift (R) | assertion_drift on the native WorldCom book (§6.4 W-T-03/W-D-07) | attested_register_compare: duplicates assertion_drift on attested cells (`adds_no_claim`). intercompany, lapping, bank_statement_drift: no sourced data → fa-gen `KitingBank` and bank tests |
| solvency (2) | — | — | balance_sheet_test on a statement book only reads back posted equity (`adds_no_claim`); cash_flow_test has no sourced obligations → fa-gen |
| lookback (2) | fraudulent_transfer: no claim (H5) | preferences (insider window) only if E5 sources the facts (§7.2 E5/E6) | fraudulent_transfer's insolvency badge reads book-wide running balances (`cutoff.rs:2299-2387`): tier A |
| ponzi / distribution / damages (4) | ponzi.net_investment | damages.attested_baseline as R on restatement books (§6.4 W-T-03/W-D-07) | distribution.rising_tide and pro_rata need every claimant and the pool: population-relative → fa-gen `Ponzi` |
| other singletons (6) | events.subsequent (L-N-02), expense.capitalization | — | completeness.unrecorded_liabilities, party.master_changes, payroll.ghost, reversal.patterns, confirm.coverage: no sourced population → fa-gen `GhostPayroll` and motifs |

### Z.6 Round 3b: a review by a second model family (2026-10-25)

The Gemini-family research pane reviewed revision 2 under a strict evidence rule: verbatim file:line
quotes and re-found source text. The operator re-checked every load-bearing code claim at 8196f5e40
before adopting it. All seven proposals were adopted:
1. **W-P-01(a) results by encoding.** Drafts accept only batchable classes, and draft planning rehearses
   through period law and the evidence minimum before promotion. So `FA-REF-008` under self-promotion is
   reached only on admitted Original or Adjusting cells.
2. **Staged migration chunks are invisible until finalize** (`migration.rs:594-613`), which settles A7m's
   question as a before/after test.
3. **Interop identity uses the native `fa verify export`.** `fa migrate import` has no `--format` flag,
   and M-T-03 is spelled with `--action prepare|stage`.
4. **A0's design constraints.** Sealing uses fresh entropy per JSON parse, and `FA-REF-012` arrives
   before any PostPlan exists, so A0 follows the year-end close review pattern.
5. **`fa-reference` models SoD, evidence, naive Lantern procedures and statement rendering.** That
   corrects revision 2's "does not cover approver identity", and A4r uses them all.
6. **The scenario-fork witness is dropped.** Scenario diffs are per-account, and probe intents are
   refused in closed periods. The replacement is explained balances over every account plus
   `fa_reference::statements::render`. The single-cell scope of `assert-balance` is stated.
7. **`subledger_to_gl_legs`** is registered, and F6's entry decomposition becomes a branch.

### Z.7 Round 4: steady-state consistency audit (2026-10-25)

A fresh-context reviewer audited revision 3 line by line against the code at 8196f5e40 and the stored
sources. Verdict: steady state. No architectural defect; the defects were splice debt from rounds 2–3.
All were applied:
- **Rules made consistent.** E-EVID (now K-EVID) is scoped to documented-entry and filler intents, and
  case Δs cite the restating filing; native placeholders are `fa:case-placeholder:v1` and filler cites
  `fa:case-filler:v1`; §3.2's variant lists match the chapters; the kernel twin covers single-cell
  bridges; the outsider check is per read kind; a declared default makes a component Sd only if it
  cannot decide the predicate.
- **Expectations renumbered.** W-N-05 → the P cell W-P-04; W-N-06 removed (W-D-05's X components render
  in Limits); W-D-07/W-N-07 → W-D-07/W-D-08; W-N-04 → the note W-NOTE-01 (new `[[note]]` row type);
  W-P-03-CF-02 → W-P-03-CF-01; L-T-02-CF-Canon → L-T-02-CF-01; E-T-01b → E-T-04; unnamed read-backs
  → C-R-01, E-R-01/02, X-R-01/02.
- **Encodings.** F6 is two intents, F6a (CIP → clearing) and F6b (the Allocation by `fa allocate`);
  `entry_decomposition` joins the closed enum, with F8 booked as 12 entries (p.261); W-D-06 rests on
  F10's dated draft JE only; W-T-03's inputs are one sentence of p.116; L-T-01 foots the two dates the
  Q2-2008 10-Q prints; a `delta` T kind serves E-T-03; Enron and Lehman name their book variants
  (§7.2a, §8.3a).
- **Product facts corrected.** `fa allocate` and `fa settle` already take `--approval` (A0 narrowed to
  `fa post`/`fa commit`; W5 probes F6b); fa-mcp needs an allowlist edit for its dev edge (A15); the
  claims-lint scan is split from the offline test because registry-check skips missing files (A10a/A10b).
- **Namespaces.** Work items carry their case letter (W1…W9, X1…X7, E1…E6, L1…L4, M0…M7, C0…C3) and
  checks are K-*. This appendix uses the new ids throughout.
- **Work graph.** 19 edges added (A8 ← A4r, A11a, A11c, A10a; A8a ← A7c, A11c, A4r; A11b, A12 ← A8a;
  A13 ← A12; A4r, A5a ← A7a; A6 ← A1b; W4 ← A5b, A8; W5 ← A5b, A8b; W8 ← A5b; W9 ← A1b, A11b, A12; E3 ←
  H7, A4, A11a, A11c; L4 ← M0; M7 ← A11a), with W5b, E3b and A10a/A10b split so A0 and A14 are formal
  edges. The first green T run moves from A8a to A12.
- **Self-containment.** A4r, A5a, A6, M2t, A16 and H9 now state their field maps, algorithms, values and
  gates.
