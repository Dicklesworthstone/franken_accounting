# Real public GL activity: Oklahoma FY2024 Q4

This workload exercises the existing retained-source migration path with a
complete agency population from Oklahoma OMES's published general ledger. It
complements the Enron, WorldCom, Lehman and XBRL reconstructions described in
[the forensic case plan](FORENSIC_CASE_STUDIES_PLAN.md). It does not represent
any of those companies' undisclosed accounting ledgers.

The broader [public-ledger replay workflow](public_ledger.md) covers three
other complete agencies and continues through ADS proof export and independent
verification. This workload adds a separate, tightly pinned Development
Finance Authority population, original byte-offset lineage, and a native Rust
integration regression that imports all 104 balanced groups in one migration
run. Both workflows preserve the source's actual aggregate granularity.

## Source and exact scope

Publisher: **State of Oklahoma, Office of Management and Enterprise Services
(OMES)**. The [official Data.gov catalog](https://catalog.data.gov/dataset/general-ledger)
lists the general-ledger resources and the Creative Commons Attribution
license. The pinned resource is
[LEDGER_FY24_QTR4.csv](https://data.ok.gov/dataset/dd1ecf41-4abc-4886-ab0f-b84d7662d8d4/resource/0c2a7e42-610e-4f1d-826f-f6b267fba68a/download/ledger_fy24_qtr4.csv).
Attribution for the retained extract: Oklahoma OMES; selection, transcoding,
normalization and the reconstruction described here are FrankenAccounting's.

The complete downloaded file is 113,856,733 bytes and contains 373,357 data
records, 36 columns, 170 business units and 908 account codes. Its SHA-256 is:

```text
141e2d5524f6aa9d25c7331bc56f623f43da9a1f00cdfee42b7c5f3ccf6fc0fe
```

The committed fixture is **every record with BUSINESS_UNIT = 90000**,
DEVELOPMENT FINANCE AUTHORITY, in that file: 312 rows, including six zero
amounts, across April–June 2024. It is not a sample of convenient transactions.
The 94,945-byte selected source has SHA-256:

```text
146940518122397bf9b66f92fa06b8b7a1cb15e58ae8c0cf0e42584933a1f64c
```

The selected records retain all 36 original fields. The adjacent
`source_rows.csv` binds each selected record to its original record number,
byte offset, byte count and SHA-256 in the complete public resource. Selection
requires a verified complete-file hash; the offline fixture requires its own
pinned hash and the pinned row index. An upstream revision is a source-review
event, not a reason to regenerate expected output automatically.

## What the data can and cannot establish

The source column is `SUM(L.POSTED_TOTAL_AMT)`. Its rows are **monthly
chartfield-level signed activity aggregates**. The file does not disclose
original journal IDs, transaction dates, preparers, approvals, source invoices
or the opening trial balance. These are not fabricated.

The adapter constructs explicitly identified balanced groups using business
unit, ledger, fiscal year, accounting period, fund and class funding. All 104
selected groups balance exactly without a plug. Each of the 306 nonzero
source rows remains a separate signed posting leg; equal account codes are
not collapsed together. The six zero rows remain in the retained source and
manifest, but do not become invalid zero-amount monetary legs.

The derived date is the last day of the source's reporting month. Oklahoma
FY2024 periods 10, 11 and 12 map to April, May and June 2024. The analysis book
uses calendar periods FY2024-P04, P05 and P06, with those original fiscal
periods retained in the manifest. The broader replay driver instead uses
Oklahoma's July fiscal calendar and labels these months FY2024-P10 through
P12; the differing analysis period codes are intentional. Neither these dates
nor the reconstruction IDs are represented as original transaction attributes.

The isolated analysis book starts from **zero at the beginning of the
selected activity window**. Consequently, its stock balances mean accumulated
Q4 activity; they are not the authority's actual balance sheet. The
`FullDetail` migration protocol is used for source retention, independently
approved staging, exact tie-out and atomic activation. That protocol name
does not upgrade the granularity of the public records.

The [OMES Statewide Accounting Manual, chapter 3](https://oklahoma.gov/content/dam/ok/en/omes/documents/statewide-accounting-manual-UA.pdf)
describes the chartfield structure and account prefixes. This workload uses
the following explicit mapping, not an account classifier that guesses at
runtime:

| Published account | Source description | Analysis-book type |
| --- | --- | --- |
| 101000 | Cash - Combining Trial Balance | Asset |
| 416101 | Personal Income Tax | Revenue |
| 548110 | Principal Payments-Bond Debt | Expense, representing the published fund expenditure |
| 548130 | Other Expenses-Bond Debt | Expense, representing the published fund expenditure |

The expenditure mapping is not an assertion that debt-principal repayment is
an accrual expense. The fixture exercises the source's fund-activity
presentation. Other chartfields remain recoverable through the source-record
references and retained source, but are not yet native queryable dimensions.

## Reproduce acquisition and preparation

From the repository root, with Python 3.11 or newer:

```bash
python3 -B tools/public-data/oklahoma_gl.py --help
python3 -B tools/public-data/oklahoma_gl.py prepare \
  --source crates/fa-oracles/data/oklahoma/source.csv \
  --output /path/to/new-oklahoma-package
```

To acquire the full public resource and prepare the same population directly:

```bash
python3 -B tools/public-data/oklahoma_gl.py fetch \
  --output /path/to/new-ledger-fy24-q4.csv
python3 -B tools/public-data/oklahoma_gl.py prepare \
  --source /path/to/new-ledger-fy24-q4.csv \
  --output /path/to/another-new-oklahoma-package
```

The downloader identifies itself as FrankenAccounting, permits public HTTPS
acquisition, bounds the download and checks the exact expected size and
SHA-256. It does not overwrite an existing destination. A failed or changed
download is not an accepted fixture.

The complete-file and offline-fixture
paths must produce byte-identical packages. Preparation is streaming over
the large file and retains only the declared agency population.

A package contains:

- `source.csv`: the complete selected source population.
- `legacy.csv`: exact signed amounts and source-record references, ready for
  the existing generic legacy CSV reader.
- `column_map.toml`: explicit source, account, amount, date, description and
  memo columns.
- `chart.json`: the four explicitly mapped analysis accounts.
- `manifest.json`: source identity, selection, row lineage, all transform
  choices, exact monthly controls, and hashes of the generated outputs.

Windows-1252 decoding is strict and UTF-8 output is explicit. No replacement
characters, floating-point amounts, rounding, inferred balancing accounts
or silent missing-row recovery are permitted. The state-wide census includes
20 fractional-cent amount cells. USD has scale two here; those values require
an explicit future precision/rounding policy and must be refused if they
enter the selected population. They are not silently rounded.

## Run the real engine

```bash
python3 -B -m unittest discover -v -s tools/public-data
cargo test -p fa-formats legacy::tests --lib
cargo test -p fa-formats --test formats_conformance \
  canonical_csv_round_trip_preserves_quoted_source_text
cargo test -p fa-cli --test legacy_migration public_oklahoma_activity \
  -- --nocapture
```

The last test is the executable import recipe. It prepares the source
package, creates a separate persisted book, imports the chart and periods,
retains source/manifest/normalization documents, declares the independently
computed period controls, and uses the actual CLI to prepare all migration
chunks. Two distinct fixture principals approve each exact proposal. The
test reopens the book between commands.

It then exercises the following meaningful failure and recovery boundaries:

1. A duplicated source remains double-entry balanced but disagrees with the
   independent period controls; preparation must refuse without publishing.
2. All 104 chunks stage durably while ordinary trial balances remain empty.
3. An exact retry returns the original result without another publication.
4. Independently approved finalization activates the staged history.
5. Every monthly account movement and cumulative balance agrees exactly
   with the source controls, including negative cash and expenditure credits.
6. Register verification agrees with journal folds.
7. A certified trial balance can be reopened and replayed with identical
   report data, without publishing another entry.
8. A known-at coordinate before finalization remains unchanged afterward.

The test principals belong only to this isolated development fixture. They
do not authenticate the publisher's accounting or stand in for real reviewer
credentials.


## Resume an interrupted complete-agency replay

The broader [complete-agency driver](public_ledger.md) now supports resuming
its persisted native book on a POSIX filesystem with advisory file locking. This applies to `scripts/public_ledger.py run`;
the separate 90000 preparation helper and Rust regression above keep their
existing interfaces.

For example, start the complete firefighters pension workload with the real
binaries and a new output directory:

```bash
python3 -B scripts/public_ledger.py run \
  --agency 31500 \
  --fa /path/to/fa \
  --fa-verify /path/to/fa-verify \
  --out /path/to/pension-replay
```

After an interruption, continue that same book:

```bash
python3 -B scripts/public_ledger.py run \
  --resume --out /path/to/pension-replay
```

Resume defaults to the original agency, source path and executable paths.
An explicit replacement path is admitted only when its bytes satisfy the
original pins. The driver checks the original source, each regenerated chart
and normalized source artifact, its own normalization code, the Python
version, and both executable hashes before continuation. A changed source,
mapping, retained input, binary or model is refused; it does not become a
new import into an old book. Use a separately reviewed new run for a changed
model or source, preserving the original run and its evidence.

The driver saves the actual native book ID before chart, document or
financial work and verifies that identity on every resume. A missing book,
another book at the same path, an abandoned migration or a native package
outside the declared source population is refused. If genesis committed but
the process died before saving its book ID, the helper refuses to adopt the
unidentified book. No schema or financial work can yet have started in that
window. Existing outputs from older driver versions without recovery pins
are also preserved and refused, rather than silently adopted.

Recovery uses the native journal and retained package inventory. A helper
transcript or a cached completed-row count cannot establish that a posting
happened.

| Interruption boundary | Continuation |
| --- | --- |
| Chart, department, period or evidence setup | Reissue the same native identity-bound requests. The native implementation returns the original chart controls, value IDs, fiscal-year creation, document custody and review attestations. |
| Migration open response lost | Inspect the deterministic native run key, then retry the identical retained declaration. |
| Preparation response lost | Discover the original native package through the document inventory and authenticate it with native package inspection. Compare its full source-row proposals, source identity and import configuration before staging. |
| Group staging stops after some publications | Read each original chunk's VID, proposal digest and recorded sequence from the native package. Reuse retained approval IDs and accept a mixture of recorded retries and new chunks only when each receipt matches its original membership. A group remains several native publications, not one atomic transaction. |
| One fund finalizes before another | Keep the original known-at snapshot taken after all chunks staged and before any activation. Check empty net **and gross** balances at that same snapshot; do not substitute the partially activated current head. |
| Approval or finalization response lost | Reuse the exact sealed finalization proposal saved durably before approval, and the original approval IDs saved before commitment. Native idempotency resolves whether commitment already happened. |
| Export or verifier interruption | Preserve the incomplete attempt and rerun all source reconciliation, exports and independent verification in a new attempt directory. |

`recovery/` retains checksummed immutable inputs, native book identity, exact
finalization plans and the original preactivation snapshot. Checkpoints are
synced before atomic exclusive publication; interrupted temporary files are
kept for investigation and never treated as authoritative. An advisory lock
prevents two copies of the helper from continuing the same run concurrently.
The checksum detects damaged helper files; the native journal and its
authenticated packages remain the authority for accounting state.

The relevant retry contracts live in native [chart installation](../crates/fa-journal/src/genesis.rs),
[period creation](../crates/fa-journal/src/period_creation.rs),
[dimension controls](../crates/fa-journal/src/dimension.rs),
[document custody and attachment](../crates/fa-journal/src/evidence.rs),
[review attestations](../crates/fa-journal/src/attestation.rs), and
[approvals](../crates/fa-journal/src/policy.rs). Approval identity includes the
security policy epoch; this isolated workload does not change that policy.
Already retained staging and finalization approval IDs are reused exactly.

Each `attempts/000001/`, `attempts/000002/`, and subsequent directory holds
its own command transcript, exports, tamper controls and failure or success
report. Existing partial exports are not overwritten. The top-level
`report.json` is published only after a complete successful native run,
including independent ADS proof verification with dimension coverage and
amount-only and dimension-only negative controls. Resuming a completed run
refuses and points to that existing report.

The resume tests cover source/model/binary mismatch, a directory-creation
race, lost setup and approval acknowledgements, native package discovery,
mixed old/new chunk receipts, immutable snapshot reuse, and checkpoint
failure before approval. Their mocked call contracts are unit tests; they
are not native crash-recovery evidence. These new tests were **UNRUN** in
the development session because the execution environment became unavailable.
Persisted native interruption acceptance remains unverified and must not be
reported as passing merely because a helper test or source oracle passes.


## Independent controls

The Python helper computes exact integer-cent controls directly from the
retained raw rows. Its tests also compare an independently written Decimal
fold with the normalized legs and pin the following source observations.
The Rust test does not obtain expected balances from FrankenAccounting's
own output.

| Source period | Raw rows | Nonzero legs | Balanced groups | Debits = credits |
| --- | ---: | ---: | ---: | ---: |
| April 2024 / FY24 period 10 | 144 | 138 | 38 | $23,014,215.04 |
| May 2024 / FY24 period 11 | 86 | 86 | 33 | $7,806,285.75 |
| June 2024 / FY24 period 12 | 82 | 82 | 33 | $7,777,114.23 |
| Total | 312 | 306 | 104 | $38,597,615.02 |

The final accumulated activity is cash $5,565,766.76; revenue
-$21,898,252.44; principal expenditure $16,352,485.68; and other bond
expenditure -$20,000.00, with debits positive. The four signed balances sum
to exactly zero.

These are independent implementation comparisons and exact read-backs from
a documented construction. They are not independently published closing
trial balances, an audit opinion, proof that the public export contains every
transaction in the state's system, or evidence that an anomaly is fraud.

## Validation status

The pinned official distribution and complete-agency selections have independent
source checks. The Development Finance Authority helper has 18 offline tests;
the integrated public-ledger/source suites now have **79 passing Python tests**,
including the 18 recovery tests. Constructed native-shaped payloads remain unit
fixtures; the native results below are separate actual executions.

The complete Development Finance Authority integration now passes: **312 source
rows, six retained zero rows, 306 monetary legs and 104 reconstructed monthly
entries**. Duplicating the complete balanced source is refused for the exact
independent FY2024-P04 trial-balance mismatch, with the observed native frontier
unchanged at 20. It cannot pass this negative control merely by returning an
unrelated usage error. This case is included in the actual **40/40** passing
native migration integration target. The formats library and conformance targets
also passed **78/78** and **28/28** tests. The
[native-target record](../evidence/public_ledger/native-tests-2026-11-03.json)
binds those counts to logs and the two corrected test-source blobs.

Fresh actual processes built from `93714f77` completed these workloads:

| Complete selection | Source rows | Monetary legs | Accounts | Migration entries | Native department values | Outcome |
|---|---:|---:|---:|---:|---:|---|
| 20400 museum | 125 | 121 | 43 | 15 | 3 | PASS |
| 31500 firefighters pension | 137 | 131 | 51 | 6 | 3 | PASS after two deliberate interruptions |
| 66000 university | 1,055 | 1,051 | 223 | 27 | 8 | PASS |

The [current native evidence](../evidence/public_ledger/validation-2026-11-03-93714f77.json)
records source and executable hashes, each completed check, complete-report and
ADS-package hashes, caller-trusted fixture public keys, and original recovery
receipts. All three actual ADS packages verify independently; their monetary
and dimension-only mutations each return verifier exit 8. Native department
reports preserve exact gross/net amounts and replay their certificates. These
results extend the earlier account-only runs with grouped staging, native
department attribution, dimension-aware export proofs and recovery.

### Reproduce the controlled recovery boundaries

`public_ledger_interrupt.py` calls the actual native commands and stops at a
declared boundary. It does not fabricate a response or simulate a transaction
crash. First it posts only the first member of the saved group; the second
attempt stops just after the first real finalization commits. Each of these
two commands intentionally returns driver exit 1. The ordinary final resume
must exit zero and produce the complete `report.json`.

```bash
python3 scripts/public_ledger_interrupt.py \
  --driver scripts/public_ledger.py --boundary partial-stage \
  --marker /tmp/pension-stage-stop.json -- \
  run --agency 31500 --out /tmp/pension-recovery \
  --fa /absolute/path/to/fa --fa-verify /absolute/path/to/fa-verify

python3 scripts/public_ledger_interrupt.py \
  --driver scripts/public_ledger.py --boundary after-finalize \
  --marker /tmp/pension-finalize-stop.json -- \
  run --resume --out /tmp/pension-recovery

python3 scripts/public_ledger.py run --resume --out /tmp/pension-recovery
```

Use new output/marker paths and retain the original source, helper and binary
pins across attempts. The executed campaign preserved the first chunk's VID,
proposal digest and CommitSeq 40, and the first finalization's control-entry ID
and CommitSeq 60. The final resume returned those original receipts without
another monetary publication and used the original all-staged invisible prefix,
CommitSeq 57, for historical checks. Both failed attempts and their genuine
native responses remain retained. The final report's duration and command count
describe its final attempt only, not the whole three-attempt campaign; read-only
recovery preflight calls precede per-attempt transcript creation.

The [public-ledger workflow](../.github/workflows/public-ledger.yml) runs the
source and native acceptance commands where the required execution environment
is available. The restored session could not bind Unix sockets, so daemon
socket regressions failed before serving; direct CLI native executions above
did complete. Full workspace Tier0 remains unpassed after a compiler SIGKILL.
These scoped native results do not constitute a repository-wide release gate.

## Remaining high-value work

The broader OMES driver now projects nonblank department, fund, product and
project codes into their corresponding native dimensions and keeps source
blanks untagged. The four-account Development Finance Authority helper described
here retains its other chartfields as evidence without projecting them. Class
funding and program have no established native dimension mapping; neither
driver invents one. The [complete-chartfield execution record](../evidence/public_ledger/validation-2026-11-03-entry-fragments.json)
separates successful museum/pension execution from the university storage
failure and acceptance of the large-Entry repair.

Grouped native staging and resumable orchestration reduce repeated intake and
preserve completed chunk publications. The full university dimension vector
exposed a 157-leg Entry above the native row limit; the
[authenticated fragment implementation](public_ledger.md#preserve-large-entries-without-losing-source-detail)
preserves that single Entry and every original leg. Its runtime acceptance is
recorded separately. Million-line bulk migration acceptance (`fa-zddh`) remains
open. Import
preparation now offers an explicit `--bind-source` opt-in that binds an
immutable native manifest before staging. For a bound run, finalization
requires every proposal in the retained package in addition to the declared
trial balances. Omitting an increase and its exact reversal causes refusal
even when net controls agree. Default preparation remains unbound, and already
staged or terminal unbound runs cannot acquire a retrospective binding. The
historical evidence above is unchanged. The driver still checks every source
chunk and gross activity against the original source: package membership does
not independently establish the CSV transformation or the source's economic
truth. See [source-bound migration completeness](migration_source_completeness.md)
for the native and independent proof boundaries.

Broader source coverage also needs a declared treatment of fractional cents
and separately sourced opening/closing controls. Other agencies' funding
groups can be unbalanced even when the agency-period total balances. The broader
driver now accepts an explicit
[`--balance-boundary agency-period`](public_ledger.md#whole-agency-activity-across-fund-and-class-boundaries)
choice that retains those nonzero funding controls and every original source
leg in one reconstructed monthly Entry. It still refuses an unbalanced whole
month, subcents and over-limit Entries, and never invents a balancing leg.
The complete Health Care Authority fixture exercises this distinction with
1,440 real rows and 1,405 monetary legs. Native acceptance is reported separately
from source normalization and these documentation statements.

The [BLMIS Glantz transaction workload](blmis_glantz_workload.md) provides a
complementary route to actual published bankruptcy-case transactions and
printed running-principal controls. Its acquisition, source validation,
accounting interpretation and native execution have their own evidence
boundaries. Neither workload relabels a monthly aggregate or a statement
reconstruction as an undisclosed corporate transaction ledger.
