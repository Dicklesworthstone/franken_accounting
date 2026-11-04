# Complete House disbursements through native accounting

The House of Representatives' April–June 2026 Statement of Disbursements is
an authentic, detailed public accounting workload with two independently
published CSVs: transaction detail and a quarterly/year-to-date summary.
The helper downloads both complete publications, authenticates their exact
bytes, reconciles the selected organization's complete population, and builds
an explicitly declared expenditure analysis book for FrankenAccounting.

The default organization is **FISCAL YEAR 2026 CHIEF ADMIN OFCR OF THE HOUSE**.
Its complete published quarter contains **3,855 monetary records**, including
47 negative amounts, 54 additional exact duplicate records, 49 active programs,
62 budget object codes, and 1,056 blank transaction dates. Its AP, GL and AR
streams contain 2,315, 1,539 and 1 records respectively. The selected population
has **$35,800,976.43 of positive activity**, **$219,622.54 of credits**, and
**$35,581,353.89 net disbursements**.

This workload adds a separate publisher summary, mixed source streams, repeated
document references, multiple office sections, monthly effective-date routing,
and a disclosed missing-date policy to the existing
[HMRC/DWP workloads](../tools/public-data/README.md). The source adapter and
native replay are separate programs: source preparation cannot produce a
native accounting `PASS`.

## Executed end-to-end result

The complete selected population passed **118 actual native calls and all 22
runner checks**, followed by **11 actual external-tool calls and all nine
oracle checks**. The final native run took 195.898 seconds on the shared
development host. It checked 352 entries, 7,710 legs, nine explicit monthly
coordinates, 105 active account/currency cells and all source-document bytes.
Beancount 3.2.0 / beanquery 0.2.0 and hledger 1.52.4 agreed on every active
cell's net amount, separate gross debit/credit activity and posting population.

The [complete execution evidence](../evidence/public_spend/house-2026-q2-cao-native-2026-11-04.json)
retains the original result, source/preparation/helper/executable hashes, all
118 native commands and their transcript hashes, both expected refusals, the
report/checkpoint/receipt hashes, and the actual external report and commands.
Native execution used frozen `fa` and `fa-verify` from
**`68b80d4e6c916013582832626f92edb0d50be08e`**. This identifies the tested native
baseline explicitly; it does not claim that later Rust edits were executed.
The source adapter and new replay/oracle helpers have separate exact identities.
The timing is one development-host observation, not a throughput benchmark.

The [source/profile evidence](../evidence/public_spend/house-2026-q2-source-profile-2026-11-03.json)
separately retains the full publication census, source-date diagnostics,
reconciliation/refusal populations and complete selected preparation controls.
Its native status correctly remains `UNRUN`: preparation alone did not execute
FrankenAccounting. The separately linked native result records the actual
execution and its command receipts.

## Original publications and exact scope

The [House publication page](https://www.house.gov/the-house-explained/open-government/statement-of-disbursements)
describes the quarterly report and links the original downloads. The exact
URLs, bounds and hashes live in
[`house_sources.toml`](../tools/public-data/house_sources.toml).

| Original file | Bytes | SHA-256 |
| --- | ---: | --- |
| April–June 2026 detail grid | 26,169,448 | `948ea680f24c2f654263e91641df4e3a1d7b9f2b3568f701be8b62421a5c3e92` |
| April–June 2026 summary grid | 621,267 | `4828ceb94cc1dc67bbdc4faa276ef0cc0e36cbc3f4dcf0a84f9e1f54b005b28b` |

The full detail publication has 133,091 records: 123,701 transaction detail,
7,771 subtotals and 1,619 office totals. The summary has 6,812 records. Both
full originals are retained in preparation and uploaded as native evidence;
only the exact selected organization's monetary observations become analysis
postings. No prefix, sample, deduplication or silent failed-row fallback is used.

The selected organization's 4,010 detail-file records include all 3,855
monetary records, 153 printed subtotals and two office totals. All 174 selected
summary records survive separately, including categories with zero quarterly
activity and nonzero year-to-date history. Subtotal and total rows never become
additional monetary postings. Original row identity includes the publication's
SHA-256 and CSV record ordinal; identical records and repeated document IDs
therefore remain separate observations.

The source is published by the House, not created for this test. Acquisition
is bounded HTTPS to the House publisher, including redirects. The
[House terms](https://www.house.gov/terms-of-use) remain the source's terms;
this adapter does not assign the repository's code license to source records
or claim endorsement. Large source files are fetched reproducibly instead
of being embedded in Git.

### What the accounting model asserts

The publication supplies expenditure amounts, not the original double-entry
journals or a complete general ledger. Each nonzero source amount creates two
explicit analysis legs: the program/category Expense account and a labeled
Equity offset, `published-disbursement-offset`. Negative observations reverse
those sides. The offset is not an inferred cash account. No opening assets,
liabilities, accruals, original approvals or missing transactions are invented.

There are 120 declared program/category accounts and one offset account.
Of the 120 categories, 104 have actual quarter activity and 16 are retained
summary-only zero-QTD categories. No zero postings are manufactured. Up to 12
original monetary records sharing one effective date form an analysis journal;
this deterministic grouping produces 352 journals and 7,710 legs for the
default organization. It does not assert that those records belonged to one
original House journal.

Every original source field remains in `records.jsonl` and `provenance.jsonl`,
including fiscal labels, organization/program/object codes, vendor fields,
document references, service periods, original amounts and original dates.
Native leg memos identify the original source row; provenance identifies its
analysis entry and both leg ordinals. These fields are retained evidence, not
a claim that every field is a native queryable dimension.

### Dates remain explicit

A present transaction date must be a valid published date inside the quarter.
The 1,056 selected records with blank transaction dates are in the GL stream.
They receive **2026-06-30 solely as the analysis effective date**. Their original
blank field, service-period dates and date-policy label are retained unchanged.
Service dates never replace transaction dates, and undated payroll is not
distributed across months by inference.

The monthly controls are therefore scoped analysis results:

| Cumulative analysis cutoff | Positive activity | Credits | Net expenditure |
| --- | ---: | ---: | ---: |
| 2026-04-30 | $2,787,112.01 | $31,896.20 | $2,755,215.81 |
| 2026-05-31 | $5,503,026.77 | $137,551.64 | $5,365,475.13 |
| 2026-06-30 | $35,800,976.43 | $219,622.54 | $35,581,353.89 |

The large June change includes the explicit assignment of undated GL activity;
it is not a reconstruction of the office's monthly economics. The native
FullDetail migration opens on 2027-01-01 and checks April–December period
controls. Its `FY2026-P04`–`P12` labels are calendar-month analysis periods,
not an assertion about the House's original fiscal-period numbering.
July–December carry only the loaded Q2 population. They do not assert
that the real organization had no later activity.

## Independent controls before native writes

The adapter parses the exact original dollar literals into integer cents and
independently folds them with `Decimal`. It reconciles every selected category,
program and office section against both its inline printed control and the
separate summary CSV. Repeated labels across office sections remain distinct;
ambiguous duplicate controls within a section are refused.

The default organization passes **174 publisher controls**: 120 category,
52 program and two office controls. The two printed office totals are
$33,719,312.93 and $1,862,040.96. Quarterly net controls come from the summary's
**QTD AMOUNT** column; **YTD AMOUNT** is retained but never substituted. Gross
debits and credits come from an independent fold of the original detail.
Zero-net accounts with actual activity remain part of the gross comparison.
Only the native net-trial-balance declaration omits zero-valued lines, as
required by its wire contract.

`verify_prepared()` regenerates every preparation artifact from both pinned
originals and compares every byte and the exact file population before the
native runner creates a book. Changing a normalized amount and its balancing
counterpart, dropping equal offsetting legs, editing a date or row identity,
or modifying a preparation receipt cannot be accepted merely because the
modified CSV remains balanced.

### Full-publication profiling keeps refusals visible

`profile` reports all 1,148 organization labels present in either publication.
For this source, 534 labels pass all publisher reconciliation controls and 614
are explicitly refused by the reviewed adapter: 610 are absent from one of
the publications' scopes, two have mismatched office-section populations,
and two have ambiguous control structures. These are scope/structure refusals,
not findings of accounting error or fraud. The profile does not claim native
execution of every admissible organization.

The full publication also includes three transaction dates outside the quarter
and two malformed service dates, `14-MAR-0026` and `17-MAR-0026`. Their original
row identities, fields and literals are explicit profile diagnostics. They do
not occur in the selected CAO population. Malformed service dates remain
unparsed evidence; an out-of-quarter or malformed transaction date in a selected
accounting population is refused rather than silently redated.

## Fetch, inspect and prepare

Python 3.11+ is sufficient for acquisition and source preparation; the helper
uses only the standard library. From the repository root:

```bash
python3 -B tools/public-data/house_disbursements.py fetch \
  --out /tmp/fa-house-source

python3 -B tools/public-data/house_disbursements.py profile \
  --detail /tmp/fa-house-source/raw-detail.csv \
  --summary /tmp/fa-house-source/raw-summary.csv \
  > /tmp/fa-house-profile.json

python3 -B tools/public-data/house_disbursements.py prepare \
  --detail /tmp/fa-house-source/raw-detail.csv \
  --summary /tmp/fa-house-source/raw-summary.csv \
  --out /tmp/fa-house-cao

python3 -B tools/public-data/house_disbursements.py verify \
  --prepared /tmp/fa-house-cao
```

An exact alternative `--organization` may be supplied to `prepare`, `verify`
and the native runner; unsupported populations fail explicitly. Acquisition
checks pinned byte counts, complete-file hashes and full-publication census.
Preparation retains both originals, selected records, summary records,
provenance, chart, mapping, import CSV, all controls and a manifest of every
artifact. Repeating an identical preparation is safe; differing existing bytes
are not overwritten.

## Run the real accounting pipeline and external engines

Build the repository's actual binaries with its pinned Rust toolchain:

```bash
cargo +nightly-2026-08-31 build --locked -Z bindeps -Z git=shallow-deps \
  -p fa-cli --bin fa -p fa-verify --bin fa-verify

python3 -B scripts/house_disbursements_replay.py \
  --prepared /tmp/fa-house-cao --out /tmp/fa-house-cao-native \
  --fa target/debug/fa --fa-verify target/debug/fa-verify
```

`--out` must be new. Each native command has a configurable `--timeout`
(300 seconds by default); it is not a total workflow deadline. Native grouped
approvals and evidence are enabled; `--stage-group-size` defaults to 64 and an
optional `--fad /absolute/path/to/fad` selects daemon transport. Fixture reviewer
roles exercise the two-principal mechanics, not independent human examination.

The runner authenticates the source preparation, then checks the following
actual operations:

1. Upload, review and read back every retained source document byte for byte.
2. Open a FullDetail migration against all nine period controls. Attempt a
   balanced one-cent alteration of a real source observation; require refusal
   against the independent controls without publishing history or staging rows.
3. Prepare and bind the complete normalized source population. Compare every
   prepared leg and its effective date, then require an exact no-write retry.
4. Stage every approved journal, attach original source evidence, verify exact
   retry receipts and prove staged activity remains invisible.
5. Finalize the entire population at one native publication. Check all monthly
   gross/net balances, pre-finalization historical invisibility and registers.
6. Reopen terminal preparation/staging requests and preserve their identities.
7. Export CSV, Beancount and hledger at one effective/known-at coordinate.
   Compare every CSV leg's source lineage, ordinal, date, account, side, exact
   amount, description and memo; verify each native export certificate.
8. Certify and replay the quarter report, produce a source-bound portable proof,
   verify it with the separate `fa-verify` executable under the retained test
   checkpoint key, and refuse a deliberately damaged proof. Its authenticated
   prefix and balance checks follow FA-INV-14.seq-range-complete and
   FA-INV-04.outsider-recomputation.

Every trial-balance response must identify the exact requested book, period,
effective cutoff, stock mode and known-at prefix. Equal amounts at different
dates are insufficient, including the months that carry identical Q2 activity.
The runner hashes its helpers and every prepared artifact before native
execution and refuses success if those bytes change during the run.

All command arguments, exits, stdout/stderr and executable identities are
retained alongside `result.json`. A missing executable is `UNRUN`, and any
failed check is `FAIL`; source preparation cannot stand in for native success.
The proof authenticates the resulting analysis book under its trusted local
key under FA-INV-14.seq-range-complete, not a House-signed or audited set of
accounts.
The standalone verifier checks the normalized 7,710-row migration witness and
native report; the source adapter separately reconciles the 3,855 original
publisher observations to the House's printed controls. `fa-verify` does not
independently parse the House's CSV publication format.

Install the real external tools as described in the
[plaintext comparison guide](conformance/plaintext-external-oracle.md),
then compare the three untouched, same-coordinate native exports:

```bash
python3 -B scripts/plaintext_oracle.py \
  --csv-gl /tmp/fa-house-cao-native/native.csv \
  --beancount /tmp/fa-house-cao-native/journal.beancount \
  --hledger-journal /tmp/fa-house-cao-native/journal.hledger \
  --out /tmp/fa-house-cao-oracle
```

`bean-check` validates Beancount syntax and assertions, `bean-query` calculates
exact net/gross amounts and posting counts, and hledger independently reports
parsed postings and balances. Original account codes come from explicit
metadata, never from reversing sanitized names. A native self-round-trip alone
is insufficient to establish agreement with these external engines.

## Focused regression tests

```bash
python3 -B -m unittest discover -s tools/public-data/tests \
  -p 'test_house_disbursements.py' -v
python3 -B -m unittest discover -s scripts/tests \
  -p 'test_house_disbursements_replay.py' -v
```

Small fabricated inputs in these unit tests are labeled as negative controls;
they are not publisher evidence. They exercise repinned one-cent summary and
subtotal mutations, missing/repeated controls, duplicate record preservation,
malformed dates, zero-net gross activity, balanced missing legs, exact retry,
source drift, wrong exported currency/class and changed lineage. The real
publication and native execution are additional, separate checks.
