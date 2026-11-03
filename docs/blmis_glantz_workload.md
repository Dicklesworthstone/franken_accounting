# Published BLMIS transaction history: Glantz Exhibits B-1 through B-6

This workload has two explicit source scopes. The default retains every
published row of account **1ZA192** in Exhibit B-2: 75 observations dated
December 7, 1992 through October 30, 2008. The new `--account all` mode acquires
and processes **all six Glantz Exhibit B accounts**, retaining 379 dated
observations, including seven transfers with zero credited principal. Their
372 monetary rows produce 744 native analysis-book legs.

Both scopes use the original hash-pinned trustee PDF. These are published
customer-account computations from a complaint, not the original BLMIS
firm-wide general ledger. They add dated real-case records and independently
printed controls to the [public-sector activity workloads](public_ledger.md).
The [forensic case plan, section 9](FORENSIC_CASE_STUDIES_PLAN.md#9-case-m--madoff--blmis-trustee-ledgers)
describes the broader three-complaint, thirteen-account program. This extension
does not complete that program or close its M0-M7 beads.

## Complete six-account ingestion and native replay

The full mode reads PDF pages 27-40. It retains every displayed column, printed
amount literal, source line and page, row hash, footnote marker, and independently
printed footer. A fresh source census found **379 dated rows** in these six
accounts. The earlier plan's 1,429 Glantz total is a source-count discrepancy,
not a population target to fill with synthetic records.

| Source account | PDF pages | Dated observations | Native monetary entries | Running principal compared with printed cells |
|---|---|---:|---:|---|
| 1T0026 | 27-30 | 117 | 112 | Exact given the trustee's credited transfers |
| 1ZA192 | 31-33 | 75 | 74 | Exact given the trustee's credited transfers |
| 1ZB010 | 34-35 | 61 | 61 | Exact under the explicitly named same-day display rule |
| 1ZB143 | 36-37 | 51 | 50 | Exact given the trustee's credited transfers |
| 1ZR010 | 38-39 | 57 | 57 | Source movements end $9 above the printed principal; 50 rows differ |
| 1ZR176 | 40 | 18 | 18 | Source movements are $1 below printed principal on rows 6-17, then close exactly |
| **Total** | **27-40** | **379** | **372** | **All differences remain visible; no balancing plugs** |

The original 75-row B-2 fixture remains code-pinned and available offline.
The new six-account mode prepares its rows from the verified original PDF in
the current invocation. It does not claim that a newly calculated row hash was
a previously reviewed repository fixture. Preparation records the exact
extraction and generated-byte hashes. Loading a prepared six-account package
re-extracts its pinned original and compares every regenerated source and
normalization file; a caller-provided checksum sidecar is insufficient.
The B-2 slice must also reproduce both existing code-owned fixture pins.

The source has several details that a simple amount/date loader would lose:

- Six transfer footnote markers are detached superscripts on their own
  extraction lines. Their positions and hashes are retained separately.
  A reported-amount asterisk on 1ZR176 has its own note semantics; it is not
  silently converted into the transfer-credit rule.
- On 1ZB010, the 2006-10-17 CHECK and STOP PAYMENT rows are printed out of the
  order used by their balances. `same_day_display_reorder` swaps only that
  specifically identified pair for computation; the raw display order remains
  in the evidence. The source does not identify the stopped check, so the
  helper creates no invented reversal lineage.
- STOP PAYMENT is **+$25,000 in the Withdrawals column**. It is a positive cash
  movement. The native gross cash flows for 1ZB010 are therefore $1,245,000 in
  and $1,552,500 out, while the printed deposit/withdrawal column totals are
  $1,220,000 and -$1,527,500. Both have the same net; the driver checks the
  signed gross movements explicitly.
- On 1ZR010, displayed deposits sum to $5,979,193 while the printed deposit
  footer is $5,979,184. The nine-dollar difference remains a source diagnostic.
  On 1ZR176, intermediate one-dollar differences remain diagnostics even
  though the closing balance agrees.

### What the native six-account driver checks

The driver creates six declared Equity analysis principal accounts and six native
counterparties, with one shared cash account and one explicitly marked
principal-transfer clearing account. Only a principal leg receives its source
account's native party tag. No customer or subsidiary identity is inferred
from an account holder's name.

Native investor analysis classifies these principal accounts by their declared
Equity type. The explicit `investor_capital` role is reserved for Liability
accounts; the driver verifies the native chart's exact types, currencies and
leaf accounts instead of assigning an incompatible role. Cash receives its
`cash` role immediately. The transfer-clearing role is assigned only after the
missing-transfer-role comparison below.

Every monetary source row posts separately in its declared computation order.
Every native leg, amount, effective date, commit receipt and party identity is
checked against the original source. The driver requests and replays an exact
certified general ledger for each account. Detail replay returns the identical
report line followed by a `report_replayed` verification receipt; the driver
checks the receipt's book, certificate, coordinate, report family, known-at and
output digest as well as the report bytes. It checks the pre-posting historical
prefix, retries every entry without new history, and reconciles all annual
account controls. For the two inconsistent accounts it requires the exact
observed discrepancy at every affected row. `PASS` means the native book
reproduces the source movements and exposes those discrepancies; it never
means that all of the trustee's printed cells are arithmetically exact.

There are 17 transfer rows. Two reviewed transfers have both account histories
in this complaint:

| Date | Origin → recipient | Reported transfer | Certified originating principal before transfer | Recomputed credited principal |
|---|---|---:|---:|---:|
| 1993-10-20 | 1ZA192 → 1ZB143 | $4,000,000 | $4,855,000 | $4,000,000 |
| 2005-12-23 | 1ZB143 → 1ZA192 | $200,000 | -$4,854,688 | $0 |

The separately named interpretive rule `trustee_transfer_credit` computes
`min(reported_transfer, max(originating_principal, 0))`. The driver obtains
the originating balance from the certified native ledger, after checking that
ledger against every original source movement. It preserves aliases such as
`TRANS TO 1Z314330 (1ZB143)` exactly; only the explicitly printed
parenthetical identifier identifies the counterpart in these reviewed pairs.
The other **13 transfer rows** retain trustee-credited principal as explicit
oracle inputs. No absent originating history or additional pair is fabricated.

`ponzi.net_investment` v5 is compared across all six accounts before and after
assigning the transfer role. Gross cash and principal transfers remain separate;
cohorts use their first actual inflow; all six nonzero account outcomes must be
present. Account 1ZR176 closes with principal of -$2,817,965 and a zero source
reconciliation gap; it does not have zero principal. The earlier missing-role result must remain
unchanged at its original recorded prefix. The source's nine-dollar closing
difference is exposed in the account comparison, not silently rounded away.

Finally the driver checks native registers against folds, projections, source
document custody, a signed accumulator checkpoint, all **744 CSV/ADS legs**,
all six actual native party-value identities, and independent ADS
accumulator proof verification. The standalone verifier must reject both a one-cent mutation
and a party-only mutation. The PDF, raw extraction layout, source records,
normalization manifest and extraction receipt are retained as native evidence
with explicit self-sourced AgentUpload custody and distinct local fixture
reviewers. Those reviewers are not independent human auditors.

### Run the complete source

Python 3.11+ and Poppler's `pdftotext` are required. Source preparation needs
no accounting executable; native replay additionally needs the pinned `fa`
and `fa-verify` builds.

```bash
# Verify the original bytes, extract all six accounts, and prepare the analysis.
python3 -B scripts/blmis_source.py prepare --account all \
  --output /path/to/new-glantz-six-package

# Re-extract the original and verify all retained/generated package bytes.
python3 -B scripts/blmis_source.py verify --account all \
  --source-dir /path/to/new-glantz-six-package

# Run source-comparator tests against the acquired original.
FA_BLMIS_GLANTZ_PDF=/path/to/new-glantz-six-package/source.pdf \
  python3 -B -m unittest discover -s scripts/tests -p 'test_blmis*.py' -v

# Acquire/verify, normalize, post, certify, replay and independently verify.
python3 -B scripts/blmis_replay.py run --account all \
  --pdf /path/to/new-glantz-six-package/source.pdf \
  --out /path/to/new-glantz-six-native \
  --fa /path/to/fa --fa-verify /path/to/fa-verify
```

Each preparation/replay destination must be new. The optional
`--pdf /path/to/original.pdf` on preparation avoids a download while still
verifying and extracting the original. Without `FA_BLMIS_GLANTZ_PDF`,
the new full-source comparator tests explicitly skip their unavailable source;
those skips are not evidence that extraction or native replay passed.

### Observed native validation (2026-11-03)

The complete PDF-first six-account command **exited 0 with `PASS`** after
1,268 native commands in 415.270 seconds. It used frozen native binaries built
from `93714f772a6279c0ea233841d1d51dbe096d9ff1` and the helper hashes recorded
in the [compact execution evidence](../evidence/blmis/glantz-six-native-2026-11-03.json).

| Check | Observed result |
|---|---|
| Original exhibit population | All 379 observations, including seven zero-principal rows |
| Native monetary history | 372 entries, 744 legs; every exact retry kept its VID, digest and recorded sequence without new history |
| Detailed account reports | Six certified ledgers and exact report/receipt replays; six pre-posting historical prefixes stayed empty |
| Source balances and transfers | Every running observation and all 17 annual controls matched the source movements and explicit discrepancies; both paired transfer credits matched certified originating principal |
| Investor principal | All six version-5 outcomes matched cash and credited transfers; the earlier cash-only result remained unchanged after the transfer role was recorded |
| Native materializations | All 143 active monthly registers and the projections verified |
| Portable exports | CSV-GL and ADS round trips passed; both source comparisons covered every monetary field, description, citation memo, provenance value and party tag on all 744 legs |
| Independent accumulator proof verification | `fa-verify` accepted the original ADS package with `complete_native_leg_identities` on 744 rows, then exited 8 for both the one-cent amount mutation and the party-only mutation |

The actual runs exposed three helper contract errors: assigning the
Liability-only `investor_capital` role to declared Equity accounts, expecting
only one event from detailed-ledger replay, and passing `--as-known-at` to a
procedure that accepts `--known-at`. The corrections retain the declared chart
types and every source comparison. The earlier failed attempts and complete
successful report and command transcript remain available outside Git; the
compact evidence records their hashes and the exact reproduction command.

All **79 Python helper tests passed with the original PDF supplied**, with no
skips. Those tests, this native execution, and any Rust workspace or
CI gate are separate results. The evidence keeps the $9 and intermediate $1
source discrepancies, the named same-day display rule, and the scope of the
trustee's credited transfers. Source custody remains `AgentUpload` with a
distinct same-harness fixture `Reviewed` attestation; this is an analysis-book
execution under its own trusted signing key.

### Fresh execution with the shared native artifact (2026-11-03)

The complete six-account workload was run again with the verified native CI
artifact from Rust source commit
`88286f8c41f3943fde51e76334b33db758422c95`, the same executable bytes used for
the seven-account migration and the Square One and Magnify workloads. This
fresh run **passed without a runner or source-helper change**. The earlier
execution above remains a separate retained result.

The [current-artifact execution summary](../evidence/blmis/glantz-six-current-native-2026-11-03.json)
records all helper hashes captured before launch, the native artifact and
compiler provenance, exact executable identities, complete report/transcript
hashes, native certificate identities, source discrepancies and verifier
results. The command ran from 08:51:13 to 08:58:17 UTC, returning exit 0 after
**1,268 native commands in 424.207 seconds**; outer process duration was
424.389 seconds. The observed calls were 1,265 `fa` commands and three
`fa-verify` commands. Native exit counts were 1,266 successes and the two
expected tamper refusals at exit 8.

All **379 original observations** were retained, including seven
zero-principal observations. All **372 monetary entries / 744 legs** were
posted and compared with their original amounts and actual publication
receipts. Both `1ZR010` and `1ZR176` participated in the native replay: the
USD 9 closing difference in the former and the intermediate USD 1 differences
in the latter remained explicit source differences. Neither account was
excluded or altered to obtain the result.

The actual command transcript was independently checked for all 372 fresh
receipts and all 372 exact retries, six byte-identical certified-ledger
replays, and six empty historical ledgers at recorded prefix 181. Native
execution also checked 17 annual balance controls and all 143 monthly
register advances and verifications.
The six-account version-5 investor analysis passed both transfer-role states,
and both paired transfer credits matched certified originating principal.
CSV and ADS source comparisons covered all 744 legs and all six actual party
bindings. Standalone ADS verification accepted complete native leg identities;
the one-cent amount mutation and the party-only mutation each failed the
actual verifier with exit 8, and both altered packages were retained.

This execution establishes the complete six-account source replay on the
shared native artifact. It is separate from the exact-footing migration
subset, from the earlier single-account workload, and from whole-workspace
gates. Current cargo workspace tests, clippy, tier0 and tier1 remain **UNRUN**
in this execution summary; no bead closure is claimed.

## Source-checked forensic observations on real records

The Glantz, [Square One](blmis_square_one_workload.md) and
[Magnify](blmis_magnify_workload.md) native replay commands now run the seven
record-silent procedures described in case-plan section 9.4. The shared
[`blmis_analytics.py`](../scripts/blmis_analytics.py) compares complete native
finding sets against predicates computed from the original published amount
and date literals. Posting receipts supply only the native identity and
publication-order bindings needed to check citations and declared tie breaks.
Native findings never supply their own expected values.

| Procedure | Version and fixed parameters | Source predicate checked |
|---|---|---|
| `jet.round_amounts` | v1, `round_power=3` | Every entry with a leg divisible by USD 1,000, its exact two leg citations and population |
| `jet.weekend` | v1 | Gregorian Saturday or Sunday on the published date, with the exact ISO weekday |
| `duplicates.same_same_same` | v1 | Complete groups with the same signed account/amount legs and date; no description-based merging |
| `duplicates.same_same_different` | v1, `window_days=30` | Each occurrence paired with the first recorded occurrence on its next distinct date within 30 days |
| `numbers.relative_size_factor` | v1, `min_rsf_bps=50000`, `min_subset_size=3` | Largest/second-largest debit ratio in exact basis points, grouped by the declared party or untagged counterpart account |
| `numbers.round_amount_density` | v1, `round_power=2`, `min_legs=20`, `z_squared=9` | Each account's excess USD 100-multiple share against the complete book's leg population, by exact integer inequality |
| `benford.first_digit` | v2, registered USD/debit defaults and minimum 500 | Eligible first-digit counts, exact rational MAD/chi-square/KS calculations, and the unchanged native severity bands |

Each comparison checks the procedure version, every parameter, claim class,
source coordinate, number of monetary entries and legs examined, complete
finding count, severity, statistic name/value/scale/population, narrative and
every entry, leg and account citation. Unknown source identities, missing or
duplicated findings, altered statistics and unrelated citation handles fail
the run. All source observations remain in the package; zero-principal rows
and footnote-governed withholding exclusions do not become artificial
monetary observations.

The procedures run at one fixed recorded prefix over the entire declared
analysis book. They do not accept an effective-date cutoff. The helper records
each native finding run, replays its retained certificate, and replays every
certificate again after the other finding records have advanced the book.
Both replays must return identical native bytes. The retained
`record-silent-analytics.json` includes source-resolved findings, the actual
native reports, certificates, account bindings, source population and the
helper's SHA-256. The complete replay's `report.json` includes the same result.

Benford's population is **one debit leg per monetary entry**, not both sides
of a balanced entry. Thus the default Glantz account has 74 observations,
the six-account Glantz book has 372, and Square One has 340 eligible debit
legs. All three correctly report that the minimum of 500 was not reached;
their thresholds are not lowered to manufacture a conformity score. Magnify's
1,586 monetary entries exercise the scored branch. The old case-plan comment
that Glantz alone exceeded the minimum counted both sides and does not describe
the current v2 procedure.

These are **record-silent observations**. The selected complaints do not label
these round-number, duplicate, weekend or digit predicates as fraud, and the
accounts are a litigation-selected population. Recurring withdrawals can
satisfy duplicate rules; round customer payments can satisfy round-amount
rules. The helper reports those observations and their exact source witnesses,
without turning their counts into fraud conclusions or false-positive rates.
The native analysis mapping, trustee transfer-credit inputs, explicit
withholding exclusions and source discrepancies remain part of the scope.
The independent source predicates and native certificate replays establish
their stated checks; this feature does not claim that standalone `fa-verify`
recomputes these analytics offline.

## Default single-account workload

The following sections describe the unchanged 1ZA192 source scope and its
original code-pinned fixture in detail.

## Primary source and retained evidence

The source is the trustee-hosted [Picard v. Glantz second amended complaint and
exhibits, docket 93, filed January 22, 2018](https://www.madofftrustee.com/document/dockets/008796-glantzcomplaint10-05394docket93.pdf).
Account 1ZA192 occupies PDF pages **31-33**, corresponding to Exhibit B pages
**5-7**, and account pages **1-3 of 3**. The pages contain 35, 35 and 5 dated rows.

The original PDF is 389,586 bytes with SHA-256:

```text
751a8a55bf02b022076af39c8637086630090b41164f70e2a04184c0d003dec1
```

The repository stores the bounded factual extraction in
[`rows.csv`](../crates/fa-oracles/data/blmis_glantz_1za192/rows.csv) and its source
metadata in [`source.json`](../crates/fa-oracles/data/blmis_glantz_1za192/source.json).
The complete complaint is downloaded only when requested by the acquisition or
native-replay command. The retained rows include all nine source columns:

| Source column | Retained meaning |
| --- | --- |
| 1 | Printed transaction date |
| 2 | Printed transaction description, including counterpart identifiers |
| 3 | Transaction amount reported in the customer statement, with footnote marker |
| 4 | Deposits credited by the trustee |
| 5 | Withdrawals credited by the trustee |
| 6 | Transfers of principal in |
| 7 | Transfers of principal out |
| 8 | Printed running principal balance |
| 9 | Trustee's two-year transfer classification amount |

Each row also carries the PDF page, exhibit page, ordinal within the page,
`pdftotext -layout` line number and SHA-256 of that exact extracted line. Its
`row_id` is a **derived citation identifier**, not a transaction identifier
published by BLMIS. The source's literal dates, amount strings, parentheses,
dash cells and descriptions remain unchanged. For example, the description
`TRANS TO 1Z314330 (1ZB143)` is preserved exactly, including the differing
identifier forms; the adapter does not silently rewrite it.

The metadata retains the independently printed footer cells, the extraction
hash and page hashes, and hashes plus concise paraphrases of the two material
transfer footnotes. It records the source as **trustee computations in a
complaint**, rather than a court finding. The retained factual cells do not
include the full complaint or account-holder heading.

The retained CSV is 13,154 bytes with SHA-256:

```text
286af73204e2451bac782d03e1270ccb70d4b8138219f571db1c4ea0d0f90a3b
```

## The material accounting distinction: reported amount versus principal

Three published rows are transfers. Their reported statement amounts and the
trustee's credited principal differ materially:

| Date | Reported statement amount | Principal movement used by trustee | Source treatment |
| --- | ---: | ---: | --- |
| 1993-10-20 | -$4,000,000 | -$4,000,000 | Transfer out |
| 1996-12-17 | $1,270,422 | $537,366 | Footnote [1]: principal remaining in the originating account is credited |
| 2005-12-23 | $200,000 | $0 | Footnote [2]: the reported transfer contributes no principal |

The helper never substitutes column 3 for columns 4-7. Credited transfer
principal is a named **oracle input** copied from the trustee's exhibit. This
workload reproduces the arithmetic given those inputs; it does not independently
reconstruct or validate the trustee's net-equity determination.

The zero-principal transfer remains one of the 75 retained source observations.
It produces no invalid zero-amount monetary entry. Its unchanged printed balance
still participates in the running-balance comparison. The resulting analysis
package contains **74 monetary entries and 148 legs**.

## Independent controls and explicit analysis accounts

The helper sums columns 4-7 in printed order and compares the result with
**every row's column 8**. It also compares the movement-column sums with the
source's separately printed footer:

| Printed footer field | Printed value |
| --- | ---: |
| Deposits | $10,439,983 |
| Withdrawals | -$16,924,380 |
| Transfers of principal in | $537,366 |
| Transfers of principal out | -$4,000,000 |
| Closing principal | -$9,947,031 |
| Two-year transfer classification | -$7,700,000 |

The last column is retained as source evidence. Reproducing its sum is not a
legal determination that a transfer is avoidable. No lookback or other legal
rule is inferred from the column label.

The optional `prepare` command constructs a small double-entry **analysis book**:

- `BLMIS-1ZA192`: an investor-capital analysis account; incoming principal is
  a credit, so its debit-minus-credit balance is the negative of the printed
  principal balance.
- `BLMIS-CASH`: the counterpart for the source's deposits and withdrawals.
- `BLMIS-TRANSFER`: a separate counterpart for the trustee-credited transfer
  principal, classified as a Liability clearing account in this analysis chart.
  It holds the native `investor_transfer` role. Transfers are not relabelled as
  cash, and the clearing classification is not a source-published BLMIS account.

These are declared analysis accounts and counterparts, not a recovered original
BLMIS chart of accounts. They represent this exhibit's selected account history
from a zero baseline immediately before its first published transaction. They
do not establish BLMIS's firm-wide assets, liabilities, opening balances or
financial statements.

The generated annual principal controls select the last **printed** balance on
or before each December 31 from 1992 through 2008. For a year without a row, the
control records both its requested year-end date and the earlier source row's
actual date. It does not invent a dated transaction or recompute the control
from the normalized legs. Before the first row, selection fails instead of
inventing an opening balance.

## Native investor principal, including credited transfers

The replay runs `ponzi.net_investment` version 5 under the named
`posted_principal_transfer_v1` rule. It registers one role-labelled native
counterparty for source account `1ZA192`, with code `BLMIS-1ZA192`, and tags only
the principal leg of each entry with that party. Cash and transfer-clearing
counterparts remain untagged. The principal account is classified as investor
capital by its explicitly declared Equity type; the `investor_capital` role
is only for Liability accounts. The cash and transfer-clearing accounts receive
their admitted `cash` and `investor_transfer` roles. Account names do not supply
any classification, and the driver checks that the native chart retains the
declared types before proceeding.

The procedure must preserve these distinct source amounts:

| Component | Source input |
|---|---:|
| Cash received | $10,439,983 |
| Cash withdrawn | $16,924,380 |
| Trustee-credited principal transferred in | $537,366 |
| Trustee-credited principal transferred out | $4,000,000 |
| Resulting principal | −$9,947,031 |

The result agrees with the exhibit's independently printed closing balance.
The native finding uses its registered statistic name
`fictitious_profit_clawback`, with value `994703100` at USD scale 2, and reports
cash and transfer components separately. The driver checks the exact investor,
procedure version, rule, effective cutoff, recorded prefix, attributed movement
count and complete attribution in the returned finding.

Transfer principal is still the trustee's supplied input. In particular,
$1,270,422 of reported transfer activity contributes only the credited $537,366,
and the reported $200,000 transfer contributes no principal or monetary entry.
The procedure does not calculate those credits from the originating accounts,
infer a principal cap, or determine a legally recoverable amount. This is an
exact accounting calculation under the declared source inputs, not an
independent net-equity or clawback determination.

The runner also exercises the absence of a declared transfer role through the
actual native procedure. Before assigning `investor_transfer`, version 5 sees
the cash-attributed result of $6,484,397. After the role assignment, it must see
$9,947,031: the $3,462,634 difference is exactly the credited net principal
transferred out. It then reads the earlier recorded prefix again and requires
the original result to remain unchanged. This compares two explicit native
role states of version 5; it does not simulate or claim to replay version 4.

## Reproduce source acquisition, extraction and preparation

Python 3.11 or newer is sufficient for explicitly offline retained-row
verification and preparation. PDF preparation and every native replay require
Poppler's `pdftotext`; install `poppler-utils` on Linux or `poppler` on macOS
and ensure `pdftotext` is on `PATH`. The reviewed extraction used version
24.02.0. Run commands from the repository root:

```bash
# Offline: verify the retained pins, all rows and the printed controls.
python3 -B scripts/blmis_source.py verify

# Fetch the complete small primary PDF, with bounded size and SHA-256 checks.
python3 -B scripts/blmis_source.py fetch --output /path/to/new-glantz.pdf

# Re-extract all three account pages and require exact reviewed byte identity.
python3 -B scripts/blmis_source.py extract \
  --pdf /path/to/new-glantz.pdf --output /path/to/new-extraction

# Acquire, extract and prepare directly from the primary PDF in one command.
python3 -B scripts/blmis_source.py prepare-pdf --output /path/to/new-pdf-package

# The same path using an already downloaded original; extraction still runs.
python3 -B scripts/blmis_source.py prepare-pdf \
  --pdf /path/to/new-glantz.pdf --output /path/to/another-new-pdf-package

# Explicitly offline: prepare from reviewed retained rows, without extraction.
python3 -B scripts/blmis_source.py prepare --output /path/to/new-package

# Offline positive, mutation and failure-boundary checks.
python3 -B -m unittest discover -v -s scripts/tests -p test_blmis_source.py
```

Output destinations must be new. The downloader verifies the complete response
before creating its output and accepts redirects only to the publisher's HTTPS
hosts. Re-extraction verifies the original PDF first, enforces the declared
nine-column layout and complete page populations, and requires the regenerated
rows and metadata to equal the committed pins. A changed source or extraction
is a review event, not permission to refresh expected results automatically.

A prepared package contains `rows.csv`, `source.json`, `legacy.csv`,
`column_map.toml`, `chart.json`, `controls.json` and `manifest.json`. The manifest
accounts for every source row, including the zero-principal observation, names
the interpretation and baseline, records each transfer input's role, and hashes
every generated payload. Same-day transactions remain in the exhibit's order.

`prepare-pdf` additionally retains `source.pdf`, the exact extractor output in
`extracted-source/layout.txt`, regenerated `extracted-source/rows.csv` and
`extracted-source/source.json`, and an `extraction.json` receipt. The receipt
records the actual extraction command, selected pages and all byte counts and
hashes; the package manifest binds these materials. Normalization reads these
newly extracted rows. The committed fixture hashes are acceptance controls,
not replacement input when extraction fails. If the extractor produces a
different layout, the original PDF and diagnostic text remain available, but
no normalized accounting input is accepted. A missing extractor returns
`UNRUN` with installation guidance.

The amount parser accepts the source's explicit whole-dollar syntax and converts
it to exact integer cents. Blank cells, malformed grouping, unexpected footnotes,
fractional values and overflowing amounts fail. An explicit printed dash is
interpreted as no movement in that column, while its original dash remains in
the evidence. No floats, inferred missing rows, balancing plugs or rounding
adjustments are used.

Extraction reports arithmetic disagreements as diagnostics rather than editing
source cells. This particular account is an exact-footing workload: verification
and preparation refuse a mismatch against its printed controls. That distinction
preserves the broader plan's ability to describe other accounts with rounded
published amounts without falsely calling them exact.

## Native persistent-book replay

Build the repository-pinned `fa` and standalone `fa-verify` binaries, then run:

```bash
cargo +nightly-2026-08-31 build --locked -Z bindeps -Z git=shallow-deps \
  -p fa-cli --bin fa -p fa-verify --bin fa-verify --jobs 1

python3 -B scripts/blmis_replay.py run --out /path/to/new-native-run

# Reuse a previously acquired, hash-verified original PDF when desired.
python3 -B scripts/blmis_replay.py run \
  --pdf /path/to/new-glantz.pdf --out /path/to/another-new-native-run

# All source and native-comparator unit tests; no native executable required.
python3 -B -m unittest discover -s scripts/tests -p 'test_blmis*.py' -v
```

Use `--fa /absolute/path/to/fa --fa-verify /absolute/path/to/fa-verify` when
binaries are outside `target/debug`. Output directories must be new. A missing
binary returns `UNRUN` with exit code 4 before an output directory is created.
A source mismatch, accounting discrepancy or failed native command fails the
run; it is never converted into a successful comparison.

The driver acquires or copies the pinned original PDF, extracts all three pages
in the current invocation, requires the reviewed rows and metadata byte for
byte, and prepares and checks the complete normalized package before creating
a monthly native book. Passing `--pdf` avoids downloading, but still performs
extraction. There is no retained-fixture fallback in `run`.

It creates the 17 fiscal years and opens the source months, registers the three
declared analysis accounts, and attaches the original PDF, exact extraction text,
extraction receipt, extracted rows, source metadata and package manifest as evidence.
These documents are honestly labelled `AgentUpload`. A distinct local test
principal records Reviewed attestations so the workload exercises the actual
evidence-admission rule. This is an explicit local test of that rule, not a
claim of authenticated human review or court approval.

The driver reads the prepared CSV, verifies every source row, amount, account,
description and memo, and submits each of the 74 monetary observations through
the native `post` command. Each command opens the persistent book anew. Separate
publications preserve the exhibit's order for same-day transactions without
inventing a source time of day or BLMIS recording sequence. This path exercises
native posting after source ingestion; the optional generic legacy-migration
variant in the wider M-T-03 plan is not implemented here.

Party registration and `party list` provide both the native Party VID and its
distinct dimension-value VID. The latter is the exact identity carried by
principal legs and checked in the exports. The driver binds these identities
to the actual creation receipt and source account code; it does not derive
the expected party identity from the export being tested.

A successful run must complete all of these checks:

- Match all 74 native principal-account lines to their actual posting receipts,
  including entry identity, leg index, effective date, recorded sequence,
  original-entry class, currency, and gross debit and credit amounts.
- Compare the native running balance against every one of the 75 independently
  printed observations. The zero-principal transfer stays in this comparison
  with an unchanged balance and no artificial zero-amount entry.
- Certify the detailed general ledger and replay the certificate with its exact
  account, unit, date, label and known-at scope, requiring a byte-identical robot
  report followed by its matching `report_replayed` verification receipt.
- Query the pre-import recorded prefix after all entries have been posted and
  require it still to contain no monetary history.
- Retry every original intent across process reopenings and require the original
  receipt identities and an unchanged journal head.
- Reconcile all three accounts at each of 17 year ends. Principal controls come
  from the last printed source balance; cash and transfer controls use their
  distinct source columns. Inactive years retain the actual earlier source date.
- Run the native investor-principal calculation with explicit party and account
  roles, compare its components and final statistic with the source, and check
  the missing-transfer-role discrepancy and immutable historical result.
- Advance and independently verify registers for every active posting month
  (62 months), then verify projections and a signed accumulator checkpoint.
- Export canonical CSV and ADS, re-read their native coordinate certificates,
  and compare **all 148 exported legs** with the original source and actual
  native posting receipts. This includes counterpart amounts and accounts,
  effective dates, recorded sequences, entry classes, leg ordinals, 74 principal
  party tags and 74 explicitly untagged counterparts.
- Verify ADS with the real standalone `fa-verify`, requiring native dimension
  coverage on all 148 rows. A legacy 13-column package with no authenticated
  dimension coverage cannot satisfy this run. Independently mutate one cent
  and one party value VID in two separate package copies; each must fail the
  actual verifier with exit 8. The party mutation leaves every monetary and
  text field unchanged.

The verifier is given the signing key of the fresh local analysis book as an
explicit caller-trusted input. This tests the book's internal commitments and
the standalone verifier; it does not authenticate the source as a trustee- or
court-signed ledger.

`report.json` is written with `status: PASS` only after all real native commands
and comparisons succeed. It includes source pins, binary and driver SHA-256
values, all posting receipts, certificate identity, annual controls, verified
register periods, native party identity, principal findings at both role states,
complete export comparisons and the actual verifier responses. The accepted
`gl.csv` and `ads/` package remain available alongside separate `ads-tampered/`
and `ads-dimension-tampered/` negative controls. `commands.jsonl` retains
commands, stdout, stderr and exit codes. A failed run retains `failure.json`
when an output directory has already been created. Keep the run directory to
inspect the original evidence, prepared package, native book and proof export.

The [public-ledger workflow](../.github/workflows/public-ledger.yml) runs the
offline BLMIS checks and schedules this native workload after its pinned native
build succeeds. It retains reports, failure records and command transcripts.
A scheduled workflow or a passing comparator unit test is not evidence of a
successful native run.

## Earlier B-2 ingestion validation

The pinned original was downloaded and its hash matched the existing case-plan
source pin. All three relevant PDF pages were rendered and visually inspected.
Re-extraction reproduced the committed factual rows and metadata byte for byte.
All 75 running balances and all six footer controls agreed exactly. The offline
suite also uses an independently written `Decimal` fold over raw source literals;
it does not derive expected principal from the adapter's normalized entries.

The offline tests cover the differing transfer credit amounts, the retained
zero-principal row, same-day ordering, source and metadata tampering, malformed
amounts, dropped rows, extra columns, altered layouts, changed printed controls,
output preservation and unavailable extraction tools. They do not substitute for
a native FrankenAccounting posting, certificate replay or verifier run. Native
execution must report its own observed result; an unavailable native run is
`UNRUN`, never a pass.

Observed after integrating PDF ingestion: **20 source tests and 31 native-comparator
unit tests passed**. The comparator tests use explicitly test-only receipt
identities and native-shaped payloads; they check refusal boundaries and do not
simulate execution of the accounting engine. The restored comparator suite also
passed after an execution-environment interruption. Both retained data files
were recovered with their original SHA-256 pins unchanged.

The new comparator coverage constructs expected cash and transfer amounts and
all exported legs independently from the original source literals with
`Decimal`. It rejects cash-only results presented as complete principal,
reported transfer amounts substituted for credited principal, a wrong party or
rule, incomplete attribution, changed source counterparts, missing or duplicate
rows, and party-only changes that preserve all monetary fields. Its mocked
native call contracts establish command and comparison behavior only; the
runner still requires real executable responses before writing `PASS`.

The PDF preparation path was also executed against a fresh download of the
389,586-byte original using Poppler 24.02.0. Its 18,432-byte
extracted layout had SHA-256
`4390c3f3da1ebab54bafc7a1147514a67aaf3d0af9d2df4d0fc354a99739657d`.
All 75 regenerated rows and the source metadata matched their existing pins;
the 148-leg package and 17 annual controls were prepared from that extraction.
The new offline tests additionally check download/extraction/normalization
order, byte lineage, extraction drift, changed returned rows, missing Poppler,
and refusal before any native client is constructed. A concurrent creator's
output directory receives no diagnostic writes: failure logging requires an
explicit successful directory-creation receipt. Their mocked extractor
contracts remain distinct from this actual PDF execution.

Earlier native implementation attempts exhausted the shared filesystem or lost
compiler processes under memory pressure. The complete six-account execution
recorded above now establishes the native result for its exact helper and
binary hashes. The historical B-2 ingestion observations in this section do
not establish an additional standalone B-2 native run or a Rust workspace gate.
