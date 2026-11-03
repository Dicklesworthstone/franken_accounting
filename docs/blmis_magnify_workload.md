# Magnify: all six published account histories

The Magnify workload adds **all 2,364 dated observations** from six Exhibit B
accounts, spanning July 11, 1983 through December 3, 2008. Together with
[Glantz's 379 observations](blmis_glantz_workload.md) and
[Square One's 1,050 observations](blmis_square_one_workload.md), the source
adapters cover the case plan's **3,793 observations across thirteen accounts**.
Those are complete account-table populations in the selected filings, not a
claim to possess every BLMIS customer account or the firm's general ledger.

The source is the trustee website's [published Magnify affidavit, docket 150,
filed October 30, 2017](https://www.madofftrustee.com/document/dockets/magnify_affidavit_opposingcounsel_10-05279_docket150.pdf).
It contains an attached copy of the second amended complaint and its Exhibit B,
docket 143-2, filed September 29, 2017. Both enclosing and embedded filing
identities appear on the table pages and are retained in the metadata. The
table occupies **physical PDF pages 112–162**, corresponding to the embedded
Exhibit B's 51 pages. These are trustee computations in a complaint, reproduced
as an affidavit attachment; they are not court findings.

## Complete account census and printed controls

The adapter reads every date, transaction description, reported statement
amount, principal-movement column, printed running balance and lookback column.
Amounts retain their original whole-dollar literals and are computed as exact
integer cents.

| Account | PDF pages | Dated rows | Source columns | Nonzero principal movements | Printed closing principal | Fold minus printed |
|---|---|---:|---:|---:|---:|---:|
| `1FN024` | 112–119 | 342 | 11 | 327 | −$7,283,377 | −$42 |
| `1FN025` | 120–121 | 58 | 11 | 45 | −$4,745,822 | $0 |
| `1FN037` | 122–159 | 1,927 | **12** | 1,179 | −$123,673,185 | +$16 |
| `1FN073` | 160 | 6 | 11 | 6 | −$1,031,098 | +$1 |
| `1FN097` | 161 | 4 | 11 | 4 | −$321,790 | $0 |
| `1FR051` | 162 | 27 | 11 | 25 | −$11,230,019 | $0 |
| **Total** | **51 pages** | **2,364** | **Two declared layouts** | **1,586** | — | — |

The case plan's blanket description of Magnify as an eleven-column source does
not cover its largest account: `1FN037` explicitly prints a twelfth column,
including **90-Day Transfers**. The helper declares the two layouts by account
and checks every page's actual header. In the five eleven-column accounts, the
ninety-day field is explicitly absent: its retained CSV field is empty and its
decoded value is `None`. A printed dash is a separate source value; the helper
does not create a fictitious zero in an absent column.

Three accounts reproduce every printed running balance exactly. The other
three retain these complete discrepancy populations:

| Account | Discrepant running balances | Maximum absolute difference | Closing difference |
|---|---:|---:|---:|
| `1FN024` | 330 of 342 | $42 | −$42 |
| `1FN037` | 1,920 of 1,927 | $18 | +$16 |
| `1FN073` | 2 of 6 | $1 | +$1 |

Each account's final page carries a source note attributing possible differences
in displayed totals to rounding. The adapter binds that note and reports the
observed differences. It does not independently establish their cause or turn
the stated rounding explanation into a tolerance for native accounting errors.

Footer checks remain distinct from running-balance checks. For example,
`1FN024`'s displayed withdrawals sum $41 below its withdrawals footer, while its
closing principal differs by $42; those controls are not silently treated as
equivalent. The six-year, two-year, ninety-day and full-history fields remain
published source inputs. Summing them does not reproduce a legal lookback test.

## Source complexity retained by the adapter

### Tax stars, zero amounts and positive corrections

Account `1FN037` contains **717 starred withdrawal cells** under its footnote
`[4]`. Their numeric reported statement amounts total **−$682,757** and remain
available separately. The note describes the trustee's exclusion of these
withholdings from principal because of subsequent IRS refunds. The helper
records that exclusion as an explicit premise; it creates no dated refund
entries, since none are supplied by this table.

The extracted stars include 511 inline `[4]` markers and 206 markers that
`pdftotext` places on the preceding line. Both forms retain their exact marker
location and line hash. Footnotes are account-scoped: `1FN024`'s `[4]` means
something else, identifying amounts that include transfers to other recipients.
Using a single global meaning for the numeral would misread this source.

The complete population contains **43 positive amounts in the Withdrawals
column**. These include cancellations, corrections and returned payments.
Their signs and printed descriptions are preserved. They are not changed to
deposits simply to fit a column-name assumption, nor are original transactions
automatically identified and reversed from descriptive text alone.

Of the 2,364 observations, 778 have no principal movement:

- 717 footnote-governed tax stars;
- 55 reported transfer observations to which the trustee assigned no principal;
- six genuine printed `(0)` cash observations.

All 778 remain in `rows.csv` and `observations.json`. Preparation produces no
zero-dollar journal entries to inflate the monetary-entry count.

### Reported transfers and principal credits remain different facts

There are **57 descriptions beginning with `TRANS`** and one additional
transfer observation whose source description contains only `(1FN024)`. That
incomplete description is visibly present in the original on January 2, 1997,
PDF page 134, extraction line 27. Its reported amount is $5 million and its
footnote `[2]` explains the inward zero-principal treatment. The helper retains
the literal description and the premise. It does not reconstruct missing
`TRANS FROM` words.

All **58 transfer observations** retain `transfer_credit_role = oracle_output`.
The statement-reported amount and the trustee's credited principal are separate
fields. The helper does not use a printed balance to manufacture a principal
movement or claim to recompute the trustee's legal net-equity determination.

A concrete example shows why this distinction matters. On March 17, 1989,
`1FN024` reports an outward transfer of $3 million, with principal debited at
**$2,816,661**. The independently summed literal movements before that event
leave **$2,816,627**. Applying the published principal debit therefore leaves
**−$34**, while the source prints a dash for zero. The receiving account
`1FN037` prints a principal credit of $2,816,661. Those source values are all
retained. The outgoing account's discrepancy later reaches −$42; that closing
difference is not substituted for the $34 difference at the transfer date.

The source also includes an incoming $682 principal transfer from account
`105102`, whose complete ledger is not part of these six tables. The helper
does not invent the missing origin history.

### Footer annotations are preserved separately

Some withdrawals and full-history footers carry annotations identifying
transfers to recipients other than the account holder, with details referenced
in Exhibit D. These markers do not change the printed principal arithmetic.
The adapter preserves both inline markers and detached markers immediately
above or below the footer, together with their monetary-column attribution.
It retains the footnote's scope instead of treating it as a tax-exclusion rule.

## Original evidence, hashes and document size

[`scripts/blmis_magnify.py`](../scripts/blmis_magnify.py) pins the complete
publisher-hosted file:

```text
source id: SRC-BLM-006
original bytes: 28947445
original SHA256:
25055acd72befe051e8939b528ebcf47be996edcbaa04c712efeb3ebb8dba8ec

reviewed rows.csv bytes: 522085
reviewed rows.csv SHA256:
f10a7bc474512a0f4db4b457d4865a4ff7909053f28f24e3dfa023afb60cf697

reviewed source.json bytes: 24684
reviewed source.json SHA256:
7350a15658dfc63da0386f8b17ca19acc09c454938df5abf94ca78e96e89fc80
```

The repository retains the factual transaction cells in
[`rows.csv`](../crates/fa-oracles/data/blmis_magnify/rows.csv) and the source
metadata in [`source.json`](../crates/fa-oracles/data/blmis_magnify/source.json).
The full PDF is downloaded on demand and retained in each original-source
package. The helper does not rewrite the PDF or substitute selected pages as
the original. The repository fixture omits account-holder headers; transaction
descriptions and their original source aliases remain unchanged.

Each row binds its physical PDF page, embedded exhibit page, account page,
source line and page-row ordinal. Exact extracted lines and pages are hashed;
footer cells, footnote text and rounding notes have separate source anchors.
Derived citation identifiers such as `SRC-BLM-006:1FN024:p116:l43` are source
locations, not purported original transaction IDs.

The 28.9 MB original exceeds the 16 MiB **inline** evidence threshold, but fits
the existing **64 MiB** registered `book-blobs` document-store bound. The native
document intake path reads against that store limit and routes larger documents
to the book's owned external blob storage. See
[`registries/document_stores.toml`](../registries/document_stores.toml),
[`crates/fa-cli/src/intake.rs`](../crates/fa-cli/src/intake.rs), and
`a_document_past_the_inline_bound_lives_in_the_blob_store_and_every_read_verifies`
in [`crates/fa/src/book/tests.rs`](../crates/fa/src/book/tests.rs).

The executed native workload below retained the complete original as one
document and recovered every byte through a separate native read process.
Lossless gzip compression was investigated and still exceeds the inline
threshold, so the source helper does not use it to disguise the document's
size.

## Reproduce the complete source package

The helper uses only the Python standard library. Install Poppler's
`pdftotext` on `PATH` for original-PDF extraction. The reviewed extraction used
version 24.02.0; another version must reproduce the fixture pins exactly.

Download, authenticate, extract and prepare all accounts:

```bash
python3 -B scripts/blmis_magnify.py prepare \
  --out artifacts/magnify-source
```

Or use an already acquired complete original:

```bash
python3 -B scripts/blmis_magnify.py prepare \
  --pdf /absolute/path/to/magnify_affidavit_opposingcounsel_10-05279_docket150.pdf \
  --out artifacts/magnify-source-local
```

Each command re-extracts the original in that invocation. Normalization reads
those newly extracted rows; the committed fixture supplies immutable acceptance
pins. A source download or extractor failure does not fall back to retained
rows. Extractor drift must be investigated, not accepted by regenerating pins.

Lower-level acquisition and extraction are also available:

```bash
python3 -B scripts/blmis_magnify.py fetch \
  --out artifacts/magnify-original.pdf

python3 -B scripts/blmis_magnify.py extract \
  --pdf artifacts/magnify-original.pdf \
  --out artifacts/magnify-extracted
```

Explicit offline operations:

```bash
python3 -B scripts/blmis_magnify.py verify

python3 -B scripts/blmis_magnify.py prepare --retained \
  --out artifacts/magnify-retained

python3 -B -m unittest discover -s scripts/tests \
  -p 'test_blmis_magnify.py' -v
```

Output locations must be new. Exit 0 means successful source/structure
verification, with arithmetic differences reported separately. Exit 1 is a
source, shape or output refusal; exit 2 is a usage error; exit 4 and `UNRUN`
mean acquisition or extraction was unavailable.

## Normalized accounting contract

The package prepares **1,586 nonzero source movements as 3,172 balanced legs**.
It declares six equity accounts, one per source account, plus an asset cash
counterpart and a liability transfer-clearing counterpart. These are an
explicit analysis chart, not the source company's original chart of accounts.
Every principal-account leg is the negative of that row's principal movement.
Its other leg records the matching cash or trustee-credited transfer movement.

The zero-before-first-row baseline is separate for each account. Original
transaction IDs and recorded timestamps are unavailable; the package supplies
derived citation IDs and source effective dates without pretending to recover
historical system time. Posting order is date, PDF page and line, preserving
each account's original same-day order.

The package includes `legacy.csv`, its generic-CSV `column_map.toml`, the
eight-account `chart.json`, annual `controls.json` grouped by source account,
all-observation `observations.json`, source rows and metadata, and a hash-bound
manifest. PDF preparation additionally retains the full `source.pdf`, the
actual extracted text and an `extraction.json` receipt.

Every annual control keeps the last independently printed balance on or before
year end, its source-row citation, the separate literal fold and the explicit
difference. Three accounts have exact printed footing; the others require a
consumer that preserves their source discrepancies. No consumer should replace
the printed controls with the fold and call the result an exact source tie-out.

## Verification scope

The actual `fetch` command authenticated the complete source PDF. A fresh
extraction reproduced both retained fixture files byte for byte, and
`prepare_pdf()` created the full normalized package. Twenty-five offline tests
cover all six source populations, both layouts, every printed gap, a separately
implemented decimal fold, footnote scoping, source stars and numeric zeros,
positive corrections, the incomplete printed description, independent footer
controls, tampering refusals and exact normalized legs. Representative original
pages were visually checked for the incomplete description, the twelve-column
header, the tax footnote and the annotated eleven-column footer.

These source results establish acquisition, extraction and preparation. The
separate executed native result below supplies the actual journal, certificate
and outsider-bundle verification evidence. This work advances case-plan §9 and
bead `fa-yugf.72` without claiming completion of that bead's separate
case-harness and expectation-loader requirements.

## Execute the complete native workload

[`scripts/blmis_magnify_replay.py`](../scripts/blmis_magnify_replay.py) drives
the real `fa` and independent `fa-verify` executables. Build both binaries from
the repository's pinned toolchain, or pass paths to verified matching builds:

```bash
python3 -B scripts/blmis_magnify_replay.py run \
  --fa /absolute/path/to/fa \
  --fa-verify /absolute/path/to/fa-verify \
  --pdf /absolute/path/to/magnify_affidavit_opposingcounsel_10-05279_docket150.pdf \
  --out artifacts/magnify-native
```

Omit `--pdf` to fetch the pinned complete original. The destination must not
exist. The runner re-extracts the PDF, checks both immutable fixture pins and
builds a new analysis book with all eight declared accounts. It registers one
native party per source account, then opens every monetary source month from
1983 through 2008. Each of the **1,586 entries** preserves its original source
date, literal description and precise source-page/line memo. The principal leg
also carries the native party dimension. No journal or source row is split to
circumvent an engine limit.

The complete original and six extraction/provenance documents enter custody as
`AgentUpload`. A separate local reviewer supplies the explicit `Reviewed`
attestation required for posting. That attestation describes this local source
verification exercise; it does not claim that the trustee or court reviewed
the constructed book. The runner retains the original custody receipts and
checks that review and posting leave them unchanged.

Immediately after the full original's intake, a separate CLI process reopens
the book and executes `document read <oid> --out original-readback.pdf`. The
readback helper verifies the same document identity and commitment, full
unredacted view, all **28,947,445 bytes**, the recovered file's SHA-256 and the
robot response's independently hashed hexadecimal payload. Both must match the
pinned original. This exercises the owned blob store above the inline limit
with the actual source, rather than inferring success from an intake receipt.
The compact readback receipt is retained in `report.json`; the actual robot
response remains in the native transcript.

The independent comparison reads printed literals with `Decimal`, rather than
using normalized journal totals as its source oracle. It checks all **2,364
observations**, including all **778 zero-principal rows**, against six actual
native running-balance reports. The tax stars require the exact account-scoped
footnote premise. Every published gap remains a separately named field; a
one-cent native error fails even when the source already has a larger printed
discrepancy.

The full run also requires these completed native checks before it emits
`PASS`:

- Six certified general ledgers, with byte-exact report replay and an unchanged
  empty preimport history for every source account.
- An exact retry of every entry, preserving its identity and commit sequence
  without appending duplicate history.
- All **91 source-account annual printed controls**, with their separate source
  folds and discrepancies; **26 cumulative year-end trial balances** check the
  complete book, including balances of accounts whose tables ended earlier.
- Native principal analysis before and after declaring transfer semantics,
  including replay of the earlier history after the role change. All credited
  transfers retain their source-input status.
- An explicit native comparison of the March 17, 1989 transfer: the source
  credit is $2,816,661, the originating literal principal before the event is
  $2,816,627, and the actual native remainder is −$34. The later −$42 closing
  difference remains separate. The $682 external origin is explicitly absent.
- Register advancement and verification for all **272 monetary source months**,
  projection verification, a signed checkpoint and accumulator verification.
- Full cold-process readback of the original PDF, with unchanged original
  custody and exact file and robot-payload hashes.
- Full CSV and ADS exports compared leg by leg against the source, including
  original text and native party dimension identities, followed by independent
  ADS proof verification with the caller-trusted local book key.
- Independent refusal of an exported one-cent amount mutation and a party-only
  dimension mutation. The original export stays intact in a separate directory.

The output contains the complete source package, book, entry intents, native
command transcript, certified report receipts, exports and proof artifacts.
`report.json` records the source comparisons, document custody, all successful
checks, binary hashes and driver hash. A fresh failed run preserves
`failure.json` and its available evidence; existing output is never overwritten.
Missing executables, acquisition or extraction report `UNRUN` with exit 4;
successful execution returns 0, and a failed invariant returns 1.

The focused runner tests exercise the six-account census, every discrepancy
population, account-scoped footnotes, corrections, zero-row retention, exact
ordering, the transfer limitation, cumulative controls and rejection of altered
native-shaped reports. Those report fixtures have explicitly synthetic
identities and are comparator tests, not native execution evidence:

```bash
python3 -B -m unittest discover -s scripts/tests \
  -p 'test_blmis_magnify_replay.py' -v
```

## Executed native result: November 3, 2026

The complete workload **passed with an observed process exit of 0** after
**4,105 native commands**. The driver measured **4,229.817 seconds**; the
outer process wrapper measured **4,230.464 seconds**. The run retained its
original checks and completed within the configured per-command time limits.
These timings describe the recorded debug-binary, separate-CLI execution, not
a production performance benchmark.

A read-only source review identifies a further scaling opportunity:
[`export.rs`](../crates/fa-cli/src/export.rs) constructs two full prefix bundles,
and [`bundle.rs`](../crates/fa-notary/src/bundle.rs)'s `stubs` recomputes a
document's chunk root for each citing entry. For this workload, that implies
about **91.8 GB of repeated original-PDF hash input** across both constructions;
this is an inference from source, not a measured disk-I/O count. File timestamps
bound CSV publication through the completed ADS certificate at **279.837
seconds**. That interval includes CSV verification and intervening work, so it
is an upper bound rather than an isolated ADS-export benchmark. No optimization
or verification shortcut was applied to the recorded run.

The checked result is retained in
[`evidence/blmis/magnify-native-2026-11-03.json`](../evidence/blmis/magnify-native-2026-11-03.json).
It binds the complete native transcript, full report, source extraction,
original and recovered PDFs, exports and signed proof files by byte count and
SHA-256. It also records the observed wrapper exit, native binary provenance,
seven executed helper hashes, six ledger certificate identities, all 26
cumulative year-end balances and all 272 verified posting months.

Every native principal balance agreed exactly with the independently folded
movement columns. The source's printed discrepancies remained visible:

| Account | Observations compared | Native entries | Native closing principal | Native minus printed |
|---|---:|---:|---:|---:|
| `1FN024` | 342 | 327 | −$7,283,419 | −$42 |
| `1FN025` | 58 | 45 | −$4,745,822 | $0 |
| `1FN037` | 1,927 | 1,179 | −$123,673,169 | +$16 |
| `1FN073` | 6 | 6 | −$1,031,097 | +$1 |
| `1FN097` | 4 | 4 | −$321,790 | $0 |
| `1FR051` | 27 | 25 | −$11,230,019 | $0 |

The transcript census independently confirmed **1,586 original posts and
1,586 exact retries**, six certified ledgers and six exact certificate replays,
six empty historical views, 26 annual trial balances, three principal-procedure
calls, and 272 register advancement/verification pairs. The original document
readback reproduced all **28,947,445 bytes** and the original SHA-256 from both
the recovered file and the native robot payload.

Both complete exports contained **3,172 exact source legs**, with 1,586 native
party-tagged principal legs and 1,586 untagged counterparts. Independent
`fa-verify` accepted the complete ADS bundle with **14,903 passing checks** and
authenticated dimension identities on every exported leg. Separate one-cent
amount and party-dimension mutations each produced the observed verifier exit
**8**, while the untampered bundle produced exit **0**.

A separate read-only artifact audit used standard-library `Decimal` directly
on the retained raw literals and imported none of the production source parser,
normalizer or export comparator. It independently checked all 2,364 source-line
hashes, detached footnote markers, 717 starred exclusions, 778 zero-principal
observations, 43 positive withdrawal corrections, actual posting/retry receipts,
all submitted intents and all CSV fields and dimension identities. That audit
also passed; its result and hash are included in the checked evidence. It ran
after CSV publication and before the final native report, so its own scope is
explicitly the source-to-CSV comparison; the completed native run supplies the
separate final proof and tamper results.

The native executables came from the verified GitHub Actions artifact for
Rust source commit
[`88286f8`](https://github.com/Dicklesworthstone/franken_accounting/commit/88286f8c41f3943fde51e76334b33db758422c95).
The executed case helpers are bound to commit
[`357e7b6`](https://github.com/Dicklesworthstone/franken_accounting/commit/357e7b6d9b4c8206ea1761c5e2258b5afa5c3a3c)
and their individual hashes. The evidence identifies the workflow, artifact,
lockfile and both executable hashes rather than attributing execution to an
unverified build.

`PASS` establishes the declared principal-history construction and its proof
chain. It preserves the −$34 transfer-event remainder, the external $682 credit
with no originating ledger, all 58 credited-transfer source inputs and the
footnote-based withholding exclusions. It does not turn those premises or the
printed balances into a legal net-equity determination, reconstruct dated IRS
refunds, or claim a complete original BLMIS general ledger.
