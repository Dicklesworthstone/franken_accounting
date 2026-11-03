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

That code path supports retaining the complete original as one document; it is
not a waiver or a claim that an excerpt is equivalent. Successful native intake
of this particular PDF still requires an executed native run. Lossless gzip
compression was investigated and still exceeds the inline threshold, so the
source helper does not use it to disguise the document's size.

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

These source results establish acquisition, extraction and preparation. They
do not stand in for an executed native journal, certificate or outsider bundle
verification. The native workload needs its own transcript and evidence. This
work advances case-plan §9 and bead `fa-yugf.72` without claiming completion of
that bead's separate case-harness and expectation-loader requirements.
