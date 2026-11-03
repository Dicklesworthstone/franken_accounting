# Square One: complete published account history with source discrepancies

This workload brings every dated transaction in the Square One complaint's
Exhibit B into a reproducible source package: **1,050 observations for trustee
account `1FR048`, from February 1, 1999 through December 3, 2008**. The package
preserves all twelve printed columns, including the reported statement amount,
principal movements, running principal balance and the three cash-withdrawal
lookback columns. It extends the [six-account Glantz workload](blmis_glantz_workload.md)
with a different source layout and a material accounting interpretation.

The source is [Picard v. Square One Fund, document 167, filed December 21,
2018](https://www.madofftrustee.com/document/dockets/009665-squareonecomplaint10-04330docket0167.pdf).
The relevant table occupies **physical PDF pages 60–78**, exhibit pages 2–20,
account pages 1–19. Its assertion status is a trustee computation in a complaint.
It is not a complete BLMIS general ledger, an independently established net-equity
determination, or a judicial finding about the listed transactions.

## What makes this a useful real-data test

**The exhibit has 709 starred withholding cells.** These are literal `*` cells
in its Withdrawals column; their numeric statement amounts remain in the
Reported column. Footnote `[1]` explains that the trustee excludes these
withholdings from principal because the IRS subsequently refunded them. The
adapter retains the original star, its inline or detached footnote-marker
location, the reported amount and the footnote's source hash. A zero principal
contribution is a named derivation under that footnote, not a numeric value
invented in the source cell. Every derived starred row names
`SRC-BLM-005:footnote:1` as a premise.

The starred reported amounts total **−$409,607**. They are retained as source
observations. They do not become ordinary withdrawals in the principal-history
book. The source does not supply dated IRS refunds, so the helper creates none.
This principal-history model therefore does not reconstruct gross tax cash
payments and subsequent refund timing.

**Withdrawals are not uniformly negative.** Three published cancellation rows
carry positive amounts in that column: $164 on April 28, 2006; $180 on August 7,
2006; and $212 on July 17, 2007. Their signs and descriptions survive extraction
and posting preparation. A separate, unstarred May 5, 1999 observation prints
`(0)` in both the Reported and Withdrawals columns. It remains a genuine printed
zero, distinct from a star and from a missing cell.

**The printed balances do not exactly equal the sum of the displayed movements.**
The independent whole-dollar fold reproduces the case plan's discrepancy census:

| Control | Literal source fold | Independently printed control | Fold minus printed |
|---|---:|---:|---:|
| Deposits | $28,097,165 | $28,097,165 | $0 |
| Withdrawals, applying footnote `[1]` | −$25,852,740 | −$25,852,737 | −$3 |
| Closing principal | $2,244,425 | $2,244,428 | −$3 |
| 90-day preferential transfers | $0 | $0 | $0 |
| 2-year cash withdrawals | −$6,410,000 | −$6,410,000 | $0 |
| 6-year cash withdrawals | −$24,271,621 | −$24,271,620 | −$1 |
| Full-history cash withdrawals | −$25,852,740 | −$25,852,737 | −$3 |

There are **1,010 discrepant running balances**, with a maximum absolute gap of
$3. The first occurs on the fourth transaction, March 31, 1999, at PDF page 60,
extraction line 17. The final gap is −$3. All amounts are processed as integer
cents; no floating-point tolerance is involved.

The source displays whole dollars. These small cumulative differences are
consistent with rounded presentation, but the adapter does not establish their
cause. It neither changes the source balances nor adds an adjustment to make
them equal. Arithmetic disagreements are reported separately from extraction
failures. Summing the lookback columns checks their published totals; it does
not independently reproduce a legal lookback calculation.

## Source identity and provenance

The complete original PDF is acquired on demand. Its size and hash are pinned
in [`scripts/blmis_square_one.py`](../scripts/blmis_square_one.py):

```text
source id:     SRC-BLM-005
original bytes: 1190822
original SHA256:
396af6d399fb75fc966254b29f9f6e2e1fb0df5bd4ce9d4a48134fe38d56897b

reviewed rows.csv SHA256:
0b3d9666f7a55926333b53241d51e30a3ce4e3b417da7f072c4fcfc3d4a34afd

reviewed source.json SHA256:
56b89c945d4b463c9929f8470a3625e58024adaeba67f656735399f892cf9284
```

The repository retains the bounded factual transaction cells in
[`crates/fa-oracles/data/blmis_square_one/rows.csv`](../crates/fa-oracles/data/blmis_square_one/rows.csv)
and their provenance in
[`source.json`](../crates/fa-oracles/data/blmis_square_one/source.json).
It does not redistribute the full complaint or the account-holder header.
Transaction descriptions are preserved; unrecognized description forms are
refused. Account-holder labels in the constructed chart are role labels.

Each row carries its PDF page, exhibit page, account page, page-row ordinal,
extraction line and the SHA-256 of that exact extracted line. A derived citation
such as `SRC-BLM-005:1FR048:p60:l14` identifies a source location; it is not a
claimed original transaction identifier. The metadata also binds the exact
nineteen-page text extraction, every extracted page, the printed footer, and
the normalized footnote text. Superscript markers detached by `pdftotext`
retain their own extraction-line numbers and hashes.

The parser declares the twelve-column header explicitly. It rejects missing
pages, wrong account or filing identity, changed headers, extra columns, blank
or malformed monetary cells, missing marker attribution, incomplete row
censuses and missing footnote premises. It preserves source page-and-line order
within each date. No transaction times are inferred.

## Reproduce acquisition, extraction and preparation

The helper uses the Python standard library. PDF extraction requires Poppler's
`pdftotext` on `PATH` (`poppler-utils` on Linux or `poppler` on macOS). The reviewed
extraction was produced with version 24.02.0. A different version is acceptable
only if its extracted rows and metadata reproduce the reviewed pins exactly.
Investigate any drift; do not regenerate the pins merely to accept it.

From the repository root, download the pinned original and prepare a new package:

```bash
python3 -B scripts/blmis_square_one.py prepare \
  --out artifacts/square-one-source
```

Or use an already acquired original:

```bash
python3 -B scripts/blmis_square_one.py prepare \
  --pdf /absolute/path/to/009665-squareonecomplaint10-04330docket0167.pdf \
  --out artifacts/square-one-source-local
```

Both commands verify the full original and run a new extraction. They retain
`source.pdf`, `extracted-source/layout.txt`, the extracted factual rows and their
metadata. Normalization consumes this invocation's extracted rows; the
committed fixture supplies acceptance pins. A failed download or missing
extractor does not silently fall back to retained rows.

The two lower-level operations are also available:

```bash
python3 -B scripts/blmis_square_one.py fetch \
  --out artifacts/square-one-original.pdf

python3 -B scripts/blmis_square_one.py extract \
  --pdf artifacts/square-one-original.pdf \
  --out artifacts/square-one-extracted
```

Offline retained-row verification and preparation are explicit:

```bash
python3 -B scripts/blmis_square_one.py verify

python3 -B scripts/blmis_square_one.py prepare --retained \
  --out artifacts/square-one-retained

python3 -B -m unittest discover -s scripts/tests \
  -p 'test_blmis_square_one.py' -v
```

Offline preparation does not claim a new original-PDF extraction. Output
locations must be new; existing evidence is never overwritten. The helper
returns exit 0 on successful structural/source verification, including a
reported arithmetic discrepancy; exit 1 for a source, shape or output refusal;
exit 2 for command usage; and exit 4 with `UNRUN` when acquisition or extraction
is unavailable.

## The prepared principal-history book

The normalized package contains **340 monetary source rows and 680 balanced
legs**. The other 710 observations remain in the source table and
`observations.json`: 709 footnote-governed stars and one printed zero. The helper
does not create zero-dollar journal entries to inflate the posting count.

For each nonzero movement, the constructed equity account `BLMIS-1FR048` takes
the negative of the principal movement, and the constructed asset account
`BLMIS-CASH` takes the equal opposite amount. These are explicit analysis
counterparts, not accounts supplied by the publisher's original double-entry
general ledger. The baseline is zero immediately before the first published
transaction; it is not a whole-firm opening trial balance.

| Output | Purpose |
|---|---|
| `rows.csv`, `source.json` | Exact retained source literals and their provenance |
| `legacy.csv` | Generic CSV input, two exact signed legs per nonzero source movement |
| `column_map.toml` | Declared generic-CSV field mapping and source-system identity |
| `chart.json` | The two constructed analysis accounts |
| `observations.json` | Every source row, posting/nonposting status, printed balance and separate fold difference |
| `controls.json` | Last printed balance on or before each year end, source-row citation, independent fold and explicit difference |
| `extraction.json` | Original acquisition/extraction receipt for the PDF path only |
| `manifest.json` | Scope, complete row mapping, counts, source diagnostics and output hashes |

The annual printed controls are never replaced with calculated balances. A
native consumer must check its exact journal fold against the independently
decoded source movements and separately check every difference from the printed
balance. The printed closing control does **not** qualify this account for a
strict, exact-printed-control migration tie-out.

## Verification scope

The source helper was run against the pinned original PDF, and re-extraction
reproduced both retained fixture files byte for byte. The 23 offline tests cover
the complete census, a separately implemented decimal fold, all printed gaps,
starred amounts and premises, positive cancellations, the literal zero,
structural corruption, source-pin tampering, no-fallback behavior and exact
normalized legs. Mutation tests change a transaction, a printed balance, a
footer and a star marker and check the resulting diagnostic or refusal.

These source checks establish extraction and preparation behavior. A native
FrankenAccounting run requires its own transcript and evidence; the source
test result alone does not claim that posting, certificates or outsider bundle
verification ran. This workload advances the Square One source population in
case-plan §9 and bead `fa-yugf.71`; it does not by itself close that bead's wider
case-harness and expectation-loading requirements.

## Run the complete native accounting path

The companion driver uses the real `fa` and independent `fa-verify` executables.
It acquires and extracts the original PDF in the same invocation, creates a new
analysis book, and posts all 340 nonzero movements. It also compares all 710
nonposting observations at their precise source positions, so a withholding
exclusion or printed zero cannot disappear from the comparison census.

```bash
python3 -B scripts/blmis_square_one_replay.py run \
  --pdf /absolute/path/to/009665-squareonecomplaint10-04330docket0167.pdf \
  --out artifacts/square-one-native \
  --fa target/debug/fa \
  --fa-verify target/debug/fa-verify
```

Omit `--pdf` to download the pinned original. The destination must be new. A
missing binary, unavailable download or missing PDF extractor returns `UNRUN`;
the driver never replaces native execution with a simulated success.

The native comparison has two independent obligations. First, every journal
amount and running balance must equal a separate `Decimal` interpretation of
the original printed movement literals, with the exact withholding footnote
premise attached to every star. Second, every difference from the independently
printed balance must survive unchanged in the report. A one-cent native error
fails even when it falls within the source's three-dollar discrepancy. The
source discrepancy is never an error tolerance or permission to auto-balance.

The run additionally checks:

- The exact two-account chart and the source account's distinct native party
  and party-dimension identities.
- Native intake and custody of the complete PDF, extracted text, transaction
  cells, metadata, observation census, extraction receipt and manifest.
- Every source posting and exact retry; retries preserve native identities and
  append no history, while a report at the preimport coordinate remains empty.
- A certified general ledger and byte-identical replay, all ten annual source
  controls, the native principal-analysis procedure, and every posting month's
  maintained registers.
- Native projections, original document custody, the signed accumulator
  checkpoint, and exact CSV and ADS exports of all 680 legs, including source
  descriptions, page-and-line citations and party dimensions.
- Independent ADS accumulator proof verification by `fa-verify`, followed by actual
  refusals of a one-cent amount mutation and a party-dimension-only mutation.

`report.json` is written with `PASS` only after all these checks finish. It
retains all 1,050 source/native comparisons, every printed discrepancy,
certificate and entry receipts, custody records, annual controls, export
comparisons, verifier results and binary hashes. `commands.jsonl` contains the
actual process arguments, exit codes and native responses. A failed run keeps
its book, transcript and `failure.json` for diagnosis; it does not overwrite a
previous run. The accumulator proof's trust root is the explicitly supplied checkpoint key
of this local analysis book, not a trustee or court signature.

The driver checks are available separately:

```bash
python3 -B -m unittest discover -s scripts/tests \
  -p 'test_blmis_square_one_replay.py' -v
```

Those tests exercise independent source arithmetic, omitted and reordered
observations, altered footnote premises, one-cent native errors, extra native
postings, source citations, cancellation signs and annual controls. They are
driver tests; a native `PASS` still requires the complete command above.

## Executed native evidence: November 3, 2026

The complete command above was executed successfully against the original PDF:
**exit 0, 955 native commands, 227.45 seconds**. The retained
[execution summary](../evidence/blmis/square-one-native-2026-11-03.json) binds the
result to the original, extracted rows, helper files, native binaries, complete
report, process transcript, CSV and ADS export hashes. It identifies the
[successful native build](https://github.com/Dicklesworthstone/franken_accounting/actions/runs/41588158231)
and its independently checked artifact digest. The binaries were compiled from
Rust source commit `88286f8c41f3943fde51e76334b33db758422c95`; the executed helpers
are in commit `e0c2a5ed43b53799f633897686f84dac1d3ae16a`. The Rust sources and Cargo
manifests are identical across those commits.

| Executed obligation | Observed result |
|---|---|
| Source population | All 1,050 observations compared, including 709 starred exclusions and 710 nonposting rows |
| Native journal and exact retries | 340 entries, 680 legs; all 340 retries retained their identities without new history |
| Printed-source differences | All 1,010 discrepant observations retained; maximum $3; closing difference −$3 |
| Native closing principal | $2,244,425, exactly equal to the independently folded source movements |
| Certified reports | General-ledger certificate replayed identically; all ten annual controls matched |
| Maintained registers | All 72 posting months advanced and verified |
| Evidence custody | All seven original document-intake identities and grades retained after review and posting |
| CSV and ADS exports | Every amount, description, citation and party dimension matched all 680 expected source legs |
| Independent ADS verifier | Exit 0; all 3,239 checks passed, including complete native dimension coverage for 680 legs |
| One-cent mutation | Actual standalone verification refused it with exit 8 |
| Party-only mutation | Actual standalone verification refused it with exit 8 |

The native procedure, historical preimport read, projection verification and
signed checkpoint checks also completed. `PASS` applies to this stated
principal-history workload. It does not certify the trustee's legal conclusion,
erase the source arithmetic differences, or substitute for the unrun
whole-workspace and release gates. No wider case-harness bead is closed by this
execution record.
