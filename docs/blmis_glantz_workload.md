# Published BLMIS transaction history: Glantz Exhibit B-2

This workload retains **every published row of account 1ZA192** from the
trustee's Glantz Exhibit B-2: 75 transactions dated December 7, 1992 through
October 30, 2008. It adds actual dated transaction records and independently
printed running balances to the [public-sector activity workloads](public_ledger.md).
The [forensic case plan, section 9](FORENSIC_CASE_STUDIES_PLAN.md#9-case-m--madoff--blmis-trustee-ledgers)
describes the broader BLMIS program. This is one complete account, not completion
of the three-complaint, thirteen-account program or its M0-M7 beads.

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
  principal. Transfers are not relabelled as cash.

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

## Reproduce source acquisition, extraction and preparation

Python 3.11 or newer is sufficient for offline verification and preparation.
Re-extraction also requires Poppler's `pdftotext`; the reviewed extraction used
version 24.02.0. Run commands from the repository root:

```bash
# Offline: verify the retained pins, all rows and the printed controls.
python3 -B scripts/blmis_source.py verify

# Fetch the complete small primary PDF, with bounded size and SHA-256 checks.
python3 -B scripts/blmis_source.py fetch --output /path/to/new-glantz.pdf

# Re-extract all three account pages and require exact reviewed byte identity.
python3 -B scripts/blmis_source.py extract \
  --pdf /path/to/new-glantz.pdf --output /path/to/new-extraction

# Prepare the complete account's explicitly constructed analysis package.
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

## Verification status

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
