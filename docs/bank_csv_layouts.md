# Import bank CSV downloads with an explicit layout

Use a declaration when a bank download differs from the canonical twelve-column
CSV format. The original CSV is retained byte for byte; the declaration becomes
part of the immutable import manifest.

```sh
fa bank import download.csv --bank-format csv --account 1000 --layout layout.json --json
```

The CLI accepts a JSON file or an inline JSON object in `--layout`.
MCP `fa_bank_import` accepts the complete declaration as the string property
`layout` and the complete CSV as `text`; it never reads a layout path on the
host. Omitting the layout preserves the existing canonical CSV parser.

For this download:

```csv
Date;Description;Amount
05/03/2026;SALE-1;150,00
06/03/2026;BILL-1;-50,00
```

save this declaration as `layout.json`:

```json
{
  "version": 1,
  "name": "bank-download-v1",
  "headers": ["Date", "Description", "Amount"],
  "delimiter": ";",
  "decimal_separator": ",",
  "date_format": "DD/MM/YYYY",
  "booking_date": "Date",
  "reference": "Description",
  "amount": {
    "column": "Amount",
    "positive": "credit"
  },
  "statement": {
    "instrument_id": "BANK-123",
    "sequence_number": 1,
    "currency": "USD",
    "statement_date": "2026-03-31",
    "opening_balance": "0,00",
    "closing_balance": "100,00"
  }
}
```

## Declaration rules

`headers` declares every column in exact order, including columns you do not map.
Names must be unique. The CSV header must match exactly; no column aliases,
reordering, currency inference or date guessing occurs.

`booking_date` is required. Optional `value_date`, `counterparty` and `reference`
name other declared columns. Without a value date mapping the booking date is
used. Unmapped counterparty and reference values are empty.

The delimiter is comma by default; comma, semicolon and tab are supported.
Quoted delimiters, doubled quotes, embedded newlines, CRLF and a UTF-8 BOM are
handled. Date formats are `YYYY-MM-DD` (default), `MM/DD/YYYY` or `DD/MM/YYYY`.
The statement's closing date is always an ISO `YYYY-MM-DD` date.

For one signed movement column, declare `amount.column` and explicitly choose
`amount.positive` as `credit` (cash inflow) or `debit` (cash outflow).
For separate columns, replace the amount object with:

```json
{"debit": "Money Out", "credit": "Money In"}
```

Both column names must appear in the declared header. Each row must have exactly
one positive amount; the other field must be blank or zero. Negative, simultaneous
and zero-only movements are refused.

The decimal separator is dot by default; dot and comma are supported.
Amounts and balances must be exact decimal strings at the currency's registered
scale. Grouping separators, scientific notation, excess precision and overflow
are refused. JSON numbers cannot stand in for statement balances.

Statement metadata is the importer's explicit declaration. It does not turn
a bank download into independently authenticated evidence of those metadata.
The instrument identifier, positive sequence number, currency, closing date,
opening balance and closing balance are all required. The parser checks:

- Every date is valid, and no booking date follows the statement closing date.
- The currency is registered and matches the selected cash account.
- Opening balance plus every signed movement equals closing balance exactly.
- Every row, mapped field and the complete import fit the published bounds.

An empty statement can be imported with only its exact header when opening and
closing balances agree. A layout has at most 32 columns and at most 16 KiB of
JSON/canonical bytes. Unknown JSON fields and duplicate keys are refused.

## Identity and replay

The returned `bank_imported` event includes `layout_name` and `layout_digest`.
These are null for the canonical CSV and other bank formats. The statement OID
and commitment still identify the original source bytes.

A declared layout is included in bank manifest version 3. Its canonical digest
binds the header order, mappings, sign/date/decimal conventions and statement
metadata. Exact repeats return the original receipt, including after reopening
the book or submitting the same declaration as inline JSON. Once a native
binding exists for a source/account pair, a different declaration is refused,
even if the new mapping would produce balanced amounts. Linked v2 imports and
declared-layout v3 imports establish that binding. Legacy unlinked v1 imports
have no native interpretation binding; they are not retroactively made unique,
and their original exact repeats retain their original receipts.

Matching, confirmation and reconciliation reopen the retained source and reparse
it using the retained layout. They keep their existing full-source disclosure
requirements. The independent verifier accepts v3 reconciled evidence and
independently validates the layout's bounded canonical shape. Inclusion authenticates
the claim; it does not independently parse CSV or prove the bank's assertions.

`--previous-import` remains optional. With no predecessor selected, a custom
layout import is explicitly unlinked; declaring a sequence or opening balance
does not establish continuity with another import.

## Wire compatibility

Existing bank manifest v1 (unlinked) and v2 (linked) bytes remain unchanged.
V3 uses the same fields through the ordered list of line OIDs, then a
length-prefixed canonical layout, a one-byte predecessor presence tag and the
existing predecessor payload when present. Only the CSV parser tag may carry v3.
The layout's fixed discriminator is `fa:bank-csv-layout:v1`.

New native `BankStatementLink` records use binding version 2, independently of
the manifest's version. The payload is exactly 192 bytes: its version header,
book/account/source identities, retained manifest OID and commitment, and native
run identity and receipt hash. Full manifests remain in their original document
storage, including the blob store for large statements. This supports all 1,022
permitted lines without copying their OIDs or the layout into one database row.
The binding digest domain is `fa:bank-statement-link:v2`.

Existing binding v1 payloads and their original digest domain remain readable.
Readers authenticate the retained manifest document and the original import
receipt before accepting an interpretation. Native callers reading an external
manifest supply its canonical interpretation to
`read_bank_statement_link_with_manifest`; the reader verifies those bytes against
the retained document commitment and the complete import closure. This does not
fetch external bytes or grant permission to disclose a stored bank statement.
