# CSV General Ledger Interoperability

## Lossless CSV GL text profile

The canonical `csv_gl_v1` writer quotes fields containing commas, double quotes,
CR/LF, boundary whitespace or a leading `#`. A double quote inside a quoted field
is doubled. Readers consume logical CSV records, retaining embedded CR, LF and
CRLF exactly; a physical newline inside a quoted memo does not start a posting.
Only standalone records can be comments. A UTF-8 byte-order mark is accepted at
the start of input. Unterminated quotes, quotes inside unquoted fields and text
following a closing quote are errors, with the starting physical line number.

Metadata comments use two additive, versioned extensions to retain text that the
original delimiter-separated comments could not represent:

* `# fa_csv_text_encoding_v1|percent-utf8` must occur once, before other metadata.
  When present, textual fields in the coordinate, account, account-role and
  assertion comments use UTF-8 bytes encoded as `%HH`; ASCII letters, digits,
  `-`, `_` and `.` remain literal. This includes encoding a literal percent sign
  as `%25`. Structural separators remain literal. Malformed escapes and invalid
  UTF-8 are refused. The writer enables this profile only when metadata contains
  a delimiter, an ASCII control or boundary whitespace, and then encodes all
  textual metadata fields consistently. Ordinary v1 output remains unchanged.
* `# fa_csv_empty_optional_v1|ENTRY|LEG|FIELD` identifies an empty-but-present
  optional string. `ENTRY` is the one-based ordinal of the entry's first CSV
  record. `LEG=0` with `FIELD=migrated_from` marks migration provenance;
  a one-based leg ordinal with `FIELD=memo` marks a leg memo. Unmarked empty
  cells represent absence. Markers must precede the CSV header and cannot repeat,
  reference a nonexistent entry or leg, or replace a nonempty field.

For example, a book name `Public | records` is emitted as
`book=Public%20%7C%20records` under the percent-UTF-8 declaration. An entry with
`migrated_from = Some("")` receives
`# fa_csv_empty_optional_v1|1|0|migrated_from`; `None` receives no such marker.
Readers lacking these extensions cannot reconstruct the original content digest
and fail the supplied coordinate certificate. These extensions describe the
FrankenAccounting CSV profile; they are not ADS or SAF-T standards claims.

The reader also checks the exact declared column header, every row's width,
consecutive leg numbers, registered unit scales, repeated entry metadata and the
declared entry count. Content and certificate digests must appear together.
A declared effective-through date is retained exactly, so a substituted earlier
date cannot be silently repaired from the data rows and pass the certificate.
`csv_gl_round_trip_preserves_real_world_text_and_escaped_metadata`,
`csv_gl_distinguishes_empty_optional_text_from_absent_text` and
`csv_gl_refuses_changed_row_identity_and_truncated_certificate_metadata` cover
identity, deterministic re-export and malformed/tampered negatives.

The legacy CSV adapters share the logical-record parser and refuse duplicate or
blank header names, incomplete declared amount columns and ragged records.
They recognize comments only before the header, preserving an unquoted source
ID beginning with `#` afterward. Historical vendor padding outside quoted fields
is accepted; whitespace inside their text remains unchanged. Every explicitly
mapped generic column must exist, including optional provenance columns, while
built-in vendor profiles retain support for absent optional metadata. Duplicate
column-map keys or account-map entries are refused. Unknown `[columns]` options
are refused when the map declares explicit date parsing under `[parsing]`;
older maps retain their ignored-key behavior. When a source supplies more than
one monetary representation (such as debit/credit and Xero's signed Gross),
all supplied values must agree exactly.
Source journal IDs and entered-by/approved-by identities retain their exact text,
so IDs `A` and ` A` cannot merge. Narration and leg memos retain whitespace,
Unicode, punctuation and embedded newlines. Typed account mappings, dates and
amounts continue to use their declared parsing rules; a whitespace-only journal
ID is invalid. The original input bytes still determine the retained source
digest. These rules do not invent missing debit/credit legs or establish that a
public spending disclosure is a complete source general ledger.

## Declaring legacy effective-date order

A generic CSV column map can declare the syntax of its effective dates in a
separate `[parsing]` section:

```toml
[columns]
entry_id_column = "Journal ID"
effective_date_column = "Posting Date"
account_column = "Account"
signed_amount_column = "Amount"
recorded_at_column = "Created At"

[parsing]
date_order = "DMY"
```

This declaration reads `04/05/2024` as **May 4, 2024**. With `date_order = "MDY"`,
the same source field means **April 5, 2024**. The resulting effective date governs
the historical period and participates in the import attestation digest; a
balanced trial balance alone cannot establish that the dates were read correctly.

| `date_order` | Accepted syntax | Example |
|---|---|---|
| `ISO` | `YYYY-MM-DD`, with two-digit month and day | `2024-05-04` |
| `YMD` | `YYYY/M/D`, with one- or two-digit month and day | `2024/5/4` |
| `MDY` | `M/D/YYYY`, with one- or two-digit month and day | `5/4/2024` |
| `DMY` | `D/M/YYYY`, with one- or two-digit day and month | `4/5/2024` |

Declaration values are case-insensitive. All four require a four-digit year,
ASCII digits and a valid civil date. Each declared syntax applies to every row;
the parser refuses a different separator, invalid leap day or another date order
instead of guessing. A blank or unsupported declaration also fails. With a valid
`[parsing]` declaration, unknown `[columns]` keys such as `date_format` or a
misspelled `recorded_at_column` are rejected before reading the source. Repeated
or unknown `[parsing]` fields are always rejected. Section order does not change
these rules.

Maps that omit `[parsing] date_order` preserve the existing date
interpretation: ISO `YYYY-MM-DD`, slash-separated year-first dates, and otherwise
slash-separated month/day/year. An empty `[parsing]` section also leaves the
legacy behavior unchanged. Existing maps keep ignoring unknown `[columns]`
keys, including a key named `date_order`; putting it under `[columns]` does not
select a new order. This compatibility matters because retained migration
packages replay the exact original mapping. The older parser rejected a
nonempty `[parsing]` section, so the new syntax cannot reinterpret a previously
admitted package's dates. Move the declaration into `[parsing]` and correct any
unknown column keys when preparing a new import that needs explicit dates.

The built-in QuickBooks, Xero and NetSuite adapters retain their legacy date
behavior. For a vendor export using day/month/year, use the generic `csv`
importer with an explicit column map and `[parsing] date_order = "DMY"`.

`date_order` applies only to `effective_date_column`. `recorded_at_column` keeps
its separate legacy timestamp parser; an ISO timestamp such as
`2024-05-04T12:34:56Z` remains unchanged by the declaration. It is retained as
source provenance and never sets FrankenAccounting's recorded commit sequence.
The original CSV bytes and retained column map remain the evidence for the
transformation.

The regression tests `legacy_csv_declared_date_order_disambiguates_periods_and_binds_attestation`,
`legacy_csv_declared_date_order_validates_syntax_and_civil_dates_without_guessing`,
`legacy_csv_omitted_date_order_preserves_existing_generic_and_vendor_dates`,
`legacy_csv_explicit_parsing_refuses_unknown_keys_and_invalid_date_order` and
`legacy_csv_old_column_keys_keep_their_recorded_date_interpretation` cover these
contracts. The native multi-format OpeningOnly migration test carries an
ambiguous DMY source date through proposal sealing, approval, staging and
finalization as the retained document date; its effective posting date is the
run's opening date.
