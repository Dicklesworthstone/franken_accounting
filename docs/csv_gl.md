# CSV General Ledger Interoperability

## Lossless CSV GL text profile

The canonical `csv_gl_v1` writer quotes fields containing commas, double quotes,
CR/LF, boundary whitespace or a leading `#`. A double quote inside a quoted field
is doubled. Readers consume logical CSV records, retaining embedded CR, LF and
CRLF exactly; a physical newline inside a quoted memo does not start a posting.
Only standalone records can be comments. A UTF-8 byte-order mark is accepted at
the start of input. Unterminated quotes, quotes inside unquoted fields and text
following a closing quote are errors, with the starting physical line number.

Strict reading is attempted first. Historical `csv_gl_v1` exports written before
quote escaping have a narrow compatibility path: their physical-line,
comma-separated interpretation is accepted only when both the retained content
digest and coordinate certificate digest verify against the exactly
reconstructed journal. The same metadata, row identity, count and balance checks
still apply. Missing digests or changed reconstructed text are refused. New
exports always use the quoted profile described above.

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

Dimensioned exports declare `dimension_encoding=fa-dimension-ids-v1` and add a
fourteenth `dimension_set_v1` column. The declaration and header must agree, and
both certificate digests are required to authenticate these native identities.
Untagged exports retain their thirteen-column representation. Values are local
to the source book; importing into another book requires an explicit mapping
to destination dimension codes instead of transplanting native value IDs.

The legacy CSV adapters share the logical-record parser and refuse duplicate or
blank header names, incomplete declared amount columns and ragged records.
They recognize comments only before the header, preserving an unquoted source
ID beginning with `#` afterward. Historical vendor padding outside quoted fields
is accepted; whitespace inside their text remains unchanged. Every explicitly
mapped generic column must exist, including optional provenance columns, while
built-in vendor profiles retain support for absent optional metadata. Duplicate
column-map keys or account-map entries are refused. When a source supplies more
than one monetary representation (such as debit/credit and Xero's signed Gross),
all supplied values must agree exactly.
Source journal IDs and entered-by/approved-by identities retain their exact text,
so IDs `A` and ` A` cannot merge. Nonblank entry descriptions and nonempty leg
memos retain their exact whitespace, Unicode, punctuation and embedded newlines.
A whitespace-only description is absent when selecting the entry summary;
a whitespace-only leg memo remains present and unchanged. Typed account mappings, dates and
amounts continue to use their declared parsing rules; a whitespace-only journal
ID is invalid. The original input bytes still determine the retained source
digest. These rules do not invent missing debit/credit legs or establish that a
public spending disclosure is a complete source general ledger.

In generic CSV, when `description_column` and `memo_column` name different
columns, populated descriptions are entry-level headers. Blank or whitespace-only
header cells may precede or follow a populated header, including interleaved
rows from different entries. Every populated header for the same exact source
entry ID must agree byte-for-byte; conflicting text is refused with source
context. If no populated description appears anywhere in an entry, its exact
source ID becomes the summary after all rows have been read.

When both mappings name the same column, or a built-in vendor profile supplies
the description, the first nonblank description becomes the entry summary and
later line descriptions may differ. Map that column as `memo_column` to retain
each line's text. Empty memo cells represent absence; nonempty memo cells,
including whitespace-only cells, remain exact.
