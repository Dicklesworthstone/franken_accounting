# Verify an external feed against its source extract

An external-feed reconciliation compares the reviewed batches in the journal with the general ledger. A recipient who also needs to detect a missing source batch can supply the expected population from the source system. Retain that declaration independently when the extract is produced. Building it from the delivered report would reproduce any omission in that report.

## Run the offline check

For example, a recipient verifying feed `ERP:AR` through civil day 20030 at recorded sequence 845 can run the following command. Supply the trusted checkpoint key, independently retained certificate digest, and control-account vertex ID for your report.

```bash
fa-verify report feed.fab --key "$TRUSTED_KEY" --expect "$CERTIFICATE_DIGEST" \
  --external-feed ERP:AR --control-account "$CONTROL_VID" \
  --through 20030 --known-at 845 --population-manifest extract.txt --json
```

The bundle comes from the certified `fa subledger reconcile-feed` report. The CLI accepts the control ID in decimal or with a `0x` hex prefix. The manifest uses fixed-width lowercase hex. The manifest stays plain text even when the bundle is supplied as hex.

## Write the manifest

This example declares one delivery containing two source rows, a debit and its offsetting credit. The identifiers and amounts are illustrative.

```text
fa:external-feed-population:v1
0123456789abcdef0123456789abcdef ERP:AR export-310 20000 20030 2
child batch-17 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
cell 000000000000000000000000000000a1 1 - 12500 0
cell 000000000000000000000000000000b2 1 - 0 12500
```

Use ASCII, one record per line, one space between fields, and no blank lines or comments. The file limit is 8 MiB. Write integers in canonical decimal, with no leading zeroes, decimal points, or plus signs.

| Line | Fields in order |
| --- | --- |
| Format | The literal `fa:external-feed-population:v1`. |
| Header | Book ID (32 lowercase hex digits), feed name, extract identifier, first and last effective day inclusive, total source detail rows in that window. Days are signed integers counted from 1970-01-01. The last day must equal `--through`. |
| `child` | A unique source batch key and its reviewed detail Workpaper OID (64 lowercase hex digits, with no prefix). |
| `cell` | Account vertex ID (32 lowercase hex digits), numeric native unit ID, dimension set, gross debit, gross credit. Amounts are nonnegative integer mantissas in that unit. Declare each nonzero account/unit/dimension combination once. |

Feed names allow up to 64 characters. Extract identifiers and batch keys allow up to 128. Use ASCII letters, digits, or `._:/-` for these fields. For dimensions, use `-` for the empty set, or a comma-separated list such as `2=0000000000000000000000000000000a,7=0000000000000000000000000000000b`. Dimension kinds are strictly ascending decimal integers, and each value is a 32-digit lowercase hex vertex ID.

Count all original deliveries in the window, including batches subsequently reversed. Include every offset account in the gross cells. Keep debit and credit separate even when both sides have the same account, unit, and dimensions. A reversal changes the financial reconciliation and adds zero source deliveries. For an empty extract, use a zero row count and omit all child and cell records.

## Read the result

| Exit | Meaning |
| --- | --- |
| 0 | The verifier authenticated and recomputed the report and matched the declared source population. Read the report's separate `reconciled` field for the financial tie-out. |
| 8 | A verification check failed. A population difference identifies an unexpected or missing child, a Workpaper mismatch, a row-count difference, or a gross cell that differs. A book, feed, or cutoff mismatch also fails verification. |
| 2 | The manifest syntax or command arguments are invalid. Correct the indicated field and rerun. |

The JSON check named `external_feed_population` records the extract identifier, window, and BLAKE3 digest of the exact manifest bytes. Its result establishes agreement with that recipient-held declaration. The source system's own extraction controls establish which upstream records the declaration covers.

## Retain and check the declaration in a live book

Use the source extract to prepare a JSON declaration. Each child names its batch key and detail Workpaper commitment (`doc_commit` from `fa subledger detail`). Each gross cell names a GL code and two exact unit-bearing amounts. Include `dimension_set` when the cell has dimensions, using objects with an integer `dimension` and its hex vertex `value`. Include all offsetting cells.

```json
{
  "feed": "ERP:AR",
  "extract_id": "export-310",
  "from": "2026-03-01",
  "through": "2026-03-31",
  "detail_rows": 2,
  "children": [
    {"batch_key": "batch-17", "doc_commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
  ],
  "totals": [
    {"account": "1200", "debits": "125.00 USD", "credits": "0.00 USD"},
    {"account": "4000", "debits": "0.00 USD", "credits": "125.00 USD"}
  ]
}
```

```bash
fa subledger manifest --input extract.json --out extract.bin
fa document add extract.bin --kind Workpaper --grade HumanUpload --mime application/vnd.franken.subledger-manifest.v1
fa attest review "$MANIFEST_OID" --as reviewer
fa subledger verify-manifest "$MANIFEST_OID" --as-known-at HEAD --json
```

Use the OID returned by document admission for `MANIFEST_OID`. The independent review must exist by the selected sequence. The comparison event reports `complete`, `incomplete`, or `mismatch` in `data.status`. A complete match exits zero. A difference exits 8 and identifies missing or unexpected keys, changed commitments, row counts, and differing gross cells. Repeat at the original recorded sequence to see the same source comparison after later deliveries. The retained comparison uses the journaled Workpaper and live journal history. The offline command above authenticates a certified financial report against a recipient-held declaration.
