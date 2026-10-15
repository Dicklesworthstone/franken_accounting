# Native full-journal proof exports

This path supplies the complete entry-payload witness required for independently scoped journal and evidence productions (plan §13.1–§13.3; fa-n6fh). It does not require choosing an account balance, a currency, or a migration run policy.

## Export an existing checkpoint

With whole-book Read and Produce authority, export a recorded checkpoint and its complete prefix to new files:

```sh
# STATE_OID is a recorded accumulator-state identifier selected by the operator.
fa --book ./book proof checkpoint --state "$STATE_OID" --out ./candidate.checkpoint --json
fa --book ./book proof prefix --with-record --state "$STATE_OID" --out ./journal.prefix --json
```

Both commands read the selected state; neither creates a checkpoint, advances the journal, or writes accounting entries. Existing output files are never overwritten. Unix output files are created with mode 0600. Omitting `--out` returns inline hex under the existing smaller response-frame limit. Bound MCP callers retain their launch authority and cannot select arbitrary host output paths.

The exported checkpoint is an **unsigned candidate**, not its own proof of authenticity. The recipient must independently establish which exact checkpoint they trust. Renaming the candidate file does not establish that trust.

## Verify offline

Once the recipient has independently trusted an 80-byte raw checkpoint:

```sh
fa-verify prefix --proof ./journal.prefix --checkpoint ./trusted.checkpoint --json
```

Native `fa:acc-prefix-proof:v2` contains every envelope and entry payload in journal order. A successful native-prefix result has `scope: seq_range_complete`, `record_check: recomputed`, and `scope_derivation: all_prefix_payloads_checked`. Every payload must reproduce its record digest and selector fields. Omitted, duplicated, reordered, inconsistent, or truncated records fail without a partial success report. The standalone verifier prints metadata, never entry payload bytes.

The original `fa proof prefix` without `--with-record` remains envelope-only v1 and preserves its wire bytes. Offline verification still accepts it, but reports `record_check: not_supplied` and `scope_derivation: not_verified`. Envelope membership alone does not establish the correctness of a filtered extract's exclusions.

## Use the same witness for an audit extract

The existing `fa-verify evidence production` and `fa-verify evidence production documents` commands accept the native v2 file as `--prefix`. The recipient independently specifies the recorded-sequence bounds, exact account or all accounts, and inclusive civil-day interval or all days. Supply the exact matching record-bearing inclusion proofs via repeated `--record`; the document mode additionally requires the exact original-cited document byte set. An authenticated empty extract still requires its complete prefix witness.

The native witness includes controls, pending entries, staged migrations, and future-effective entries. Those are authenticated as journal records, without asserting that their amounts currently contribute to a posted balance. Empty and control-only books therefore need no chart account or unit, and staged records need no migration body merely to establish journal membership.

## Disclosure, limits, and claim boundaries

`--with-record` discloses **every entry payload in the selected checkpoint**, including entries outside a later recipient filter. This is not an account-private export or a compact privacy-preserving scope index. Entry payloads retain their canonical sealed fields; the export does not open or decrypt them. Exporting a full prefix grants the recipient no authority to obtain referenced documents or other book data.

Native export and v2 verification are bounded to 65,536 leaves, 8 MiB per entry payload, and 64 MiB of total framed prefix bytes. The evidence-production composition has its own 64 MiB aggregate budget, which also counts selected inclusion proofs and, in full-document mode, document bytes. Reaching a limit causes refusal, never truncation or silent downgrade. Verification has linear full-prefix payload cost.

These proofs establish journal membership, ordering, and payload-derived selectors against the selected trusted checkpoint. They do not prove signatures, economic truth, accounting admission, authorization, migration tie-out or posted visibility, document availability, supplemental evidence, or full provenance closure. The original cited-document mode adds its separately stated byte-recomputation checks, not those broader claims.
