# Verify original evidence from one native journal prefix

The existing `fa proof prefix --with-record` export contains every entry
payload at an existing recorded accumulator checkpoint. The offline verifier
can now derive a recipient-scoped original citation inventory directly from
that file, without separately exporting an inclusion proof for each entry.
The `--from-prefix` mode is explicit; the existing multi-proof mode is unchanged.

## Export once, choose the verification scope independently

On the book owner's machine, choose an existing `STATE_OID` and a new output path:

```sh
fa --book ./book proof prefix --with-record \
  --state "$STATE_OID" --out ./journal.prefix --json
```

Export requires whole-book Read and Produce authority. The prefix discloses
**every checkpoint entry payload**, including entries outside the recipient's
later account/date selection. It is not a private scope index. Do not export it
where that disclosure is unauthorized. `--out` creates a new private file and
never overwrites an existing file.

On the recipient's machine, obtain and trust the exact 80-byte checkpoint
independently of the untrusted prefix. Choose the request independently too;
`KNOWN_AT` must not exceed the trusted checkpoint's `through_seq`.

```sh
fa-verify evidence production --from-prefix \
  --prefix ./journal.prefix --checkpoint ./trusted.checkpoint \
  --expect-first-seq 0 --expect-known-at "$KNOWN_AT" \
  --expect-account all --expect-days all --json
```

All four `--expect-*` options are required. Sequence bounds are inclusive;
`--expect-days` takes `FIRST:LAST` signed i32 civil-day numbers or `all`, not
calendar strings. An account selector is one exact numeric account ID in 32
hexadecimal digits, not an account code or subtree. `all` includes all accounts
or effective days; unrestricted days also include undated controls. Earlier
known-at horizons select locally from the complete trusted prefix. Pending,
Migration and control entries are journal records here, not posted balances.

The result authenticates every prefix payload and its selection fields, then
checks the selected entries' full original citation lists and entry framing.
Empty results require a valid complete witness. The metadata report identifies
`record_source: complete_native_prefix` and `separate_record_set_checked: false`:
it derives records from the prefix; it does **not** check a separately supplied
record extract. No entry or document payload bytes are printed.

## Also verify all originally cited document bytes

Supply each distinct document once, in strictly ascending document-OID order:

```sh
fa-verify evidence production documents --from-prefix \
  --prefix ./journal.prefix --checkpoint ./trusted.checkpoint \
  --expect-first-seq 0 --expect-known-at "$KNOWN_AT" \
  --expect-account all --expect-days all \
  --document "$DOCUMENT_OID" "$DOCUMENT_KIND" ./original.bin --json
```

Repeat `--document OID64 KIND FILE` for every distinct original citation target.
The kind is its decimal u8 tag. Obtain locators from the authenticated inventory;
the verifier takes expected public commitments only from authenticated entry
citations, never from these file arguments. Shared documents are hashed once
with all entry/role associations retained. Empty cited documents are mandatory.
Missing, extra, reordered, duplicate, substituted, truncated or changed files
fail the entire operation. No `--document` arguments are valid only when the
selected authenticated original citation set is empty.

The entry/citation scope is `seq_range_complete`; full document bytes are checked
by `recomputation`. This covers original citations, not supplemental evidence or
full provenance. It does not establish custody, signatures, evidence sufficiency,
role truth, accounting validity, migration visibility or permission to disclose.
A raw checkpoint is unsigned; the operator supplies the trust premise.

## Input modes and limits

`--from-prefix` accepts only native payload-complete v2 prefixes. It refuses
legacy envelope-only prefixes and balance proofs rather than silently weakening
its checks. It cannot be combined with `--record`. Without the switch, supply
the exact matching record-bearing inclusions as before; the prior v1/v2/v3
acceptance rules remain unchanged and `separate_record_set_checked` is true.

There is one 64 MiB aggregate input budget: prefix, any inclusion proofs, and
all supplied document bytes. The verifier admits at most 65,536 prefix leaves,
4,096 selected entries, and 65,536 original citation associations/distinct
documents. Each file is read against the remaining budget. Invalid syntax is
rejected before any file is opened; no successful partial report is emitted.

Library entry points are `evidence::inventory::production::prefix::verify_evidence_prefix_for`
and `evidence::inventory::production::documents::verify_document_prefix_for` in
`fa-verify`. Both return the existing metadata report types without linking the
producer or adding dependencies, a bundle format, or new trust anchors.
