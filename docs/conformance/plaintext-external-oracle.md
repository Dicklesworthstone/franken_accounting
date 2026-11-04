# External Beancount and hledger differential on public records

`scripts/plaintext_oracle.py` runs the actual `bean-check`, `bean-query` and
`hledger` executables against untouched native exports. It compares every
account/currency cell with the native CSV GL export using exact integer minor
units: signed net balance, separate gross debits and credits, and total and
directional posting counts. A balanced journal can still be wrong; matching a
grand total or merely passing `bean-check` is insufficient.

This implements a bounded part of plan §16.3 / `fa-sa4w`. The
[earlier matrix](beancount.md) remains a self round-trip result. The external
result below is separately executed evidence, and does not close the bead's
requirement to cover every fixture, lots and documented valuation divergences.

The related [source-text repair and regression record](plaintext-source-text.md)
documents a native memo that became additional Beancount postings and a
semicolon-truncated hledger description. Its production text codecs have
separate compiled tests; that record explicitly distinguishes them from the
whole-crate/native rebuild that the session's memory limit prevented.

## Executed public-data result

On 2026-11-03 all three tools accepted the complete HMRC March 2025 published
expenditure model: **1,430 source records, 127 native migration entries, 2,860
postings and 135 account/GBP cells**. All 11 external commands exited zero and
all nine comparison/preservation checks passed. The original extract contains
125 negative records, one additional exact duplicate, 71 split transaction
references and 134 expense types. The source model retains them; it does not
discard credits or deduplicate the publication.

The native `fa` / `fa-verify` artifacts in this observation came from frozen
commit **`68b80d4e6c916013582832626f92edb0d50be08e`**. This is an external-tool
acceptance of that baseline's exports, **not execution evidence for later Rust
changes in the current tree**. The new Python helper and its exact SHA-256 are
identified independently. The native replay itself completed 29 checks over
100 CLI calls; its report and executable hashes are included in the compact
[execution evidence](../../evidence/public_spend/hmrc-2025-03-plaintext-oracle-2026-11-03.json).
That evidence includes the original tool report, versions, complete command
arguments, exits, stdout/stderr hashes, compared-controls digest and input hashes.
Large journals and tool outputs are retained by each local run rather than
copied into Git.

| Coordinate or tool | Observed value |
|---|---|
| Book | `Published expenditure model: hmrc-2025-03` |
| Effective through | `2025-03-31` |
| Known at | `554` |
| Native base unit | `GBP@2` |
| Beancount | `3.2.0` |
| beanquery | `0.2.0`, using Beancount `3.2.0` |
| hledger | `1.52.4`, Linux x86-64 |

The [publisher's original release](https://www.gov.uk/government/publications/hmrc-spending-over-25000-march-2025)
and the pinned bytes in `tools/public-data/sources.toml` define the source.
The [public expenditure acquisition and native replay guide](../../tools/public-data/README.md)
explains preparation, source reconciliation, custody, approvals and certified
replay. HMRC supplies published payment observations, not its original complete
double-entry general ledger. The helper tests the declared expense/offset
analysis model; the offset account is explicit modeling, not a recovered
departmental cash or payable account.

## Install the exercised external tools

Python 3.11 or newer runs the helper using only the standard library. External
tools are test executables, not linked accounting-engine dependencies. For the
same versions on Linux x86-64, use a fresh tools directory:

```sh
ORACLE_TOOLS="$(mktemp -d)"
python3 -m venv "$ORACLE_TOOLS/python"
"$ORACLE_TOOLS/python/bin/python" -m pip install 'beancount==3.2.0' 'beanquery==0.2.0'
curl --fail --location \
  --output "$ORACLE_TOOLS/hledger-linux-x64.tar.gz" \
  https://github.com/hledgerorg/hledger/releases/download/1.52.4/hledger-linux-x64.tar.gz
printf '%s  %s\n' \
  f76a2e4088e162b7658e43077502569d5a6fdacd219b19bfb9aab6588b69643a \
  "$ORACLE_TOOLS/hledger-linux-x64.tar.gz" | sha256sum --check
mkdir "$ORACLE_TOOLS/hledger"
tar -xzf "$ORACLE_TOOLS/hledger-linux-x64.tar.gz" -C "$ORACLE_TOOLS/hledger" hledger
"$ORACLE_TOOLS/python/bin/bean-check" --version
"$ORACLE_TOOLS/python/bin/bean-query" --version
"$ORACLE_TOOLS/hledger/hledger" --version
```

`bean-query` is supplied by the separate
[beanquery project](https://github.com/beancount/beanquery). The upstream
[Beancount query language](https://beancount.github.io/docs/beancount_query_language/)
and [hledger 1.52 manual](https://hledger.org/1.52/hledger.html) document the
query/report interfaces. The harness rejects unexpected output schemas instead
of guessing how another tool version represents a balance.

## Export one coordinate and run

Choose an explicit known-at sequence and the same period for all three native
exports. These example values are the exercised HMRC coordinate; set `FA` and
`BOOK` to the executable and already imported book being tested:

```sh
FA=/absolute/path/to/fa
BOOK=/absolute/path/to/imported/book
EXPORTS="$(mktemp -d)"
"$FA" --book "$BOOK" export csv-gl --period FY2025-P03 --as-known-at 554 \
  --out "$EXPORTS/native.csv" --json
"$FA" --book "$BOOK" export beancount --period FY2025-P03 --as-known-at 554 \
  --out "$EXPORTS/journal.beancount" --json
"$FA" --book "$BOOK" export hledger --period FY2025-P03 --as-known-at 554 \
  --out "$EXPORTS/journal.hledger" --json
python3 -B scripts/plaintext_oracle.py \
  --csv-gl "$EXPORTS/native.csv" \
  --beancount "$EXPORTS/journal.beancount" \
  --hledger-journal "$EXPORTS/journal.hledger" \
  --bean-check "$ORACLE_TOOLS/python/bin/bean-check" \
  --bean-query "$ORACLE_TOOLS/python/bin/bean-query" \
  --hledger "$ORACLE_TOOLS/hledger/hledger" \
  --out "$EXPORTS/external-oracle"
```

Executable flags are optional when all three programs are on `PATH`.
`--timeout` sets a per-command limit in seconds, default 300. `--out` must be a
new directory. Inputs are copied byte-for-byte into `inputs/`; the originals,
snapshots and executable files are hashed before and after execution. No text
rewriting, implied-account repair or journal normalization precedes the tools.

The output contains `report.json`, exact CSV-derived `expected.json`,
`hledger-posting-controls.json`, `inputs.json`, `commands.jsonl` and every raw
stdout/stderr file. Each transcript row records the exact argument array,
exit status, elapsed milliseconds, byte counts and SHA-256 hashes. The command
line prints a compact JSON summary and exits **0 for PASS, 1 for FAIL, 4 for
UNRUN**. An absent executable before execution yields UNRUN without creating
an output directory. A timeout or startup failure during execution preserves
the partial transcript and an UNRUN report. Malformed data, nonzero tool exits,
diagnostics, missing cells or mismatched totals fail.

## What the comparison establishes

The input profile is native monetary exports with explicit nonzero posting
amounts, declared unit scales, and a complete native account chart. The helper
checks book name, base unit, effective cutoff, known-at sequence, content digest
and certificate digest agree across all three exports before running tools.
It validates CSV entry/leg counts and dates. Accounts map only through explicit
`fa_code` metadata in Beancount open declarations and hledger account
declarations; each mapping must agree with the CSV chart and account type, be
unique and cover the whole chart. Sanitized account names are never reversed to
guess original codes. The versioned `fa_book_name_hex_v1`, `fa_code_hex_v1` and
`fa_name_hex_v1` alternatives preserve unsafe text through strict lowercase hex
and UTF-8 decoding; duplicate raw/encoded identities are rejected. Includes,
plugins and automatic posting rules are outside this native-export profile.

Native writers preserve multiline source text as data. Beancount quoted fields
escape newline, carriage return, tab, backspace and form feed, and unsafe posting
memos use `fa_memo_hex_v1`. Hledger unsafe entry IDs and descriptions use
`fa_entry_id_hex_v1` and `fa_description_hex_v1`, alongside the account/header
extensions above. These markers encode exact UTF-8 as lowercase hex; safe older
exports remain compatible. The existing narrower hledger export profile still
excludes posting memos, `migrated_from` and assertions. Support for these markers
is separate from the frozen baseline observation reported above.

`bean-check` first validates the untouched Beancount snapshot. Three
`bean-query -f csv` queries group `sum(number)` and `count(*)` by account and
currency, once for all postings and once per sign. `hledger --no-conf ... print
-O csv` supplies independently parsed monetary postings and transaction counts.
Three `hledger balance --flat --no-total --empty -O csv` reports per currency
check net, positive and negative balances independently of the posting-control
calculation. No commodity conversion or valuation flag is used.

Every decimal is parsed into an integer at its declared scale. Scientific
notation, binary floats, fractional minor units, ambiguous/malformed schemas,
duplicate cells and missing or foreign cells are rejected. Zero-net accounts
with real activity remain in the comparison, while declared accounts with no
postings do not acquire invented monetary rows. Gross controls and counts catch
offsetting additions/removals and changes hidden by unchanged net balances.

The result does not establish original-source completeness, evidence custody,
native certificate validity, lot/cost-basis correctness, base-currency valuation,
dimensions, regulatory compliance or audited financial statements. Those need
their separate source/native/verifier checks. It also does not prove individual
posting identity when a different population preserves all compared aggregates.
Executable hashes bind the invoked files; Python launcher hashes do not bind
the entire installed dependency closure. Frozen baseline acceptance must not
be relabeled as current-tree execution.

## Run the counterexamples with real tools

```sh
FA_ORACLE_BEAN_CHECK="$ORACLE_TOOLS/python/bin/bean-check" \
FA_ORACLE_BEAN_QUERY="$ORACLE_TOOLS/python/bin/bean-query" \
FA_ORACLE_HLEDGER="$ORACLE_TOOLS/hledger/hledger" \
python3 -B -m unittest discover -s scripts/tests -p 'test_plaintext_oracle.py' -v
```

The small test books are declared synthetic controls. They cover multiple
currencies, a three-decimal unit, a zero-net active account, an unused declared
account and explicit nonreversible account-code mapping. Real tool runs reject
a one-cent balanced modification in either format, changes preserving both net
balance and total posting count while changing gross activity, extra cancelling
entries, and removal of cancelling entries from either export. Parser tests
exercise malformed/duplicate output, metadata mismatches, missing tools and
preservation of existing evidence directories. When executables are absent,
external tests explicitly skip as UNRUN; parser-test success is not external
accounting acceptance.
