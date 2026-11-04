# Source text must remain data in plaintext exports

Complex source records can contain newlines, semicolons, quotes, literal
backslashes and meaningful boundary whitespace. Exporting those fields must
not create accounting instructions or silently change retained descriptions.

## Defects reproduced with a real native executable

An isolated synthetic regression book, explicitly separate from the published
House/HMRC datasets, posted a balanced **$12,345.67** expense with two native
legs. Its memo contained newlines followed by posting-shaped text. The original
Beancount writer inserted that memo directly into a line comment, so the later
lines became two extra postings. Actual Beancount 3.2.0 parsed four postings
and an expense of **$1,012,344.67**. Its two exported balance assertions failed,
and `bean-check` exited one. The native book itself still held the original
two-leg amount.

The same book's description, `Invoice; vendor note`, exposed a second defect:
actual hledger 1.52.4 read only `Invoice` as the description. The semicolon
started a comment even though it came from source text.

The frozen native artifact came from
`68b80d4e6c916013582832626f92edb0d50be08e`. Its original
`crates/fa-formats/src/beancount.rs` is byte-identical to the module committed
before this repair: Git blob `1fb32cf8b3eff93c881e8a7b04c4863f95c1b31f`.
This establishes a native pre-repair reproduction, not a simulation of the
original writer. The
[retained evidence](../../evidence/conformance/plaintext-source-text-2026-11-04.json)
identifies the original inputs, exports, external diagnostics and validation
boundaries.

## Repair

Beancount quoted strings use a single-pass escape encoder/decoder for quotes,
literal backslashes, newlines, carriage returns, tabs, backspaces and form
feeds. A memo that cannot be preserved by the original inline-comment spelling
is emitted as posting metadata containing its exact UTF-8 bytes in hex. Its
newlines therefore cannot become additional postings. Empty and boundary-space
memos retain their distinction from an absent memo.

Hledger's unquoted grammar uses readable single-line descriptions and explicit
hex metadata whenever a delimiter or whitespace would change the original
text. Account metadata scanning stops before the final free-text account name:
a name containing `fa_code:...` cannot replace the declared account identity.

Both formats preserve unsafe book names in an additive versioned field. The
readers continue to accept ordinary earlier exports. Safe text retains its
ordinary spelling; no blanket rewriting of the journal is required.

| Location | Additive field | Meaning |
| --- | --- | --- |
| Either format's header | `fa_book_name_hex_v1` | Exact UTF-8 book name |
| Beancount posting metadata | `fa_memo_hex_v1` | Exact UTF-8 posting memo |
| Hledger account comment | `fa_code_hex_v1`, `fa_name_hex_v1` | Exact original account code/name |
| Hledger transaction comment | `fa_entry_id_hex_v1`, `fa_description_hex_v1` | Exact entry ID/description |

Hex fields are encoded from UTF-8 bytes, not Unicode code-point numbers.
Malformed hex and invalid UTF-8 refuse; duplicate, misplaced or incorrectly
indented Beancount memo metadata refuses. This extension does not expand
hledger's narrower accounting profile to retain posting memos, migration
provenance or balance assertions that its existing native reader omits.

The repair also chooses the earliest effective date across **all** entries and
assertions when opening Beancount accounts. Recorded order may differ from
effective-date order, so using only the first recorded entry could leave an
older imported transaction before its account's opening date.

## Validation and its limits

The text utilities and memo-suffix construction are in the real production
module `crates/fa-formats/src/beancount/text.rs`, called by the writer/reader.
Its focused tests can compile and execute with the pinned compiler without
loading the native storage/runtime dependency graph. They exercise the actual
production codecs, not copied stand-ins or a substitute accounting engine.
**All eight production-codec tests passed** with the pinned compiler, including
the memo-to-extra-postings negative, absent/empty/whitespace distinctions,
all ASCII control bytes, Unicode, literal backslashes and malformed encodings.
An independently reviewed assembler importing this same compiled production
module also passed **five cases, 31 commands and 30 checks** with actual
Beancount and hledger. Injection-shaped text, empty values, whitespace/CRLF,
controls/Unicode and an absent memo each retained one transaction, two postings
and the expected **±$12,345.67** balances. Beancount preserved exact narration;
hledger retained exact source narration and IDs in the explicit metadata.
The evidence embeds the small assembler and comparator sources, exact commands,
tool versions and hashes. This is production-codec integration, not execution
of a rebuilt native ledger.

```bash
TEXT_TESTS="$(mktemp -d)"
rustc +nightly-2026-08-31 --edition=2024 --test \
  crates/fa-formats/src/beancount/text.rs --out-dir "$TEXT_TESTS"
"$TEXT_TESTS/text"
```

The eight whole-format regressions in
`crates/fa-formats/tests/plaintext_text.rs` additionally cover exact journal
identity, posting counts, hledger metadata isolation and legacy account-opening
dates. They should be run with the complete crate and followed by a fresh
native build and the external oracle:

```bash
cargo +nightly-2026-08-31 test --locked \
  -Z bindeps -Z git=shallow-deps -p fa-formats --test plaintext_text
cargo +nightly-2026-08-31 test --locked \
  -Z bindeps -Z git=shallow-deps -p fa-formats
```

**Whole-crate compilation, these eight tests, and a repaired native executable
remain UNRUN in the recorded session.** The pinned `asupersync` compiler was
terminated by SIGKILL before reaching `fa-formats`, including one-job/no-debug,
optimization-disabled, Cranelift and deferred-unused-codegen attempts. The
workspace metadata-only check reached the same resource failure. No complete
Tier 0 or Tier 1 success is claimed.

Actual Beancount/hledger grammar checks and the separately executed
[external monetary differential](plaintext-external-oracle.md) complement the
production-codec tests, but do not replace those unrun whole-format regressions.
The real House and HMRC native runs identify their frozen baseline explicitly;
they must not be relabeled as runs of this repaired writer.
