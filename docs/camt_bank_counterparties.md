# Preserving counterparties from CAMT bank statements

A balanced bank statement can still identify the wrong counterparty. The old
CAMT reader selected the first descendant `Nm` anywhere beneath an entry.
In a real structured statement that name can belong to an intermediary bank,
the account holder, an account label or an ultimate party. Monetary continuity
alone does not detect the misattribution.

The reader now follows the declared transaction party role. The implementation
applies to both CAMT052 account reports and CAMT053 statements, within the
existing bounded one-statement, one-account import profile.

## Ordinary entry attribution

| Entry direction | Selected party under `NtryDtls/TxDtls/RltdPties` |
|---|---|
| `CRDT` — incoming funds | `Dbtr` |
| `DBIT` — outgoing funds | `Cdtr` |

Both the older direct `Dbtr/Nm` or `Cdtr/Nm` form and the newer
`Dbtr/Pty/Nm` or `Cdtr/Pty/Nm` form are supported. Name decoding preserves
Unicode and XML entities. For example, `Payee &quot;Europe&quot; &#x20AC;`
becomes `Payee "Europe" €`.

The selector ignores names belonging to agents, accounts, unrelated nested
elements, initiators and ultimate parties. A single transaction without its
selected party name remains unnamed. It does not borrow another role or
invent a counterparty.

The supported role structure follows the
[ISO 20022 Bank-to-Customer Cash Management V08 message definitions](https://www.iso20022.org/sites/default/files/documents/messages/mdr_part_2/ISO20022_MDRPart2_BankToCustomerCashManagement_2018_2019_v1_0.pdf)
and the direct party representation in the
[Westpac CAMT053 guide](https://www.westpac.com.au/content/dam/public/wbc/documents/pdf/col/accountsexportformatscamt053.pdf).
These references define the source semantics; the reader supports the bounded
profile described here, not every message variant in those publications.

## Batches and attribution that needs more information

The current native bank-line model retains one line per `Ntry`, including its
original entry amount. Multiple `TxDtls` therefore require a selected
counterparty name in every detail and exact agreement among those names. This
is agreement of reported text, not a claim to resolve legal identity.

The parser refuses:

- Distinct counterparties or partially named transaction details within a batch.
- A missing detail group when another group supplies transaction details.
- A declared batch count that differs from the supplied transaction population.
- A batch or transaction direction that contradicts the entry direction.
- Conflicting or ambiguous direct-name, party and agent choices.
- A positive `RvslInd` (`true` or `1`) or any `RtrInf` return information.

Reversals need original-transaction attribution: their current credit/debit
indicator is not enough to recover the ordinary debtor/creditor relationship.
The Westpac guide documents that a true reversal indicator changes how the
reported direction relates to the original entry. Returns likewise need an
explicit interpretation. The importer refuses these cases rather than
assigning a plausible but unsupported name. False or zero reversal indicators
remain valid ordinary entries.

These conditions fail before native publication. No new partial import,
source document or bank line is retained by the refused operation. A later
profile can support transaction-level splits or original-transaction
attribution while preserving the source and making its interpretation explicit.

## Compatibility and native use

The original simplified direct `Ntry/Nm` representation remains supported
without transaction details. If structured details are also present, the
direct name must agree with the complete structured attribution. It cannot
override or fill a missing structured role.

Import an admissible statement into an existing book and its configured bank
account using the normal command:

```bash
fa --book /path/to/book bank import statement.xml \
  --bank-format camt053 --account 1000 --json
```

Use `camt052` for an intraday report. The original bytes are retained as
evidence, while bank-line descriptions carry their native source-document
links. An exact retry returns the original import identity and does not move
the book head.

Existing immutable imports are not rewritten. If an older parser stored the
wrong first-name attribution, reparsing the retained source with the corrected
reader may fail source-interpretation verification. Preserve that evidence and
resolve the historical interpretation explicitly; do not relabel the old
record as if the correction had been present at import time.

## Regression checks and execution status

Six new format regressions cover both directions, both party representations,
role ordering, namespaces, Unicode/entities, missing names, legacy consistency,
homogeneous batches, incomplete or conflicting batches, and reversal/return
refusals. Existing CAMT format tests remain in place.

The new native CLI regression imports both CAMT052 and CAMT053 into fresh
books and checks original-source cold readback, both line identities and
amounts, exact decoded descriptions, native source links, atomic publication
and unchanged-head retry behavior. Four ambiguous-source mutations must refuse
without changing the head, retained-document census or original bank-line
results.

Run the actual targets with the repository's pinned toolchain:

```bash
cargo +nightly-2026-08-31 test --locked -Z bindeps -Z git=shallow-deps \
  -p fa-formats --lib camt --jobs 1 -- --nocapture

cargo +nightly-2026-08-31 test --locked -Z bindeps -Z git=shallow-deps \
  -p fa-cli --test bank camt --jobs 1 -- --nocapture
```

The hosted public-ledger workflow executes these same targets. Before
publication, whole-workspace formatting passed with the pinned compiler, as did
all-target compile checks for `fa-model`, `fa-verbs` and `fa-formats` and the
native `fa-cli` bank-test target. These checks compile the added regressions;
they do not execute them. The
[validation record](../evidence/formats/camt-counterparty-validation-2026-11-03.json)
retains source hashes, exact commands, exits and that distinction. Local runtime
tests remain unrun under the measured dependency-codegen resource limit, and
the hosted runtime results must name the revision containing this repair before
being reported as acceptance.
