# Source-bound migration completeness

Net trial balances cannot establish that a full-detail migration retained every
transaction. Omitting an increase and its exact reversal leaves every account's
net balance unchanged. The source-binding contract gives the native kernel and
the independent verifier an immutable population against which to check the
staged journal.

## Bind the prepared population before staging

`fa migrate import --action prepare --intent import.json` retains the exact
review package and then binds its complete population to an empty Open run.
Preparation still requires the current Human operator's `read`, `post` and
`migrate` authority. Binding requires no extra approver under the native
BindSource rule; each chunk and Finalize keep their independent approvals.

An identical preparation retry reuses the original package and binding. If
preparation stopped after retaining the package, the retry completes binding
without regenerating proposals. Staging an authenticated retained package for
an empty Open run also completes this step before its first chunk, after the
complete staging selection has passed syntax and identifier checks.

Prepared and show receipts expose `source_manifest_digest` and `source_complete`.
The latter is the native exact membership result: a newly bound empty run is
incomplete, and a fully staged bound run is complete even while its balances
remain invisible until Finalize. Both fields are null for an unbound run.
Existing unbound runs with staged chunks, including their finalization and
exact retries, retain their historical contract. The importer never binds
them retroactively, and show never writes a binding. An existing binding must
match the authenticated package exactly; a different package cannot replace it.

The native `bind_migration_source` facade operation binds an empty, Open
migration run to its retained prepared package. The immutable `SourceManifest`
contains the book and run identity, original RunBody digest, source and package
document OIDs and public commitments, declared source-row count, and the exact
ordered list of expected migration entry identities and proposal digests.

Binding authenticates the supplied package bytes against the retained
DocumentRecord's public commitment. The kernel decodes the package's existing
versioned envelope, immutable run-body commitment, sealed request, and sealed entry
proposals. It derives the expected migration entry identities and proposal
digests itself and requires the manifest's list to equal the package list in
order. Supplying a smaller manifest alongside the original complete package
therefore fails at native admission.

The original source document and retained package are distinct, book-scoped
documents. Both OIDs must derive from their public commitments, and the
BindSource control cites both commitments with evidence role 1. The source-row
count is declared preparation provenance. The kernel does not run a second CSV
parser or independently establish that the package's transformation of the
original source was correct.

`MigrationControl` kind 3 is BindSource. It retains the original RunBody digest
in its control origin and commits the manifest digest in its control payload.
The canonical source object and this control are published atomically. The
operation neither rewrites the RunBody nor activates staged entries. A source
root is immutable; missing or inconsistent storage under an existing binding
is corruption, never a reason to treat the run as legacy-unbound.

Source manifests use the same bounded native object fragmentation mechanism
as large migration bodies. Their format is `FA-MIGRATION-SOURCE\0`, version 1;
their digest uses the length-framed `fa:migration-source:v1` domain. The wire
population contains 1–4,096 unique entry identities. The declared row count
must be at least the number of chunks. The manifest decoder is bounded to
256 KiB. This storage avoids the ordinary inline-document payload ceiling.

## Admission, completion, and historical visibility

After binding, native staging admits only exact expected `(entry identity,
proposal digest)` members. A different proposal under the same idempotency key,
an unexpected entry, or a manifest bound after staging begins is refused.
Existing idempotent retry behavior remains in force: retrying an already
recorded identical entry does not create another journal member.

The package's source order is immutable, but members may be submitted in any
order, including through grouped staging. Finalization requires complete,
unique membership against the manifest. A passing monetary trial balance
cannot excuse a missing source member. Open and Abandoned runs may contain a
partial population; those chunks remain invisible to posted balances under
the existing migration policy.

For bound runs, both Finalize and Abandon commit the length-framed
`fa:migration-tie-out:v2` transcript: original RunBody digest, source-manifest
digest, and the canonical actual chunk list ordered by publication sequence
and entry identity. This preserves the distinction between the package's
source order and actual publication order. Historical unbound runs retain the
original v1 tie-out domain and lifecycle behavior.

Retained source reads use immutable bodies, canonical source storage, and
authoritative lifecycle controls at the requested frontier. Mutable run-state
mirrors do not supply proof inputs. Native report certificates append source
root and fragment observations after their existing ordered input queries;
certificates at older, unbound prefixes retain their prior query sequence
(FA-INV-14).

## Portable balance and report proofs

Payload-complete balance proof v4 (FA-INV-14) uses the existing v3 fields, followed by
`list(bind_leaf_index u64, bytes(source_manifest))`. Every prefix payload is
authenticated and its selectors are derived before account or effective-date
filtering. For each selected source-bound run, the verifier checks every member
of that run, including members outside the requested account, unit, or cutoff.
Finalized membership must be exact, and the terminal transcript must match
actual publication order. Neither an omitted offsetting pair nor an excluded
account can disappear behind a matching balance claim.

Report bundles preserve major versions 1, 2, and 3 and use minor 1 when source
closure is required. The new manifest-witness list follows the Open-body
witness list, before registry or functional-currency closure. The independent
reader checks the two lists against their respective control kinds. A manifest
cannot be smuggled through a legacy Open-body field. Historical comparisons
select both immutable witnesses when their earlier frontier contains staged
chunks from a bound run; a frontier before staging needs neither witness.

Legacy unbound balances retain v1/v2/v3 encoding, and legacy report bundles
retain minor 0. An explicit legacy producer refuses a selected source-bound
population rather than silently omitting its manifest. Automatically produced
bundle balances use v4 when a bound run is selected. This requires whole-book
disclosure authority because completeness includes all prefix payloads.
An empty account selection or another scope with no candidates from a bound
run makes no claim about that run's source population.

Balance and report transports remain bounded to 64 MiB including framing.
Each record or witness field is bounded to 8 MiB; the source codec's tighter
bound applies to its decoded population. Oversized closure is refused, never
truncated. Unknown manifest versions, future balance versions, and unsupported
report major/minor versions fail closed.

## What the independent check establishes

Against an independently trusted checkpoint, the source closure proves the
exact admitted proposal population committed by the native BindSource
control, its source/package locators and public commitments, historical
visibility, and the reported arithmetic. Full package bytes are not required
inside every balance or report proof: native admission authenticated the
package when binding, and the portable proof authenticates the resulting
control commitment (FA-INV-14).

This is not independent replay of the package parser, verification of the
source's economic truth, or assurance that a preparer supplied every record
that exists outside the retained source. It also does not add approval,
authorization, or economic tie-out assurance to the existing offline balance
scope. Reproduction of acquisition and transformation must retain and replay
the original source and prepared package separately.

The independent tests build their own canonical wire fixtures without using
the producer's codec. They cover exact offsetting omission, foreign or changed
members, duplicate/replayed members, late and duplicate bindings, source
substitution, invalid document identities, manifest version/shape errors,
cutoff and account exclusion, legacy downgrade, arbitrary submission order,
and report-frontier closure. Separate model-to-verifier tests exercise the
notary's v4 producer. These detached journal fixtures test proof semantics;
native admission and full import execution require the native integration
suite as well (FA-INV-14).
