# FrankenAccounting Threat and Trust Model

> Normative companion to [`registries/threat_model.toml`](../registries/threat_model.toml), [`COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENACCOUNTING.md`](../COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENACCOUNTING.md) §8.5, §14.1–§14.6, and bead `fa-oaz`.
>
> Every row in `registries/threat_model.toml` is validated at compile time by [`fa_registry::threat_model::ThreatModel`](../crates/fa-registry/src/threat_model.rs) and at gate time by [`tools/registry-check`](../tools/registry-check/src/main.rs), including foreign-key resolution against [`registries/invariants.toml`](../registries/invariants.toml), [`registries/refusal_catalog.toml`](../registries/refusal_catalog.toml), and workspace `#[test]` functions.

---

## 1. Trust Boundaries (`[[trust_boundary]]`)

| ID | Name | Posture | Trusted Actors | Untrusted Inputs | Enforcement Surface |
|---|---|---|---|---|---|
| `TB-01` | `embedded_fa` | `fa` | `host_process`, `book_key_holder` | `intent_payload`, `document_bytes`, `gql_query`, `capability_token`, `approval_record` | `fa::Book::session` / `fa_journal::post` / `fa_policy::admit` |
| `TB-02` | `cli_fa` | `fa-cli` | `local_os_user_with_book_access` | `cli_argv`, `intent_json_file`, `plan_artifact_stdin`, `imported_files` | `fa-cli::dispatch` / `fa-intents::PlanCertificate` / `fa::Book` |
| `TB-03` | `daemon_fad` | `fad` | `fad_supervisor` | `rpc_request_frame`, `caller_principal_claim`, `capability_token` | `fad::serve` / `fa-policy::admit` / `writer_lease` |
| `TB-04` | `mcp_fa_mcp` | `fa-mcp` | `launch_bound_mcp_host` | `mcp_tool_arguments`, `agent_uploaded_documents`, `document_extracted_text`, `external_descriptions` | `fa-mcp::ServerConfig::session` / `Profile::Agent` / `fa-policy::admit` |
| `TB-05` | `offline_bundle_fa_verify` | `fa-verify` | `trusted_public_key_set`, `external_witness` | `fab_bundle_bytes`, `checkpoint_bytes`, `production_receipt_bytes`, `inline_document_bytes` | `fa-verify::verify_bundle` |

### Key Boundary Invariants
1. **Authorization precedes observation (`FA-INV-10.core`):** Capability holder binding, profile restrictions (`Profile::Agent`), required operation caveats, and amount ceilings are checked before any storage read or write.
2. **Launch-bound MCP sessions (`TB-04`):** In `fa-mcp`, the caller's principal, profile, and granted operations are bound at server launch (`ServerConfig`), never overridden by per-call tool arguments.
3. **Zero-trust offline verification (`TB-05`):** `fa-verify` has zero workspace or third-party dependencies and accepts only raw `.fab` bundle bytes, trusted Ed25519 public keys, and an optional signed `ProductionReceipt`.

---

## 2. Threat Enumeration (`[[threat]]`, Plan §14.1)

| ID | Name | Boundary | Status | Mitigating Clauses | Mitigating Refusals | Residual Risk / Activating Bead |
|---|---|---|---|---|---|---|
| `FA-THR-01` | `insider_history_alteration` | `TB-01` | `live` | `FA-INV-02.payload-immutable`, `FA-INV-14.consistency`, `FA-INV-14.signed` | `FA-REF-121`, `FA-REF-127` | Unwitnessed tail rewrite if insider holds both book directory and local signing key before external witness co-signing (`fa-l3c`). |
| `FA-THR-02` | `preparer_approver_collusion` | `TB-01` | `live` | `FA-INV-10.sod`, `FA-INV-10.approval-binds-proposal`, `FA-INV-03.transition-approvals` | `FA-REF-008`, `FA-REF-012`, `FA-REF-016`, `FA-REF-111` | Out-of-band collusion by two distinct human principals with disjoint roles; surfaced post-commit by Lantern JET procedures (`fa-lantern`). |
| `FA-THR-03` | `compromised_or_confused_agent` | `TB-04` | `live` | `FA-INV-10.core`, `FA-INV-11.core`, `FA-INV-05.evidence-minimum` | `FA-REF-007`, `FA-REF-013`, `FA-REF-015`, `FA-REF-086` | Agent trunk writes fail closed (`FA-REF-013`) until draft branches (`fa-s7x`) land; untrusted content boundary marking tracked by `fa-9rw`. |
| `FA-THR-04` | `stolen_capability_token` | `TB-03` | `live` | `FA-INV-10.core`, `FA-INV-10.current-policy` | `FA-REF-011`, `FA-REF-014`, `FA-REF-022`, `FA-REF-023` | Local CLI `--as` / `--grant` outside bound `fad`/`fa-mcp` sessions uses embedded capabilities until cryptographic token minting (`fa-v62`, `fa-r3q`) lands. |
| `FA-THR-05` | `rollback_attack` | `TB-05` | `live` | `FA-INV-14.consistency`, `FA-INV-14.witnessed` | `FA-REF-094`, `FA-REF-124` | A witness refuses to cosign a rolled-back or forked history (`FA-REF-124`) and `fa-verify` checks a quorum of named witnesses; the witness policy, trust anchors and cosignatures are not yet journaled controls (`fa-qtfd`), so the verifier names its witnesses and quorum. |
| `FA-THR-06` | `privileged_material_disclosure` | `TB-05` | `live` | `FA-INV-10.core`, `FA-INV-14.public-commitment` | `FA-REF-128` | Sub-chunk redaction is disclosure-only; proven selective chunk disclosure requires 4 KiB chunk-aligned redaction contracts. |
| `FA-THR-07` | `subpoenaed_administrator_non_alteration` | `TB-05` | `live` | `FA-INV-14.signed`, `FA-INV-14.seq-range-complete`, `FA-INV-04.outsider-recomputation` | `FA-REF-127` | Staged or pre-opening migration balance proofs refuse with `FA-REF-133` until authenticated migration visibility witnesses (`fa-e00`) land. |
| `FA-THR-08` | `erasure_retention_tension` | `TB-01` | `live` | `FA-INV-05.closure`, `FA-INV-14.public-commitment` | `FA-REF-088`, `FA-REF-117` | Substrate erasure tombstones (`R-ERASE`) and per-Party subject keys (`fa-v74`) are not yet live; `ErasureCut` fails closed with `FA-REF-088` while `LegalHold` (`FA-REF-117`) is live. |

---

## 3. Surviving Public Values (`[[surviving_public_value]]`, Plan §8.5)

When an `Erasable<T>` field or document is sealed or (eventually) crypto-erased, public identifiers and digests remain in the commit stream, accumulator leaves, and certificates. Plan §8.5 requires every surviving public value derived from private or erasable input to be inventoried and protected against low-entropy guessing oracles:

1. **`SPV-01` (`entry_and_supersession_vid`):** Derived from `(book_id, principal_ref, idempotency_key)` or `target_vid` via domain-separated BLAKE3. Callers must use opaque tokens/UUIDs for `idempotency_key`, never raw PII.
2. **`SPV-02` (`proposal_and_entry_digest`):** Computed over the canonical binary wire *after* every `Erasable<T>` field is sealed with a 24-byte nonce and 32-byte salt under `SealKey`. Because the hash covers high-entropy AEAD ciphertext, `proposal_digest` and `entry_digest` never leak a plaintext guessing oracle after key destruction.
3. **`SPV-03` (`idempotency_semantic_digest`):** Keyed BLAKE3 under `Book.seal_key` over canonical logical plaintext for idempotent retry comparison. Evaluated only inside the authorized kernel boundary; refuses with `FA-REF-033` (`EQUIVALENCE_UNVERIFIABLE`) if the sealing key is unavailable.
4. **`SPV-04` (`document_public_commitment`):** `doc_commit = BLAKE3("fa:doc:v1" || kind || length || chunk_root)`. Unkeyed by design so `fa-verify` can verify disclosed 4 KiB chunks offline without book secrets.
5. **`SPV-05` (`accumulator_leaf_envelope`):** Public Merkle leaf (`LeafEnvelope`) binding `(book_id, branch_id, recorded_seq, ordinal, class, effective_day, vid, entry_digest)`. Contains zero plaintext memos or party fields.
6. **`SPV-06` (`plan_and_report_certificate`):** Binds structural coordinates, witness sets, exact integer mantissas, and randomized `proposal_digest`. Amounts, accounts, dates, and lineage are never in erasure scope.

---

## 4. Tamper Matrix (`[[tamper_vector]]`, INT-10)

| ID | Artifact | Tamper Action | Detected By | Refusal / Grade | Executable Negative Test |
|---|---|---|---|---|---|
| `TV-01` | `entry_payload` | Flip byte in committed `EntryPayload` or leg mantissa | `fa_model::Entry::decode` / `fa_verify::envelope` | `EntryError::DigestMismatch` / `Grade::Fail(record)` | `fa-model::lib::entry::tests::tampered_bytes_are_refused` |
| `TV-02` | `register_cell` | Mutate register balance, insert phantom zero cell, or corrupt watermark | `fa_registers::verify_registers` | `RegisterDrift` (`FA-INV-04.core`) | `fa-registers::tests/registers.rs::materialize_then_verify_is_green_and_a_tampered_register_is_drift` |
| `TV-03` | `projection_mirror` | Alter `Leg` scalar mirror or drop `HAS_LEG` / `POSTS_TO` edge | `fa_journal::verify_projections` | `ProjectionDrift` (`FA-INV-16.core`) | `fa-journal::tests/genesis.rs::projection_verifier_detects_every_scalar_mirror_and_preserves_known_at` |
| `TV-04` | `document_blob` | Modify or delete document blob so bytes disagree with `doc_commit` | `fa_journal::read_document` / `fa_verify::verify_bundle` | `FA-REF-085` / `FA-REF-116` / `Grade::Fail(public_commitment)` | `fa-journal::tests/genesis.rs::an_external_document_reads_back_verified_and_a_missing_or_changed_blob_is_refused` |
| `TV-05` | `accumulator_state` | Forge `AccumulatorState` root or claim non-extending sequence | `fa_notary::verify_accumulator` / `fa_notary::checkpoint` | `FA-REF-121` / `FA-REF-124` | `fa-notary::tests/notary.rs::recomputation_finds_a_forged_state_and_blocks_checkpoints_over_it` |
| `TV-06` | `transparency_checkpoint` | Flip bit in `TransparencyCheckpoint` signature/body or use untrusted key | `fa_notary::verify_accumulator` / `fa_verify::verify_bundle` | `FA-REF-127` / `Grade::Fail(checkpoint)` | `fa-notary::tests/notary.rs::a_tampered_stored_checkpoint_is_a_finding_and_refused` |
| `TV-07` | `bundle_omitted_or_padded_entry` | Omit in-scope entry or pad out-of-scope entry in `.fab` bundle | `fa_verify::verify_bundle` | `Grade::Fail(entries)` | `fa-notary::tests/notary.rs::planted_bundle_defects_fail_the_predicate_they_break` |
| `TV-08` | `bundle_swapped_payload` | Swap entry payloads under `LeafEnvelope`s or drop cited document stub | `fa_verify::verify_bundle` | `Grade::Fail(record)` / `Grade::Fail(closure)` | `fa-notary::tests/notary.rs::planted_bundle_defects_fail_the_predicate_they_break` |
| `TV-09` | `bundle_production_receipt` | Attach `ProductionReceipt` over wrong bundle, untrusted key, or flipped bit | `fa_verify::verify_bundle` | `Grade::Fail(production_receipt)` | `fa-notary::tests/notary.rs::planted_bundle_defects_fail_the_predicate_they_break` |
| `TV-10` | `plan_certificate` | Tamper with `PlanCertificate`, change caller principal, or commit stale basis | `fa_cli::dispatch` / `fa_journal::post` | `FA-REF-034` (`PLAN_INVALIDATED`) | `fa-cli::tests/plans.rs::tampered_wrong_caller_and_stale_plans_cannot_publish_or_consume_the_key` |

---

## 5. Storage-Level Tamper-Evidence Red-Team Matrix (`fa-70o`)

Executed end-to-end against real persisted directory books in [`crates/fa-cli/tests/tamper.rs`](../crates/fa-cli/tests/tamper.rs) (`tamper_evidence_red_team_matrix`). An adversary holding the book's substrate keys (`book.keys`) mutates the store (`fgdb::Database` + `WriteBatch`) or filesystem blobs directly, bypassing Folio:

| ID | Storage-Level Attack | Detector / Claim Boundary | Invariant / Gate | Observed Exit | Finding / Status |
|---|---|---|---|---|---|
| `T01` | Rewrite `Entry._fa_payload` without recomputing `_fa_digest` | `fa verify accumulator --json` | `FA-INV-14 / FA-INV-04` | `8` | `entry accumulator differs from the journal: 2 state findings, 0 unchained states` |
| `T02` | Rewrite `Entry._fa_payload` and recompute `_fa_digest` in place | `fa verify accumulator --json` | `FA-INV-14 / FA-INV-04` | `8` | `entry accumulator differs from the journal: 2 state findings, 0 unchained states` (`checkpointed journal entry <vid>` head vs prefix mismatch) |
| `T03` | Retire (delete) a committed `Entry` vertex from the store | `fa verify accumulator --json` | `FA-INV-14 / FA-INV-04` | `8` | `entry accumulator differs from the journal: 2 state findings, 0 unchained states` (`checkpointed journal entry <vid> was retired or is absent`) |
| `T04` | Insert a back-dated `Entry` vertex with forged watermark (`IdentitySpent` blocks `VId` reuse) | `fa verify registers --period FY2026-P03 --json` | `FA-INV-04 / FA-INV-06` | `8` | `stored registers differ from the refold in FY2026-P03; ... 2 posted cells differ` |
| `T05` | Edit a `Leg` vertex scalar mirror (`side` / `amount`) in place | `fa verify projections --json` | `FA-INV-16` | `8` | `leg projections differ from canonical entry payloads: entry <vid> leg 0: side mirror differs from the payload` |
| `T06` | Edit a materialized `Register` cell (`debits_posted` + `watermark`) | `fa verify registers --period FY2026-P03 --json` | `FA-INV-04` | `8` | `stored registers differ from the refold in FY2026-P03; ... 1 posted cells differ` |
| `T07` | Delete or corrupt a committed `AccumulatorState` vertex | `fa verify accumulator --json` | `FA-INV-14` | `8` | `entry accumulator differs from the journal: 0 state findings, 3 unchained states; broken chain: accumulator state <oid> is named but absent` |
| `T08` | Truncate `ACCUMULATOR_HEAD` to an earlier checkpoint OID | `fa verify accumulator --json` | `FA-INV-14` | `8` | `entry accumulator differs from the journal: 0 state findings, 2 unchained states` |
| `T09` | Swap inline `Document` payload bytes in the substrate | `fa document read <oid> --json` | `FA-INV-05 (FA-REF-085)` | `8` | `document <oid>: the payload is not the document this vertex's identity names` |
| `T10` | Swap external blob bytes in `<book>/blobs/<shard>/<locator>` | `fa document read <oid> --json` | `FA-INV-05 (FA-REF-085)` | `8` | `document <oid>: the stored bytes do not reproduce the recorded size and commitment` |
| `T11` | Edit a `LimitCell` availability witness (`debits_posted`) | `fa verify availability --json` | `FA-INV-04` | `8` | `1 limited accounts' stored cells differ from the refold` |
| `T12` | Edit an open-item `Leg.applied` settlement mirror in place | `fa verify open-items --json` | `FA-INV-04` | `8` | `1 applied mirrors differ from the open-item fold` |
| `T13` | Edit `Period.state` mirror (`Open` -> `SoftClosed`) without a `PeriodControl` entry | `fa verify periods --json` | `FA-INV-02` | `8` | `1 period state or mirror discrepancy(s) found: period FY2026-P03 state mirror is SoftClosed, but journaled transitions from Future refold to Open` |
| `T14` | Roll the book directory back to an older checkpointed snapshot | `fa verify accumulator --json` (`undetectable_until = "witnessed checkpoints (fa-l3c)"` locally; out-of-band: `fa-verify consistency / checkpoint against retained external witness receipt`) | `FA-INV-14` | `0` | Local verify exits `0` (`undetectable_until = "witnessed checkpoints (fa-l3c)"`) |
| `T15` | Wholesale rewrite of the book directory with a fresh self-consistent chain | `fa verify accumulator --json` (`undetectable_until = "witnessed checkpoints (fa-l3c)"` locally; out-of-band: `fa-verify checkpoint / bundle against out-of-band witnessed root`) | `FA-INV-14` | `0` | Local verify exits `0` (`undetectable_until = "witnessed checkpoints (fa-l3c)"`) |

### Explicit No-Claim Boundary
An adversary who holds both the book directory and the book's signing keys (`book.keys`) — and faces no external witness holding a previously exported or co-signed `TransparencyCheckpoint` (`fa-l3c`) — can always roll the entire directory back to an older checkpointed snapshot (`T14`) or replace the directory with a freshly generated, self-consistent journal and checkpoint chain (`T15`). Local `fa verify` proves internal consistency of the local store against its own journal and checkpoints; detecting whole-directory rollback or wholesale history replacement requires an out-of-band witnessed checkpoint verified via `fa-verify`.
